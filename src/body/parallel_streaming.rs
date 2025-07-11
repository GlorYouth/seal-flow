//! Implements the common logic for parallel streaming encryption and decryption.
//! This is the backend for both symmetric and hybrid parallel streaming modes.
//!
//! 实现并行流式加密和解密的通用逻辑。
//! 这是对称和混合并行流式模式的后端。

use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::buffer::BufferPool;
use crate::common::{derive_nonce, OrderedChunk, CHANNEL_BOUND, DEFAULT_CHUNK_SIZE};
use crate::error::{Error, Result};
use crate::keys::TypedSymmetricKey;
use crate::algorithms::symmetric::SymmetricAlgorithmWrapper;
use rayon::prelude::*;
use std::collections::BinaryHeap;
use std::io::{Read, Write};
use std::sync::Arc;
use std::thread;

use super::traits::ParallelStreamingBodyProcessor;

/// The core pipeline for parallel streaming encryption.
///
/// 并行流式加密的核心管道。
fn encrypt_pipeline<R, W>(
    algorithm: SymmetricAlgorithmWrapper,
    key: TypedSymmetricKey,
    base_nonce: [u8; 12],
    mut reader: R,
    mut writer: W,
    aad: Option<&[u8]>,
) -> Result<()>
where
    R: Read + Send,
    W: Write,
{
    let aad_arc = Arc::new(aad.map(|d| d.to_vec()));
    let pool = Arc::new(BufferPool::new(DEFAULT_CHUNK_SIZE as usize));
    let tag_size = algorithm.tag_size();

    // 2. Setup channels for producer-consumer pipeline
    let (raw_chunk_tx, raw_chunk_rx) = crossbeam_channel::bounded(CHANNEL_BOUND);
    let (enc_chunk_tx, enc_chunk_rx) = crossbeam_channel::bounded(CHANNEL_BOUND);
    let (io_error_tx, io_error_rx) = crossbeam_channel::unbounded();

    thread::scope(|s| {
        // --- Thread 1: I/O Reader (Producer) ---
        // --- 线程 1: I/O 读取器 (生产者) ---
        let raw_chunk_tx_clone = raw_chunk_tx.clone();
        let pool_for_reader = Arc::clone(&pool);
        s.spawn(move || {
            let mut chunk_index = 0u64;
            loop {
                let mut buffer = pool_for_reader.acquire();
                let chunk_size = buffer.capacity();
                buffer.resize(chunk_size, 0); // Fill with 0s to get a mutable slice

                let mut bytes_read_total = 0;
                while bytes_read_total < chunk_size {
                    match reader.read(&mut buffer[bytes_read_total..]) {
                        Ok(0) => break, // EOF
                        Ok(n) => bytes_read_total += n,
                        Err(e) => {
                            pool_for_reader.release(buffer);
                            let _ = io_error_tx.send(e);
                            return; // Stop thread 停止线程
                        }
                    }
                }

                if bytes_read_total > 0 {
                    buffer.truncate(bytes_read_total);
                    if raw_chunk_tx_clone.send((chunk_index, buffer)).is_err() {
                        break; // Receiver has hung up, buffer is lost 接收端已挂起，缓冲区丢失
                    }
                    chunk_index += 1;
                } else {
                    pool_for_reader.release(buffer);
                }

                if bytes_read_total < chunk_size {
                    break; // EOF reached 已到达文件末尾
                }
            }
        });

        // --- Thread 2: Parallel Encryptor (Consumer/Producer) ---
        // --- 线程 2: 并行加密器 (消费者/生产者) ---
        let enc_chunk_tx_clone = enc_chunk_tx.clone();
        let algo_clone = algorithm.clone();
        let aad_clone = Arc::clone(&aad_arc);
        let in_pool = Arc::clone(&pool);
        let out_pool = Arc::new(BufferPool::new(DEFAULT_CHUNK_SIZE as usize + tag_size));
        let writer_pool = Arc::clone(&out_pool);
        s.spawn(move || {
            raw_chunk_rx
                .into_iter()
                .par_bridge()
                .for_each(|(index, in_buffer)| {
                    let mut out_buffer = out_pool.acquire();
                    let nonce = derive_nonce(&base_nonce, index);
                    let aad_val = aad_clone.as_deref();

                    // Resize buffer to its full capacity to get a mutable slice
                    // 将缓冲区大小调整为其全部容量以获得可变切片
                    let capacity = out_buffer.capacity();
                    out_buffer.resize(capacity, 0);

                    let result = algo_clone
                        .encrypt_to_buffer(
                            key.clone(),
                            &nonce,
                            &in_buffer,
                            &mut out_buffer,
                            aad_val,
                        )
                        .map(|bytes_written| {
                            out_buffer.truncate(bytes_written);
                            out_buffer
                        })
                        .map_err(Error::from);

                    in_pool.release(in_buffer);

                    if enc_chunk_tx_clone.send((index, result)).is_err() {
                        // If send fails, the output buffer might be lost, which is acceptable
                        // as the pipeline is shutting down.
                        // 如果发送失败，输出缓冲区可能会丢失，这是可以接受的，因为管道正在关闭。
                    }
                });
        });

        // --- Main Thread: I/O Writer (Re-sequencer) ---
        // --- 主线程: I/O 写入器 (重新排序器) ---
        let mut final_result: Result<()> = Ok(());
        let mut pending_chunks = BinaryHeap::new();
        drop(raw_chunk_tx);
        drop(enc_chunk_tx);

        let mut next_chunk_to_write = 0;
        while let Ok((index, result)) = enc_chunk_rx.recv() {
            pending_chunks.push(OrderedChunk {
                index,
                data: result,
            });

            while let Some(top_chunk) = pending_chunks.peek() {
                if top_chunk.index == next_chunk_to_write {
                    // It's safe to unwrap as we just peeked.
                    // 这里可以安全地 unwrap，因为我们刚刚 peek 过。
                    let chunk = pending_chunks.pop().unwrap();
                    match chunk.data {
                        Ok(data) => {
                            if let Err(e) = writer.write_all(&data) {
                                final_result = Err(e.into());
                                break; // Break inner while 跳出内部 while 循环
                            }
                            writer_pool.release(data);
                            next_chunk_to_write += 1;
                        }
                        Err(e) => {
                            final_result = Err(e);
                            break; // Break inner while 跳出内部 while 循环
                        }
                    }
                } else {
                    break;
                }
            }
            if final_result.is_err() {
                break; // Break outer while 跳出外部 while 循环
            }
        }

        // Check for I/O errors from the reader thread if no other error has occurred
        // 如果没有发生其他错误，检查读取器线程的 I/O 错误
        if final_result.is_ok() {
            if let Ok(e) = io_error_rx.try_recv() {
                final_result = Err(e.into());
            }
        }

        // If any error occurred, we need to clean up remaining buffers
        // 如果发生任何错误，我们需要清理剩余的缓冲区
        if final_result.is_err() {
            for chunk in pending_chunks {
                if let Ok(buf) = chunk.data {
                    writer_pool.release(buf);
                }
            }
        }

        final_result
    })
}

/// The core pipeline for parallel streaming decryption.
///
/// 并行流式解密的核心管道。
fn decrypt_pipeline<R, W>(
    algorithm: SymmetricAlgorithmWrapper,
    key: TypedSymmetricKey,
    base_nonce: [u8; 12],
    chunk_size: u32,
    mut reader: R,
    mut writer: W,
    aad: Option<&[u8]>,
) -> Result<()>
where
    R: Read + Send,
    W: Write,
{
    let encrypted_chunk_size = (chunk_size as usize) + algorithm.tag_size();
    let aad_arc = Arc::new(aad.map(|d| d.to_vec()));
    let pool = Arc::new(BufferPool::new(encrypted_chunk_size));

    // 2. Setup channels
    let (enc_chunk_tx, enc_chunk_rx) = crossbeam_channel::bounded(CHANNEL_BOUND);
    let (dec_chunk_tx, dec_chunk_rx) = crossbeam_channel::bounded(CHANNEL_BOUND);
    let (io_error_tx, io_error_rx) = crossbeam_channel::unbounded();

    thread::scope(|s| {
        // --- Thread 1: I/O Reader ---
        // --- 线程 1: I/O 读取器 ---
        let enc_chunk_tx_clone = enc_chunk_tx.clone();
        let pool_for_reader = Arc::clone(&pool);
        s.spawn(move || {
            let mut chunk_index = 0u64;
            loop {
                let mut buffer = pool_for_reader.acquire();
                let chunk_size_local = buffer.capacity();
                buffer.resize(chunk_size_local, 0);

                let mut bytes_read_total = 0;
                while bytes_read_total < chunk_size_local {
                    match reader.read(&mut buffer[bytes_read_total..]) {
                        Ok(0) => break, // EOF
                        Ok(n) => bytes_read_total += n,
                        Err(e) => {
                            pool_for_reader.release(buffer);
                            let _ = io_error_tx.send(e);
                            return;
                        }
                    }
                }

                if bytes_read_total > 0 {
                    buffer.truncate(bytes_read_total);
                    if enc_chunk_tx_clone.send((chunk_index, buffer)).is_err() {
                        break;
                    }
                    chunk_index += 1;
                } else {
                    pool_for_reader.release(buffer);
                }

                if bytes_read_total < chunk_size_local {
                    break; // EOF reached 已到达文件末尾
                }
            }
        });

        // --- Thread 2: Parallel Decryptor ---
        // --- 线程 2: 并行解密器 ---
        let dec_chunk_tx_clone = dec_chunk_tx.clone();
        let algo_clone = algorithm.clone();
        let aad_clone = Arc::clone(&aad_arc);
        let in_pool = Arc::clone(&pool);
        let out_pool = Arc::new(BufferPool::new(chunk_size as usize));
        let writer_pool = Arc::clone(&out_pool);
        s.spawn(move || {
            enc_chunk_rx
                .into_iter()
                .par_bridge()
                .for_each(|(index, in_buffer)| {
                    let mut out_buffer = out_pool.acquire();
                    let nonce = derive_nonce(&base_nonce, index);
                    let aad_val = aad_clone.as_deref();

                    // Resize buffer to its full capacity to get a mutable slice
                    // 将缓冲区大小调整为其全部容量以获得可变切片
                    let capacity = out_buffer.capacity();
                    out_buffer.resize(capacity, 0);

                    let result = algo_clone
                        .decrypt_to_buffer(
                            key.clone(),
                            &nonce,
                            &in_buffer,
                            &mut out_buffer,
                            aad_val,
                        )
                        .map(|bytes_written| {
                            out_buffer.truncate(bytes_written);
                            out_buffer
                        })
                        .map_err(Error::from);

                    in_pool.release(in_buffer);

                    if dec_chunk_tx_clone.send((index, result)).is_err() {
                        // Pipeline shutting down
                        // 管道正在关闭
                    }
                });
        });

        // --- Main Thread: I/O Writer (Re-sequencer) ---
        // --- 主线程: I/O 写入器 (重新排序器) ---
        let mut final_result: Result<()> = Ok(());
        let mut pending_chunks = BinaryHeap::new();
        drop(enc_chunk_tx);
        drop(dec_chunk_tx);

        let mut next_chunk_to_write = 0;
        while let Ok((index, result)) = dec_chunk_rx.recv() {
            pending_chunks.push(OrderedChunk {
                index,
                data: result,
            });

            while let Some(top_chunk) = pending_chunks.peek() {
                if top_chunk.index == next_chunk_to_write {
                    // It's safe to unwrap as we just peeked.
                    // 这里可以安全地 unwrap，因为我们刚刚 peek 过。
                    let chunk = pending_chunks.pop().unwrap();
                    match chunk.data {
                        Ok(data) => {
                            if let Err(e) = writer.write_all(&data) {
                                final_result = Err(e.into());
                                break;
                            }
                            writer_pool.release(data);
                            next_chunk_to_write += 1;
                        }
                        Err(e) => {
                            final_result = Err(e);
                            break;
                        }
                    }
                } else {
                    break;
                }
            }
            if final_result.is_err() {
                break;
            }
        }

        if final_result.is_ok() {
            if let Ok(e) = io_error_rx.try_recv() {
                final_result = Err(e.into());
            }
        }

        // If any error occurred, we need to clean up remaining buffers
        // 如果发生任何错误，我们需要清理剩余的缓冲区
        if final_result.is_err() {
            for chunk in pending_chunks {
                if let Ok(buf) = chunk.data {
                    writer_pool.release(buf);
                }
            }
        }

        final_result
    })
}

impl ParallelStreamingBodyProcessor for Box<dyn SymmetricAlgorithm> {
    fn encrypt_body_pipeline<'a>(
        &self,
        key: TypedSymmetricKey,
        base_nonce: [u8; 12],
        reader: Box<dyn Read + Send + 'a>,
        writer: Box<dyn Write + Send + 'a>,
        aad: Option<&'a [u8]>,
    ) -> Result<()> {
        encrypt_pipeline(self.algorithm().into_symmetric_wrapper(), key, base_nonce, reader, writer, aad)
    }

    fn decrypt_body_pipeline<'a>(
        &self,
        key: TypedSymmetricKey,
        base_nonce: [u8; 12],
        reader: Box<dyn Read + Send + 'a>,
        writer: Box<dyn Write + Send + 'a>,
        aad: Option<&'a [u8]>,
    ) -> Result<()> {
        decrypt_pipeline(
            self.algorithm().into_symmetric_wrapper(),
            key,
            base_nonce,
            DEFAULT_CHUNK_SIZE,
            reader,
            writer,
            aad,
        )
    }
}
