//! Implements the common logic for parallel streaming encryption and decryption.
//! This is the backend for both symmetric and hybrid parallel streaming modes.
//!
//! 实现并行流式加密和解密的通用逻辑。
//! 这是对称和混合并行流式模式的后端。

use crate::common::buffer::BufferPool;
use crate::common::header::SymmetricParams;
use crate::common::{derive_nonce, OrderedChunk};
use crate::error::{Error, FormatError, Result};
use seal_crypto_wrapper::prelude::TypedSymmetricKey;
use seal_crypto_wrapper::wrappers::symmetric::SymmetricAlgorithmWrapper;
use rayon::prelude::*;
use std::borrow::Cow;
use std::collections::BinaryHeap;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::sync::Arc;
use crossbeam_utils::thread;

// --- Encryptor ---

pub struct ParallelStreamingEncryptor<'a> {
    pub symmetric_params: SymmetricParams,
    pub(crate) aad: Option<Vec<u8>>,
    pub(crate) channel_bound: usize,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> ParallelStreamingEncryptor<'a> {
    pub(crate) fn new(
        symmetric_params: SymmetricParams,
        aad: Option<Vec<u8>>,
        channel_bound: usize,
    ) -> Self {
        Self {
            symmetric_params,
            aad,
            channel_bound,
            _lifetime: PhantomData,
        }
    }

    pub fn run<R, W>(self, mut reader: R, mut writer: W, key: Cow<'a, TypedSymmetricKey>) -> Result<()>
    where
        R: Read + Send,
        W: Write + Send,
    {
        if self.symmetric_params.algorithm != key.algorithm() {
            return Err(Error::Format(FormatError::InvalidKeyType.into()));
        }

        let algorithm = SymmetricAlgorithmWrapper::from_enum(self.symmetric_params.algorithm);

        let key = Arc::new(key.into_owned());
        let aad_arc = Arc::new(self.aad);
        let pool = Arc::new(BufferPool::new(self.symmetric_params.chunk_size as usize));
        let tag_size = algorithm.tag_size();
        let base_nonce = self.symmetric_params.base_nonce;

        let (raw_chunk_tx, raw_chunk_rx) = crossbeam_channel::bounded(self.channel_bound);
        let (enc_chunk_tx, enc_chunk_rx) = crossbeam_channel::bounded(self.channel_bound);
        let (io_error_tx, io_error_rx) = crossbeam_channel::unbounded();

        thread::scope(|s| {
            let raw_chunk_tx_clone = raw_chunk_tx.clone();
            let pool_for_reader = Arc::clone(&pool);
            s.spawn(move |_| {
                let mut chunk_index = 0u64;
                loop {
                    let mut buffer = pool_for_reader.acquire();
                    let chunk_size = buffer.capacity();
                    buffer.resize(chunk_size, 0);

                    let mut bytes_read_total = 0;
                    while bytes_read_total < chunk_size {
                        match reader.read(&mut buffer[bytes_read_total..]) {
                            Ok(0) => break,
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
                        if raw_chunk_tx_clone.send((chunk_index, buffer)).is_err() {
                            break;
                        }
                        chunk_index += 1;
                    } else {
                        pool_for_reader.release(buffer);
                    }

                    if bytes_read_total < chunk_size {
                        break;
                    }
                }
            });

            let enc_chunk_tx_clone = enc_chunk_tx.clone();
            let algo_clone = algorithm.clone();
            let aad_clone = Arc::clone(&aad_arc);
            let in_pool = Arc::clone(&pool);
            let out_pool = Arc::new(BufferPool::new(self.symmetric_params.chunk_size as usize + tag_size));
            let writer_pool = Arc::clone(&out_pool);
            let key_clone = Arc::clone(&key);
            s.spawn(move |_| {
                raw_chunk_rx
                    .into_iter()
                    .par_bridge()
                    .for_each(|(index, in_buffer)| {
                        let mut out_buffer = out_pool.acquire();
                        let nonce = derive_nonce(&base_nonce, index);
                        let aad_val = aad_clone.as_deref();
                        let capacity = out_buffer.capacity();
                        out_buffer.resize(capacity, 0);

                        let result = algo_clone
                            .encrypt_to_buffer(
                                &in_buffer,
                                &mut out_buffer,
                                key_clone.as_ref(),
                                &nonce,
                                aad_val,
                            )
                            .map(|bytes_written| {
                                out_buffer.truncate(bytes_written);
                                out_buffer
                            })
                            .map_err(Error::from);

                        in_pool.release(in_buffer);

                        if enc_chunk_tx_clone.send((index, result)).is_err() {}
                    });
            });

            let mut final_result: Result<()> = Ok(());
            let mut pending_chunks = BinaryHeap::new();
            drop(raw_chunk_tx);
            drop(enc_chunk_tx);

            let mut next_chunk_to_write = 0;
            while let Ok((index, result)) = enc_chunk_rx.recv() {
                pending_chunks.push(OrderedChunk { index, data: result });

                while let Some(top_chunk) = pending_chunks.peek() {
                    if top_chunk.index == next_chunk_to_write {
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

            if final_result.is_err() {
                for chunk in pending_chunks {
                    if let Ok(buf) = chunk.data {
                        writer_pool.release(buf);
                    }
                }
            }

            final_result
        }).unwrap()
    }
}

// --- Decryptor ---

pub struct ParallelStreamingDecryptor<'a> {
    pub(crate) algorithm: SymmetricAlgorithmWrapper,
    pub(crate) nonce: Box<[u8]>,
    pub(crate) aad: Option<Vec<u8>>,
    pub(crate) chunk_size: usize,
    pub(crate) channel_bound: usize,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> ParallelStreamingDecryptor<'a> {
    pub(crate) fn new(
        algorithm: SymmetricAlgorithmWrapper,
        nonce: Box<[u8]>,
        aad: Option<Vec<u8>>,
        chunk_size: usize,
        channel_bound: usize,
    ) -> Self {
        Self {
            algorithm,
            nonce,
            aad,
            chunk_size,
            channel_bound,
            _lifetime: PhantomData,
        }
    }

    pub fn run<R, W>(self, mut reader: R, mut writer: W, key: Cow<'a, TypedSymmetricKey>) -> Result<()>
    where
        R: Read + Send,
        W: Write + Send,
    {
        let encrypted_chunk_size = self.chunk_size + self.algorithm.tag_size();
        let key = Arc::new(key.into_owned());
        let aad_arc = Arc::new(self.aad);
        let pool = Arc::new(BufferPool::new(encrypted_chunk_size));
        let base_nonce = self.nonce;

        let (enc_chunk_tx, enc_chunk_rx) = crossbeam_channel::bounded(self.channel_bound);
        let (dec_chunk_tx, dec_chunk_rx) = crossbeam_channel::bounded(self.channel_bound);
        let (io_error_tx, io_error_rx) = crossbeam_channel::unbounded();

        thread::scope(|s| {
            let enc_chunk_tx_clone = enc_chunk_tx.clone();
            let pool_for_reader = Arc::clone(&pool);
            s.spawn(move |_| {
                let mut chunk_index = 0u64;
                loop {
                    let mut buffer = pool_for_reader.acquire();
                    let chunk_size_local = buffer.capacity();
                    buffer.resize(chunk_size_local, 0);

                    let mut bytes_read_total = 0;
                    while bytes_read_total < chunk_size_local {
                        match reader.read(&mut buffer[bytes_read_total..]) {
                            Ok(0) => break,
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
                        break;
                    }
                }
            });

            let dec_chunk_tx_clone = dec_chunk_tx.clone();
            let algo_clone = self.algorithm.clone();
            let aad_clone = Arc::clone(&aad_arc);
            let in_pool = Arc::clone(&pool);
            let out_pool = Arc::new(BufferPool::new(self.chunk_size));
            let writer_pool = Arc::clone(&out_pool);
            let key_clone = Arc::clone(&key);
            s.spawn(move |_| {
                enc_chunk_rx
                    .into_iter()
                    .par_bridge()
                    .for_each(|(index, in_buffer)| {
                        let mut out_buffer = out_pool.acquire();
                        let nonce = derive_nonce(&base_nonce, index);
                        let aad_val = aad_clone.as_deref();
                        let capacity = out_buffer.capacity();
                        out_buffer.resize(capacity, 0);

                        let result = algo_clone
                            .decrypt_to_buffer(
                                &in_buffer,
                                &mut out_buffer,
                                key_clone.as_ref(),
                                &nonce,
                                aad_val,
                            )
                            .map(|bytes_written| {
                                out_buffer.truncate(bytes_written);
                                out_buffer
                            })
                            .map_err(Error::from);

                        in_pool.release(in_buffer);

                        if dec_chunk_tx_clone.send((index, result)).is_err() {}
                    });
            });

            let mut final_result: Result<()> = Ok(());
            let mut pending_chunks = BinaryHeap::new();
            drop(enc_chunk_tx);
            drop(dec_chunk_tx);

            let mut next_chunk_to_write = 0;
            while let Ok((index, result)) = dec_chunk_rx.recv() {
                pending_chunks.push(OrderedChunk { index, data: result });

                while let Some(top_chunk) = pending_chunks.peek() {
                    if top_chunk.index == next_chunk_to_write {
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
            if final_result.is_err() {
                for chunk in pending_chunks {
                    if let Ok(buf) = chunk.data {
                        writer_pool.release(buf);
                    }
                }
            }

            final_result
        }).unwrap()
    }
}
