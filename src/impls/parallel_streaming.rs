//! Implements the common logic for parallel streaming encryption and decryption.
use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::buffer::BufferPool;
use crate::common::header::{derive_nonce, DEFAULT_CHUNK_SIZE};
use crate::error::{Error, Result};
use bytes::BytesMut;
use rayon::prelude::*;
use std::collections::BinaryHeap;
use std::io::{Read, Write};
use std::sync::Arc;
use std::thread;

const CHANNEL_BOUND: usize = 16; // Bound the channel to avoid unbounded memory usage

/// A wrapper for chunks to allow ordering in a min-heap.
pub(crate) struct OrderedChunk {
    pub(crate) index: u64,
    pub(crate) data: Result<BytesMut>,
}

impl PartialEq for OrderedChunk {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
    }
}

impl Eq for OrderedChunk {}

impl PartialOrd for OrderedChunk {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrderedChunk {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Create a min-heap on the index by reversing the comparison
        other.index.cmp(&self.index)
    }
}

/// The core pipeline for parallel streaming encryption.
pub fn encrypt_pipeline<S, R, W>(
    key: S::Key,
    base_nonce: [u8; 12],
    mut reader: R,
    mut writer: W,
    aad: Option<&[u8]>,
) -> Result<()>
where
    S: SymmetricAlgorithm,
    S::Key: Sync + Send,
    R: Read + Send,
    W: Write,
{
    let key_arc = Arc::new(key);
    let aad_arc = Arc::new(aad.map(|d| d.to_vec()));
    let pool = Arc::new(BufferPool::new(DEFAULT_CHUNK_SIZE as usize));

    // 2. Setup channels for producer-consumer pipeline
    let (raw_chunk_tx, raw_chunk_rx) = crossbeam_channel::bounded(CHANNEL_BOUND);
    let (enc_chunk_tx, enc_chunk_rx) = crossbeam_channel::bounded(CHANNEL_BOUND);
    let (io_error_tx, io_error_rx) = crossbeam_channel::unbounded();

    thread::scope(|s| {
        // --- Thread 1: I/O Reader (Producer) ---
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
                            return; // Stop thread
                        }
                    }
                }

                if bytes_read_total > 0 {
                    buffer.truncate(bytes_read_total);
                    if raw_chunk_tx_clone.send((chunk_index, buffer)).is_err() {
                        break; // Receiver has hung up, buffer is lost
                    }
                    chunk_index += 1;
                } else {
                    pool_for_reader.release(buffer);
                }

                if bytes_read_total < chunk_size {
                    break; // EOF reached
                }
            }
        });

        // --- Thread 2: Parallel Encryptor (Consumer/Producer) ---
        let enc_chunk_tx_clone = enc_chunk_tx.clone();
        let key_clone = Arc::clone(&key_arc);
        let aad_clone = Arc::clone(&aad_arc);
        let in_pool = Arc::clone(&pool);
        let out_pool = Arc::new(BufferPool::new(DEFAULT_CHUNK_SIZE as usize + S::TAG_SIZE));
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
                    let capacity = out_buffer.capacity();
                    out_buffer.resize(capacity, 0);

                    let result = S::encrypt_to_buffer(
                        &key_clone,
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
                    }
                });
        });

        // --- Main Thread: I/O Writer (Re-sequencer) ---
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
                    let chunk = pending_chunks.pop().unwrap();
                    match chunk.data {
                        Ok(data) => {
                            if let Err(e) = writer.write_all(&data) {
                                final_result = Err(e.into());
                                break; // Break inner while
                            }
                            writer_pool.release(data);
                            next_chunk_to_write += 1;
                        }
                        Err(e) => {
                            final_result = Err(e);
                            break; // Break inner while
                        }
                    }
                } else {
                    break;
                }
            }
            if final_result.is_err() {
                break; // Break outer while
            }
        }

        // Check for I/O errors from the reader thread if no other error has occurred
        if final_result.is_ok() {
            if let Ok(e) = io_error_rx.try_recv() {
                final_result = Err(e.into());
            }
        }

        // If any error occurred, we need to clean up remaining buffers
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
#[allow(clippy::too_many_arguments)]
pub fn decrypt_pipeline<S, R, W>(
    key: S::Key,
    base_nonce: [u8; 12],
    chunk_size: u32,
    mut reader: R,
    mut writer: W,
    aad: Option<&[u8]>,
) -> Result<()>
where
    S: SymmetricAlgorithm,
    S::Key: Sync + Send,
    R: Read + Send,
    W: Write,
{
    let encrypted_chunk_size = (chunk_size as usize) + S::TAG_SIZE;
    let key_arc = Arc::new(key);
    let aad_arc = Arc::new(aad.map(|d| d.to_vec()));
    let pool = Arc::new(BufferPool::new(encrypted_chunk_size));

    // 2. Setup channels
    let (enc_chunk_tx, enc_chunk_rx) = crossbeam_channel::bounded(CHANNEL_BOUND);
    let (dec_chunk_tx, dec_chunk_rx) = crossbeam_channel::bounded(CHANNEL_BOUND);
    let (io_error_tx, io_error_rx) = crossbeam_channel::unbounded();

    thread::scope(|s| {
        // --- Thread 1: I/O Reader ---
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
                    break; // EOF reached
                }
            }
        });

        // --- Thread 2: Parallel Decryptor ---
        let dec_chunk_tx_clone = dec_chunk_tx.clone();
        let key_clone = Arc::clone(&key_arc);
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
                    let capacity = out_buffer.capacity();
                    out_buffer.resize(capacity, 0);

                    let result = S::decrypt_to_buffer(
                        &key_clone,
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
                    }
                });
        });

        // --- Main Thread: I/O Writer (Re-sequencer) ---
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