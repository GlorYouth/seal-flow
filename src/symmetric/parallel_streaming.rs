//! Implements a parallel streaming symmetric encryption/decryption scheme.
//! This mode is designed for high-performance processing of large files or data streams
//! by overlapping I/O with parallel computation.

use super::common::{create_header, derive_nonce, DEFAULT_CHUNK_SIZE};
use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, Result};
use bytes::BytesMut;
use rayon::prelude::*;
use std::collections::BinaryHeap;
use std::io::{Read, Write};
use std::sync::Arc;
use std::thread;
use crate::common::buffer::BufferPool;

const CHANNEL_BOUND: usize = 16; // Bound the channel to avoid unbounded memory usage

/// A wrapper for chunks to allow ordering in a min-heap.
struct OrderedChunk {
    index: u64,
    data: Result<BytesMut>,
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

/// Encrypts data from a reader and writes to a writer using a parallel streaming approach.
pub fn encrypt<S, R, W>(key: S::Key, mut reader: R, mut writer: W, key_id: String) -> Result<()>
where
    S: SymmetricAlgorithm,
    S::Key: Sync + Send,
    R: Read + Send,
    W: Write,
{
    // 1. Setup Header and write it
    let (header, base_nonce) = create_header::<S>(key_id)?;
    let key_arc = Arc::new(key.into());
    let pool = Arc::new(BufferPool::new(DEFAULT_CHUNK_SIZE as usize));

    let header_bytes = header.encode_to_vec()?;
    writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
    writer.write_all(&header_bytes)?;

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
                    if raw_chunk_tx_clone
                        .send((chunk_index, buffer))
                        .is_err()
                    {
                        break; // Receiver has hung up, buffer is lost
                    }
                    chunk_index += 1;
                }

                if bytes_read_total < chunk_size {
                    break; // EOF reached
                }
            }
        });

        // --- Thread 2: Parallel Encryptor (Consumer/Producer) ---
        let enc_chunk_tx_clone = enc_chunk_tx.clone();
        let key_clone = Arc::clone(&key_arc);
        let in_pool = Arc::clone(&pool);
        let out_pool = Arc::new(BufferPool::new(
            DEFAULT_CHUNK_SIZE as usize + S::TAG_SIZE,
        ));
        let writer_pool = Arc::clone(&out_pool);
        s.spawn(move || {
            raw_chunk_rx.into_iter().par_bridge().for_each(
                |(index, in_buffer)| {
                    let mut out_buffer = out_pool.acquire();
                    let nonce = derive_nonce(&base_nonce, index);

                    // Resize buffer to its full capacity to get a mutable slice
                    let capacity = out_buffer.capacity();
                    out_buffer.resize(capacity, 0);

                    let result = S::encrypt_to_buffer(
                        &key_clone,
                        &nonce,
                        &in_buffer,
                        &mut out_buffer,
                        None,
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
                },
            );
        });

        // --- Main Thread: I/O Writer (Re-sequencer) ---
        let mut final_result: Result<()> = Ok(());
        let mut pending_chunks = BinaryHeap::new();
        drop(raw_chunk_tx);
        drop(enc_chunk_tx);

        let mut next_chunk_to_write = 0;
        while let Ok((index, result)) = enc_chunk_rx.recv() {
            pending_chunks.push(OrderedChunk { index, data: result });

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

/// Decrypts a stream and writes the output to another stream.
pub fn decrypt_body_stream<S, R, W>(
    key: S::Key,
    header: &Header,
    mut reader: R,
    mut writer: W,
) -> Result<()>
where
    S: SymmetricAlgorithm,
    S::Key: Sync + Send,
    R: Read + Send,
    W: Write,
{
    let (chunk_size, base_nonce) = match &header.payload {
        HeaderPayload::Symmetric {
            stream_info: Some(info),
            ..
        } => (info.chunk_size, info.base_nonce),
        _ => return Err(Error::InvalidHeader),
    };

    let encrypted_chunk_size = (chunk_size as usize) + S::TAG_SIZE;
    let key_arc = Arc::new(key.into());
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
                    if enc_chunk_tx_clone
                        .send((chunk_index, buffer))
                        .is_err()
                    {
                        break;
                    }
                    chunk_index += 1;
                }

                if bytes_read_total < chunk_size_local {
                    break; // EOF reached
                }
            }
        });

        // --- Thread 2: Parallel Decryptor ---
        let dec_chunk_tx_clone = dec_chunk_tx.clone();
        let key_clone = Arc::clone(&key_arc);
        let in_pool = Arc::clone(&pool);
        let out_pool = Arc::new(BufferPool::new(chunk_size as usize));
        let writer_pool = Arc::clone(&out_pool);
        s.spawn(move || {
            enc_chunk_rx.into_iter().par_bridge().for_each(
                |(index, in_buffer)| {
                    let mut out_buffer = out_pool.acquire();
                    let nonce = derive_nonce(&base_nonce, index);

                    // Resize buffer to its full capacity to get a mutable slice
                    let capacity = out_buffer.capacity();
                    out_buffer.resize(capacity, 0);

                    let result = S::decrypt_to_buffer(
                        &key_clone,
                        &nonce,
                        &in_buffer,
                        &mut out_buffer,
                        None,
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
                },
            );
        });

        // --- Main Thread: I/O Writer (Re-sequencer) ---
        let mut final_result: Result<()> = Ok(());
        let mut pending_chunks = BinaryHeap::new();
        drop(enc_chunk_tx);
        drop(dec_chunk_tx);

        let mut next_chunk_to_write = 0;
        while let Ok((index, result)) = dec_chunk_rx.recv() {
            pending_chunks.push(OrderedChunk { index, data: result });

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

/// A pending decryptor for a parallel stream, waiting for a key.
///
/// This state is entered after the header has been successfully read from the
/// stream, allowing the user to inspect the header (e.g., to find the `key_id`)
/// before supplying the appropriate key to proceed with decryption.
pub struct PendingDecryptor<R: Read + Send> {
    reader: R,
    header: Header,
}

impl<R: Read + Send> PendingDecryptor<R> {
    /// Creates a new `PendingDecryptor` by reading the header from the stream.
    pub fn from_reader(mut reader: R) -> Result<Self> {
        let header = Header::decode_from_prefixed_reader(&mut reader)?;
        Ok(Self { reader, header })
    }

    /// Returns a reference to the header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Consumes the `PendingDecryptor` and decrypts the rest of the stream,
    /// writing the plaintext to the provided writer.
    pub fn decrypt_to_writer<S: SymmetricAlgorithm, W: Write>(
        self,
        key: S::Key,
        writer: W,
    ) -> Result<()>
    where
        S::Key: Sync + Send,
    {
        decrypt_body_stream::<S, R, W>(key, &self.header, self.reader, writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::prelude::SymmetricKeyGenerator;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
    use std::io::Cursor;

    fn get_test_data(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 256) as u8).collect()
    }

    #[test]
    fn test_parallel_streaming_roundtrip() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = get_test_data(1024 * 1024); // 1 MiB

        let mut encrypted_data = Vec::new();
        encrypt::<Aes256Gcm, _, _>(
            key.clone(),
            Cursor::new(&plaintext),
            &mut encrypted_data,
            "test_key".to_string(),
        )
        .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        assert_eq!(pending.header().payload.key_id(), Some("test_key"));
        pending
            .decrypt_to_writer::<Aes256Gcm, _>(key, &mut decrypted_data)
            .unwrap();

        assert_eq!(plaintext, decrypted_data);
    }

    #[test]
    fn test_empty_input() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"";

        let mut encrypted_data = Vec::new();
        encrypt::<Aes256Gcm, _, _>(
            key.clone(),
            Cursor::new(&plaintext),
            &mut encrypted_data,
            "test_key".to_string(),
        )
        .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        pending
            .decrypt_to_writer::<Aes256Gcm, _>(key, &mut decrypted_data)
            .unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[test]
    fn test_exact_chunk_multiple() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = get_test_data((DEFAULT_CHUNK_SIZE * 3) as usize);

        let mut encrypted_data = Vec::new();
        encrypt::<Aes256Gcm, _, _>(
            key.clone(),
            Cursor::new(&plaintext),
            &mut encrypted_data,
            "test_key".to_string(),
        )
        .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        pending
            .decrypt_to_writer::<Aes256Gcm, _>(key, &mut decrypted_data)
            .unwrap();

        assert_eq!(plaintext, decrypted_data);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = get_test_data(1024);

        let mut encrypted_data = Vec::new();
        encrypt::<Aes256Gcm, _, _>(
            key.clone(),
            Cursor::new(&plaintext),
            &mut encrypted_data,
            "test_key".to_string(),
        )
        .unwrap();

        // Tamper
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        encrypted_data[header_len + 10] ^= 1;

        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let result = pending.decrypt_to_writer::<Aes256Gcm, _>(key, &mut decrypted_data);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = Aes256Gcm::generate_key().unwrap();
        let key2 = Aes256Gcm::generate_key().unwrap();
        let plaintext = get_test_data(1024);

        let mut encrypted_data = Vec::new();
        encrypt::<Aes256Gcm, _, _>(
            key1,
            Cursor::new(&plaintext),
            &mut encrypted_data,
            "key1".to_string(),
        )
        .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let result = pending.decrypt_to_writer::<Aes256Gcm, _>(key2, &mut decrypted_data);
        assert!(result.is_err());
    }
}
