//! Implements a parallel streaming hybrid encryption/decryption scheme.

use super::common::{create_header, derive_nonce, DEFAULT_CHUNK_SIZE};
use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::buffer::BufferPool;
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, Result};
use bytes::BytesMut;
use rayon::prelude::*;
use seal_crypto::zeroize::Zeroizing;
use std::collections::BinaryHeap;
use std::io::{Read, Write};
use std::sync::Arc;
use std::thread;

const CHANNEL_BOUND: usize = 16;

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
        other.index.cmp(&self.index)
    }
}

pub fn encrypt<A, S, R, W>(
    public_key: &A::PublicKey,
    mut reader: R,
    mut writer: W,
    kek_id: String,
) -> Result<()>
where
    A: AsymmetricAlgorithm,
    A::EncapsulatedKey: Into<Vec<u8>> + Send,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync,
    R: Read + Send,
    W: Write,
{
    let (header, base_nonce, shared_secret) =
        create_header::<A, S>(&public_key.clone().into(), kek_id)?;
    let key_arc = Arc::new(shared_secret.into());
    let pool = Arc::new(BufferPool::new(DEFAULT_CHUNK_SIZE as usize));

    let header_bytes = header.encode_to_vec()?;
    writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
    writer.write_all(&header_bytes)?;

    let (raw_chunk_tx, raw_chunk_rx) = crossbeam_channel::bounded(CHANNEL_BOUND);
    let (enc_chunk_tx, enc_chunk_rx) = crossbeam_channel::bounded(CHANNEL_BOUND);
    let (io_error_tx, io_error_rx) = crossbeam_channel::unbounded();

    thread::scope(|s| {
        let pool_for_reader = Arc::clone(&pool);
        s.spawn(move || {
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
                    if raw_chunk_tx.send((chunk_index, buffer)).is_err() {
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

        let in_pool = Arc::clone(&pool);
        let out_pool = Arc::new(BufferPool::new(DEFAULT_CHUNK_SIZE as usize + S::TAG_SIZE));
        let writer_pool = Arc::clone(&out_pool);
        let enc_chunk_tx_clone = enc_chunk_tx.clone();
        s.spawn(move || {
            raw_chunk_rx
                .into_iter()
                .par_bridge()
                .for_each(|(index, in_buffer)| {
                    let mut out_buffer = out_pool.acquire();
                    let nonce = derive_nonce(&base_nonce, index);
                    let capacity = out_buffer.capacity();
                    out_buffer.resize(capacity, 0);

                    let result = S::encrypt_to_buffer(
                        &key_arc,
                        &nonce,
                        &in_buffer,
                        &mut out_buffer,
                        None,
                    )
                    .map(|written| {
                        out_buffer.truncate(written);
                        out_buffer
                    })
                    .map_err(Error::from);

                    in_pool.release(in_buffer);
                    if enc_chunk_tx_clone.send((index, result)).is_err() {}
                });
        });

        let mut final_result: Result<()> = Ok(());
        let mut pending_chunks = BinaryHeap::new();
        let mut next_chunk_to_write = 0;
        drop(enc_chunk_tx); // Drop our sender to signal completion

        while let Ok((index, result)) = enc_chunk_rx.recv() {
            pending_chunks.push(OrderedChunk { index, data: result });
            while let Some(top) = pending_chunks.peek() {
                if top.index == next_chunk_to_write {
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
    })
}

/// A pending decryptor for a parallel hybrid stream, waiting for the private key.
///
/// This state is entered after the header has been successfully read from the
/// stream, allowing the user to inspect the header (e.g., to find the `kek_id`)
/// before supplying the appropriate private key to proceed with decryption.
pub struct PendingDecryptor<R>
where
    R: Read + Send,
{
    reader: R,
    header: Header,
}

impl<R> PendingDecryptor<R>
where
    R: Read + Send,
{
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
    pub fn decrypt_to_writer<A, S, W: Write>(self, sk: &A::PrivateKey, writer: W) -> Result<()>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
        S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync,
        A::PrivateKey: Clone,
        A::EncapsulatedKey: From<Vec<u8>>,
    {
        decrypt_body_stream::<A, S, _, _>(sk, &self.header, self.reader, writer)
    }
}

/// Decrypts a data stream body and writes to a writer using a parallel streaming approach.
pub fn decrypt_body_stream<A, S, R, W>(
    private_key: &A::PrivateKey,
    header: &Header,
    mut reader: R,
    mut writer: W,
) -> Result<()>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync,
    A::PrivateKey: Clone,
    A::EncapsulatedKey: From<Vec<u8>>,
    R: Read + Send,
    W: Write,
{
    let (chunk_size, base_nonce, encapsulated_key) = match &header.payload {
        HeaderPayload::Hybrid {
            stream_info: Some(info),
            encrypted_dek,
            ..
        } => (
            info.chunk_size,
            info.base_nonce,
            encrypted_dek.clone().into(),
        ),
        _ => return Err(Error::InvalidHeader),
    };

    let shared_secret = A::decapsulate(&private_key.clone().into(), &encapsulated_key)?;
    let key_arc = Arc::new(shared_secret.into());
    let encrypted_chunk_size = (chunk_size as usize) + S::TAG_SIZE;
    let pool = Arc::new(BufferPool::new(encrypted_chunk_size));

    let (enc_chunk_tx, enc_chunk_rx) = crossbeam_channel::bounded(CHANNEL_BOUND);
    let (dec_chunk_tx, dec_chunk_rx) = crossbeam_channel::bounded(CHANNEL_BOUND);
    let (io_error_tx, io_error_rx) = crossbeam_channel::unbounded();

    thread::scope(|s| {
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
                    if enc_chunk_tx.send((chunk_index, buffer)).is_err() {
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

        let in_pool = Arc::clone(&pool);
        let out_pool = Arc::new(BufferPool::new(chunk_size as usize));
        let writer_pool = Arc::clone(&out_pool);
        let dec_chunk_tx_clone = dec_chunk_tx.clone();
        s.spawn(move || {
            enc_chunk_rx
                .into_iter()
                .par_bridge()
                .for_each(|(index, in_buffer)| {
                    let mut out_buffer = out_pool.acquire();
                    let nonce = derive_nonce(&base_nonce, index);
                    let capacity = out_buffer.capacity();
                    out_buffer.resize(capacity, 0);

                    let result = S::decrypt_to_buffer(
                        &key_arc,
                        &nonce,
                        &in_buffer,
                        &mut out_buffer,
                        None,
                    )
                    .map(|written| {
                        out_buffer.truncate(written);
                        out_buffer
                    })
                    .map_err(Error::from);

                    in_pool.release(in_buffer);
                    if dec_chunk_tx_clone.send((index, result)).is_err() {}
                });
        });

        let mut final_result: Result<()> = Ok(());
        let mut pending_chunks = BinaryHeap::new();
        let mut next_chunk_to_write = 0;
        drop(dec_chunk_tx);

        while let Ok((index, result)) = dec_chunk_rx.recv() {
            pending_chunks.push(OrderedChunk { index, data: result });
            while let Some(top) = pending_chunks.peek() {
                if top.index == next_chunk_to_write {
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::prelude::KeyGenerator;
    use seal_crypto::schemes::asymmetric::traditional::rsa::Rsa2048;
    use seal_crypto::schemes::hash::Sha256;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
    use std::io::Cursor;

    fn get_test_data(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 256) as u8).collect()
    }

    #[test]
    fn test_hybrid_parallel_streaming_roundtrip() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let kek_id = "test-kek-id".to_string();
        let plaintext = get_test_data(1024 * 1024); // 1 MiB

        let mut encrypted_data = Vec::new();
        encrypt::<Rsa2048, Aes256Gcm, _, _>(
            &pk,
            Cursor::new(&plaintext),
            &mut encrypted_data,
            kek_id.clone(),
        )
        .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        assert_eq!(pending.header().payload.kek_id(), Some(kek_id.as_str()));
        pending
            .decrypt_to_writer::<Rsa2048<Sha256>, Aes256Gcm, _>(&sk, &mut decrypted_data)
            .unwrap();

        assert_eq!(plaintext, decrypted_data);
    }

    #[test]
    fn test_empty_input() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let kek_id = "test-kek-id".to_string();
        let plaintext = get_test_data(0);

        let mut encrypted_data = Vec::new();
        encrypt::<Rsa2048, Aes256Gcm, _, _>(
            &pk,
            Cursor::new(&plaintext),
            &mut encrypted_data,
            kek_id.clone(),
        )
        .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        assert_eq!(pending.header().payload.kek_id(), Some(kek_id.as_str()));
        pending
            .decrypt_to_writer::<Rsa2048<Sha256>, Aes256Gcm, _>(&sk, &mut decrypted_data)
            .unwrap();

        assert_eq!(plaintext, decrypted_data);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let kek_id = "test-kek-id".to_string();
        let plaintext = get_test_data(1024);

        let mut encrypted_data = Vec::new();
        encrypt::<Rsa2048, Aes256Gcm, _, _>(
            &pk,
            Cursor::new(&plaintext),
            &mut encrypted_data,
            kek_id.clone(),
        )
        .unwrap();

        // Tamper
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        encrypted_data[header_len + 10] ^= 1;

        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let result =
            pending.decrypt_to_writer::<Rsa2048<Sha256>, Aes256Gcm, _>(&sk, &mut decrypted_data);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let (pk, _) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let (_, sk2) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let kek_id = "test-kek-id".to_string();
        let plaintext = get_test_data(1024);

        let mut encrypted_data = Vec::new();
        encrypt::<Rsa2048, Aes256Gcm, _, _>(
            &pk,
            Cursor::new(&plaintext),
            &mut encrypted_data,
            kek_id.clone(),
        )
        .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let result =
            pending.decrypt_to_writer::<Rsa2048<Sha256>, Aes256Gcm, _>(&sk2, &mut decrypted_data);
        assert!(result.is_err());
    }
}
