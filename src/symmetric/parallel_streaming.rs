//! Implements a parallel streaming symmetric encryption/decryption scheme.
//! This mode is designed for high-performance processing of large files or data streams
//! by overlapping I/O with parallel computation.

use super::common::{create_header, derive_nonce, DEFAULT_CHUNK_SIZE};
use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, Result};
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::{mpsc, Arc};
use std::thread;

const CHANNEL_BOUND: usize = 16; // Bound the channel to avoid unbounded memory usage

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

    let header_bytes = header.encode_to_vec()?;
    writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
    writer.write_all(&header_bytes)?;

    // 2. Setup channels for producer-consumer pipeline
    let (raw_chunk_tx, raw_chunk_rx) = mpsc::sync_channel::<(u64, Vec<u8>)>(CHANNEL_BOUND);
    let (enc_chunk_tx, enc_chunk_rx) = mpsc::sync_channel::<(u64, Result<Vec<u8>>)>(CHANNEL_BOUND);
    let (io_error_tx, io_error_rx) = mpsc::channel::<std::io::Error>();

    thread::scope(|s| {
        // --- Thread 1: I/O Reader (Producer) ---
        s.spawn(move || {
            let mut chunk_index = 0u64;
            loop {
                let mut chunk = vec![0; DEFAULT_CHUNK_SIZE as usize];
                let mut bytes_read = 0;
                while bytes_read < chunk.len() {
                    match reader.read(&mut chunk[bytes_read..]) {
                        Ok(0) => break, // EOF
                        Ok(n) => bytes_read += n,
                        Err(e) => {
                            let _ = io_error_tx.send(e);
                            return; // Stop thread
                        }
                    }
                }

                if bytes_read > 0 {
                    chunk.truncate(bytes_read);
                    if raw_chunk_tx.send((chunk_index, chunk)).is_err() {
                        break; // Receiver has hung up
                    }
                    chunk_index += 1;
                }

                if bytes_read < DEFAULT_CHUNK_SIZE as usize {
                    break; // EOF reached
                }
            }
        });

        // --- Thread 2: Parallel Encryptor (Consumer/Producer) ---
        let enc_chunk_tx_clone = enc_chunk_tx.clone();
        let key_clone = Arc::clone(&key_arc);
        s.spawn(move || {
            raw_chunk_rx
                .into_iter()
                .par_bridge()
                .for_each(|(index, chunk)| {
                    let nonce = derive_nonce(&base_nonce, index);
                    let encrypted = S::encrypt(&key_clone, &nonce, &chunk, None)
                        .map_err(Error::from);
                    if enc_chunk_tx_clone.send((index, encrypted)).is_err() {
                        return;
                    }
                });
        });

        // --- Main Thread: I/O Writer (Re-sequencer) ---
        let mut next_chunk_to_write = 0u64;
        let mut out_of_order_buffer = BTreeMap::new();
        drop(enc_chunk_tx); // Drop original sender

        loop {
            if let Ok(io_err) = io_error_rx.try_recv() {
                return Err(Error::Io(io_err));
            }

            match enc_chunk_rx.recv() {
                Ok((index, encrypted_result)) => {
                    let encrypted_chunk = encrypted_result?;
                    out_of_order_buffer.insert(index, encrypted_chunk);

                    while let Some(chunk_to_write) =
                        out_of_order_buffer.remove(&next_chunk_to_write)
                    {
                        writer.write_all(&chunk_to_write)?;
                        next_chunk_to_write += 1;
                    }
                }
                Err(_) => break, // Channel closed
            }
        }

        while let Some(chunk_to_write) = out_of_order_buffer.remove(&next_chunk_to_write) {
            writer.write_all(&chunk_to_write)?;
            next_chunk_to_write += 1;
        }

        Ok(())
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

/// Decrypts a data stream body and writes to a writer using a parallel streaming approach.
///
/// This function assumes the header has already been read and consumed from the reader.
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

    // 2. Setup channels
    let (enc_chunk_tx, enc_chunk_rx) = mpsc::sync_channel::<(u64, Vec<u8>)>(CHANNEL_BOUND);
    let (dec_chunk_tx, dec_chunk_rx) = mpsc::sync_channel::<(u64, Result<Vec<u8>>)>(CHANNEL_BOUND);
    let (io_error_tx, io_error_rx) = mpsc::channel::<std::io::Error>();

    thread::scope(|s| {
        // --- Thread 1: I/O Reader ---
        s.spawn(move || {
            let mut chunk_index = 0u64;
            loop {
                let mut chunk = vec![0; encrypted_chunk_size];
                let mut bytes_read = 0;

                while bytes_read < chunk.len() {
                    match reader.read(&mut chunk[bytes_read..]) {
                        Ok(0) => break, // EOF
                        Ok(n) => bytes_read += n,
                        Err(e) => {
                            let _ = io_error_tx.send(e);
                            return;
                        }
                    }
                }

                if bytes_read > 0 {
                    chunk.truncate(bytes_read);
                    if enc_chunk_tx.send((chunk_index, chunk)).is_err() {
                        break;
                    }
                    chunk_index += 1;
                }

                if bytes_read < encrypted_chunk_size {
                    break; // EOF reached
                }
            }
        });

        // --- Thread 2: Parallel Decryptor ---
        let dec_chunk_tx_clone = dec_chunk_tx.clone();
        let key_clone = Arc::clone(&key_arc);
        s.spawn(move || {
            enc_chunk_rx
                .into_iter()
                .par_bridge()
                .for_each(|(index, chunk)| {
                    let nonce = derive_nonce(&base_nonce, index);
                    let decrypted = S::decrypt(&key_clone, &nonce, &chunk, None)
                        .map_err(Error::from);
                    if dec_chunk_tx_clone.send((index, decrypted)).is_err() {
                        return;
                    }
                });
        });

        // --- Main Thread: I/O Writer (Re-sequencer) ---
        let mut next_chunk_to_write = 0u64;
        let mut out_of_order_buffer = BTreeMap::new();
        drop(dec_chunk_tx);

        loop {
            if let Ok(io_err) = io_error_rx.try_recv() {
                return Err(Error::Io(io_err));
            }

            match dec_chunk_rx.recv() {
                Ok((index, decrypted_result)) => {
                    let decrypted_chunk = decrypted_result?;
                    out_of_order_buffer.insert(index, decrypted_chunk);
                    while let Some(chunk_to_write) =
                        out_of_order_buffer.remove(&next_chunk_to_write)
                    {
                        writer.write_all(&chunk_to_write).map_err(Error::Io)?;
                        next_chunk_to_write += 1;
                    }
                }
                Err(_) => {
                    break;
                }
            }
        }

        while let Some(chunk_to_write) = out_of_order_buffer.remove(&next_chunk_to_write) {
            writer.write_all(&chunk_to_write).map_err(Error::Io)?;
            next_chunk_to_write += 1;
        }

        Ok(())
    })
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
