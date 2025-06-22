//! Implements a parallel streaming symmetric encryption/decryption scheme.
//! This mode is designed for high-performance processing of large files or data streams
//! by overlapping I/O with parallel computation.

use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::{Header, HeaderPayload, SealMode, StreamInfo};
use crate::error::{Error, Result};
use rand::{rngs::OsRng, TryRngCore};
use rayon::prelude::*;
use seal_crypto::prelude::*;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::thread;

const DEFAULT_CHUNK_SIZE: u32 = 65536; // 64 KiB
const CHANNEL_BOUND: usize = 16; // Bound the channel to avoid unbounded memory usage

/// Derives a nonce for a specific chunk index.
fn derive_nonce(base_nonce: &[u8; 12], i: u64) -> [u8; 12] {
    let mut nonce_bytes = *base_nonce;
    let i_bytes = i.to_le_bytes();
    for j in 0..8 {
        nonce_bytes[4 + j] ^= i_bytes[j];
    }
    nonce_bytes
}

/// Encrypts data from a reader and writes to a writer using a parallel streaming approach.
pub fn encrypt<S, R, W>(key: &S::Key, mut reader: R, mut writer: W, key_id: String) -> Result<()>
where
    S: SymmetricAlgorithm,
    S::Key: Sync + Clone + Send,
    R: Read + Send,
    W: Write,
{
    // 1. Setup Header and write it
    let mut base_nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut base_nonce)?;

    let header = Header {
        version: 1,
        mode: SealMode::Symmetric,
        payload: HeaderPayload::Symmetric {
            key_id,
            algorithm: S::ALGORITHM,
            stream_info: Some(StreamInfo {
                chunk_size: DEFAULT_CHUNK_SIZE,
                base_nonce,
            }),
        },
    };

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
        let key_clone = key.clone();
        s.spawn(move || {
            raw_chunk_rx
                .into_iter()
                .par_bridge()
                .for_each(|(index, chunk)| {
                    let nonce = derive_nonce(&base_nonce, index);
                    let encrypted =
                        S::Scheme::encrypt(&key_clone.clone().into(), &nonce, &chunk, None)
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

/// Decrypts data from a reader and writes to a writer using a parallel streaming approach.
pub fn decrypt<S, R, W>(key: &S::Key, mut reader: R, mut writer: W) -> Result<()>
where
    S: SymmetricAlgorithm,
    S::Key: Sync + Clone + Send,
    R: Read + Send,
    W: Write,
{
    // 1. Read and parse header
    let mut header_len_bytes = [0u8; 4];
    reader
        .read_exact(&mut header_len_bytes)
        .map_err(Error::Io)?;
    let header_len = u32::from_le_bytes(header_len_bytes);

    let mut header_bytes = vec![0; header_len as usize];
    reader.read_exact(&mut header_bytes).map_err(Error::Io)?;
    let (header, _) = Header::decode_from_slice(&header_bytes)?;

    let (chunk_size, base_nonce) = match header.payload {
        HeaderPayload::Symmetric {
            stream_info: Some(info),
            ..
        } => (info.chunk_size, info.base_nonce),
        _ => return Err(Error::InvalidHeader),
    };

    let encrypted_chunk_size = (chunk_size as usize) + S::Scheme::TAG_SIZE;

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
        let key_clone = key.clone();
        s.spawn(move || {
            enc_chunk_rx
                .into_iter()
                .par_bridge()
                .for_each(|(index, chunk)| {
                    let nonce = derive_nonce(&base_nonce, index);
                    let decrypted =
                        S::Scheme::decrypt(&key_clone.clone().into(), &nonce, &chunk, None)
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
    use crate::algorithms::{definitions::Aes256Gcm, traits::SymmetricAlgorithm};
    use std::io::Cursor;

    fn get_test_data(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 256) as u8).collect()
    }

    #[test]
    fn test_parallel_streaming_roundtrip() {
        let key = <Aes256Gcm as SymmetricAlgorithm>::Scheme::generate_key().unwrap();
        let plaintext = get_test_data(DEFAULT_CHUNK_SIZE as usize * 3 + 100);
        let mut source = Cursor::new(&plaintext);
        let mut encrypted_dest = Vec::new();

        encrypt::<Aes256Gcm, _, _>(
            &key,
            &mut source,
            &mut encrypted_dest,
            "test_key_id".to_string(),
        )
        .unwrap();

        let mut encrypted_source = Cursor::new(&encrypted_dest);
        let mut decrypted_dest = Vec::new();
        decrypt::<Aes256Gcm, _, _>(&key, &mut encrypted_source, &mut decrypted_dest).unwrap();

        assert_eq!(plaintext, decrypted_dest);
    }

    #[test]
    fn test_empty_input() {
        let key = <Aes256Gcm as SymmetricAlgorithm>::Scheme::generate_key().unwrap();
        let plaintext: Vec<u8> = Vec::new();
        let mut source = Cursor::new(&plaintext);
        let mut encrypted_dest = Vec::new();

        encrypt::<Aes256Gcm, _, _>(
            &key,
            &mut source,
            &mut encrypted_dest,
            "test_key_id".to_string(),
        )
        .unwrap();

        let mut encrypted_source = Cursor::new(&encrypted_dest);
        let mut decrypted_dest = Vec::new();
        decrypt::<Aes256Gcm, _, _>(&key, &mut encrypted_source, &mut decrypted_dest).unwrap();

        assert_eq!(plaintext, decrypted_dest);
    }

    #[test]
    fn test_exact_chunk_multiple() {
        let key = <Aes256Gcm as SymmetricAlgorithm>::Scheme::generate_key().unwrap();
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize * 2];
        let mut source = Cursor::new(&plaintext);
        let mut encrypted_dest = Vec::new();

        encrypt::<Aes256Gcm, _, _>(
            &key,
            &mut source,
            &mut encrypted_dest,
            "test_key_id".to_string(),
        )
        .unwrap();

        let mut encrypted_source = Cursor::new(&encrypted_dest);
        let mut decrypted_dest = Vec::new();
        decrypt::<Aes256Gcm, _, _>(&key, &mut encrypted_source, &mut decrypted_dest).unwrap();

        assert_eq!(plaintext, decrypted_dest);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = <Aes256Gcm as SymmetricAlgorithm>::Scheme::generate_key().unwrap();
        let plaintext = b"some important data";
        let mut source = Cursor::new(plaintext);
        let mut encrypted_dest = Vec::new();

        encrypt::<Aes256Gcm, _, _>(
            &key,
            &mut source,
            &mut encrypted_dest,
            "test_key_id".to_string(),
        )
        .unwrap();

        // Tamper with the ciphertext body
        if encrypted_dest.len() > 50 {
            encrypted_dest[50] ^= 1;
        }

        let mut encrypted_source = Cursor::new(&encrypted_dest);
        let mut decrypted_dest = Vec::new();
        let result = decrypt::<Aes256Gcm, _, _>(&key, &mut encrypted_source, &mut decrypted_dest);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = <Aes256Gcm as SymmetricAlgorithm>::Scheme::generate_key().unwrap();
        let key2 = <Aes256Gcm as SymmetricAlgorithm>::Scheme::generate_key().unwrap();
        let plaintext = b"some data";
        let mut source = Cursor::new(plaintext);
        let mut encrypted_dest = Vec::new();

        encrypt::<Aes256Gcm, _, _>(
            &key1,
            &mut source,
            &mut encrypted_dest,
            "test_key_id".to_string(),
        )
        .unwrap();

        let mut encrypted_source = Cursor::new(&encrypted_dest);
        let mut decrypted_dest = Vec::new();
        let result = decrypt::<Aes256Gcm, _, _>(&key2, &mut encrypted_source, &mut decrypted_dest);
        assert!(result.is_err());
    }
}
