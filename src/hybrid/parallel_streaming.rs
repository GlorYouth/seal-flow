//! Implements a parallel streaming hybrid encryption/decryption scheme.

use crate::common::header::{Header, HeaderPayload, SealMode, StreamInfo};
use crate::error::{Error, Result};
use rand::{rngs::OsRng, TryRngCore};
use rayon::iter::ParallelIterator;
use rayon::prelude::*;

use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use seal_crypto::traits::{
    kem::Kem,
    symmetric::{SymmetricCipher, SymmetricDecryptor, SymmetricEncryptor},
};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::thread;
use seal_crypto::zeroize::Zeroizing;

const DEFAULT_CHUNK_SIZE: u32 = 65536; // 64 KiB
const CHANNEL_BOUND: usize = 16;

fn derive_nonce(base_nonce: &[u8; 12], i: u64) -> [u8; 12] {
    let mut nonce_bytes = *base_nonce;
    let i_bytes = i.to_le_bytes();
    for j in 0..8 {
        nonce_bytes[4 + j] ^= i_bytes[j];
    }
    nonce_bytes
}

pub fn encrypt<A, S, R, W>(
    public_key: &A::PublicKey,
    mut reader: R,
    mut writer: W,
    kek_id: String,
) -> Result<()>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm<Key = Zeroizing<Vec<u8>>>,
    A::Scheme: Kem<EncapsulatedKey = Vec<u8>>,
    A::PublicKey: Sync,
    S::Key: Sync,
    R: Read + Send,
    W: Write,
{
    let (shared_secret, encapsulated_key) = A::Scheme::encapsulate(public_key)?;

    let mut base_nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut base_nonce)?;

    let header = Header {
        version: 1,
        mode: SealMode::Hybrid,
        payload: HeaderPayload::Hybrid {
            kek_id,
            kek_algorithm: A::ALGORITHM,
            dek_algorithm: S::ALGORITHM,
            encrypted_dek: encapsulated_key,
            stream_info: Some(StreamInfo {
                chunk_size: DEFAULT_CHUNK_SIZE,
                base_nonce,
            }),
        },
    };

    let header_bytes = header.encode_to_vec()?;
    writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
    writer.write_all(&header_bytes)?;

    let (raw_chunk_tx, raw_chunk_rx) = mpsc::sync_channel::<(u64, Vec<u8>)>(CHANNEL_BOUND);
    let (enc_chunk_tx, enc_chunk_rx) = mpsc::sync_channel::<(u64, Result<Vec<u8>>)>(CHANNEL_BOUND);
    let (io_error_tx, io_error_rx) = mpsc::channel::<std::io::Error>();

    thread::scope(|s| {
        s.spawn(move || {
            let mut chunk_index = 0u64;
            loop {
                let mut chunk = vec![0; DEFAULT_CHUNK_SIZE as usize];
                let mut bytes_read = 0;
                while bytes_read < chunk.len() {
                    match reader.read(&mut chunk[bytes_read..]) {
                        Ok(0) => break,
                        Ok(n) => bytes_read += n,
                        Err(e) => {
                            let _ = io_error_tx.send(e);
                            return;
                        }
                    }
                }
                if bytes_read > 0 {
                    chunk.truncate(bytes_read);
                    if raw_chunk_tx.send((chunk_index, chunk)).is_err() {
                        break;
                    }
                    chunk_index += 1;
                }
                if bytes_read < DEFAULT_CHUNK_SIZE as usize {
                    break;
                }
            }
        });

        let enc_chunk_tx_clone = enc_chunk_tx.clone();
        s.spawn(move || {
            raw_chunk_rx
                .into_iter()
                .par_bridge()
                .for_each(|(index, chunk)| {
                    let nonce = derive_nonce(&base_nonce, index);
                    let encrypted =
                        S::Scheme::encrypt(&shared_secret, &nonce, &chunk, None).map_err(Error::from);
                    if enc_chunk_tx_clone.send((index, encrypted)).is_err() {
                        return;
                    }
                });
        });

        let mut next_chunk_to_write = 0u64;
        let mut out_of_order_buffer = BTreeMap::new();
        drop(enc_chunk_tx);

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
                Err(_) => break,
            }
        }
        while let Some(chunk_to_write) = out_of_order_buffer.remove(&next_chunk_to_write) {
            writer.write_all(&chunk_to_write)?;
            next_chunk_to_write += 1;
        }
        Ok(())
    })
}

pub fn decrypt<A, S, R, W>(
    private_key: &A::PrivateKey,
    mut reader: R,
    mut writer: W,
) -> Result<()>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm<Key = Zeroizing<Vec<u8>>>,
    <A::Scheme as Kem>::EncapsulatedKey: From<Vec<u8>>,
    S::Key: Sync,
    R: Read + Send,
    W: Write,
{
    let mut header_len_bytes = [0u8; 4];
    reader.read_exact(&mut header_len_bytes)?;
    let header_len = u32::from_le_bytes(header_len_bytes);

    let mut header_bytes = vec![0; header_len as usize];
    reader.read_exact(&mut header_bytes)?;
    let (header, _) = Header::decode_from_slice(&header_bytes).map_err(Error::from)?;

    let (chunk_size, base_nonce, encapsulated_key) = match header.payload {
        HeaderPayload::Hybrid {
            stream_info: Some(info),
            encrypted_dek,
            ..
        } => (info.chunk_size, info.base_nonce, encrypted_dek.into()),
        _ => return Err(Error::InvalidHeader),
    };

    let shared_secret = A::Scheme::decapsulate(private_key, &encapsulated_key)?;

    let encrypted_chunk_size = (chunk_size as usize) + S::Scheme::TAG_SIZE;

    let (enc_chunk_tx, enc_chunk_rx) = mpsc::sync_channel::<(u64, Vec<u8>)>(CHANNEL_BOUND);
    let (dec_chunk_tx, dec_chunk_rx) = mpsc::sync_channel::<(u64, Result<Vec<u8>>)>(CHANNEL_BOUND);
    let (io_error_tx, io_error_rx) = mpsc::channel::<std::io::Error>();

    thread::scope(|s| {
        s.spawn(move || {
            let mut chunk_index = 0u64;
            loop {
                let mut chunk = vec![0; encrypted_chunk_size];
                let mut bytes_read = 0;
                while bytes_read < chunk.len() {
                    match reader.read(&mut chunk[bytes_read..]) {
                        Ok(0) => break,
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
                    break;
                }
            }
        });

        let dec_chunk_tx_clone = dec_chunk_tx.clone();
        s.spawn(move || {
            enc_chunk_rx
                .into_iter()
                .par_bridge()
                .for_each(|(index, chunk)| {
                    let nonce = derive_nonce(&base_nonce, index);
                    let decrypted =
                        S::Scheme::decrypt(&shared_secret, &nonce, &chunk, None).map_err(Error::from);
                    if dec_chunk_tx_clone.send((index, decrypted)).is_err() {
                        return;
                    }
                });
        });

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
                        writer.write_all(&chunk_to_write)?;
                        next_chunk_to_write += 1;
                    }
                }
                Err(_) => break,
            }
        }

        while let Some(chunk_to_write) = out_of_order_buffer.remove(&next_chunk_to_write) {
            writer.write_all(&chunk_to_write)?;
            next_chunk_to_write += 1;
        }

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::definitions::{Aes256Gcm, Rsa2048};
    use crate::algorithms::traits::AsymmetricAlgorithm;
    use seal_crypto::traits::key::KeyGenerator;
    use std::io::Cursor;

    fn get_test_data(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 256) as u8).collect()
    }

    #[test]
    fn test_hybrid_parallel_streaming_roundtrip() {
        let (pk, sk) = <Rsa2048 as AsymmetricAlgorithm>::Scheme::generate_keypair().unwrap();
        let plaintext = get_test_data(DEFAULT_CHUNK_SIZE as usize * 3 + 100);
        let mut source = Cursor::new(&plaintext);
        let mut encrypted_dest = Vec::new();

        encrypt::<Rsa2048, Aes256Gcm, _, _>(
            &pk,
            &mut source,
            &mut encrypted_dest,
            "test_kek_id".to_string(),
        )
        .unwrap();

        let mut encrypted_source = Cursor::new(&encrypted_dest);
        let mut decrypted_dest = Vec::new();
        decrypt::<Rsa2048, Aes256Gcm, _, _>(
            &sk,
            &mut encrypted_source,
            &mut decrypted_dest,
        )
        .unwrap();

        assert_eq!(plaintext, decrypted_dest);
    }

    #[test]
    fn test_empty_input() {
        let (pk, sk) = <Rsa2048 as AsymmetricAlgorithm>::Scheme::generate_keypair().unwrap();
        let plaintext: Vec<u8> = Vec::new();
        let mut source = Cursor::new(&plaintext);
        let mut encrypted_dest = Vec::new();

        encrypt::<Rsa2048, Aes256Gcm, _, _>(
            &pk,
            &mut source,
            &mut encrypted_dest,
            "test_kek_id".to_string(),
        )
        .unwrap();

        let mut encrypted_source = Cursor::new(&encrypted_dest);
        let mut decrypted_dest = Vec::new();
        decrypt::<Rsa2048, Aes256Gcm, _, _>(
            &sk,
            &mut encrypted_source,
            &mut decrypted_dest,
        )
        .unwrap();

        assert_eq!(plaintext, decrypted_dest);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (pk, sk) = <Rsa2048 as AsymmetricAlgorithm>::Scheme::generate_keypair().unwrap();
        let plaintext = b"some important data";
        let mut source = Cursor::new(plaintext);
        let mut encrypted_dest = Vec::new();

        encrypt::<Rsa2048, Aes256Gcm, _, _>(
            &pk,
            &mut source,
            &mut encrypted_dest,
            "test_kek_id".to_string(),
        )
        .unwrap();

        // Tamper with the ciphertext body
        if encrypted_dest.len() > 100 {
            // Tamper after the header
            encrypted_dest[100] ^= 1;
        }

        let mut encrypted_source = Cursor::new(&encrypted_dest);
        let mut decrypted_dest = Vec::new();
        let result = decrypt::<Rsa2048, Aes256Gcm, _, _>(
            &sk,
            &mut encrypted_source,
            &mut decrypted_dest,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let (pk1, _) = <Rsa2048 as AsymmetricAlgorithm>::Scheme::generate_keypair().unwrap();
        let (_, sk2) = <Rsa2048 as AsymmetricAlgorithm>::Scheme::generate_keypair().unwrap();
        let plaintext = b"some data";
        let mut source = Cursor::new(plaintext);
        let mut encrypted_dest = Vec::new();

        encrypt::<Rsa2048, Aes256Gcm, _, _>(
            &pk1,
            &mut source,
            &mut encrypted_dest,
            "test_kek_id".to_string(),
        )
        .unwrap();

        let mut encrypted_source = Cursor::new(&encrypted_dest);
        let mut decrypted_dest = Vec::new();
        let result = decrypt::<Rsa2048, Aes256Gcm, _, _>(
            &sk2,
            &mut encrypted_source,
            &mut decrypted_dest,
        );
        assert!(result.is_err());
    }
}