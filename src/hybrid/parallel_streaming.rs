//! Implements a parallel streaming hybrid encryption/decryption scheme.

use crate::common::header::{Header, HeaderPayload, SealMode, StreamInfo};
use crate::error::{Error, Result};
use rand::{rngs::OsRng, TryRngCore};
use rayon::iter::ParallelIterator;
use rayon::prelude::*;

use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use seal_crypto::zeroize::Zeroizing;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::thread;

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

pub fn encrypt<A, S, R: Read + Send + Sync, W: Write + Send + Sync>(
    public_key: &A::PublicKey,
    mut reader: R,
    mut writer: W,
    kek_id: String,
) -> Result<()>
where
    A: AsymmetricAlgorithm,
    A::EncapsulatedKey: Into<Vec<u8>> + Send,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>>,
{
    let (shared_secret, encapsulated_key) = A::encapsulate(&public_key.clone().into())?;

    let mut base_nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut base_nonce)?;

    let header = Header {
        version: 1,
        mode: SealMode::Hybrid,
        payload: HeaderPayload::Hybrid {
            kek_id,
            kek_algorithm: A::ALGORITHM,
            dek_algorithm: S::ALGORITHM,
            encrypted_dek: encapsulated_key.into(),
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
                    let encrypted = S::encrypt(&shared_secret.clone().into(), &nonce, &chunk, None)
                        .map_err(Error::from);
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

/// Reads and decodes the header from the beginning of a reader.
pub fn decode_header_from_stream<R: Read>(reader: &mut R) -> Result<Header> {
    let mut header_len_bytes = [0u8; 4];
    reader.read_exact(&mut header_len_bytes)?;
    let header_len = u32::from_le_bytes(header_len_bytes);

    let mut header_bytes = vec![0; header_len as usize];
    reader.read_exact(&mut header_bytes)?;
    let (header, _) = Header::decode_from_slice(&header_bytes).map_err(Error::from)?;
    Ok(header)
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
        let header = decode_header_from_stream(&mut reader)?;
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
        S::Key: From<Zeroizing<Vec<u8>>>,
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
    S::Key: From<Zeroizing<Vec<u8>>>,
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
    let encrypted_chunk_size = (chunk_size as usize) + S::TAG_SIZE;

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
                    let decrypted = S::decrypt(&shared_secret.clone().into(), &nonce, &chunk, None)
                        .map_err(Error::from);
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
        let header_len =
            4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
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
