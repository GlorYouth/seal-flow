//! Implements `std::io` traits for synchronous, streaming symmetric encryption.

use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::{Header, HeaderPayload, SealMode, StreamInfo};
use crate::error::{Error, Result};
use rand::{rngs::OsRng, TryRngCore};
use seal_crypto::prelude::*;
use std::io::{self, Read, Write};

const DEFAULT_CHUNK_SIZE: u32 = 65536; // 64 KiB

/// Implements `std::io::Write` for synchronous, streaming symmetric encryption.
pub struct Encryptor<W: Write, S: SymmetricAlgorithm>
where
    S::Key: Send + Sync + Clone,
{
    writer: W,
    symmetric_key: S::Key,
    base_nonce: [u8; 12],
    chunk_size: usize,
    buffer: Vec<u8>,
    chunk_counter: u64,
    _phantom: std::marker::PhantomData<S>,
}

impl<W: Write, S: SymmetricAlgorithm> Encryptor<W, S>
where
    S::Key: Send + Sync + Clone,
{
    pub fn new(mut writer: W, key: S::Key, key_id: String) -> Result<Self> {
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

        Ok(Self {
            writer,
            symmetric_key: key,
            base_nonce,
            chunk_size: DEFAULT_CHUNK_SIZE as usize,
            buffer: Vec::with_capacity(DEFAULT_CHUNK_SIZE as usize),
            chunk_counter: 0,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<W: Write, S: SymmetricAlgorithm> Write for Encryptor<W, S>
where
    S::Key: Send + Sync + Clone,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);

        while self.buffer.len() >= self.chunk_size {
            let chunk = self.buffer.drain(..self.chunk_size).collect::<Vec<u8>>();
            let mut nonce = self.base_nonce;
            let counter_bytes = self.chunk_counter.to_le_bytes();
            for i in 0..8 {
                nonce[4 + i] ^= counter_bytes[i];
            }

            let encrypted_chunk =
                S::encrypt(&self.symmetric_key.clone().into(), &nonce, &chunk, None)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            self.writer.write_all(&encrypted_chunk)?;
            self.chunk_counter += 1;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            let final_chunk = self.buffer.drain(..).collect::<Vec<u8>>();
            let mut nonce = self.base_nonce;
            let counter_bytes = self.chunk_counter.to_le_bytes();
            for i in 0..8 {
                nonce[4 + i] ^= counter_bytes[i];
            }

            let encrypted_chunk = S::encrypt(
                &self.symmetric_key.clone().into(),
                &nonce,
                &final_chunk,
                None,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            self.writer.write_all(&encrypted_chunk)?;
            self.chunk_counter += 1;
        }
        self.writer.flush()
    }
}

/// Implements `std::io::Read` for synchronous, streaming symmetric decryption.
pub struct Decryptor<R: Read, S: SymmetricAlgorithm>
where
    S::Key: Send + Sync + Clone,
{
    reader: R,
    symmetric_key: S::Key,
    base_nonce: [u8; 12],
    encrypted_chunk_size: usize,
    buffer: io::Cursor<Vec<u8>>,
    chunk_counter: u64,
    is_done: bool,
    _phantom: std::marker::PhantomData<S>,
}

impl<R: Read, S: SymmetricAlgorithm> Decryptor<R, S>
where
    S::Key: Send + Sync + Clone,
{
    pub fn new(mut reader: R, key: &S::Key) -> Result<Self> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let header_len = u32::from_le_bytes(len_buf) as usize;

        let mut header_bytes = vec![0u8; header_len];
        reader.read_exact(&mut header_bytes)?;
        let (header, _) = Header::decode_from_slice(&header_bytes)?;

        let (chunk_size, base_nonce) = match header.payload {
            HeaderPayload::Symmetric {
                stream_info: Some(info),
                ..
            } => (info.chunk_size, info.base_nonce),
            _ => return Err(Error::InvalidHeader),
        };

        let tag_len = S::TAG_SIZE;
        let encrypted_chunk_size = chunk_size as usize + tag_len;

        Ok(Self {
            reader,
            symmetric_key: key.clone(),
            base_nonce,
            encrypted_chunk_size,
            buffer: io::Cursor::new(Vec::new()),
            chunk_counter: 0,
            is_done: false,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<R: Read, S: SymmetricAlgorithm> Read for Decryptor<R, S>
where
    S::Key: Send + Sync + Clone,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes_read_from_buf = self.buffer.read(buf)?;
        if bytes_read_from_buf > 0 || self.is_done {
            return Ok(bytes_read_from_buf);
        }

        let mut encrypted_chunk = vec![0u8; self.encrypted_chunk_size];
        let bytes_read = self.reader.read(&mut encrypted_chunk)?;
        if bytes_read == 0 {
            self.is_done = true;
            return Ok(0);
        }

        let mut nonce = self.base_nonce;
        let counter_bytes = self.chunk_counter.to_le_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= counter_bytes[i];
        }

        let decrypted_chunk = S::decrypt(
            &self.symmetric_key.clone().into(),
            &nonce,
            &encrypted_chunk[..bytes_read],
            None,
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        self.buffer = io::Cursor::new(decrypted_chunk);
        self.chunk_counter += 1;

        self.buffer.read(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::definitions::Aes256Gcm;
    use std::io::{Cursor, Read, Write};

    fn test_streaming_roundtrip(plaintext: &[u8]) {
        let key = Aes256Gcm::generate_key().unwrap();

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, Aes256Gcm>::new(
            &mut encrypted_data,
            key.clone(),
            "test_key_id".to_string(),
        )
        .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.flush().unwrap();

        // Decrypt
        let mut decryptor =
            Decryptor::<_, Aes256Gcm>::new(Cursor::new(&encrypted_data), &key).unwrap();
        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[test]
    fn test_roundtrip_long_message() {
        let plaintext = b"This is a very long test message to test the streaming encryption and decryption. It should be longer than a single chunk to ensure that the chunking logic is working correctly. Let's add more data to make sure it spans multiple chunks. Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        test_streaming_roundtrip(plaintext);
    }

    #[test]
    fn test_roundtrip_empty_message() {
        test_streaming_roundtrip(b"");
    }

    #[test]
    fn test_roundtrip_exact_chunk_size() {
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];
        test_streaming_roundtrip(&plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some important data";

        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, Aes256Gcm>::new(
            &mut encrypted_data,
            key.clone(),
            "test_key_id".to_string(),
        )
        .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.flush().unwrap();

        // Tamper with the ciphertext body (after the header).
        // First 4 bytes are header length.
        let header_len_bytes: [u8; 4] = encrypted_data[0..4].try_into().unwrap();
        let header_len = u32::from_le_bytes(header_len_bytes) as usize;

        // Tamper the first byte of the actual ciphertext.
        let ciphertext_start_index = 4 + header_len;
        assert!(
            encrypted_data.len() > ciphertext_start_index,
            "Not enough data to tamper"
        );
        encrypted_data[ciphertext_start_index] ^= 1;

        let mut decryptor =
            Decryptor::<_, Aes256Gcm>::new(Cursor::new(&encrypted_data), &key).unwrap();
        let mut decrypted_data = Vec::new();
        let result = decryptor.read_to_end(&mut decrypted_data);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = Aes256Gcm::generate_key().unwrap();
        let key2 = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some data";

        let mut encrypted_data = Vec::new();
        let mut encryptor =
            Encryptor::<_, Aes256Gcm>::new(&mut encrypted_data, key1, "test_key_id_1".to_string())
                .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.flush().unwrap();

        let mut decryptor =
            Decryptor::<_, Aes256Gcm>::new(Cursor::new(&encrypted_data), &key2).unwrap();
        let mut decrypted_data = Vec::new();
        let result = decryptor.read_to_end(&mut decrypted_data);

        assert!(result.is_err());
    }
}
