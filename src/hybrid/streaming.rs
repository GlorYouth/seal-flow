//! Synchronous, streaming hybrid encryption and decryption implementation.
use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::header::{Header, HeaderPayload, SealMode, StreamInfo};
use crate::error::{Error, Result};
use rand::{rngs::OsRng, TryRngCore};
use seal_crypto::prelude::*;
use seal_crypto::zeroize::Zeroizing;
use std::io::{self, Read, Write};

const DEFAULT_CHUNK_SIZE: u32 = 65536; // 64 KiB

/// Implements `std::io::Write` for synchronous, streaming hybrid encryption.
pub struct Encryptor<W: Write, A: AsymmetricAlgorithm, S: SymmetricAlgorithm> {
    writer: W,
    symmetric_key: Zeroizing<Vec<u8>>, // This is the derived DEK
    base_nonce: [u8; 12],
    chunk_size: usize,
    buffer: Vec<u8>,
    chunk_counter: u64,
    _phantom: std::marker::PhantomData<(A, S)>,
}

impl<W: Write, A, S> Encryptor<W, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    Vec<u8>: From<<<A as AsymmetricAlgorithm>::Scheme as Kem>::EncapsulatedKey>,
{
    /// Creates a new streaming encryptor.
    ///
    /// This will perform the KEM encapsulate operation immediately to generate the DEK,
    /// and write the complete header to the underlying writer.
    pub fn new(mut writer: W, pk: &A::PublicKey, kek_id: String) -> Result<Self> {
        // 1. KEM Encapsulate: Generate DEK and wrap it.
        let (shared_secret, encapsulated_key) = A::Scheme::encapsulate(&pk.clone().into())?;

        // 2. Prepare streaming parameters.
        let mut base_nonce = [0u8; 12];
        OsRng.try_fill_bytes(&mut base_nonce)?;

        // 3. Construct the header.
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

        // 4. Write header to the underlying writer.
        let header_bytes = header.encode_to_vec()?;
        writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&header_bytes)?;

        Ok(Self {
            writer,
            symmetric_key: shared_secret,
            base_nonce,
            chunk_size: DEFAULT_CHUNK_SIZE as usize,
            buffer: Vec::with_capacity(DEFAULT_CHUNK_SIZE as usize),
            chunk_counter: 0,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<W: Write, A, S> Write for Encryptor<W, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    <<S as SymmetricAlgorithm>::Scheme as SymmetricKeyGenerator>::Key: From<Zeroizing<Vec<u8>>>,
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
                S::Scheme::encrypt(&self.symmetric_key.clone().into(), &nonce, &chunk, None)
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

            let encrypted_chunk =
                S::Scheme::encrypt(&self.symmetric_key.clone().into(), &nonce, &final_chunk, None)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            self.writer.write_all(&encrypted_chunk)?;
            self.chunk_counter += 1;
        }
        self.writer.flush()
    }
}

/// Implements `std::io::Read` for synchronous, streaming hybrid decryption.
pub struct Decryptor<R: Read, A: AsymmetricAlgorithm, S: SymmetricAlgorithm> {
    reader: R,
    symmetric_key: Zeroizing<Vec<u8>>, // The recovered DEK
    base_nonce: [u8; 12],
    encrypted_chunk_size: usize,
    buffer: io::Cursor<Vec<u8>>,
    chunk_counter: u64,
    is_done: bool,
    _phantom: std::marker::PhantomData<(A, S)>,
}

impl<R: Read, A, S> Decryptor<R, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    <A::Scheme as Kem>::EncapsulatedKey: From<Vec<u8>>,
{
    /// Creates a new streaming decryptor.
    ///
    /// This will read the header from the underlying reader and perform the KEM
    /// decapsulate operation immediately to recover the DEK.
    pub fn new(mut reader: R, sk: &A::PrivateKey) -> Result<Self> {
        // 1. Read header.
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let header_len = u32::from_le_bytes(len_buf) as usize;

        let mut header_bytes = vec![0u8; header_len];
        reader.read_exact(&mut header_bytes)?;
        let (header, _) = Header::decode_from_slice(&header_bytes)?;

        // 2. Extract info and encapsulated key.
        let (encapsulated_key, chunk_size, base_nonce) = match header.payload {
            HeaderPayload::Hybrid {
                encrypted_dek,
                stream_info: Some(info),
                ..
            } => (encrypted_dek.into(), info.chunk_size, info.base_nonce),
            _ => return Err(Error::InvalidHeader),
        };

        // 3. KEM Decapsulate to recover the DEK.
        let shared_secret = A::Scheme::decapsulate(&sk.clone().into(), &encapsulated_key)?;

        let tag_len = S::Scheme::TAG_SIZE;
        let encrypted_chunk_size = chunk_size as usize + tag_len;

        Ok(Self {
            reader,
            symmetric_key: shared_secret,
            base_nonce,
            encrypted_chunk_size,
            buffer: io::Cursor::new(Vec::new()),
            chunk_counter: 0,
            is_done: false,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<R: Read, A, S> Read for Decryptor<R, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    <<S as SymmetricAlgorithm>::Scheme as SymmetricKeyGenerator>::Key: From<Zeroizing<Vec<u8>>>,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes_read_from_buf = self.buffer.read(buf)?;
        if bytes_read_from_buf > 0 || self.is_done {
            return Ok(bytes_read_from_buf);
        }

        let mut encrypted_chunk = vec![0u8; self.encrypted_chunk_size];
        let bytes_read = self.reader.read(&mut encrypted_chunk)?;
        if bytes_read == 0 {
            // This is a clean EOF on a chunk boundary.
            self.is_done = true;
            return Ok(0);
        }

        // Handle cases where the last chunk is smaller than the full chunk size.
        let final_encrypted_chunk = &encrypted_chunk[..bytes_read];

        let mut nonce = self.base_nonce;
        let counter_bytes = self.chunk_counter.to_le_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= counter_bytes[i];
        }

        let plaintext_chunk =
            S::Scheme::decrypt(&self.symmetric_key.clone().into(), &nonce, final_encrypted_chunk, None)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decryption failed"))?;

        self.buffer = io::Cursor::new(plaintext_chunk);
        self.chunk_counter += 1;

        // Recursively call read to fill the user's buffer from our new internal buffer.
        self.read(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::definitions::{Aes256Gcm, Rsa2048};
    use crate::algorithms::traits::AsymmetricAlgorithm;
    use std::io::{Cursor, Read, Write};

    fn test_hybrid_streaming_roundtrip(plaintext: &[u8]) {
        let (pk, sk) = <Rsa2048 as AsymmetricAlgorithm>::Scheme::generate_keypair().unwrap();

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor =
            Encryptor::<_, Rsa2048, Aes256Gcm>::new(&mut encrypted_data, &pk, "test_kek_id".to_string())
                .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.flush().unwrap();

        // Decrypt
        let mut decryptor =
            Decryptor::<_, Rsa2048, Aes256Gcm>::new(Cursor::new(&encrypted_data), &sk).unwrap();
        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[test]
    fn test_roundtrip_long_message() {
        let plaintext = b"This is a very long test message to test the hybrid streaming encryption and decryption. It needs to be longer than a single chunk to ensure the chunking logic is working correctly.";
        test_hybrid_streaming_roundtrip(plaintext);
    }

    #[test]
    fn test_roundtrip_empty_message() {
        test_hybrid_streaming_roundtrip(b"");
    }

    #[test]
    fn test_roundtrip_exact_chunk_size() {
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];
        test_hybrid_streaming_roundtrip(&plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (pk, sk) = <Rsa2048 as AsymmetricAlgorithm>::Scheme::generate_keypair().unwrap();
        let plaintext = b"some important data";

        let mut encrypted_data = Vec::new();
        let mut encryptor =
            Encryptor::<_, Rsa2048, Aes256Gcm>::new(&mut encrypted_data, &pk, "test_kek_id".to_string())
                .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.flush().unwrap();

        // Tamper with the ciphertext body
        if encrypted_data.len() > 300 {
            encrypted_data[300] ^= 1;
        }

        let mut decryptor =
            Decryptor::<_, Rsa2048, Aes256Gcm>::new(Cursor::new(&encrypted_data), &sk).unwrap();
        let mut decrypted_data = Vec::new();
        let result = decryptor.read_to_end(&mut decrypted_data);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let (pk, _) = <Rsa2048 as AsymmetricAlgorithm>::Scheme::generate_keypair().unwrap();
        let plaintext = b"some data";

        let mut encrypted_data = Vec::new();
        let mut encryptor =
            Encryptor::<_, Rsa2048, Aes256Gcm>::new(&mut encrypted_data, &pk, "test_kek_id".to_string())
                .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.flush().unwrap();

        // Decrypt with the wrong private key should fail
        let (_, sk2) = <Rsa2048 as AsymmetricAlgorithm>::Scheme::generate_keypair().unwrap();
        let result = Decryptor::<_, Rsa2048, Aes256Gcm>::new(Cursor::new(&encrypted_data), &sk2);

        assert!(result.is_err());
    }
}
