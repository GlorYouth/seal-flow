//! Implements `std::io` traits for synchronous, streaming symmetric encryption.

use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::{Header, HeaderPayload, SealMode, StreamInfo};
use crate::error::{Error, Result};
use rand::{rngs::OsRng, TryRngCore};
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

    /// Finalizes the encryption stream.
    ///
    /// This method must be called to ensure that the last partial chunk of data is
    /// encrypted and the authentication tag is written to the underlying writer.
    pub fn finish(mut self) -> Result<()> {
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
        }
        self.writer.flush()?;
        Ok(())
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
        self.writer.flush()
    }
}

/// A decryptor that is pending the provision of a key.
///
/// This state is entered after the header has been successfully read from the
/// stream, allowing the user to inspect the header (e.g., to find the `key_id`)
/// before supplying the appropriate key to proceed with decryption.
pub struct PendingDecryptor<R: Read> {
    reader: R,
    header: Header,
}

impl<R: Read> PendingDecryptor<R> {
    /// Creates a new `PendingDecryptor` by reading the header from the provided reader.
    pub fn from_reader(mut reader: R) -> Result<Self> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let header_len = u32::from_le_bytes(len_buf) as usize;

        let mut header_bytes = vec![0u8; header_len];
        reader.read_exact(&mut header_bytes)?;
        let (header, _) = Header::decode_from_slice(&header_bytes)?;

        Ok(Self { reader, header })
    }

    /// Returns a reference to the header that was read from the stream.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Consumes the `PendingDecryptor` and returns a full `Decryptor` instance,
    /// ready to decrypt the stream.
    pub fn into_decryptor<S: SymmetricAlgorithm>(
        self,
        key: &S::Key,
    ) -> Result<Decryptor<R, S>>
    where
        S::Key: Send + Sync + Clone,
    {
        let (chunk_size, base_nonce) = match &self.header.payload {
            HeaderPayload::Symmetric {
                stream_info: Some(info),
                ..
            } => (info.chunk_size, info.base_nonce),
            _ => return Err(Error::InvalidHeader),
        };

        let tag_len = S::TAG_SIZE;
        let encrypted_chunk_size = chunk_size as usize + tag_len;

        Ok(Decryptor {
            reader: self.reader,
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
    use seal_crypto::prelude::SymmetricKeyGenerator;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
    use std::io::{Cursor, Read, Write};

    fn test_streaming_roundtrip(plaintext: &[u8]) {
        let key = Aes256Gcm::generate_key().unwrap();
        let key_id = "test_key_id".to_string();

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor =
            Encryptor::<_, Aes256Gcm>::new(&mut encrypted_data, key.clone(), key_id.clone())
                .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt using the new two-step process
        let pending_decryptor =
            PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        assert_eq!(pending_decryptor.header().payload.key_id(), Some(key_id.as_str()));

        let mut decryptor = pending_decryptor.into_decryptor::<Aes256Gcm>(&key).unwrap();
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
        encryptor.finish().unwrap();

        // Tamper with the ciphertext body, after the header
        let header_len =
            4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        if encrypted_data.len() > header_len {
            encrypted_data[header_len] ^= 1;
        }

        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let mut decryptor = pending.into_decryptor::<Aes256Gcm>(&key).unwrap();
        let result = decryptor.read_to_end(&mut Vec::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = Aes256Gcm::generate_key().unwrap();
        let key2 = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some data";

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor =
            Encryptor::<_, Aes256Gcm>::new(&mut encrypted_data, key1, "key1".to_string()).unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt with the wrong key
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let mut decryptor = pending.into_decryptor::<Aes256Gcm>(&key2).unwrap();
        let result = decryptor.read_to_end(&mut Vec::new());

        assert!(result.is_err());
    }
}
