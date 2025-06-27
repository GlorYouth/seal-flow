//! Implements `std::io` traits for synchronous, streaming symmetric encryption.

use super::common::{create_header, derive_nonce, DEFAULT_CHUNK_SIZE};
use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, Result};
use std::io::{self, Read, Write};

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
    encrypted_chunk_buffer: Vec<u8>,
    _phantom: std::marker::PhantomData<S>,
}

impl<W: Write, S: SymmetricAlgorithm> Encryptor<W, S>
where
    S::Key: Send + Sync + Clone,
{
    pub fn new(mut writer: W, key: S::Key, key_id: String) -> Result<Self> {
        let (header, base_nonce) = create_header::<S>(key_id)?;

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
            encrypted_chunk_buffer: vec![0u8; DEFAULT_CHUNK_SIZE as usize + S::TAG_SIZE],
            _phantom: std::marker::PhantomData,
        })
    }

    /// Finalizes the encryption stream.
    ///
    /// This method must be called to ensure that the last partial chunk of data is
    /// encrypted and the authentication tag is written to the underlying writer.
    pub fn finish(mut self) -> Result<()> {
        if !self.buffer.is_empty() {
            let nonce = derive_nonce(&self.base_nonce, self.chunk_counter);
            let bytes_written = S::encrypt_to_buffer(
                &self.symmetric_key,
                &nonce,
                &self.buffer,
                &mut self.encrypted_chunk_buffer,
                None,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            self.writer
                .write_all(&self.encrypted_chunk_buffer[..bytes_written])?;
            self.chunk_counter += 1;
            self.buffer.clear();
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
        let mut input = buf;

        // If there's pending data in the buffer, try to fill and process it first.
        if !self.buffer.is_empty() {
            let space_in_buffer = self.chunk_size - self.buffer.len();
            let fill_len = std::cmp::min(space_in_buffer, input.len());
            self.buffer.extend_from_slice(&input[..fill_len]);
            input = &input[fill_len..];

            if self.buffer.len() == self.chunk_size {
                let nonce = derive_nonce(&self.base_nonce, self.chunk_counter);

                let bytes_written = S::encrypt_to_buffer(
                    &self.symmetric_key,
                    &nonce,
                    &self.buffer,
                    &mut self.encrypted_chunk_buffer,
                    None,
                )
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                self.writer
                    .write_all(&self.encrypted_chunk_buffer[..bytes_written])?;
                self.chunk_counter += 1;
                self.buffer.clear();
            }
        }

        // Process full chunks directly from the input buffer.
        while input.len() >= self.chunk_size {
            let chunk = &input[..self.chunk_size];
            let nonce = derive_nonce(&self.base_nonce, self.chunk_counter);

            let bytes_written = S::encrypt_to_buffer(
                &self.symmetric_key,
                &nonce,
                chunk,
                &mut self.encrypted_chunk_buffer,
                None,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            self.writer
                .write_all(&self.encrypted_chunk_buffer[..bytes_written])?;

            self.chunk_counter += 1;
            input = &input[self.chunk_size..];
        }

        // Buffer any remaining data.
        if !input.is_empty() {
            self.buffer.extend_from_slice(input);
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
        let header = Header::decode_from_prefixed_reader(&mut reader)?;
        Ok(Self { reader, header })
    }

    /// Returns a reference to the header that was read from the stream.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Consumes the `PendingDecryptor` and returns a full `Decryptor` instance,
    /// ready to decrypt the stream.
    pub fn into_decryptor<S: SymmetricAlgorithm>(self, key: S::Key) -> Result<Decryptor<R, S>>
    where
        S::Key: Send + Sync,
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
        let key_material = key.into();

        Ok(Decryptor {
            reader: self.reader,
            symmetric_key: key_material,
            base_nonce,
            encrypted_chunk_size,
            buffer: io::Cursor::new(Vec::new()),
            encrypted_chunk_buffer: vec![0; encrypted_chunk_size],
            chunk_counter: 0,
            is_done: false,
            _phantom: std::marker::PhantomData,
        })
    }
}

/// Implements `std::io::Read` for synchronous, streaming symmetric decryption.
pub struct Decryptor<R: Read, S: SymmetricAlgorithm>
where
    S::Key: Send + Sync,
{
    reader: R,
    symmetric_key: S::Key,
    base_nonce: [u8; 12],
    encrypted_chunk_size: usize,
    buffer: io::Cursor<Vec<u8>>,
    encrypted_chunk_buffer: Vec<u8>,
    chunk_counter: u64,
    is_done: bool,
    _phantom: std::marker::PhantomData<S>,
}

impl<R: Read, S: SymmetricAlgorithm> Decryptor<R, S>
where
    S::Key: Send + Sync,
{
    pub fn new(
        reader: R,
        key: S::Key,
        base_nonce: [u8; 12],
        encrypted_chunk_size: usize,
    ) -> Self {
        Self {
            reader,
            symmetric_key: key,
            base_nonce,
            encrypted_chunk_size,
            buffer: io::Cursor::new(Vec::new()),
            encrypted_chunk_buffer: vec![0; encrypted_chunk_size],
            chunk_counter: 0,
            is_done: false,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<R: Read, S: SymmetricAlgorithm> Read for Decryptor<R, S>
where
    S::Key: Send + Sync,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If there's data in the decrypted buffer, serve it first.
        let bytes_read_from_buf = self.buffer.read(buf)?;
        if bytes_read_from_buf > 0 {
            return Ok(bytes_read_from_buf);
        }

        // If the buffer is empty and we're done, signal EOF.
        if self.is_done {
            return Ok(0);
        }

        // Buffer is empty, so we need to read and decrypt the next chunk.
        let bytes_read = self.reader.read(&mut self.encrypted_chunk_buffer)?;
        if bytes_read == 0 {
            self.is_done = true;
            return Ok(0);
        }

        let nonce = derive_nonce(&self.base_nonce, self.chunk_counter);

        // Prepare the output buffer inside the cursor
        let decrypted_buf = self.buffer.get_mut();
        decrypted_buf.clear();
        // Resize to max possible decrypted size. The actual size will be truncated later.
        decrypted_buf.resize(self.encrypted_chunk_size, 0);

        let bytes_written = S::decrypt_to_buffer(
            &self.symmetric_key,
            &nonce,
            &self.encrypted_chunk_buffer[..bytes_read],
            decrypted_buf,
            None,
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        decrypted_buf.truncate(bytes_written);
        self.buffer.set_position(0);
        self.chunk_counter += 1;

        // Now, try to read from the newly filled buffer into the user's buffer.
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
        assert_eq!(
            pending_decryptor.header().payload.key_id(),
            Some(key_id.as_str())
        );

        let mut decryptor = pending_decryptor.into_decryptor::<Aes256Gcm>(key).unwrap();
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
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        if encrypted_data.len() > header_len {
            encrypted_data[header_len] ^= 1;
        }

        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let mut decryptor = pending.into_decryptor::<Aes256Gcm>(key).unwrap();
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
        let mut decryptor = pending.into_decryptor::<Aes256Gcm>(key2).unwrap();
        let result = decryptor.read_to_end(&mut Vec::new());

        assert!(result.is_err());
    }
}
