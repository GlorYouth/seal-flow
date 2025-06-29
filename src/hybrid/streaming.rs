//! Synchronous, streaming hybrid encryption and decryption implementation.
use super::common::create_header;
use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::header::{derive_nonce, DEFAULT_CHUNK_SIZE};
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, Result};
use seal_crypto::prelude::*;
use seal_crypto::zeroize::Zeroizing;
use std::io::{self, Read, Write};

/// An `std::io::Write` adapter for streaming hybrid encryption.
pub struct Encryptor<W, A, S>
where
    W: Write,
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>>,
{
    writer: W,
    symmetric_key: S::Key,
    base_nonce: [u8; 12],
    chunk_size: usize,
    buffer: Vec<u8>,
    chunk_counter: u64,
    encrypted_chunk_buffer: Vec<u8>,
    aad: Option<Vec<u8>>,
    _phantom: std::marker::PhantomData<(A, S)>,
}

impl<W, A, S> Encryptor<W, A, S>
where
    W: Write,
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    Vec<u8>: From<<A as Kem>::EncapsulatedKey>,
    <S as SymmetricKeySet>::Key: From<Zeroizing<Vec<u8>>>,
    A::EncapsulatedKey: Into<Vec<u8>>,
{
    /// Creates a new streaming encryptor.
    ///
    /// This will perform the KEM encapsulate operation immediately to generate the DEK,
    /// and write the complete header to the underlying writer.
    pub fn new(
        mut writer: W,
        pk: &A::PublicKey,
        kek_id: String,
        aad: Option<&[u8]>,
    ) -> Result<Self> {
        // 1. Create header, nonce, and DEK
        let (header, base_nonce, symmetric_key) = create_header::<A, S>(pk, kek_id)?;

        // 2. Write header length and header to the writer
        let header_bytes = header.encode_to_vec()?;
        writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&header_bytes)?;

        Ok(Self {
            writer,
            symmetric_key: symmetric_key.into(),
            base_nonce,
            chunk_size: DEFAULT_CHUNK_SIZE as usize,
            buffer: Vec::with_capacity(DEFAULT_CHUNK_SIZE as usize),
            chunk_counter: 0,
            encrypted_chunk_buffer: vec![0u8; DEFAULT_CHUNK_SIZE as usize + S::TAG_SIZE],
            aad: aad.map(|d| d.to_vec()),
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
                self.aad.as_deref(),
            )
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            self.writer
                .write_all(&self.encrypted_chunk_buffer[..bytes_written])?;
        }
        self.writer.flush()?;
        Ok(())
    }
}

impl<W: Write, A, S> Write for Encryptor<W, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>>,
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
                    self.aad.as_deref(),
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
                self.aad.as_deref(),
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

/// A pending hybrid decryptor that has read the header and is waiting for the private key.
pub struct PendingDecryptor<R: Read> {
    reader: R,
    header: Header,
}

impl<R: Read> PendingDecryptor<R> {
    /// Creates a new `PendingDecryptor` by reading the header from the stream.
    pub fn from_reader(mut reader: R) -> Result<Self> {
        let header = Header::decode_from_prefixed_reader(&mut reader)?;

        Ok(Self { reader, header })
    }

    /// Returns a reference to the header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Consumes the pending decryptor and returns a full `Decryptor` by providing the private key.
    pub fn into_decryptor<A, S>(
        self,
        sk: &A::PrivateKey,
        aad: Option<&[u8]>,
    ) -> Result<Decryptor<R, A, S>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
        A::PrivateKey: Clone,
        A::EncapsulatedKey: From<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        let (encapsulated_key, chunk_size, base_nonce) = match self.header.payload {
            HeaderPayload::Hybrid {
                encrypted_dek,
                stream_info: Some(info),
                ..
            } => (encrypted_dek.into(), info.chunk_size, info.base_nonce),
            _ => return Err(Error::InvalidHeader),
        };

        let shared_secret = A::decapsulate(&sk.clone().into(), &encapsulated_key)?;
        let key_material = shared_secret.into();
        let tag_len = S::TAG_SIZE;
        let encrypted_chunk_size = chunk_size as usize + tag_len;

        Ok(Decryptor {
            reader: self.reader,
            symmetric_key: key_material,
            base_nonce,
            encrypted_chunk_size,
            buffer: io::Cursor::new(Vec::new()),
            encrypted_chunk_buffer: vec![0; encrypted_chunk_size],
            chunk_counter: 0,
            is_done: false,
            aad: aad.map(|d| d.to_vec()),
            _phantom: std::marker::PhantomData,
        })
    }
}

/// Implements `std::io::Read` for synchronous, streaming hybrid decryption.
pub struct Decryptor<R: Read, A: AsymmetricAlgorithm, S: SymmetricAlgorithm>
where
    R: Read,
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>>,
{
    reader: R,
    symmetric_key: S::Key,
    base_nonce: [u8; 12],
    encrypted_chunk_size: usize,
    buffer: io::Cursor<Vec<u8>>,
    encrypted_chunk_buffer: Vec<u8>,
    chunk_counter: u64,
    is_done: bool,
    aad: Option<Vec<u8>>,
    _phantom: std::marker::PhantomData<(A, S)>,
}

impl<R: Read, A, S> Read for Decryptor<R, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>>,
    A::PrivateKey: Clone,
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

        // Buffer is empty, so we need to read the next chunk.
        let mut total_bytes_read = 0;
        while total_bytes_read < self.encrypted_chunk_size {
            match self
                .reader
                .read(&mut self.encrypted_chunk_buffer[total_bytes_read..])
            {
                Ok(0) => {
                    self.is_done = true;
                    break; // EOF
                }
                Ok(n) => total_bytes_read += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        if total_bytes_read == 0 {
            // We've hit EOF and there's no partial chunk to process.
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
            &self.encrypted_chunk_buffer[..total_bytes_read],
            decrypted_buf,
            self.aad.as_deref(),
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
    use seal_crypto::prelude::KeyGenerator;
    use seal_crypto::schemes::asymmetric::traditional::rsa::Rsa2048;
    use seal_crypto::schemes::hash::Sha256;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
    use std::io::Cursor;

    fn test_hybrid_streaming_roundtrip(plaintext: &[u8], aad: Option<&[u8]>) {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let kek_id = "test_kek_id".to_string();

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor =
            Encryptor::<_, Rsa2048, Aes256Gcm>::new(&mut encrypted_data, &pk, kek_id.clone(), aad)
                .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt
        let pending_decryptor =
            PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        assert_eq!(
            pending_decryptor.header().payload.kek_id(),
            Some(kek_id.as_str())
        );

        let mut decryptor = pending_decryptor
            .into_decryptor::<Rsa2048, Aes256Gcm>(&sk, aad)
            .unwrap();
        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[test]
    fn test_roundtrip_long_message() {
        let plaintext = b"This is a very long test message to test the streaming encryption and decryption. It should be longer than a single chunk to ensure that the chunking logic is working correctly. Let's add more data to make sure it spans multiple chunks. Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        test_hybrid_streaming_roundtrip(plaintext, None);
    }

    #[test]
    fn test_roundtrip_empty_message() {
        test_hybrid_streaming_roundtrip(b"", None);
    }

    #[test]
    fn test_roundtrip_exact_chunk_size() {
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];
        test_hybrid_streaming_roundtrip(&plaintext, None);
    }

    #[test]
    fn test_aad_roundtrip() {
        let plaintext = b"streaming hybrid data with aad";
        let aad = b"streaming hybrid context";
        test_hybrid_streaming_roundtrip(plaintext, Some(aad));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"some important data";

        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, Rsa2048, Aes256Gcm>::new(
            &mut encrypted_data,
            &pk,
            "test_kek_id".to_string(),
            None,
        )
        .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Tamper with the ciphertext body
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        if encrypted_data.len() > header_len {
            encrypted_data[header_len] ^= 1;
        }

        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let mut decryptor = pending
            .into_decryptor::<Rsa2048, Aes256Gcm>(&sk, None)
            .unwrap();

        let result = decryptor.read_to_end(&mut Vec::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let (pk, _) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let (_, sk2) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"some data";

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, Rsa2048, Aes256Gcm>::new(
            &mut encrypted_data,
            &pk,
            "test_kek_id".to_string(),
            None,
        )
        .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt with the wrong key
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let result = pending.into_decryptor::<Rsa2048, Aes256Gcm>(&sk2, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"some important data";
        let aad1 = b"correct aad";
        let aad2 = b"wrong aad";

        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, Rsa2048, Aes256Gcm>::new(
            &mut encrypted_data,
            &pk,
            "test_kek_id".to_string(),
            Some(aad1),
        )
        .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt with wrong AAD
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();

        let mut decryptor = pending
            .into_decryptor::<Rsa2048, Aes256Gcm>(&sk, Some(aad2))
            .unwrap();
        let result = decryptor.read_to_end(&mut Vec::new());
        assert!(result.is_err());

        // Decrypt with no AAD
        let pending2 = PendingDecryptor::from_reader(Cursor::new(encrypted_data)).unwrap();
        let mut decryptor2 = pending2
            .into_decryptor::<Rsa2048, Aes256Gcm>(&sk, None)
            .unwrap();
        let result2 = decryptor2.read_to_end(&mut Vec::new());
        assert!(result2.is_err());
    }
}
