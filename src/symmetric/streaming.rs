//! Implements `std::io` traits for synchronous, streaming symmetric encryption.
//!
//! 为同步、流式对称加密实现 `std::io` trait。

use crate::algorithms::traits::SymmetricAlgorithm;
use crate::body::streaming::{DecryptorImpl, EncryptorImpl};
use crate::common::header::{Header, HeaderPayload};
use crate::common::PendingImpl;
use crate::error::{Error, FormatError, Result};
use crate::keys::TypedSymmetricKey;
use crate::symmetric::common::create_header;
use crate::symmetric::traits::SymmetricStreamingProcessor;
use std::io::{Read, Write};

/// Implements `std::io::Write` for synchronous, streaming symmetric encryption.
pub struct Encryptor<W: Write> {
    inner: EncryptorImpl<W>,
}

impl<W: Write> Encryptor<W> {
    pub fn new<S: SymmetricAlgorithm>(
        mut writer: W,
        algorithm: &S,
        key: TypedSymmetricKey,
        key_id: String,
        aad: Option<&[u8]>,
    ) -> Result<Self> {
        let (header, base_nonce) = create_header(algorithm, key_id)?;
        let header_bytes = header.encode_to_vec()?;
        writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&header_bytes)?;
        let inner = EncryptorImpl::new(writer, algorithm.clone_box_symmetric(), key, base_nonce, aad)?;
        Ok(Self { inner })
    }

    pub fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    pub fn finish(self) -> Result<()> {
        self.inner.finish()
    }
}

/// A decryptor that is pending the provision of a key.
pub struct PendingDecryptor<R: Read> {
    reader: R,
    header: Header,
}

impl<R: Read> PendingDecryptor<R> {
    pub fn from_reader(mut reader: R) -> Result<Self> {
        let header = Header::decode_from_prefixed_reader(&mut reader)?;
        Ok(Self { reader, header })
    }

    pub fn into_decryptor<S: SymmetricAlgorithm>(
        self,
        algorithm: &S,
        key: TypedSymmetricKey,
        aad: Option<&[u8]>,
    ) -> Result<Decryptor<R>> {
        let base_nonce = match &self.header.payload {
            HeaderPayload::Symmetric {
                stream_info: Some(info),
                ..
            } => info.base_nonce,
            _ => return Err(Error::Format(FormatError::InvalidHeader)),
        };
        let inner = DecryptorImpl::new(self.reader, algorithm.clone_box_symmetric(), key, base_nonce, aad);
        Ok(Decryptor { inner })
    }
}

/// Implements `std::io::Read` for synchronous, streaming symmetric decryption.
pub struct Decryptor<R: Read> {
    inner: DecryptorImpl<R>,
}

impl<R: Read> Read for Decryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Read> PendingImpl for PendingDecryptor<R> {
    fn header(&self) -> &Header {
        &self.header
    }
}

pub struct Streaming<'a, S: SymmetricAlgorithm> {
    algorithm: &'a S,
}

impl<'a, S: SymmetricAlgorithm> Streaming<'a, S> {
    pub fn new(algorithm: &'a S) -> Self {
        Self { algorithm }
    }
}

impl<'a, S: SymmetricAlgorithm> SymmetricStreamingProcessor for Streaming<'a, S> {
    fn encrypt_to_stream<'b>(
        &self,
        key: TypedSymmetricKey,
        key_id: String,
        writer: Box<dyn Write + 'b>,
        aad: Option<&[u8]>,
    ) -> Result<Box<dyn Write + 'b>> {
        let encryptor = Encryptor::new(Box::new(writer), self.algorithm, key, key_id, aad)?;
        Ok(Box::new(StreamEncryptor {
            encryptor: Some(encryptor),
            _marker: std::marker::PhantomData,
        }))
    }

    fn decrypt_from_stream<'b>(
        &self,
        key: TypedSymmetricKey,
        reader: Box<dyn Read + 'b>,
        aad: Option<&[u8]>,
    ) -> Result<Box<dyn Read + 'b>> {
        let pending = PendingDecryptor::from_reader(reader)?;
        let decryptor = pending.into_decryptor(self.algorithm, key, aad)?;
        Ok(Box::new(decryptor))
    }
}

struct StreamEncryptor<'a, W: Write> {
    encryptor: Option<Encryptor<W>>,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<W: Write> Write for StreamEncryptor<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.encryptor
            .as_mut()
            .unwrap()
            .write(buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<W: Write> Drop for StreamEncryptor<'_, W> {
    fn drop(&mut self) {
        if let Some(encryptor) = self.encryptor.take() {
            encryptor.finish().unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::definitions::symmetric::Aes256GcmWrapper;
    use crate::keys::TypedSymmetricKey;
    use seal_crypto::prelude::SymmetricKeyGenerator;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
    use std::io::Cursor;
    use std::io::Write;

    fn get_wrapper() -> Aes256GcmWrapper {
        Aes256GcmWrapper::new()
    }

    fn test_streaming_roundtrip(plaintext: &[u8], aad: Option<&[u8]>) {
        let wrapper = get_wrapper();
        let key_id = "test_key_id".to_string();
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::new(
            &mut encrypted_data,
            &wrapper,
            key.clone(),
            key_id.clone(),
            aad,
        )
        .unwrap();
        encryptor.write(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt using the new two-step process
        let pending_decryptor =
            PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        assert_eq!(
            pending_decryptor.header().payload.key_id(),
            Some(key_id.as_str())
        );

        let mut decryptor = pending_decryptor
            .into_decryptor(&wrapper, key, aad)
            .unwrap();
        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[test]
    fn test_processor_roundtrip() {
        let wrapper = get_wrapper();
        let processor = Streaming::new(&wrapper);
        let plaintext = b"This is a processor test for streaming.";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let aad = Some(b"streaming aad" as &[u8]);

        // Encrypt
        let mut encrypted_data = Vec::new();
        {
            let mut encrypt_stream = processor
                .encrypt_to_stream(
                    key.clone(),
                    "proc_key".to_string(),
                    Box::new(&mut encrypted_data),
                    aad,
                )
                .unwrap();
            encrypt_stream.write_all(plaintext).unwrap();
        }

        // Decrypt
        let mut decrypt_stream = processor
            .decrypt_from_stream(key.clone(), Box::new(Cursor::new(&encrypted_data)), aad)
            .unwrap();
        let mut decrypted_data = Vec::new();
        decrypt_stream.read_to_end(&mut decrypted_data).unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[test]
    fn test_roundtrip_long_message() {
        let plaintext = b"This is a very long test message to test the streaming encryption and decryption. It should be longer than a single chunk to ensure that the chunking logic is working correctly. Let's add more data to make sure it spans multiple chunks. Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        test_streaming_roundtrip(plaintext, None);
    }

    #[test]
    fn test_roundtrip_empty_message() {
        test_streaming_roundtrip(b"", None);
    }

    #[test]
    fn test_roundtrip_exact_chunk_size() {
        let plaintext = vec![42u8; crate::common::DEFAULT_CHUNK_SIZE as usize];
        test_streaming_roundtrip(&plaintext, None);
    }

    #[test]
    fn test_aad_roundtrip() {
        let plaintext = b"streaming data with aad";
        let aad = b"streaming context";
        test_streaming_roundtrip(plaintext, Some(aad));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let wrapper = get_wrapper();
        let plaintext = b"some important data";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::new(
            &mut encrypted_data,
            &wrapper,
            key.clone(),
            "test_key_id".to_string(),
            None,
        )
        .unwrap();
        encryptor.write(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Tamper with the ciphertext body, after the header
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        if encrypted_data.len() > header_len {
            encrypted_data[header_len] ^= 1;
        }

        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let mut decryptor = pending.into_decryptor(&wrapper, key, None).unwrap();
        let result = decryptor.read_to_end(&mut Vec::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let wrapper1 = get_wrapper();
        let wrapper2 = get_wrapper();
        let plaintext = b"some data";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::new(
            &mut encrypted_data,
            &wrapper1,
            key.clone(),
            "key1".to_string(),
            None,
        )
        .unwrap();
        encryptor.write(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt with the wrong key
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let mut decryptor = pending.into_decryptor(&wrapper2, key, None).unwrap();
        let result = decryptor.read_to_end(&mut Vec::new());

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let wrapper = get_wrapper();
        let plaintext = b"some important data";
        let aad1 = b"correct aad";
        let aad2 = b"wrong aad";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::new(
            &mut encrypted_data,
            &wrapper,
            key.clone(),
            "test_key_id".to_string(),
            Some(aad1),
        )
        .unwrap();
        encryptor.write(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt with wrong AAD
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let mut decryptor = pending
            .into_decryptor(&wrapper, key.clone(), Some(aad2))
            .unwrap();
        let result = decryptor.read_to_end(&mut Vec::new());
        assert!(result.is_err());

        // Decrypt with no AAD
        let pending2 = PendingDecryptor::from_reader(Cursor::new(encrypted_data)).unwrap();
        let mut decryptor2 = pending2.into_decryptor(&wrapper, key, None).unwrap();
        let result2 = decryptor2.read_to_end(&mut Vec::new());
        assert!(result2.is_err());
    }
}
