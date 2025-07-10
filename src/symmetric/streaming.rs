//! Implements `std::io` traits for synchronous, streaming symmetric encryption.
//!
//! 为同步、流式对称加密实现 `std::io` trait。

use crate::algorithms::traits::SymmetricAlgorithm;
use crate::body::streaming::{DecryptorImpl, EncryptorImpl};
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, FormatError, Result};
use crate::keys::{SymmetricKey, TypedSymmetricKey};
use crate::symmetric::common::create_header;
use crate::symmetric::pending::PendingDecryptor;
use crate::symmetric::traits::{SymmetricStreamingPendingDecryptor, SymmetricStreamingProcessor};
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
        let inner =
            EncryptorImpl::new(writer, algorithm.clone_box_symmetric(), key, base_nonce, aad)?;
        Ok(Self { inner })
    }

    pub fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    pub fn finish(self) -> Result<()> {
        self.inner.finish()
    }
}

impl<'a, S> SymmetricStreamingPendingDecryptor<'a> for PendingDecryptor<Box<dyn Read + 'a>, S>
where
    S: SymmetricAlgorithm,
{
    fn into_decryptor(
        self: Box<Self>,
        key: SymmetricKey,
        aad: Option<&[u8]>,
    ) -> Result<Box<dyn Read + 'a>> {
        let algorithm = self.header.payload.symmetric_algorithm();
        let typed_key = key.into_typed(algorithm)?;

        let base_nonce = match &self.header.payload {
            HeaderPayload::Symmetric {
                stream_info: Some(info),
                ..
            } => info.base_nonce,
            _ => return Err(Error::Format(FormatError::InvalidHeader)),
        };
        let inner = DecryptorImpl::new(
            self.source,
            self.algorithm.clone_box_symmetric(),
            typed_key,
            base_nonce,
            aad,
        );
        Ok(Box::new(Decryptor { inner }))
    }

    fn header(&self) -> &Header {
        &self.header
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

pub struct Streaming<'s, S: SymmetricAlgorithm> {
    algorithm: &'s S,
}

impl<'s, S: SymmetricAlgorithm> Streaming<'s, S> {
    pub fn new(algorithm: &'s S) -> Self {
        Self { algorithm }
    }
}

impl<'s, S: SymmetricAlgorithm> SymmetricStreamingProcessor for Streaming<'s, S> {
    fn encrypt_symmetric_to_stream<'b>(
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

    fn begin_decrypt_symmetric_from_stream<'a>(
        &self,
        mut reader: Box<dyn Read + 'a>,
    ) -> Result<Box<dyn SymmetricStreamingPendingDecryptor<'a> + 'a>> {
        let header = Header::decode_from_prefixed_reader(&mut reader)?;
        let pending = PendingDecryptor {
            source: reader,
            header,
            algorithm: self.algorithm.clone(),
        };
        Ok(Box::new(pending))
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
    use crate::keys::{SymmetricKey as UntypedSymmetricKey, TypedSymmetricKey};
    use seal_crypto::prelude::SymmetricKeyGenerator;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
    use std::io::Cursor;
    use std::io::Write;

    fn get_wrapper() -> Aes256GcmWrapper {
        Aes256GcmWrapper::new()
    }

    fn test_streaming_roundtrip(plaintext: &[u8], aad: Option<&[u8]>) {
        let wrapper = get_wrapper();
        let processor = Streaming::new(&wrapper);
        let key_id = "test_key_id".to_string();
        let raw_key = Aes256Gcm::generate_key().unwrap();
        let key = TypedSymmetricKey::Aes256Gcm(raw_key.clone());
        let untyped_key = UntypedSymmetricKey::Aes256Gcm(raw_key);
        // Encrypt
        let mut encrypted_data = Vec::new();
        {
            let mut encryptor = processor
                .encrypt_symmetric_to_stream(
                    key.clone(),
                    key_id.clone(),
                    Box::new(&mut encrypted_data),
                    aad,
                )
                .unwrap();
            encryptor.write_all(plaintext).unwrap();
        }

        // Decrypt using the new two-step process
        let pending_decryptor = processor
            .begin_decrypt_symmetric_from_stream(Box::new(Cursor::new(&encrypted_data)))
            .unwrap();
        assert_eq!(
            pending_decryptor.header().payload.key_id(),
            Some(key_id.as_str())
        );

        let mut decryptor = pending_decryptor.into_decryptor(untyped_key, aad).unwrap();
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
                .encrypt_symmetric_to_stream(
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
            .begin_decrypt_symmetric_from_stream(Box::new(Cursor::new(&encrypted_data)))
            .unwrap()
            .into_decryptor(key.clone(), aad)
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
        let processor = Streaming::new(&wrapper);
        let plaintext = b"some important data";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let mut encrypted_data = Vec::new();
        {
            let mut encryptor = processor
                .encrypt_symmetric_to_stream(
                    key.clone(),
                    "test_key_id".to_string(),
                    Box::new(&mut encrypted_data),
                    None,
                )
                .unwrap();
            encryptor.write_all(plaintext).unwrap();
        }

        // Tamper with the ciphertext body, after the header
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        if encrypted_data.len() > header_len {
            encrypted_data[header_len] ^= 1;
        }

        let pending = processor
            .begin_decrypt_symmetric_from_stream(Box::new(Cursor::new(&encrypted_data)))
            .unwrap();
        let mut decryptor = pending.into_decryptor(key, None).unwrap();
        let result = decryptor.read_to_end(&mut Vec::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let wrapper = get_wrapper();
        let processor = Streaming::new(&wrapper);
        let key_id = "test_key_id".to_string();

        let correct_raw_key = Aes256Gcm::generate_key().unwrap();
        let correct_key = TypedSymmetricKey::Aes256Gcm(correct_raw_key.clone());
        let correct_untyped_key = UntypedSymmetricKey::Aes256Gcm(correct_raw_key);

        let wrong_raw_key = Aes256Gcm::generate_key().unwrap();
        let _wrong_key = TypedSymmetricKey::Aes256Gcm(wrong_raw_key.clone());
        let wrong_untyped_key = UntypedSymmetricKey::Aes256Gcm(wrong_raw_key);

        let plaintext = b"some data";

        // Encrypt with the correct key
        let mut encrypted_data = Vec::new();
        {
            let mut encryptor = processor
                .encrypt_symmetric_to_stream(
                    correct_key.clone(),
                    key_id.clone(),
                    Box::new(&mut encrypted_data),
                    None,
                )
                .unwrap();
            encryptor.write_all(plaintext).unwrap();
        }

        // Attempt to decrypt with the wrong key
        let pending_decryptor = processor
            .begin_decrypt_symmetric_from_stream(Box::new(Cursor::new(&encrypted_data)))
            .unwrap();

        let decryptor_result = pending_decryptor.into_decryptor(wrong_untyped_key, None);

        // We expect an error during the creation of the decryptor,
        // or on the first read.
        if let Ok(mut decryptor) = decryptor_result {
            let mut buf = Vec::new();
            let read_result = decryptor.read_to_end(&mut buf);
            assert!(read_result.is_err(), "Decryption should fail on read");
        }
        // If into_decryptor itself fails, the test passes as well.
    }

    #[test]
    fn test_wrong_aad_fails() {
        let wrapper = get_wrapper();
        let processor = Streaming::new(&wrapper);
        let key_id = "test_key_id".to_string();
        let raw_key = Aes256Gcm::generate_key().unwrap();
        let key = TypedSymmetricKey::Aes256Gcm(raw_key.clone());
        let untyped_key = UntypedSymmetricKey::Aes256Gcm(raw_key);
        let plaintext = b"some data";
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";

        // Encrypt with AAD
        let mut encrypted_data = Vec::new();
        {
            let mut encryptor = processor
                .encrypt_symmetric_to_stream(
                    key.clone(),
                    key_id.clone(),
                    Box::new(&mut encrypted_data),
                    Some(aad),
                )
                .unwrap();
            encryptor.write_all(plaintext).unwrap();
        }

        // Decrypt with correct AAD
        let pending = processor
            .begin_decrypt_symmetric_from_stream(Box::new(Cursor::new(&encrypted_data)))
            .unwrap();
        let mut decryptor = pending
            .into_decryptor(untyped_key.clone(), Some(aad))
            .unwrap();
        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).unwrap();
        assert_eq!(decrypted_data, plaintext);

        // Decrypt with wrong AAD should fail
        let pending_fail = processor
            .begin_decrypt_symmetric_from_stream(Box::new(Cursor::new(&encrypted_data)))
            .unwrap();
        let decryptor_result = pending_fail.into_decryptor(untyped_key.clone(), Some(wrong_aad));
        assert!(
            decryptor_result.is_err()
                || decryptor_result
                    .unwrap()
                    .read_to_end(&mut Vec::new())
                    .is_err()
        );

        // Decrypt with no AAD should also fail
        let pending_fail2 = processor
            .begin_decrypt_symmetric_from_stream(Box::new(Cursor::new(&encrypted_data)))
            .unwrap();
        let decryptor_result2 = pending_fail2.into_decryptor(untyped_key, None);
        assert!(
            decryptor_result2.is_err()
                || decryptor_result2
                    .unwrap()
                    .read_to_end(&mut Vec::new())
                    .is_err()
        );
    }
}
