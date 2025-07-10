//! Implements the ordinary (single-threaded, in-memory) symmetric encryption scheme.
//!
//! 实现普通（单线程，内存中）对称加密方案。

use crate::algorithms::traits::SymmetricAlgorithm;
use crate::body::traits::OrdinaryBodyProcessor;
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, FormatError, Result};
use crate::keys::TypedSymmetricKey;
use crate::symmetric::common::create_header;
use crate::symmetric::pending::PendingDecryptor;
use crate::symmetric::traits::{SymmetricOrdinaryPendingDecryptor, SymmetricOrdinaryProcessor};
use crate::keys::SymmetricKey;

impl<'a, S> SymmetricOrdinaryPendingDecryptor<'a> for PendingDecryptor<&'a [u8], S>
where
    S: SymmetricAlgorithm + OrdinaryBodyProcessor,
{
    fn into_plaintext(
        self: Box<Self>,
        key: SymmetricKey,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let algorithm = self.header.payload.symmetric_algorithm();
        let typed_key = key.into_typed(algorithm)?;

        let base_nonce = match &self.header.payload {
            HeaderPayload::Symmetric {
                stream_info: Some(info),
                ..
            } => info.base_nonce,
            _ => return Err(Error::Format(FormatError::InvalidHeader)),
        };

        self.algorithm
            .decrypt_body_in_memory(typed_key, &base_nonce, self.source, aad)
    }

    fn header(&self) -> &Header {
        &self.header
    }
}

pub struct Ordinary<'s, S: SymmetricAlgorithm + OrdinaryBodyProcessor> {
    algorithm: &'s S,
}

impl<'s, S: SymmetricAlgorithm + OrdinaryBodyProcessor> Ordinary<'s, S> {
    pub fn new(algorithm: &'s S) -> Self {
        Self { algorithm }
    }
}

impl<'s, S: SymmetricAlgorithm + OrdinaryBodyProcessor> SymmetricOrdinaryProcessor
    for Ordinary<'s, S>
{
    fn encrypt_symmetric_in_memory(
        &self,
        key: TypedSymmetricKey,
        key_id: String,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let (header, base_nonce) = create_header(self.algorithm, key_id)?;
        let header_bytes = header.encode_to_vec()?;

        self.algorithm
            .encrypt_body_in_memory(key, &base_nonce, header_bytes, plaintext, aad)
    }

    fn begin_decrypt_symmetric_in_memory<'a>(
        &self,
        ciphertext: &'a [u8],
    ) -> Result<Box<dyn SymmetricOrdinaryPendingDecryptor<'a> + 'a>> {
        let (header, ciphertext_body) = Header::decode_from_prefixed_slice(ciphertext)?;
        let pending = PendingDecryptor {
            source: ciphertext_body,
            header,
            algorithm: self.algorithm.clone(),
        };
        Ok(Box::new(pending))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::definitions::symmetric::Aes256GcmWrapper;
    use crate::common::DEFAULT_CHUNK_SIZE;
    use crate::keys::SymmetricKey as UntypedSymmetricKey;
    use seal_crypto::prelude::SymmetricKeyGenerator;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;

    fn get_wrapper() -> Aes256GcmWrapper {
        Aes256GcmWrapper::new()
    }

    #[test]
    fn test_symmetric_ordinary_roundtrip() {
        let wrapper = get_wrapper();
        let processor = Ordinary::new(&wrapper);
        let plaintext = b"This is a test message that is longer than one chunk to ensure the chunking logic works correctly. Let's add some more data to be sure.";
        let raw_key = Aes256Gcm::generate_key().unwrap();
        let key = TypedSymmetricKey::Aes256Gcm(raw_key.clone());
        let untyped_key = UntypedSymmetricKey::Aes256Gcm(raw_key);
        let encrypted = processor
            .encrypt_symmetric_in_memory(key.clone(), "test_key_id".to_string(), plaintext, None)
            .unwrap();
        let pending = processor
            .begin_decrypt_symmetric_in_memory(&encrypted)
            .unwrap();
        let decrypted = pending.into_plaintext(untyped_key, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_processor_roundtrip() {
        let wrapper = get_wrapper();
        let processor = Ordinary::new(&wrapper);
        let plaintext = b"This is a processor test.";
        let raw_key = Aes256Gcm::generate_key().unwrap();
        let key = TypedSymmetricKey::Aes256Gcm(raw_key.clone());
        let untyped_key = UntypedSymmetricKey::Aes256Gcm(raw_key);
        let encrypted = processor
            .encrypt_symmetric_in_memory(key.clone(), "proc_key".to_string(), plaintext, None)
            .unwrap();
        let pending = processor
            .begin_decrypt_symmetric_in_memory(&encrypted)
            .unwrap();
        let decrypted = pending.into_plaintext(untyped_key, None).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_empty_plaintext() {
        let wrapper = get_wrapper();
        let processor = Ordinary::new(&wrapper);
        let plaintext = b"";
        let raw_key = Aes256Gcm::generate_key().unwrap();
        let key = TypedSymmetricKey::Aes256Gcm(raw_key.clone());
        let untyped_key = UntypedSymmetricKey::Aes256Gcm(raw_key);
        let encrypted = processor
            .encrypt_symmetric_in_memory(key.clone(), "test_key_id".to_string(), plaintext, None)
            .unwrap();
        let pending = processor
            .begin_decrypt_symmetric_in_memory(&encrypted)
            .unwrap();
        let decrypted = pending.into_plaintext(untyped_key, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let wrapper = get_wrapper();
        let processor = Ordinary::new(&wrapper);
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];
        let raw_key = Aes256Gcm::generate_key().unwrap();
        let key = TypedSymmetricKey::Aes256Gcm(raw_key.clone());
        let untyped_key = UntypedSymmetricKey::Aes256Gcm(raw_key);
        let encrypted = processor
            .encrypt_symmetric_in_memory(key.clone(), "test_key_id".to_string(), &plaintext, None)
            .unwrap();
        let pending = processor
            .begin_decrypt_symmetric_in_memory(&encrypted)
            .unwrap();
        let decrypted = pending.into_plaintext(untyped_key, None).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let wrapper = get_wrapper();
        let processor = Ordinary::new(&wrapper);
        let plaintext = b"some important data";
        let raw_key = Aes256Gcm::generate_key().unwrap();
        let key = TypedSymmetricKey::Aes256Gcm(raw_key.clone());
        let untyped_key = UntypedSymmetricKey::Aes256Gcm(raw_key);
        let mut encrypted = processor
            .encrypt_symmetric_in_memory(key.clone(), "test_key_id".to_string(), plaintext, None)
            .unwrap();

        // Tamper with the ciphertext body
        let header_len = 4 + u32::from_le_bytes(encrypted[0..4].try_into().unwrap()) as usize;
        if encrypted.len() > header_len {
            encrypted[header_len] ^= 1;
        }

        let pending = processor.begin_decrypt_symmetric_in_memory(&encrypted).unwrap();
        let result = pending.into_plaintext(untyped_key, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let wrapper = get_wrapper();
        let processor = Ordinary::new(&wrapper);
        let plaintext = b"some data to protect";
        let aad = b"some context data";
        let wrong_aad = b"wrong context data";
        let raw_key = Aes256Gcm::generate_key().unwrap();
        let key = TypedSymmetricKey::Aes256Gcm(raw_key.clone());
        let untyped_key = UntypedSymmetricKey::Aes256Gcm(raw_key);
        // Encrypt with AAD
        let encrypted = processor
            .encrypt_symmetric_in_memory(key.clone(), "aad_key".to_string(), plaintext, Some(aad))
            .unwrap();

        // Decrypt with correct AAD
        let pending = processor.begin_decrypt_symmetric_in_memory(&encrypted).unwrap();
        let decrypted = pending.into_plaintext(untyped_key.clone(), Some(aad)).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Decrypt with wrong AAD should fail
        let pending = processor.begin_decrypt_symmetric_in_memory(&encrypted).unwrap();
        let result = pending.into_plaintext(untyped_key, Some(wrong_aad));
        assert!(result.is_err());
    }
}
