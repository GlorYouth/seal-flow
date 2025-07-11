//! Implements the ordinary (single-threaded, in-memory) symmetric encryption scheme.
//!
//! 实现普通（单线程，内存中）对称加密方案。

use crate::body::config::BodyDecryptConfig;
use crate::body::traits::OrdinaryBodyProcessor;
use crate::common::config::{ArcConfig, DecryptorConfig};
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, FormatError, Result};
use crate::keys::TypedSymmetricKey;
use crate::symmetric::config::SymmetricConfig;
use crate::symmetric::pending::PendingDecryptor;
use crate::symmetric::traits::{SymmetricOrdinaryPendingDecryptor, SymmetricOrdinaryProcessor};
use std::borrow::Cow;

impl<'a> SymmetricOrdinaryPendingDecryptor<'a> for PendingDecryptor<&'a [u8]> {
    fn into_plaintext(
        self: Box<Self>,
        key: &TypedSymmetricKey,
        aad: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let (nonce, &chunk_size) = match &self.header.payload {
            HeaderPayload::Symmetric {
                stream_info: Some(info),
                chunk_size,
                ..
            } => (info.base_nonce, chunk_size),
            _ => return Err(Error::Format(FormatError::InvalidHeader)),
        };

        let config = BodyDecryptConfig {
            key: Cow::Borrowed(key),
            nonce,
            aad,
            config: DecryptorConfig {
                chunk_size,
                arc_config: self.config,
            },
        };

        self.algorithm
            .algorithm
            .decrypt_body_in_memory(self.source, config)
    }

    fn header(&self) -> &Header {
        &self.header
    }
}

pub struct Ordinary {}

impl Ordinary {
    pub fn new() -> Self {
        Self {}
    }
}

impl SymmetricOrdinaryProcessor for Ordinary {
    fn encrypt_symmetric_in_memory<'a>(
        &self,
        plaintext: &[u8],
        config: SymmetricConfig<'a>,
    ) -> Result<Vec<u8>> {
        let algo = config.algorithm.clone();
        let config = config.into_encrypt_config()?;

        algo.as_ref().encrypt_body_in_memory(plaintext, config)
    }

    fn begin_decrypt_symmetric_in_memory<'a>(
        &self,
        ciphertext: &'a [u8],
        config: ArcConfig,
    ) -> Result<Box<dyn SymmetricOrdinaryPendingDecryptor<'a> + 'a>> {
        let (header, ciphertext_body) = Header::decode_from_prefixed_slice(ciphertext)?;
        let algorithm = header
            .payload
            .symmetric_algorithm()
            .into_symmetric_wrapper();
        let pending = PendingDecryptor {
            source: ciphertext_body,
            header,
            algorithm,
            config,
        };
        Ok(Box::new(pending))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::symmetric::SymmetricAlgorithmWrapper;
    use crate::common::DEFAULT_CHUNK_SIZE;
    use crate::prelude::SymmetricAlgorithmEnum;

    fn get_wrapper() -> SymmetricAlgorithmWrapper {
        SymmetricAlgorithmEnum::Aes256Gcm.into_symmetric_wrapper()
    }

    #[test]
    fn test_symmetric_ordinary_roundtrip() {
        let wrapper = get_wrapper();
        let processor = Ordinary::new();
        let plaintext = b"This is a test message that is longer than one chunk to ensure the chunking logic works correctly. Let's add some more data to be sure.";
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        let encrypted = processor
            .encrypt_symmetric_in_memory(
                plaintext,
                SymmetricConfig {
                    algorithm: Cow::Borrowed(&wrapper),
                    key_id: "test_key_id".to_string(),
                    config: config.clone(),
                    key: Cow::Borrowed(&key),
                    aad: None,
                },
            )
            .unwrap();
        let pending = processor
            .begin_decrypt_symmetric_in_memory(&encrypted, config)
            .unwrap();
        let decrypted = pending.into_plaintext(&key, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_processor_roundtrip() {
        let wrapper = get_wrapper();
        let processor = Ordinary::new();
        let plaintext = b"This is a processor test.";
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        let encrypted = processor
            .encrypt_symmetric_in_memory(
                plaintext,
                SymmetricConfig {
                    algorithm: Cow::Borrowed(&wrapper),
                    key_id: "proc_key".to_string(),
                    config: config.clone(),
                    key: Cow::Borrowed(&key),
                    aad: None,
                },
            )
            .unwrap();
        let pending = processor
            .begin_decrypt_symmetric_in_memory(&encrypted, config)
            .unwrap();
        let decrypted = pending.into_plaintext(&key, None).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_empty_plaintext() {
        let wrapper = get_wrapper();
        let processor = Ordinary::new();
        let plaintext = b"";
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        let encrypted = processor
            .encrypt_symmetric_in_memory(
                plaintext,
                SymmetricConfig {
                    algorithm: Cow::Borrowed(&wrapper),
                    key_id: "test_key_id".to_string(),
                    config: config.clone(),
                    key: Cow::Borrowed(&key),
                    aad: None,
                },
            )
            .unwrap();
        let pending = processor
            .begin_decrypt_symmetric_in_memory(&encrypted, config)
            .unwrap();
        let decrypted = pending.into_plaintext(&key, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let wrapper = get_wrapper();
        let processor = Ordinary::new();
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        let encrypted = processor
            .encrypt_symmetric_in_memory(
                &plaintext,
                SymmetricConfig {
                    algorithm: Cow::Borrowed(&wrapper),
                    key_id: "test_key_id".to_string(),
                    config: config.clone(),
                    key: Cow::Borrowed(&key),
                    aad: None,
                },
            )
            .unwrap();
        let pending = processor
            .begin_decrypt_symmetric_in_memory(&encrypted, config)
            .unwrap();
        let decrypted = pending.into_plaintext(&key, None).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let wrapper = get_wrapper();
        let processor = Ordinary::new();
        let plaintext = b"some important data";
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        let mut encrypted = processor
            .encrypt_symmetric_in_memory(
                plaintext,
                SymmetricConfig {
                    algorithm: Cow::Borrowed(&wrapper),
                    key_id: "test_key_id".to_string(),
                    config: config.clone(),
                    key: Cow::Borrowed(&key),
                    aad: None,
                },
            )
            .unwrap();

        // Tamper with the ciphertext body
        let header_len = 4 + u32::from_le_bytes(encrypted[0..4].try_into().unwrap()) as usize;
        if encrypted.len() > header_len {
            encrypted[header_len] ^= 1;
        }

        let pending = processor
            .begin_decrypt_symmetric_in_memory(&encrypted, config)
            .unwrap();
        let result = pending.into_plaintext(&key, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let wrapper = get_wrapper();
        let processor = Ordinary::new();
        let plaintext = b"some data to protect";
        let aad = b"some context data";
        let wrong_aad = b"wrong context data";
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        // Encrypt with AAD
        let encrypted = processor
            .encrypt_symmetric_in_memory(
                plaintext,
                SymmetricConfig {
                    algorithm: Cow::Borrowed(&wrapper),
                    key_id: "aad_key".to_string(),
                    config: config.clone(),
                    key: Cow::Borrowed(&key),
                    aad: Some(aad.to_vec()),
                },
            )
            .unwrap();

        // Decrypt with correct AAD
        let pending = processor
            .begin_decrypt_symmetric_in_memory(&encrypted, config.clone())
            .unwrap();
        let decrypted = pending.into_plaintext(&key, Some(aad.to_vec())).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Decrypt with wrong AAD should fail
        let pending = processor
            .begin_decrypt_symmetric_in_memory(&encrypted, config)
            .unwrap();
        let result = pending.into_plaintext(&key, Some(wrong_aad.to_vec()));
        assert!(result.is_err());
    }
}
