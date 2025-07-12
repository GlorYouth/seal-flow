//! Implements the parallel (multi-threaded, in-memory) symmetric encryption scheme.
//!
//! 实现并行（多线程，内存中）对称加密方案。

use crate::body::traits::ParallelBodyProcessor;
use crate::common::config::ArcConfig;
use crate::common::header::Header;
use crate::error::{Error, FormatError, Result};
use crate::keys::TypedSymmetricKey;
use crate::symmetric::config::SymmetricConfig;
use crate::symmetric::pending::PendingDecryptor;
use crate::symmetric::traits::{SymmetricParallelPendingDecryptor, SymmetricParallelProcessor};

impl<'a> SymmetricParallelPendingDecryptor<'a> for PendingDecryptor<&'a [u8]> {
    fn into_plaintext(
        self: Box<Self>,
        key: &TypedSymmetricKey,
        aad: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let body_config =
            super::common::prepare_body_decrypt_config(&self.header, key, aad, self.config)?;

        self.algorithm
            .algorithm
            .decrypt_body_parallel(self.source, body_config)
    }

    fn header(&self) -> &Header {
        &self.header
    }
}

pub struct Parallel;

impl Parallel {
    pub fn new() -> Self {
        Self
    }
}

impl SymmetricParallelProcessor for Parallel {
    fn encrypt_symmetric_parallel<'a>(
        &self,
        plaintext: &[u8],
        config: SymmetricConfig<'a>,
    ) -> Result<Vec<u8>> {
        let algo = config.algorithm.clone();
        let (body_config, header_bytes) = config.into_body_config_and_header()?;

        let encrypted_body = algo.as_ref().encrypt_body_parallel(plaintext, body_config)?;

        let mut final_output =
            Vec::with_capacity(4 + header_bytes.len() + encrypted_body.len());
        final_output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        final_output.extend_from_slice(&header_bytes);
        final_output.extend_from_slice(&encrypted_body);

        Ok(final_output)
    }

    fn begin_decrypt_symmetric_parallel<'a>(
        &self,
        ciphertext: &'a [u8],
        config: ArcConfig,
    ) -> Result<Box<dyn SymmetricParallelPendingDecryptor<'a> + 'a>> {
        let (header, ciphertext_body) = Header::decode_from_prefixed_slice(ciphertext)?;
        if !header.is_symmetric() {
            return Err(Error::Format(FormatError::InvalidHeader));
        }
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
    use crate::error::CryptoError;
    use crate::error::Error as FlowError;
    use crate::prelude::SymmetricAlgorithmEnum;
    use std::borrow::Cow;

    fn get_wrapper() -> SymmetricAlgorithmWrapper {
        SymmetricAlgorithmEnum::Aes256Gcm.into_symmetric_wrapper()
    }

    #[test]
    fn test_symmetric_parallel_roundtrip() {
        let wrapper = get_wrapper();
        let processor = Parallel::new();
        let plaintext = b"This is a test message that is longer than one chunk to ensure the chunking logic works correctly. Let's add some more data to be sure.";
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();

        let encrypted = processor
            .encrypt_symmetric_parallel(
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
            .begin_decrypt_symmetric_parallel(&encrypted, config.clone())
            .unwrap();
        let decrypted = pending.into_plaintext(&key, None).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Tamper with the ciphertext body
        let header_len = Header::decode_from_prefixed_slice(&encrypted)
            .unwrap()
            .0
            .encode_to_vec()
            .unwrap()
            .len();
        let ciphertext_start_index = 4 + header_len;

        assert!(
            encrypted.len() > ciphertext_start_index,
            "Not enough data to tamper"
        );
        let mut encrypted_tampered = encrypted.clone();
        encrypted_tampered[ciphertext_start_index] ^= 1;

        let pending = processor
            .begin_decrypt_symmetric_parallel(&encrypted_tampered, config.clone())
            .unwrap();
        let result = pending.into_plaintext(&key, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_processor_roundtrip() {
        let wrapper = get_wrapper();
        let processor = Parallel::new();
        let plaintext = b"This is a parallel processor test.";
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        let encrypted = processor
            .encrypt_symmetric_parallel(
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
            .begin_decrypt_symmetric_parallel(&encrypted, config.clone())
            .unwrap();
        let decrypted = pending.into_plaintext(&key, None).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_empty_plaintext() {
        let wrapper = get_wrapper();
        let processor = Parallel::new();
        let plaintext = b"";
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        let encrypted = processor
            .encrypt_symmetric_parallel(
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
            .begin_decrypt_symmetric_parallel(&encrypted, config.clone())
            .unwrap();
        let decrypted = pending.into_plaintext(&key, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let wrapper = get_wrapper();
        let processor = Parallel::new();
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        let encrypted = processor
            .encrypt_symmetric_parallel(
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
            .begin_decrypt_symmetric_parallel(&encrypted, config.clone())
            .unwrap();
        let decrypted = pending.into_plaintext(&key, None).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let wrapper = get_wrapper();
        let processor = Parallel::new();
        let plaintext = b"some data";
        let key = wrapper.generate_typed_key().unwrap();
        let wrong_key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        let encrypted = processor
            .encrypt_symmetric_parallel(
                plaintext,
                SymmetricConfig {
                    algorithm: Cow::Borrowed(&wrapper),
                    key_id: "test_key_id_1".to_string(),
                    config: config.clone(),
                    key: Cow::Borrowed(&key),
                    aad: None,
                },
            )
            .unwrap();

        let pending = processor
            .begin_decrypt_symmetric_parallel(&encrypted, config)
            .unwrap();
        let result = pending.into_plaintext(&wrong_key, None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FlowError::Crypto(CryptoError::Backend(_))
        ));
    }

    #[test]
    fn test_internal_functions() {
        let wrapper = get_wrapper();
        let processor = Parallel::new();
        let plaintext = b"some plaintext for parallel";
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        let encrypted = processor
            .encrypt_symmetric_parallel(
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

        // Test the separated functions
        let pending = processor
            .begin_decrypt_symmetric_parallel(&encrypted, config)
            .unwrap();
        assert_eq!(pending.header().payload.key_id(), Some("test_key_id"));

        let decrypted_body = pending.into_plaintext(&key, None).unwrap();

        assert_eq!(plaintext, decrypted_body.as_slice());
    }

    #[test]
    fn test_aad_roundtrip() {
        let wrapper = get_wrapper();
        let processor = Parallel::new();
        let plaintext = b"some parallel data to protect";
        let aad = b"some parallel context data".to_vec();
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        // Encrypt with AAD
        let encrypted = processor
            .encrypt_symmetric_parallel(
                plaintext,
                SymmetricConfig {
                    algorithm: Cow::Borrowed(&wrapper),
                    key_id: "aad_key".to_string(),
                    config: config.clone(),
                    key: Cow::Borrowed(&key),
                    aad: Some(aad.clone()),
                },
            )
            .unwrap();

        // Decrypt with correct AAD
        let pending = processor
            .begin_decrypt_symmetric_parallel(&encrypted, config.clone())
            .unwrap();
        let decrypted = pending.into_plaintext(&key, Some(aad.clone())).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Decrypt with wrong AAD fails
        let pending_fail = processor
            .begin_decrypt_symmetric_parallel(&encrypted, config.clone())
            .unwrap();
        let result_fail = pending_fail.into_plaintext(&key, Some(b"wrong aad".to_vec()));
        assert!(result_fail.is_err());

        // Decrypt with no AAD fails
        let pending_fail2 = processor
            .begin_decrypt_symmetric_parallel(&encrypted, config.clone())
            .unwrap();
        let result_fail2 = pending_fail2.into_plaintext(&key, None);
        assert!(result_fail2.is_err());
    }
}
