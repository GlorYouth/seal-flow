//! Implements parallel, in-memory hybrid encryption and decryption.
//!
//! 实现并行、内存中的混合加密和解密。

use super::traits::{HybridParallelPendingDecryptor, HybridParallelProcessor};
use crate::algorithms::definitions::hybrid::HybridAlgorithmWrapper;
use crate::algorithms::traits::HybridAlgorithm;
use crate::body::config::BodyDecryptConfig;
use crate::body::traits::ParallelBodyProcessor;
use crate::common::config::{ArcConfig, DecryptorConfig};
use crate::common::header::{Header, HeaderPayload, SpecificHeaderPayload};
use crate::error::{Error, FormatError, Result};
use crate::hybrid::config::HybridConfig;
use crate::hybrid::pending::PendingDecryptor;
use crate::keys::{TypedAsymmetricPrivateKey, TypedSymmetricKey};
use seal_crypto::zeroize::Zeroizing;
use std::borrow::Cow;

pub struct Parallel;

impl Parallel {
    pub fn new() -> Self {
        Self
    }
}

impl HybridParallelProcessor for Parallel {
    fn encrypt_parallel<'a>(&self, plaintext: &[u8], config: HybridConfig<'a>) -> Result<Vec<u8>> {
        let algo = config.algorithm.clone();
        let (body_config, header_bytes) = config.into_body_config_and_header()?;
        let encrypted_body = algo
            .as_ref()
            .symmetric_algorithm()
            .encrypt_body_parallel(plaintext, body_config)?;

        let mut final_output =
            Vec::with_capacity(4 + header_bytes.len() + encrypted_body.len());
        final_output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        final_output.extend_from_slice(&header_bytes);
        final_output.extend_from_slice(&encrypted_body);

        Ok(final_output)
    }

    fn begin_decrypt_hybrid_parallel<'a>(
        &self,
        ciphertext: &'a [u8],
        config: ArcConfig,
    ) -> Result<Box<dyn HybridParallelPendingDecryptor + 'a>> {
        let (header, _) = Header::decode_from_prefixed_slice(ciphertext)?;
        let asym_algo = header
            .payload
            .asymmetric_algorithm()
            .ok_or(FormatError::InvalidHeader)?
            .into_asymmetric_wrapper();
        let sym_algo = header
            .payload
            .symmetric_algorithm()
            .into_symmetric_wrapper();
        let algorithm = HybridAlgorithmWrapper::new(asym_algo, sym_algo);

        let pending = PendingDecryptor {
            source: ciphertext,
            header,
            algorithm,
            config,
        };
        Ok(Box::new(pending))
    }
}

impl<'a> HybridParallelPendingDecryptor for PendingDecryptor<&'a [u8]> {
    fn into_plaintext(
        self: Box<Self>,
        private_key: &TypedAsymmetricPrivateKey,
        aad: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let (header, ciphertext_body) = Header::decode_from_prefixed_slice(self.source)?;
        let (encapsulated_key, base_nonce, derivation_info, chunk_size) =
            if let HeaderPayload {
                base_nonce,
                chunk_size,
                specific_payload: SpecificHeaderPayload::Hybrid {
                    encrypted_dek,
                    derivation_info,
                    ..
                },
                ..
            } = header.payload
            {
                (
                    Zeroizing::new(encrypted_dek.clone()),
                    base_nonce,
                    derivation_info.clone(),
                    chunk_size,
                )
            } else {
                return Err(Error::Format(FormatError::InvalidHeader));
            };

        let shared_secret = self
            .algorithm
            .asymmetric_algorithm()
            .decapsulate_key(private_key, &encapsulated_key)?;

        // 3. Derive key if derivation info is present.
        let dek = if let Some(info) = derivation_info {
            info.derive_key(&shared_secret)?
        } else {
            shared_secret
        };

        let dek = TypedSymmetricKey::from_bytes(
            dek.as_ref(),
            self.algorithm.symmetric_algorithm().algorithm(),
        )?;

        let body_config = BodyDecryptConfig {
            key: Cow::Owned(dek),
            nonce: base_nonce,
            aad,
            config: DecryptorConfig {
                chunk_size,
                arc_config: self.config,
            },
        };

        self.algorithm
            .symmetric_algorithm()
            .decrypt_body_parallel(ciphertext_body, body_config)
    }

    fn header(&self) -> &Header {
        &self.header
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::definitions::{
        asymmetric::Rsa2048Sha256Wrapper, symmetric::Aes256GcmWrapper,
    };
    use crate::algorithms::traits::AsymmetricAlgorithm;
    use crate::common::header::{DerivationInfo, KdfInfo};
    use crate::common::DerivationSet;
    use crate::common::DEFAULT_CHUNK_SIZE;
    use crate::keys::TypedAsymmetricPublicKey;
    use seal_crypto::prelude::KeyBasedDerivation;
    use seal_crypto::schemes::kdf::hkdf::HkdfSha256;

    fn get_test_algorithm() -> HybridAlgorithmWrapper {
        HybridAlgorithmWrapper::new(Rsa2048Sha256Wrapper::new(), Aes256GcmWrapper::new())
    }

    fn generate_test_keys() -> (TypedAsymmetricPublicKey, TypedAsymmetricPrivateKey) {
        Rsa2048Sha256Wrapper::new()
            .generate_keypair()
            .unwrap()
            .into_keypair()
    }

    #[test]
    fn test_hybrid_parallel_roundtrip_with_kdf() {
        let algorithm = get_test_algorithm();
        let processor = Parallel::new();
        let (pk, sk) = generate_test_keys();
        let plaintext = b"This is a test message with KDF in parallel.";
        let salt = b"salt-parallel";
        let info = b"info-parallel";
        let output_len = 32;

        let kdf_info = KdfInfo {
            kdf_algorithm: crate::common::algorithms::KdfAlgorithm::HkdfSha256,
            salt: Some(salt.to_vec()),
            info: Some(info.to_vec()),
            output_len,
        };

        let deriver = HkdfSha256::default();
        let kdf_fn = Box::new(move |ikm: &TypedSymmetricKey| {
            deriver
                .derive(ikm.as_ref(), Some(salt), Some(info), output_len as usize)
                .map(|dk| TypedSymmetricKey::from_bytes(dk.as_bytes(), ikm.algorithm()))?
        });

        let config = HybridConfig {
            algorithm: Cow::Borrowed(&algorithm),
            public_key: Cow::Borrowed(&pk),
            kek_id: "test_kek_id_kdf".to_string(),
            signer: None,
            aad: None,
            derivation_config: Some(DerivationSet {
                derivation_info: DerivationInfo::Kdf(kdf_info),
                deriver_fn: kdf_fn,
            }),
            config: ArcConfig::default(),
        };

        let encrypted = processor.encrypt_parallel(plaintext, config).unwrap();

        let pending = processor
            .begin_decrypt_hybrid_parallel(&encrypted, ArcConfig::default())
            .unwrap();
        let decrypted = pending.into_plaintext(&sk, None).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_hybrid_parallel_roundtrip() {
        let algorithm = get_test_algorithm();
        let processor = Parallel::new();
        let (pk, sk) = generate_test_keys();
        let plaintext = b"This is a test message for hybrid parallel encryption, which should be long enough to span multiple chunks to properly test the implementation.";

        let config = HybridConfig {
            algorithm: Cow::Borrowed(&algorithm),
            public_key: Cow::Borrowed(&pk),
            kek_id: "test_kek_id".to_string(),
            signer: None,
            aad: None,
            derivation_config: None,
            config: ArcConfig::default(),
        };

        let encrypted = processor.encrypt_parallel(plaintext, config).unwrap();

        // Test convenience function
        let pending = processor
            .begin_decrypt_hybrid_parallel(&encrypted, ArcConfig::default())
            .unwrap();
        let decrypted = pending.into_plaintext(&sk, None).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Tamper with the ciphertext body
        let mut encrypted_tampered = encrypted;
        if encrypted_tampered.len() > 300 {
            encrypted_tampered[300] ^= 1;
        }

        let pending = processor
            .begin_decrypt_hybrid_parallel(&encrypted_tampered, ArcConfig::default())
            .unwrap();
        let result = pending.into_plaintext(&sk, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let algorithm = get_test_algorithm();
        let processor = Parallel::new();
        let (pk, sk) = generate_test_keys();
        let plaintext = b"";

        let config = HybridConfig {
            algorithm: Cow::Borrowed(&algorithm),
            public_key: Cow::Borrowed(&pk),
            kek_id: "test_kek_id".to_string(),
            signer: None,
            aad: None,
            derivation_config: None,
            config: ArcConfig::default(),
        };

        let encrypted = processor.encrypt_parallel(plaintext, config).unwrap();

        let pending = processor
            .begin_decrypt_hybrid_parallel(&encrypted, ArcConfig::default())
            .unwrap();
        let decrypted = pending.into_plaintext(&sk, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let algorithm = get_test_algorithm();
        let processor = Parallel::new();
        let (pk, sk) = generate_test_keys();
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];

        let config = HybridConfig {
            algorithm: Cow::Borrowed(&algorithm),
            public_key: Cow::Borrowed(&pk),
            kek_id: "test_kek_id".to_string(),
            signer: None,
            aad: None,
            derivation_config: None,
            config: ArcConfig::default(),
        };

        let encrypted = processor.encrypt_parallel(&plaintext, config).unwrap();

        let pending = processor
            .begin_decrypt_hybrid_parallel(&encrypted, ArcConfig::default())
            .unwrap();
        let decrypted = pending.into_plaintext(&sk, None).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let algorithm = get_test_algorithm();
        let processor = Parallel::new();
        let (pk, _) = generate_test_keys();
        let (_, sk2) = generate_test_keys();
        let plaintext = b"some data";

        let config = HybridConfig {
            algorithm: Cow::Borrowed(&algorithm),
            public_key: Cow::Borrowed(&pk),
            kek_id: "test_kek_id".to_string(),
            signer: None,
            aad: None,
            derivation_config: None,
            config: ArcConfig::default(),
        };

        let encrypted = processor.encrypt_parallel(plaintext, config).unwrap();

        let pending = processor
            .begin_decrypt_hybrid_parallel(&encrypted, ArcConfig::default())
            .unwrap();
        let result = pending.into_plaintext(&sk2, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_aad_roundtrip() {
        let algorithm = get_test_algorithm();
        let processor = Parallel::new();
        let (pk, sk) = generate_test_keys();
        let plaintext = b"some parallel data to protect";
        let aad = b"some parallel context data".to_vec();

        // Encrypt with AAD
        let config = HybridConfig {
            algorithm: Cow::Borrowed(&algorithm),
            public_key: Cow::Borrowed(&pk),
            kek_id: "aad_key".to_string(),
            signer: None,
            aad: Some(aad.clone()),
            derivation_config: None,
            config: ArcConfig::default(),
        };
        let encrypted = processor.encrypt_parallel(plaintext, config).unwrap();

        // Decrypt with correct AAD
        let pending = processor
            .begin_decrypt_hybrid_parallel(&encrypted, ArcConfig::default())
            .unwrap();
        let decrypted = pending.into_plaintext(&sk, Some(aad)).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Decrypt with wrong AAD fails
        let pending_fail = processor
            .begin_decrypt_hybrid_parallel(&encrypted, ArcConfig::default())
            .unwrap();
        let result_fail = pending_fail.into_plaintext(&sk, Some(b"wrong aad".to_vec()));
        assert!(result_fail.is_err());

        // Decrypt with no AAD fails
        let pending_fail2 = processor
            .begin_decrypt_hybrid_parallel(&encrypted, ArcConfig::default())
            .unwrap();
        let result_fail2 = pending_fail2.into_plaintext(&sk, None);
        assert!(result_fail2.is_err());
    }
}
