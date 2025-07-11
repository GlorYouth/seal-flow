//! Implements parallel, in-memory hybrid encryption and decryption.
//!
//! 实现并行、内存中的混合加密和解密。

use super::common::create_header;
use super::traits::{HybridParallelPendingDecryptor, HybridParallelProcessor};
use crate::algorithms::definitions::hybrid::HybridAlgorithmWrapper;
use crate::algorithms::traits::HybridAlgorithm as HybridAlgorithmTrait;
use crate::body::traits::ParallelBodyProcessor;
use crate::common::header::{Header, HeaderPayload};
use crate::common::{DerivationSet, SignerSet};
use crate::error::{Error, FormatError, Result};
use crate::hybrid::pending::PendingDecryptor;
use crate::keys::{TypedAsymmetricPublicKey, TypedSymmetricKey, TypedAsymmetricPrivateKey};
use seal_crypto::zeroize::Zeroizing;

pub struct Parallel;

impl Parallel {
    pub fn new() -> Self {
        Self
    }
}

impl HybridParallelProcessor for Parallel {
    fn encrypt_parallel(
        &self,
        algorithm: &HybridAlgorithmWrapper,
        public_key: &TypedAsymmetricPublicKey,
        plaintext: &[u8],
        kek_id: String,
        signer: Option<SignerSet>,
        aad: Option<&[u8]>,
        derivation_config: Option<DerivationSet>,
    ) -> Result<Vec<u8>> {
        let (info, deriver_fn) = derivation_config
            .map(|d| (d.derivation_info, d.deriver_fn))
            .unzip();

        // 1. Create header, nonce, and shared secret
        let (header, base_nonce, shared_secret) =
            create_header(algorithm, public_key, kek_id, signer, aad, info)?;

        // 2. Derive key if a deriver function is specified
        let dek = if let Some(f) = deriver_fn {
            f(&shared_secret)?
        } else {
            shared_secret
        };

        // 3. Serialize the header and prepare for encryption
        let header_bytes = header.encode_to_vec()?;

        algorithm
            .symmetric_algorithm()
            .encrypt_body_parallel(dek, &base_nonce, header_bytes, plaintext, aad)
    }

    fn begin_decrypt_hybrid_parallel(
        &self,
        ciphertext: &[u8],
    ) -> Result<Box<dyn HybridParallelPendingDecryptor>> {
        let (header, _) = Header::decode_from_prefixed_slice(ciphertext)?;
        let asym_algo = header.payload.asymmetric_algorithm().ok_or(FormatError::InvalidHeader)?.into_asymmetric_wrapper();
        let sym_algo = header.payload.symmetric_algorithm().into_symmetric_wrapper();
        let algorithm = HybridAlgorithmWrapper::new(asym_algo, sym_algo);

        let pending = PendingDecryptor {
            source: ciphertext,
            header,
            algorithm,
        };
        Ok(Box::new(pending))
    }
}

impl<'a> HybridParallelPendingDecryptor for PendingDecryptor<&'a [u8]> {
    fn into_plaintext(
        self: Box<Self>,
        private_key: &TypedAsymmetricPrivateKey,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let (header, ciphertext_body) = Header::decode_from_prefixed_slice(self.source)?;
        let (encapsulated_key, base_nonce, derivation_info) = match &header.payload {
            HeaderPayload::Hybrid {
                encrypted_dek,
                stream_info: Some(info),
                derivation_info,
                ..
            } => (
                Zeroizing::new(encrypted_dek.clone()),
                info.base_nonce,
                derivation_info.clone(),
            ),
            _ => return Err(Error::Format(FormatError::InvalidHeader)),
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
            dek.as_slice(),
            self.algorithm.symmetric_algorithm().algorithm(),
        )?;

        self.algorithm
            .symmetric_algorithm()
            .decrypt_body_parallel(dek, &base_nonce, ciphertext_body, aad)
    }

    fn header(&self) -> &Header {
        &self.header
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::definitions::{
        asymmetric::Rsa2048Sha256Wrapper, hybrid::HybridAlgorithmWrapper, symmetric::Aes256GcmWrapper,
    };
    use crate::algorithms::traits::AsymmetricAlgorithm;
    use crate::common::header::{DerivationInfo, KdfInfo};
    use crate::common::DEFAULT_CHUNK_SIZE;
    use crate::common::DerivationSet;
    use crate::keys::{TypedAsymmetricPublicKey, TypedAsymmetricPrivateKey};
    use seal_crypto::prelude::KeyBasedDerivation;
    use seal_crypto::schemes::kdf::hkdf::HkdfSha256;

    fn get_test_algorithm() -> HybridAlgorithmWrapper {
        HybridAlgorithmWrapper::new(
            Box::new(Rsa2048Sha256Wrapper::new()),
            Box::new(Aes256GcmWrapper::new()),
        )
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

        let encrypted = processor
            .encrypt_parallel(
                &algorithm,
                &pk,
                plaintext,
                "test_kek_id_kdf".to_string(),
                None,
                None,
                Some(DerivationSet {
                    derivation_info: DerivationInfo::Kdf(kdf_info),
                    deriver_fn: kdf_fn,
                }),
            )
            .unwrap();

        let pending = processor
            .begin_decrypt_hybrid_parallel(&encrypted)
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

        let encrypted = processor
            .encrypt_parallel(
                &algorithm,
                &pk,
                plaintext,
                "test_kek_id".to_string(),
                None,
                None,
                None,
            )
            .unwrap();

        // Test convenience function
        let pending = processor
            .begin_decrypt_hybrid_parallel(&encrypted)
            .unwrap();
        let decrypted = pending.into_plaintext(&sk, None).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Tamper with the ciphertext body
        let mut encrypted_tampered = encrypted;
        if encrypted_tampered.len() > 300 {
            encrypted_tampered[300] ^= 1;
        }

        let pending = processor
            .begin_decrypt_hybrid_parallel(&encrypted_tampered)
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

        let encrypted = processor
            .encrypt_parallel(
                &algorithm,
                &pk,
                plaintext,
                "test_kek_id".to_string(),
                None,
                None,
                None,
            )
            .unwrap();

        let pending = processor
            .begin_decrypt_hybrid_parallel(&encrypted)
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

        let encrypted = processor
            .encrypt_parallel(
                &algorithm,
                &pk,
                &plaintext,
                "test_kek_id".to_string(),
                None,
                None,
                None,
            )
            .unwrap();

        let pending = processor
            .begin_decrypt_hybrid_parallel(&encrypted)
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

        let encrypted = processor
            .encrypt_parallel(
                &algorithm,
                &pk,
                plaintext,
                "test_kek_id".to_string(),
                None,
                None,
                None,
            )
            .unwrap();

        let pending = processor
            .begin_decrypt_hybrid_parallel(&encrypted)
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
        let aad = b"some parallel context data";

        // Encrypt with AAD
        let encrypted = processor
            .encrypt_parallel(
                &algorithm,
                &pk,
                plaintext,
                "aad_key".to_string(),
                None,
                Some(aad),
                None,
            )
            .unwrap();

        // Decrypt with correct AAD
        let pending = processor
            .begin_decrypt_hybrid_parallel(&encrypted)
            .unwrap();
        let decrypted = pending.into_plaintext(&sk, Some(aad)).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Decrypt with wrong AAD fails
        let pending_fail = processor
            .begin_decrypt_hybrid_parallel(&encrypted)
            .unwrap();
        let result_fail = pending_fail.into_plaintext(&sk, Some(b"wrong aad"));
        assert!(result_fail.is_err());

        // Decrypt with no AAD fails
        let pending_fail2 = processor
            .begin_decrypt_hybrid_parallel(&encrypted)
            .unwrap();
        let result_fail2 = pending_fail2.into_plaintext(&sk, None);
        assert!(result_fail2.is_err());
    }
}
