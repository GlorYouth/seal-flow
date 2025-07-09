//! Ordinary (single-threaded, in-memory) hybrid encryption and decryption.
//!
//! 普通（单线程、内存中）混合加密和解密。

use super::common::create_header;
use super::traits::HybridOrdinaryProcessor;
use crate::algorithms::traits::HybridAlgorithm as HybridAlgorithmTrait;
use crate::body::traits::OrdinaryBodyProcessor;
use crate::common::header::{Header, HeaderPayload};
use crate::common::{DerivationSet, PendingImpl, SignerSet};
use crate::error::{Error, FormatError, Result};
use crate::keys::{TypedAsymmetricPrivateKey, TypedAsymmetricPublicKey, TypedSymmetricKey};
use seal_crypto::zeroize::Zeroizing;

impl<H: HybridAlgorithmTrait + ?Sized> HybridOrdinaryProcessor for H {
    fn encrypt_in_memory(
        &self,
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
            create_header(self, public_key, kek_id, signer, aad, info)?;

        // 2. Derive key if a deriver function is specified
        let dek = if let Some(f) = deriver_fn {
            f(&shared_secret)?
        } else {
            shared_secret
        };

        // 3. Serialize the header.
        let header_bytes = header.encode_to_vec()?;

        self.symmetric_algorithm()
            .encrypt_in_memory(dek, &base_nonce, header_bytes, plaintext, aad)
    }

    fn decrypt_in_memory(
        &self,
        private_key: &TypedAsymmetricPrivateKey,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // 1. Extract metadata and the encrypted DEK from the header.
        let (header, ciphertext_body) = Header::decode_from_prefixed_slice(ciphertext)?;
        let (encapsulated_key, _chunk_size, base_nonce, derivation_info) = match &header.payload {
            HeaderPayload::Hybrid {
                encrypted_dek,
                stream_info: Some(info),
                derivation_info,
                ..
            } => (
                Zeroizing::new(encrypted_dek.clone()),
                info.chunk_size,
                info.base_nonce,
                derivation_info.clone(),
            ),
            _ => return Err(Error::Format(FormatError::InvalidHeader)),
        };

        // 2. KEM Decapsulate to recover the shared secret.
        let shared_secret = self
            .asymmetric_algorithm()
            .decapsulate_key(private_key, &encapsulated_key)?;

        // 3. Derive key if derivation info is present.
        let dek = if let Some(info) = derivation_info {
            info.derive_key(&shared_secret)?
        } else {
            shared_secret
        };

        let dek =
            TypedSymmetricKey::from_bytes(dek.as_slice(), self.symmetric_algorithm().algorithm())?;

        self.symmetric_algorithm()
            .decrypt_in_memory(dek, &base_nonce, ciphertext_body, aad)
    }
}

/// A pending decryptor for in-memory hybrid-encrypted data.
///
/// This state is entered after the header has been successfully parsed from
/// the ciphertext, allowing the user to inspect the header (e.g., to find
/// the `kek_id`) before supplying the appropriate private key to proceed with
/// decryption.
///
/// 一个用于内存中混合加密数据的待定解密器。
///
/// 从密文中成功解析标头后，进入此状态，允许用户在提供适当的私钥以继续解密之前检查标头（例如，查找 `kek_id`）。
pub struct PendingDecryptor<'a> {
    header: Header,
    ciphertext_with_header: &'a [u8],
}

impl<'a> PendingDecryptor<'a> {
    /// Creates a new `PendingDecryptor` by parsing the header from the ciphertext.
    ///
    /// 通过从密文中解析标头来创建一个新的 `PendingDecryptor`。
    pub fn from_ciphertext(ciphertext: &'a [u8]) -> Result<Self> {
        let (header, _) = Header::decode_from_prefixed_slice(ciphertext)?;
        Ok(Self {
            header,
            ciphertext_with_header: ciphertext,
        })
    }

    /// Consumes the `PendingDecryptor` and returns the decrypted plaintext.
    ///
    /// 消费 `PendingDecryptor` 并返回解密的明文。
    pub fn into_plaintext(
        self,
        algorithm: impl HybridAlgorithmTrait,
        sk: &TypedAsymmetricPrivateKey,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        HybridOrdinaryProcessor::decrypt_in_memory(&algorithm, sk, self.ciphertext_with_header, aad)
    }
}

impl<'a> PendingImpl for PendingDecryptor<'a> {
    fn header(&self) -> &Header {
        &self.header
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::definitions::hybrid::HybridAlgorithm;
    use crate::algorithms::definitions::{
        asymmetric::Rsa2048Sha256Wrapper, symmetric::Aes256GcmWrapper,
    };
    use crate::algorithms::traits::AsymmetricAlgorithm;
    use crate::common::header::{DerivationInfo, KdfInfo};
    use crate::common::DerivationSet;
    use seal_crypto::prelude::KeyBasedDerivation;
    use seal_crypto::schemes::kdf::hkdf::HkdfSha256;

    fn get_test_algorithm() -> HybridAlgorithm {
        HybridAlgorithm::new(
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
    fn test_hybrid_ordinary_roundtrip_with_kdf() {
        let algorithm = get_test_algorithm();
        let (pk, sk) = generate_test_keys();
        let plaintext = b"This is a test message with KDF.";
        let salt = b"salt";
        let info = b"info";
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

        let encrypted = HybridOrdinaryProcessor::encrypt_in_memory(
            &algorithm,
            &pk,
            plaintext,
            "test_kek_id".to_string(),
            None,
            None,
            Some(DerivationSet {
                derivation_info: DerivationInfo::Kdf(kdf_info),
                deriver_fn: kdf_fn,
            }),
        )
        .unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending.into_plaintext(algorithm, &sk, None).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_hybrid_ordinary_roundtrip() {
        let algorithm = get_test_algorithm();
        let (pk, sk) = generate_test_keys();
        let plaintext = b"This is a test message for hybrid ordinary encryption, which should be long enough to span multiple chunks to properly test the implementation.";

        let encrypted = HybridOrdinaryProcessor::encrypt_in_memory(
            &algorithm,
            &pk,
            plaintext,
            "test_kek_id".to_string(),
            None,
            None,
            None,
        )
        .unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        assert_eq!(pending.header().payload.kek_id(), Some("test_kek_id"));
        let decrypted_full = pending.into_plaintext(algorithm, &sk, None).unwrap();
        assert_eq!(plaintext, decrypted_full.as_slice());
    }

    #[test]
    fn test_empty_plaintext() {
        let algorithm = get_test_algorithm();
        let (pk, sk) = generate_test_keys();
        let plaintext = b"";

        let encrypted = HybridOrdinaryProcessor::encrypt_in_memory(
            &algorithm,
            &pk,
            plaintext,
            "test_kek_id".to_string(),
            None,
            None,
            None,
        )
        .unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending.into_plaintext(algorithm, &sk, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let algorithm = get_test_algorithm();
        let (pk, sk) = generate_test_keys();
        let plaintext = vec![42u8; crate::common::DEFAULT_CHUNK_SIZE as usize];

        let encrypted = HybridOrdinaryProcessor::encrypt_in_memory(
            &algorithm,
            &pk,
            &plaintext,
            "test_kek_id".to_string(),
            None,
            None,
            None,
        )
        .unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending.into_plaintext(algorithm, &sk, None).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let algorithm = get_test_algorithm();
        let (pk, sk) = generate_test_keys();
        let plaintext = b"some important data";

        let mut encrypted = HybridOrdinaryProcessor::encrypt_in_memory(
            &algorithm,
            &pk,
            plaintext,
            "test_kek_id".to_string(),
            None,
            None,
            None,
        )
        .unwrap();

        // Tamper with the ciphertext body
        if encrypted.len() > 300 {
            encrypted[300] ^= 1; // Tamper after the header
        }

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result = pending.into_plaintext(algorithm, &sk, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let algorithm = get_test_algorithm();
        let (pk, _) = generate_test_keys();
        let (_, sk2) = generate_test_keys();
        let plaintext = b"some data";

        let encrypted = HybridOrdinaryProcessor::encrypt_in_memory(
            &algorithm,
            &pk,
            plaintext,
            "test_kek_id".to_string(),
            None,
            None,
            None,
        )
        .unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result = pending.into_plaintext(algorithm, &sk2, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_aad_roundtrip() {
        let algorithm = get_test_algorithm();
        let (pk, sk) = generate_test_keys();
        let plaintext = b"some important data with aad";
        let aad = b"some important context";

        let encrypted = HybridOrdinaryProcessor::encrypt_in_memory(
            &algorithm,
            &pk,
            plaintext,
            "aad_kek_id".to_string(),
            None,
            Some(aad),
            None,
        )
        .unwrap();

        // Decrypt with correct AAD
        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending
            .into_plaintext(algorithm.clone(), &sk, Some(aad))
            .unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Decrypt with wrong AAD fails
        let pending_fail = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result_fail = pending_fail.into_plaintext(algorithm.clone(), &sk, Some(b"wrong aad"));
        assert!(result_fail.is_err());

        // Decrypt with no AAD fails
        let pending_fail2 = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result_fail2 = pending_fail2.into_plaintext(algorithm, &sk, None);
        assert!(result_fail2.is_err());
    }
}
