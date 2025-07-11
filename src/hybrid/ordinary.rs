//! Ordinary (single-threaded, in-memory) hybrid encryption and decryption.
//!
//! 普通（单线程、内存中）混合加密和解密。

use super::common::create_header;
use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::header::{Header, HeaderPayload};
use crate::common::{DerivationSet, PendingImpl, SignerSet};
use crate::error::{Error, FormatError, Result};
use crate::impls::ordinary::{decrypt_in_memory, encrypt_in_memory};
use seal_crypto::prelude::Key;

/// Performs hybrid encryption on in-memory data.
///
/// 对内存中的数据执行混合加密。
pub fn encrypt<'a, A, S>(
    pk: &A::PublicKey,
    plaintext: &[u8],
    kek_id: String,
    signer: Option<SignerSet>,
    aad: Option<&[u8]>,
    derivation_config: Option<DerivationSet>,
) -> Result<Vec<u8>>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    let (info, deriver_fn) = derivation_config
        .map(|d| (d.derivation_info, d.deriver_fn))
        .unzip();

    // 1. Create header, nonce, and shared secret
    // 1. 创建标头、nonce 和共享密钥
    let (header, base_nonce, shared_secret) = create_header::<A, S>(pk, kek_id, signer, aad, info)?;

    // 2. Derive key if a deriver function is specified
    // 2. 如果指定了派生函数，则派生密钥
    let dek = if let Some(f) = deriver_fn {
        f(&shared_secret)?
    } else {
        shared_secret
    };

    // 3. Serialize the header.
    // 3. 序列化标头。
    let header_bytes = header.encode_to_vec()?;
    let key_material: S::Key = Key::from_bytes(dek.as_slice())?;

    encrypt_in_memory::<S>(key_material, base_nonce, header_bytes, plaintext, aad)
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
    ciphertext_body: &'a [u8],
}

impl<'a> PendingDecryptor<'a> {
    /// Creates a new `PendingDecryptor` by parsing the header from the ciphertext.
    ///
    /// 通过从密文中解析标头来创建一个新的 `PendingDecryptor`。
    pub fn from_ciphertext(ciphertext: &'a [u8]) -> Result<Self> {
        let (header, ciphertext_body) = Header::decode_from_prefixed_slice(ciphertext)?;
        Ok(Self {
            header,
            ciphertext_body,
        })
    }

    /// Consumes the `PendingDecryptor` and returns the decrypted plaintext.
    ///
    /// 消费 `PendingDecryptor` 并返回解密的明文。
    pub fn into_plaintext<A, S>(self, sk: &A::PrivateKey, aad: Option<&[u8]>) -> Result<Vec<u8>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
    {
        decrypt_body::<A, S>(sk, &self.header, self.ciphertext_body, aad)
    }
}

impl<'a> PendingImpl for PendingDecryptor<'a> {
    fn header(&self) -> &Header {
        &self.header
    }
}

/// Performs hybrid decryption on an in-memory ciphertext body.
///
/// This function assumes `decode_header` has been called and its results are provided.
///
/// 对内存中的密文体执行混合解密。
///
/// 此函数假定已经调用了 `decode_header` 并提供了其结果。
pub fn decrypt_body<A, S>(
    sk: &A::PrivateKey,
    header: &Header,
    ciphertext_body: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    // 1. Extract metadata and the encrypted DEK from the header.
    // 1. 从标头中提取元数据和加密的 DEK。
    let (encapsulated_key, chunk_size, base_nonce, derivation_info) = match &header.payload {
        HeaderPayload::Hybrid {
            encrypted_dek,
            stream_info: Some(info),
            derivation_info,
            ..
        } => (
            encrypted_dek.clone(),
            info.chunk_size,
            info.base_nonce,
            derivation_info.clone(),
        ),
        _ => return Err(Error::Format(FormatError::InvalidHeader)),
    };

    // 2. KEM Decapsulate to recover the shared secret.
    // 2. KEM 解封装以恢复共享密钥。
    let shared_secret = A::decapsulate(
        sk,
        &A::EncapsulatedKey::from_bytes(encapsulated_key.as_slice())?,
    )?;

    // 3. Derive key if derivation info is present.
    // 3. 如果存在派生信息，则派生密钥。
    let dek = if let Some(info) = derivation_info {
        info.derive_key(&shared_secret)?
    } else {
        shared_secret
    };

    let key_material: S::Key = Key::from_bytes(dek.as_slice())?;

    decrypt_in_memory::<S>(key_material, base_nonce, chunk_size, ciphertext_body, aad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::header::{DerivationInfo, KdfInfo};
    use crate::common::DerivationSet;
    use seal_crypto::prelude::KeyBasedDerivation;
    use seal_crypto::prelude::KeyGenerator;
    use seal_crypto::schemes::asymmetric::traditional::rsa::Rsa2048;
    use seal_crypto::schemes::hash::Sha256;
    use seal_crypto::schemes::kdf::hkdf::HkdfSha256;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
    use seal_crypto::zeroize::Zeroizing;

    type TestKem = Rsa2048<Sha256>;
    type TestDek = Aes256Gcm;

    #[test]
    fn test_hybrid_ordinary_roundtrip_with_kdf() {
        let (pk, sk) = TestKem::generate_keypair().unwrap();
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
        let kdf_fn = Box::new(move |ikm: &[u8]| {
            deriver
                .derive(ikm, Some(salt), Some(info), output_len as usize)
                .map(|dk| Zeroizing::new(dk.as_bytes().to_vec()))
                .map_err(|e| e.into())
        });

        let encrypted = encrypt::<TestKem, TestDek>(
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
        let decrypted = pending
            .into_plaintext::<TestKem, TestDek>(&sk, None)
            .unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_hybrid_ordinary_roundtrip() {
        let (pk, sk) = TestKem::generate_keypair().unwrap();
        let plaintext = b"This is a test message for hybrid ordinary encryption, which should be long enough to span multiple chunks to properly test the implementation.";

        let encrypted = encrypt::<TestKem, TestDek>(
            &pk,
            plaintext,
            "test_kek_id".to_string(),
            None,
            None,
            None,
        )
        .unwrap();

        // Test convenience function
        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted_full = pending
            .into_plaintext::<TestKem, TestDek>(&sk, None)
            .unwrap();
        assert_eq!(plaintext, decrypted_full.as_slice());

        // Test separated functions
        let (header, body) = Header::decode_from_prefixed_slice(&encrypted).unwrap();
        assert_eq!(header.payload.kek_id(), Some("test_kek_id"));
        let decrypted_parts = decrypt_body::<TestKem, TestDek>(&sk, &header, body, None).unwrap();
        assert_eq!(plaintext, decrypted_parts.as_slice());
    }

    #[test]
    fn test_empty_plaintext() {
        let (pk, sk) = TestKem::generate_keypair().unwrap();
        let plaintext = b"";

        let encrypted = encrypt::<TestKem, TestDek>(
            &pk,
            plaintext,
            "test_kek_id".to_string(),
            None,
            None,
            None,
        )
        .unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending
            .into_plaintext::<TestKem, TestDek>(&sk, None)
            .unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let (pk, sk) = TestKem::generate_keypair().unwrap();
        let plaintext = vec![42u8; crate::common::DEFAULT_CHUNK_SIZE as usize];

        let encrypted = encrypt::<TestKem, TestDek>(
            &pk,
            &plaintext,
            "test_kek_id".to_string(),
            None,
            None,
            None,
        )
        .unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending
            .into_plaintext::<TestKem, TestDek>(&sk, None)
            .unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (pk, sk) = TestKem::generate_keypair().unwrap();
        let plaintext = b"some important data";

        let mut encrypted = encrypt::<TestKem, TestDek>(
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
        let result = pending.into_plaintext::<TestKem, TestDek>(&sk, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let (pk, _) = TestKem::generate_keypair().unwrap();
        let (_, sk2) = TestKem::generate_keypair().unwrap();
        let plaintext = b"some data";

        let encrypted = encrypt::<TestKem, TestDek>(
            &pk,
            plaintext,
            "test_kek_id".to_string(),
            None,
            None,
            None,
        )
        .unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result = pending.into_plaintext::<TestKem, TestDek>(&sk2, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_aad_roundtrip() {
        let (pk, sk) = TestKem::generate_keypair().unwrap();
        let plaintext = b"some important data with aad";
        let aad = b"some important context";

        let encrypted = encrypt::<TestKem, TestDek>(
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
            .into_plaintext::<TestKem, TestDek>(&sk, Some(aad))
            .unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Decrypt with wrong AAD fails
        let pending_fail = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result_fail = pending_fail.into_plaintext::<TestKem, TestDek>(&sk, Some(b"wrong aad"));
        assert!(result_fail.is_err());

        // Decrypt with no AAD fails
        let pending_fail2 = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result_fail2 = pending_fail2.into_plaintext::<TestKem, TestDek>(&sk, None);
        assert!(result_fail2.is_err());
    }
}
