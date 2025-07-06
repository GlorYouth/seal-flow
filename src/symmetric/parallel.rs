//! Implements the parallel (multi-threaded, in-memory) symmetric encryption scheme.
//!
//! 实现并行（多线程，内存中）对称加密方案。

use super::common::create_header;
use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::{Header, HeaderPayload};
use crate::common::PendingImpl;
use crate::error::{Error, FormatError, Result};
use crate::impls::parallel::{decrypt_parallel, encrypt_parallel};

/// Encrypts in-memory data using parallel processing.
///
/// 使用并行处理加密内存中的数据。
pub fn encrypt<'a, S>(
    key: S::Key,
    plaintext: &[u8],
    key_id: String,
    aad: Option<&[u8]>,
) -> Result<Vec<u8>>
where
    S: SymmetricAlgorithm,
{
    // 1. Setup Header
    let (header, base_nonce) = create_header::<S>(key_id)?;
    let header_bytes = header.encode_to_vec()?;
    encrypt_parallel::<S>(key, base_nonce, header_bytes, plaintext, aad)
}

/// Decrypts a ciphertext body in parallel using the provided key and header.
///
/// This function assumes `decode_header` has been called and its results are provided.
///
/// 使用提供的密钥和标头并行解密密文体。
///
/// 此函数假定已经调用了 `decode_header` 并提供了其结果。
pub fn decrypt_body<S>(
    key: S::Key,
    header: &Header,
    ciphertext_body: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>>
where
    S: SymmetricAlgorithm,
{
    // Extract stream info from Header
    let (chunk_size, base_nonce) = match &header.payload {
        HeaderPayload::Symmetric {
            stream_info: Some(info),
            ..
        } => (info.chunk_size, info.base_nonce),
        _ => return Err(Error::Format(FormatError::InvalidHeader)),
    };

    decrypt_parallel::<S>(key, base_nonce, chunk_size, ciphertext_body, aad)
}

/// A pending decryptor for in-memory data that will be processed in parallel.
///
/// This state is entered after the header has been successfully parsed from
/// the ciphertext, allowing the user to inspect the header (e.g., to find
/// the `key_id`) before supplying the appropriate key to proceed with decryption.
///
/// 一个用于将要并行处理的内存数据的待处理解密器。
///
/// 当从密文中成功解析标头后，进入此状态，允许用户在提供适当的密钥以继续解密之前检查标头（例如，查找 `key_id`）。
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
    pub fn into_plaintext<S: SymmetricAlgorithm>(
        self,
        key: S::Key,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>
    where
        S::Key: Send + Sync,
    {
        decrypt_body::<S>(key, &self.header, self.ciphertext_body, aad)
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
    use crate::common::DEFAULT_CHUNK_SIZE;
    use crate::error::Error as FlowError;
    use crate::error::CryptoError;
    use seal_crypto::prelude::SymmetricKeyGenerator;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;

    #[test]
    fn test_symmetric_parallel_roundtrip() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"This is a test message that is longer than one chunk to ensure the chunking logic works correctly. Let's add some more data to be sure.";

        let encrypted =
            encrypt::<Aes256Gcm>(key.clone(), plaintext, "test_key_id".to_string(), None).unwrap();

        // Test the convenience function
        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending
            .into_plaintext::<Aes256Gcm>(key.clone(), None)
            .unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Test the separated functions
        let (header, body) = Header::decode_from_prefixed_slice(&encrypted).unwrap();
        assert_eq!(header.payload.key_id(), Some("test_key_id"));
        let decrypted_body = decrypt_body::<Aes256Gcm>(key.clone(), &header, body, None).unwrap();
        assert_eq!(plaintext, decrypted_body.as_slice());

        // Tamper with the ciphertext body
        let header_len = u32::from_le_bytes(encrypted[0..4].try_into().unwrap()) as usize;
        let ciphertext_start_index = 4 + header_len;

        assert!(
            encrypted.len() > ciphertext_start_index,
            "Not enough data to tamper"
        );
        let mut encrypted_tampered = encrypted;
        encrypted_tampered[ciphertext_start_index] ^= 1;

        let pending = PendingDecryptor::from_ciphertext(&encrypted_tampered).unwrap();
        let result = pending.into_plaintext::<Aes256Gcm>(key, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"";

        let encrypted =
            encrypt::<Aes256Gcm>(key.clone(), plaintext, "test_key_id".to_string(), None).unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending.into_plaintext::<Aes256Gcm>(key, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];

        let encrypted =
            encrypt::<Aes256Gcm>(key.clone(), &plaintext, "test_key_id".to_string(), None).unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending.into_plaintext::<Aes256Gcm>(key, None).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = Aes256Gcm::generate_key().unwrap();
        let key2 = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some data";

        let encrypted =
            encrypt::<Aes256Gcm>(key1, plaintext, "test_key_id_1".to_string(), None).unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result = pending.into_plaintext::<Aes256Gcm>(key2, None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FlowError::Crypto(CryptoError::Backend(_))
        ));
    }

    #[test]
    fn test_internal_functions() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some plaintext for parallel";
        let encrypted =
            encrypt::<Aes256Gcm>(key.clone(), plaintext, "test_key_id".to_string(), None).unwrap();

        // Test the separated functions
        let (header, body) = Header::decode_from_prefixed_slice(&encrypted).unwrap();
        assert_eq!(header.payload.key_id(), Some("test_key_id"));
        let decrypted_body = decrypt_body::<Aes256Gcm>(key, &header, body, None).unwrap();
        assert_eq!(plaintext, decrypted_body.as_slice());
    }

    #[test]
    fn test_aad_roundtrip() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some parallel data to protect";
        let aad = b"some parallel context data";

        // Encrypt with AAD
        let encrypted =
            encrypt::<Aes256Gcm>(key.clone(), plaintext, "aad_key".to_string(), Some(aad)).unwrap();

        // Decrypt with correct AAD
        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending
            .into_plaintext::<Aes256Gcm>(key.clone(), Some(aad))
            .unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Decrypt with wrong AAD fails
        let pending_fail = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result_fail = pending_fail.into_plaintext::<Aes256Gcm>(key.clone(), Some(b"wrong aad"));
        assert!(result_fail.is_err());

        // Decrypt with no AAD fails
        let pending_fail2 = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result_fail2 = pending_fail2.into_plaintext::<Aes256Gcm>(key, None);
        assert!(result_fail2.is_err());
    }
}
