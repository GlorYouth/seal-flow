//! Implements the parallel (multi-threaded, in-memory) symmetric encryption scheme.
//!
//! 实现并行（多线程，内存中）对称加密方案。

use crate::algorithms::traits::SymmetricAlgorithm;
use crate::body::traits::ParallelBodyProcessor;
use crate::common::header::{Header, HeaderPayload};
use crate::common::PendingImpl;
use crate::error::{Error, FormatError, Result};
use crate::keys::TypedSymmetricKey;
use crate::symmetric::common::create_header;
use crate::symmetric::traits::SymmetricParallelProcessor;

/// A pending decryptor for in-memory data that will be processed in parallel.
struct PendingDecryptor<'a> {
    header: Header,
    ciphertext_body: &'a [u8],
}

impl<'a> PendingDecryptor<'a> {
    fn from_ciphertext(ciphertext: &'a [u8]) -> Result<Self> {
        let (header, ciphertext_body) = Header::decode_from_prefixed_slice(ciphertext)?;
        Ok(Self {
            header,
            ciphertext_body,
        })
    }

    fn into_plaintext<S: SymmetricAlgorithm + ParallelBodyProcessor>(
        self,
        algorithm: &S,
        key: TypedSymmetricKey,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let base_nonce = match &self.header.payload {
            HeaderPayload::Symmetric {
                stream_info: Some(info),
                ..
            } => info.base_nonce,
            _ => return Err(Error::Format(FormatError::InvalidHeader)),
        };

        algorithm.decrypt_body_parallel(key, &base_nonce, self.ciphertext_body, aad)
    }
}

impl<'a> PendingImpl for PendingDecryptor<'a> {
    fn header(&self) -> &Header {
        &self.header
    }
}

pub struct Parallel<'a, S: SymmetricAlgorithm + ParallelBodyProcessor> {
    algorithm: &'a S,
}

impl<'a, S: SymmetricAlgorithm + ParallelBodyProcessor> Parallel<'a, S> {
    pub fn new(algorithm: &'a S) -> Self {
        Self { algorithm }
    }
}

impl<'a, S: SymmetricAlgorithm + ParallelBodyProcessor> SymmetricParallelProcessor
    for Parallel<'a, S>
{
    fn encrypt_symmetric_parallel(
        &self,
        key: TypedSymmetricKey,
        key_id: String,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let (header, base_nonce) = create_header(self.algorithm, key_id)?;
        let header_bytes = header.encode_to_vec()?;
        self.algorithm
            .encrypt_body_parallel(key, &base_nonce, header_bytes, plaintext, aad)
    }

    fn decrypt_symmetric_parallel(
        &self,
        key: TypedSymmetricKey,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let pending = PendingDecryptor::from_ciphertext(ciphertext)?;
        pending.into_plaintext(self.algorithm, key, aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::definitions::symmetric::Aes256GcmWrapper;
    use crate::common::DEFAULT_CHUNK_SIZE;
    use crate::error::CryptoError;
    use crate::error::Error as FlowError;
    use seal_crypto::prelude::SymmetricKeyGenerator;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;

    fn get_wrapper() -> Aes256GcmWrapper {
        Aes256GcmWrapper::new()
    }

    #[test]
    fn test_symmetric_parallel_roundtrip() {
        let wrapper = get_wrapper();
        let processor = Parallel::new(&wrapper);
        let plaintext = b"This is a test message that is longer than one chunk to ensure the chunking logic works correctly. Let's add some more data to be sure.";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());

        let encrypted = processor
            .encrypt_symmetric_parallel(key.clone(), "test_key_id".to_string(), plaintext, None)
            .unwrap();

        let decrypted = processor
            .decrypt_symmetric_parallel(key.clone(), &encrypted, None)
            .unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Tamper with the ciphertext body
        let header_len = 4 + u32::from_le_bytes(encrypted[0..4].try_into().unwrap()) as usize;
        let ciphertext_start_index = 4 + header_len;

        assert!(
            encrypted.len() > ciphertext_start_index,
            "Not enough data to tamper"
        );
        let mut encrypted_tampered = encrypted.clone();
        encrypted_tampered[ciphertext_start_index] ^= 1;

        let result = processor.decrypt_symmetric_parallel(key.clone(), &encrypted_tampered, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_processor_roundtrip() {
        let wrapper = get_wrapper();
        let processor = Parallel::new(&wrapper);
        let plaintext = b"This is a parallel processor test.";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let encrypted = processor
            .encrypt_symmetric_parallel(key.clone(), "proc_key".to_string(), plaintext, None)
            .unwrap();
        let decrypted = processor
            .decrypt_symmetric_parallel(key.clone(), &encrypted, None)
            .unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_empty_plaintext() {
        let wrapper = get_wrapper();
        let processor = Parallel::new(&wrapper);
        let plaintext = b"";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());

        let encrypted = processor
            .encrypt_symmetric_parallel(key.clone(), "test_key_id".to_string(), plaintext, None)
            .unwrap();

        let decrypted = processor
            .decrypt_symmetric_parallel(key.clone(), &encrypted, None)
            .unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let wrapper = get_wrapper();
        let processor = Parallel::new(&wrapper);
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());

        let encrypted = processor
            .encrypt_symmetric_parallel(key.clone(), "test_key_id".to_string(), &plaintext, None)
            .unwrap();

        let decrypted = processor
            .decrypt_symmetric_parallel(key.clone(), &encrypted, None)
            .unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let wrapper = get_wrapper();
        let processor = Parallel::new(&wrapper);
        let plaintext = b"some data";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());

        let encrypted = processor
            .encrypt_symmetric_parallel(key.clone(), "test_key_id_1".to_string(), plaintext, None)
            .unwrap();

        let result = processor.decrypt_symmetric_parallel(key.clone(), &encrypted, None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FlowError::Crypto(CryptoError::Backend(_))
        ));
    }

    #[test]
    fn test_internal_functions() {
        let wrapper = get_wrapper();
        let processor = Parallel::new(&wrapper);
        let plaintext = b"some plaintext for parallel";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());

        let encrypted = processor
            .encrypt_symmetric_parallel(key.clone(), "test_key_id".to_string(), plaintext, None)
            .unwrap();

        // Test the separated functions
        let (header, _body) = Header::decode_from_prefixed_slice(&encrypted).unwrap();
        assert_eq!(header.payload.key_id(), Some("test_key_id"));

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted_body = pending.into_plaintext(&wrapper, key.clone(), None).unwrap();

        assert_eq!(plaintext, decrypted_body.as_slice());
    }

    #[test]
    fn test_aad_roundtrip() {
        let wrapper = get_wrapper();
        let processor = Parallel::new(&wrapper);
        let plaintext = b"some parallel data to protect";
        let aad = b"some parallel context data";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());

        // Encrypt with AAD
        let encrypted = processor
            .encrypt_symmetric_parallel(key.clone(), "aad_key".to_string(), plaintext, Some(aad))
            .unwrap();

        // Decrypt with correct AAD
        let decrypted = processor
            .decrypt_symmetric_parallel(key.clone(), &encrypted, Some(aad))
            .unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Decrypt with wrong AAD fails
        let result_fail = processor.decrypt_symmetric_parallel(key.clone(), &encrypted, Some(b"wrong aad"));
        assert!(result_fail.is_err());

        // Decrypt with no AAD fails
        let result_fail2 = processor.decrypt_symmetric_parallel(key.clone(), &encrypted, None);
        assert!(result_fail2.is_err());
    }
}
