//! Implements the parallel (multi-threaded, in-memory) symmetric encryption scheme.
//!
//! 实现并行（多线程，内存中）对称加密方案。

use crate::algorithms::symmetric::SymmetricAlgorithmWrapper;
use crate::body::traits::ParallelBodyProcessor;
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, FormatError, Result};
use crate::keys::TypedSymmetricKey;
use crate::symmetric::common::create_header;
use crate::symmetric::pending::PendingDecryptor;
use crate::symmetric::traits::{SymmetricParallelPendingDecryptor, SymmetricParallelProcessor};

impl SymmetricParallelPendingDecryptor for PendingDecryptor<&[u8]> {
    fn into_plaintext(
        self: Box<Self>,
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

        self.algorithm.algorithm
            .decrypt_body_parallel(key, &base_nonce, self.source, aad)
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

impl SymmetricParallelProcessor
    for Parallel
{
    fn encrypt_symmetric_parallel(
        &self,
        algorithm: &SymmetricAlgorithmWrapper,
        key: TypedSymmetricKey,
        key_id: String,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let (header, base_nonce) = create_header(&algorithm, key_id)?;
        let header_bytes = header.encode_to_vec()?;
        algorithm
            .encrypt_body_parallel(key, &base_nonce, header_bytes, plaintext, aad)
    }

    fn begin_decrypt_symmetric_parallel(
        &self,
        ciphertext: &[u8],
    ) -> Result<Box<dyn SymmetricParallelPendingDecryptor>> {
        let (header, ciphertext_body) = Header::decode_from_prefixed_slice(ciphertext)?;
        let algorithm = header.payload.symmetric_algorithm().into_symmetric_wrapper();
        let pending = PendingDecryptor {
            source: ciphertext_body,
            header,
            algorithm,
        };
        Ok(Box::new(pending))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::SymmetricAlgorithmEnum;
    use crate::common::DEFAULT_CHUNK_SIZE;
    use crate::error::CryptoError;
    use crate::error::Error as FlowError;

    fn get_wrapper() -> SymmetricAlgorithmWrapper {
        SymmetricAlgorithmEnum::Aes256Gcm.into_symmetric_wrapper()
    }

    #[test]
    fn test_symmetric_parallel_roundtrip() {
        let wrapper = get_wrapper();
        let processor = Parallel::new();
        let plaintext = b"This is a test message that is longer than one chunk to ensure the chunking logic works correctly. Let's add some more data to be sure.";
        let key = wrapper.generate_typed_key().unwrap();

        let encrypted = processor
            .encrypt_symmetric_parallel(&wrapper, key.clone(), "test_key_id".to_string(), plaintext, None)
            .unwrap();

        let pending = processor
            .begin_decrypt_symmetric_parallel(&encrypted)
            .unwrap();
        let decrypted = pending.into_plaintext(key.clone(), None).unwrap();
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

        let pending = processor
            .begin_decrypt_symmetric_parallel(&encrypted_tampered)
            .unwrap();
        let result = pending.into_plaintext(key, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_processor_roundtrip() {
        let wrapper = get_wrapper();
        let processor = Parallel::new();
        let plaintext = b"This is a parallel processor test.";
        let key = wrapper.generate_typed_key().unwrap();
        let encrypted = processor
            .encrypt_symmetric_parallel(&wrapper, key.clone(), "proc_key".to_string(), plaintext, None)
            .unwrap();
        let pending = processor
            .begin_decrypt_symmetric_parallel(&encrypted)
            .unwrap();
        let decrypted = pending.into_plaintext(key, None).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_empty_plaintext() {
        let wrapper = get_wrapper();
        let processor = Parallel::new();
        let plaintext = b"";
        let key = wrapper.generate_typed_key().unwrap();

        let encrypted = processor
            .encrypt_symmetric_parallel(&wrapper, key.clone(), "test_key_id".to_string(), plaintext, None)
            .unwrap();

        let pending = processor
            .begin_decrypt_symmetric_parallel(&encrypted)
            .unwrap();
        let decrypted = pending.into_plaintext(key, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let wrapper = get_wrapper();
        let processor = Parallel::new();
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];
        let key = wrapper.generate_typed_key().unwrap();

        let encrypted = processor
            .encrypt_symmetric_parallel(&wrapper, key.clone(), "test_key_id".to_string(), &plaintext, None)
            .unwrap();

        let pending = processor
            .begin_decrypt_symmetric_parallel(&encrypted)
            .unwrap();
        let decrypted = pending.into_plaintext(key, None).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let wrapper = get_wrapper();
        let processor = Parallel::new();
        let plaintext = b"some data";
        let key = wrapper.generate_typed_key().unwrap();

        let encrypted = processor
            .encrypt_symmetric_parallel(&wrapper, key.clone(), "test_key_id_1".to_string(), plaintext, None)
            .unwrap();

        let pending = processor
            .begin_decrypt_symmetric_parallel(&encrypted)
            .unwrap();
        let result = pending.into_plaintext(key, None);
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

        let encrypted = processor
            .encrypt_symmetric_parallel(&wrapper, key.clone(), "test_key_id".to_string(), plaintext, None)
            .unwrap();

        // Test the separated functions
        let pending = processor.begin_decrypt_symmetric_parallel(&encrypted).unwrap();
        assert_eq!(pending.header().payload.key_id(), Some("test_key_id"));

        let decrypted_body = pending.into_plaintext(key, None).unwrap();

        assert_eq!(plaintext, decrypted_body.as_slice());
    }

    #[test]
    fn test_aad_roundtrip() {
        let wrapper = get_wrapper();
        let processor = Parallel::new();
        let plaintext = b"some parallel data to protect";
        let aad = b"some parallel context data";
        let key = wrapper.generate_typed_key().unwrap();

        // Encrypt with AAD
        let encrypted = processor
            .encrypt_symmetric_parallel(&wrapper, key.clone(), "aad_key".to_string(), plaintext, Some(aad))
            .unwrap();

        // Decrypt with correct AAD
        let pending = processor.begin_decrypt_symmetric_parallel(&encrypted).unwrap();
        let decrypted = pending.into_plaintext(key.clone(), Some(aad)).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Decrypt with wrong AAD fails
        let pending_fail = processor.begin_decrypt_symmetric_parallel(&encrypted).unwrap();
        let result_fail = pending_fail.into_plaintext(key.clone(), Some(b"wrong aad"));
        assert!(result_fail.is_err());

        // Decrypt with no AAD fails
        let pending_fail2 = processor.begin_decrypt_symmetric_parallel(&encrypted).unwrap();
        let result_fail2 = pending_fail2.into_plaintext(key.clone(), None);
        assert!(result_fail2.is_err());
    }
}
