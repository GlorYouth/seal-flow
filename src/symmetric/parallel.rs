//! Implements the parallel (multi-threaded, in-memory) symmetric encryption scheme.
//!
//! 实现并行（多线程，内存中）对称加密方案。

use crate::algorithms::traits::SymmetricAlgorithm;
use crate::body::traits::ParallelBodyProcessor;
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, FormatError, Result};
use crate::keys::{SymmetricKey, TypedSymmetricKey};
use crate::symmetric::common::create_header;
use crate::symmetric::pending::PendingDecryptor;
use crate::symmetric::traits::{SymmetricParallelPendingDecryptor, SymmetricParallelProcessor};

impl<'a, S> SymmetricParallelPendingDecryptor<'a> for PendingDecryptor<&'a [u8], S>
where
    S: SymmetricAlgorithm + ParallelBodyProcessor,
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
            .decrypt_body_parallel(typed_key, &base_nonce, self.source, aad)
    }

    fn header(&self) -> &Header {
        &self.header
    }
}

pub struct Parallel<'s, S: SymmetricAlgorithm + ParallelBodyProcessor> {
    algorithm: &'s S,
}

impl<'s, S: SymmetricAlgorithm + ParallelBodyProcessor> Parallel<'s, S> {
    pub fn new(algorithm: &'s S) -> Self {
        Self { algorithm }
    }
}

impl<'s, S: SymmetricAlgorithm + ParallelBodyProcessor> SymmetricParallelProcessor
    for Parallel<'s, S>
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

    fn begin_decrypt_symmetric_parallel<'a>(
        &self,
        ciphertext: &'a [u8],
    ) -> Result<Box<dyn SymmetricParallelPendingDecryptor<'a> + 'a>> {
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
    use crate::error::CryptoError;
    use crate::error::Error as FlowError;
    use crate::keys::SymmetricKey as UntypedSymmetricKey;
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
        let raw_key = Aes256Gcm::generate_key().unwrap();
        let key = TypedSymmetricKey::Aes256Gcm(raw_key.clone());
        let untyped_key = UntypedSymmetricKey::Aes256Gcm(raw_key);

        let encrypted = processor
            .encrypt_symmetric_parallel(key.clone(), "test_key_id".to_string(), plaintext, None)
            .unwrap();

        let pending = processor
            .begin_decrypt_symmetric_parallel(&encrypted)
            .unwrap();
        let decrypted = pending.into_plaintext(untyped_key.clone(), None).unwrap();
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
        let result = pending.into_plaintext(untyped_key, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_processor_roundtrip() {
        let wrapper = get_wrapper();
        let processor = Parallel::new(&wrapper);
        let plaintext = b"This is a parallel processor test.";
        let raw_key = Aes256Gcm::generate_key().unwrap();
        let key = TypedSymmetricKey::Aes256Gcm(raw_key.clone());
        let untyped_key = UntypedSymmetricKey::Aes256Gcm(raw_key);
        let encrypted = processor
            .encrypt_symmetric_parallel(key.clone(), "proc_key".to_string(), plaintext, None)
            .unwrap();
        let pending = processor
            .begin_decrypt_symmetric_parallel(&encrypted)
            .unwrap();
        let decrypted = pending.into_plaintext(untyped_key, None).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_empty_plaintext() {
        let wrapper = get_wrapper();
        let processor = Parallel::new(&wrapper);
        let plaintext = b"";
        let raw_key = Aes256Gcm::generate_key().unwrap();
        let key = TypedSymmetricKey::Aes256Gcm(raw_key.clone());
        let untyped_key = UntypedSymmetricKey::Aes256Gcm(raw_key);

        let encrypted = processor
            .encrypt_symmetric_parallel(key.clone(), "test_key_id".to_string(), plaintext, None)
            .unwrap();

        let pending = processor
            .begin_decrypt_symmetric_parallel(&encrypted)
            .unwrap();
        let decrypted = pending.into_plaintext(untyped_key, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let wrapper = get_wrapper();
        let processor = Parallel::new(&wrapper);
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];
        let raw_key = Aes256Gcm::generate_key().unwrap();
        let key = TypedSymmetricKey::Aes256Gcm(raw_key.clone());
        let untyped_key = UntypedSymmetricKey::Aes256Gcm(raw_key);

        let encrypted = processor
            .encrypt_symmetric_parallel(key.clone(), "test_key_id".to_string(), &plaintext, None)
            .unwrap();

        let pending = processor
            .begin_decrypt_symmetric_parallel(&encrypted)
            .unwrap();
        let decrypted = pending.into_plaintext(untyped_key, None).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let wrapper = get_wrapper();
        let processor = Parallel::new(&wrapper);
        let plaintext = b"some data";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let wrong_raw_key = Aes256Gcm::generate_key().unwrap();
        let wrong_untyped_key = UntypedSymmetricKey::Aes256Gcm(wrong_raw_key);

        let encrypted = processor
            .encrypt_symmetric_parallel(key.clone(), "test_key_id_1".to_string(), plaintext, None)
            .unwrap();

        let pending = processor
            .begin_decrypt_symmetric_parallel(&encrypted)
            .unwrap();
        let result = pending.into_plaintext(wrong_untyped_key, None);
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
        let raw_key = Aes256Gcm::generate_key().unwrap();
        let key = TypedSymmetricKey::Aes256Gcm(raw_key.clone());
        let untyped_key = UntypedSymmetricKey::Aes256Gcm(raw_key);

        let encrypted = processor
            .encrypt_symmetric_parallel(key.clone(), "test_key_id".to_string(), plaintext, None)
            .unwrap();

        // Test the separated functions
        let pending = processor.begin_decrypt_symmetric_parallel(&encrypted).unwrap();
        assert_eq!(pending.header().payload.key_id(), Some("test_key_id"));

        let decrypted_body = pending.into_plaintext(untyped_key, None).unwrap();

        assert_eq!(plaintext, decrypted_body.as_slice());
    }

    #[test]
    fn test_aad_roundtrip() {
        let wrapper = get_wrapper();
        let processor = Parallel::new(&wrapper);
        let plaintext = b"some parallel data to protect";
        let aad = b"some parallel context data";
        let raw_key = Aes256Gcm::generate_key().unwrap();
        let key = TypedSymmetricKey::Aes256Gcm(raw_key.clone());
        let untyped_key = UntypedSymmetricKey::Aes256Gcm(raw_key);

        // Encrypt with AAD
        let encrypted = processor
            .encrypt_symmetric_parallel(key.clone(), "aad_key".to_string(), plaintext, Some(aad))
            .unwrap();

        // Decrypt with correct AAD
        let pending = processor.begin_decrypt_symmetric_parallel(&encrypted).unwrap();
        let decrypted = pending.into_plaintext(untyped_key.clone(), Some(aad)).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Decrypt with wrong AAD fails
        let pending_fail = processor.begin_decrypt_symmetric_parallel(&encrypted).unwrap();
        let result_fail = pending_fail.into_plaintext(untyped_key, Some(b"wrong aad"));
        assert!(result_fail.is_err());

        // Decrypt with no AAD fails
        let pending_fail2 = processor.begin_decrypt_symmetric_parallel(&encrypted).unwrap();
        let result_fail2 = pending_fail2.into_plaintext(key.clone(), None);
        assert!(result_fail2.is_err());
    }
}
