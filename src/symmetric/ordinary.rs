//! Implements the ordinary (single-threaded, in-memory) symmetric encryption scheme.
//!
//! 实现普通（单线程，内存中）对称加密方案。

use crate::algorithms::traits::SymmetricAlgorithm;
use crate::body::traits::OrdinaryBodyProcessor;
use crate::common::header::{Header, HeaderPayload};
use crate::common::PendingImpl;
use crate::error::{Error, FormatError, Result};
use crate::symmetric::common::create_header;
use crate::keys::TypedSymmetricKey;
use crate::symmetric::traits::SymmetricOrdinaryProcessor;

/// A pending decryptor for in-memory data, waiting for a key.
struct PendingDecryptor<'a> {
    header: Header,
    ciphertext_body: &'a [u8],
}

impl<'a> PendingDecryptor<'a> {
    /// Creates a new `PendingDecryptor` by parsing the header from the ciphertext.
    fn from_ciphertext(ciphertext: &'a [u8]) -> Result<Self> {
        let (header, ciphertext_body) = Header::decode_from_prefixed_slice(ciphertext)?;
        Ok(Self {
            header,
            ciphertext_body,
        })
    }

    /// Consumes the `PendingDecryptor` and returns the decrypted plaintext.
    fn into_plaintext<S: SymmetricAlgorithm + OrdinaryBodyProcessor>(
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

        algorithm.decrypt_in_memory(key, &base_nonce, self.ciphertext_body, aad)
    }
}

impl<'a> PendingImpl for PendingDecryptor<'a> {
    fn header(&self) -> &Header {
        &self.header
    }
}

pub struct Ordinary<'a, S: SymmetricAlgorithm + OrdinaryBodyProcessor> {
    algorithm: &'a S,
}

impl<'a, S: SymmetricAlgorithm + OrdinaryBodyProcessor> Ordinary<'a, S> {
    pub fn new(algorithm: &'a S) -> Self {
        Self { algorithm }
    }
}

impl<'a, S: SymmetricAlgorithm + OrdinaryBodyProcessor> SymmetricOrdinaryProcessor
    for Ordinary<'a, S>
{
    fn encrypt_in_memory(
        &self,
        key: TypedSymmetricKey,
        key_id: String,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let (header, base_nonce) = create_header(self.algorithm, key_id)?;
        let header_bytes = header.encode_to_vec()?;

        self.algorithm
            .encrypt_in_memory(key, &base_nonce, header_bytes, plaintext, aad)
    }

    fn decrypt_in_memory(
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
    use crate::keys::TypedSymmetricKey;
    use crate::common::DEFAULT_CHUNK_SIZE;
    use seal_crypto::prelude::SymmetricKeyGenerator;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;

    fn get_wrapper() -> Aes256GcmWrapper {
        Aes256GcmWrapper::new()
    }

    #[test]
    fn test_symmetric_ordinary_roundtrip() {
        let wrapper = get_wrapper();
        let processor = Ordinary::new(&wrapper);
        let plaintext = b"This is a test message that is longer than one chunk to ensure the chunking logic works correctly. Let's add some more data to be sure.";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let encrypted = processor
            .encrypt_in_memory(key.clone(), "test_key_id".to_string(), plaintext, None)
            .unwrap();
        let decrypted = processor
            .decrypt_in_memory(key.clone(), &encrypted, None)
            .unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_processor_roundtrip() {
        let wrapper = get_wrapper();
        let processor = Ordinary::new(&wrapper);
        let plaintext = b"This is a processor test.";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let encrypted = processor
            .encrypt_in_memory(key.clone(), "proc_key".to_string(), plaintext, None)
            .unwrap();
        let decrypted = processor
            .decrypt_in_memory(key.clone(), &encrypted, None)
            .unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_empty_plaintext() {
        let wrapper = get_wrapper();
        let processor = Ordinary::new(&wrapper);
        let plaintext = b"";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let encrypted = processor
            .encrypt_in_memory(key.clone(), "test_key_id".to_string(), plaintext, None)
            .unwrap();
        let decrypted = processor
            .decrypt_in_memory(key.clone(), &encrypted, None)
            .unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let wrapper = get_wrapper();
        let processor = Ordinary::new(&wrapper);
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let encrypted = processor
            .encrypt_in_memory(
                key.clone(),
                "test_key_id".to_string(),
                &plaintext,
                None,
            )
            .unwrap();
        let decrypted = processor
            .decrypt_in_memory(key.clone(), &encrypted, None)
            .unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let wrapper = get_wrapper();
        let processor = Ordinary::new(&wrapper);
        let plaintext = b"some important data";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let mut encrypted = processor
            .encrypt_in_memory(key.clone(), "test_key_id".to_string(), plaintext, None)
            .unwrap();

        // Tamper with the ciphertext body
        let header_len = 4 + u32::from_le_bytes(encrypted[0..4].try_into().unwrap()) as usize;
        if encrypted.len() > header_len {
            encrypted[header_len] ^= 1;
        }

        let result = processor.decrypt_in_memory(key.clone(), &encrypted, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let wrapper = get_wrapper();
        let processor = Ordinary::new(&wrapper);
        let plaintext = b"some data to protect";
        let aad = b"some context data";
        let wrong_aad = b"wrong context data";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        // Encrypt with AAD
        let encrypted = processor
            .encrypt_in_memory(key.clone(), "aad_key".to_string(), plaintext, Some(aad))
            .unwrap();

        // Decrypt with correct AAD
        let decrypted = processor
            .decrypt_in_memory(key.clone(), &encrypted, Some(aad))
            .unwrap();
        assert_eq!(&plaintext[..], &decrypted[..]);

        // Decrypt with wrong AAD fails
        let result_fail = processor.decrypt_in_memory(key.clone(), &encrypted, Some(wrong_aad));
        assert!(result_fail.is_err());

        // Decrypt with no AAD fails
        let result_fail2 = processor.decrypt_in_memory(key.clone(), &encrypted, None);
        assert!(result_fail2.is_err());
    }
}
