//! Implements the ordinary (single-threaded, in-memory) symmetric encryption scheme.

use super::common::create_header;
use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::{Header, HeaderPayload};
use crate::common::PendingImpl;
use crate::error::{Error, Result};
use crate::impls::ordinary::{decrypt_in_memory, encrypt_in_memory};

/// Encrypts plaintext using a chunking mechanism.
pub fn encrypt<S: SymmetricAlgorithm>(
    key: S::Key,
    plaintext: &[u8],
    key_id: String,
    aad: Option<&[u8]>,
) -> Result<Vec<u8>>
where
    S::Key: Send + Sync,
{
    let (header, base_nonce) = create_header::<S>(key_id)?;
    let header_bytes = header.encode_to_vec()?;

    encrypt_in_memory::<S>(key, base_nonce, header_bytes, plaintext, aad)
}

/// A pending decryptor for in-memory data, waiting for a key.
///
/// This state is entered after the header has been successfully parsed from
/// the ciphertext, allowing the user to inspect the header (e.g., to find
/// the `key_id`) before supplying the appropriate key to proceed with decryption.
pub struct PendingDecryptor<'a> {
    header: Header,
    ciphertext_body: &'a [u8],
}

impl<'a> PendingDecryptor<'a> {
    /// Creates a new `PendingDecryptor` by parsing the header from the ciphertext.
    pub fn from_ciphertext(ciphertext: &'a [u8]) -> Result<Self> {
        let (header, ciphertext_body) = Header::decode_from_prefixed_slice(ciphertext)?;
        Ok(Self {
            header,
            ciphertext_body,
        })
    }

    /// Consumes the `PendingDecryptor` and returns the decrypted plaintext.
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

/// Decrypts a ciphertext body using the provided key and header.
///
/// This function assumes `decode_header` has been called and its results are provided.
pub fn decrypt_body<S: SymmetricAlgorithm>(
    key: S::Key,
    header: &Header,
    ciphertext_body: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>>
where
    S::Key: Send + Sync,
{
    let (chunk_size, base_nonce) = match &header.payload {
        HeaderPayload::Symmetric {
            stream_info: Some(info),
            ..
        } => (info.chunk_size, info.base_nonce),
        _ => return Err(Error::InvalidHeader),
    };

    decrypt_in_memory::<S>(key, base_nonce, chunk_size, ciphertext_body, aad)
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
    use seal_crypto::prelude::SymmetricKeyGenerator;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;

    #[test]
    fn test_symmetric_ordinary_roundtrip() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"This is a test message that is longer than one chunk to ensure the chunking logic works correctly. Let's add some more data to be sure.";

        let encrypted =
            encrypt::<Aes256Gcm>(key.clone(), plaintext, "test_key_id".to_string(), None).unwrap();

        // Test the full convenience function
        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted_full = pending
            .into_plaintext::<Aes256Gcm>(key.clone(), None)
            .unwrap();
        assert_eq!(plaintext, decrypted_full.as_slice());

        // Test the separated functions
        let (header, body) = Header::decode_from_prefixed_slice(&encrypted).unwrap();
        assert_eq!(header.payload.key_id().unwrap(), "test_key_id");
        let decrypted_parts = decrypt_body::<Aes256Gcm>(key, &header, body, None).unwrap();
        assert_eq!(plaintext, decrypted_parts.as_slice());
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
    fn test_tampered_ciphertext_fails() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some important data";

        let mut encrypted =
            encrypt::<Aes256Gcm>(key.clone(), plaintext, "test_key_id".to_string(), None).unwrap();

        // Tamper with the ciphertext body
        if !encrypted.is_empty() {
            let len = encrypted.len();
            encrypted[len / 2] ^= 1;
        }

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result = pending.into_plaintext::<Aes256Gcm>(key, None);
        assert!(result.is_err());
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
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some data";

        let mut encrypted =
            encrypt::<Aes256Gcm>(key.clone(), plaintext, "test_key_id".to_string(), None).unwrap();

        // Tamper with the nonce in the header
        if encrypted.len() > 20 {
            // Ensure there's a header to tamper with
            encrypted[20] ^= 1;
        }

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result = pending.into_plaintext::<Aes256Gcm>(key, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_internal_functions() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some plaintext";
        let encrypted =
            encrypt::<Aes256Gcm>(key.clone(), plaintext, "test_key_id".to_string(), None).unwrap();

        // Test the separated functions
        let (header, body) = Header::decode_from_prefixed_slice(&encrypted).unwrap();
        assert_eq!(header.payload.key_id().unwrap(), "test_key_id");
        let decrypted_parts = decrypt_body::<Aes256Gcm>(key, &header, body, None).unwrap();
        assert_eq!(plaintext, decrypted_parts.as_slice());
    }

    #[test]
    fn test_aad_roundtrip() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some data to protect";
        let aad = b"some context data";

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
