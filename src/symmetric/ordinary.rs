//! Implements the ordinary (single-threaded, in-memory) symmetric encryption scheme.

use super::common::{create_header, derive_nonce, DEFAULT_CHUNK_SIZE};
use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, Result};

/// Encrypts plaintext using a chunking mechanism.
pub fn encrypt<S: SymmetricAlgorithm>(
    key: S::Key,
    plaintext: &[u8],
    key_id: String,
) -> Result<Vec<u8>>
where
    S::Key: Send + Sync,
{
    let (header, base_nonce_bytes) = create_header::<S>(key_id)?;
    let header_bytes = header.encode_to_vec()?;

    let key_material = key.into();

    let mut encrypted_body = Vec::with_capacity(
        plaintext.len() + (plaintext.len() / DEFAULT_CHUNK_SIZE as usize + 1) * S::TAG_SIZE,
    );

    let mut temp_chunk_buffer = vec![0u8; DEFAULT_CHUNK_SIZE as usize + S::TAG_SIZE];

    for (i, chunk) in plaintext.chunks(DEFAULT_CHUNK_SIZE as usize).enumerate() {
        let nonce = derive_nonce(&base_nonce_bytes, i as u64);
        let bytes_written =
            S::encrypt_to_buffer(&key_material, &nonce, chunk, &mut temp_chunk_buffer, None)?;
        encrypted_body.extend_from_slice(&temp_chunk_buffer[..bytes_written]);
    }

    let mut final_output = Vec::with_capacity(4 + header_bytes.len() + encrypted_body.len());
    final_output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    final_output.extend_from_slice(&header_bytes);
    final_output.extend_from_slice(&encrypted_body);

    Ok(final_output)
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

    /// Returns a reference to the header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Consumes the `PendingDecryptor` and returns the decrypted plaintext.
    pub fn into_plaintext<S: SymmetricAlgorithm>(self, key: S::Key) -> Result<Vec<u8>>
    where
        S::Key: Send + Sync,
    {
        decrypt_body::<S>(key, &self.header, self.ciphertext_body)
    }
}

/// Decrypts a ciphertext body using the provided key and header.
///
/// This function assumes `decode_header` has been called and its results are provided.
pub fn decrypt_body<S: SymmetricAlgorithm>(
    key: S::Key,
    header: &Header,
    ciphertext_body: &[u8],
) -> Result<Vec<u8>>
where
    S::Key: Send + Sync,
{
    let (chunk_size, base_nonce_array) = match &header.payload {
        HeaderPayload::Symmetric {
            stream_info: Some(info),
            ..
        } => (info.chunk_size, info.base_nonce),
        _ => return Err(Error::InvalidHeader),
    };

    let key_material = key.into();
    let mut plaintext = Vec::with_capacity(ciphertext_body.len());
    let chunk_size_with_tag = chunk_size as usize + S::TAG_SIZE;

    // Reusable buffer for decrypted chunks, sized for the largest possible chunk.
    let mut decrypted_chunk_buffer = vec![0u8; chunk_size as usize];

    let mut cursor = 0;
    let mut chunk_index = 0;
    while cursor < ciphertext_body.len() {
        let remaining_len = ciphertext_body.len() - cursor;
        let current_chunk_len = std::cmp::min(remaining_len, chunk_size_with_tag);

        if current_chunk_len == 0 {
            break;
        }

        let encrypted_chunk = &ciphertext_body[cursor..cursor + current_chunk_len];

        let nonce = derive_nonce(&base_nonce_array, chunk_index as u64);
        let bytes_written = S::decrypt_to_buffer(
            &key_material,
            &nonce,
            encrypted_chunk,
            &mut decrypted_chunk_buffer,
            None,
        )?;

        plaintext.extend_from_slice(&decrypted_chunk_buffer[..bytes_written]);

        cursor += current_chunk_len;
        chunk_index += 1;
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::prelude::SymmetricKeyGenerator;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;

    #[test]
    fn test_symmetric_ordinary_roundtrip() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"This is a test message that is longer than one chunk to ensure the chunking logic works correctly. Let's add some more data to be sure.";

        let encrypted = encrypt::<Aes256Gcm>(key.clone(), plaintext, "test_key_id".to_string()).unwrap();

        // Test the full convenience function
        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted_full = pending.into_plaintext::<Aes256Gcm>(key.clone()).unwrap();
        assert_eq!(plaintext, decrypted_full.as_slice());

        // Test the separated functions
        let (header, body) = Header::decode_from_prefixed_slice(&encrypted).unwrap();
        assert_eq!(header.payload.key_id().unwrap(), "test_key_id");
        let decrypted_parts = decrypt_body::<Aes256Gcm>(key, &header, body).unwrap();
        assert_eq!(plaintext, decrypted_parts.as_slice());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"";

        let encrypted = encrypt::<Aes256Gcm>(key.clone(), plaintext, "test_key_id".to_string()).unwrap();
        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending.into_plaintext::<Aes256Gcm>(key).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];

        let encrypted = encrypt::<Aes256Gcm>(key.clone(), &plaintext, "test_key_id".to_string()).unwrap();
        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending.into_plaintext::<Aes256Gcm>(key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some important data";

        let mut encrypted =
            encrypt::<Aes256Gcm>(key.clone(), plaintext, "test_key_id".to_string()).unwrap();

        // Tamper with the ciphertext body
        if !encrypted.is_empty() {
            let len = encrypted.len();
            encrypted[len / 2] ^= 1;
        }

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result = pending.into_plaintext::<Aes256Gcm>(key);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = Aes256Gcm::generate_key().unwrap();
        let key2 = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some data";

        let encrypted =
            encrypt::<Aes256Gcm>(key1, plaintext, "test_key_id_1".to_string()).unwrap();
        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result = pending.into_plaintext::<Aes256Gcm>(key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some data";

        let mut encrypted =
            encrypt::<Aes256Gcm>(key.clone(), plaintext, "test_key_id".to_string()).unwrap();

        // Tamper with the nonce in the header
        if encrypted.len() > 20 {
            // Ensure there's a header to tamper with
            encrypted[20] ^= 1;
        }

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result = pending.into_plaintext::<Aes256Gcm>(key);
        assert!(result.is_err());
    }

    #[test]
    fn test_internal_functions() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some plaintext";
        let encrypted = encrypt::<Aes256Gcm>(key.clone(), plaintext, "test_key_id".to_string()).unwrap();

        // Test the separated functions
        let (header, body) = Header::decode_from_prefixed_slice(&encrypted).unwrap();
        assert_eq!(header.payload.key_id().unwrap(), "test_key_id");
        let decrypted_parts = decrypt_body::<Aes256Gcm>(key, &header, body).unwrap();
        assert_eq!(plaintext, decrypted_parts.as_slice());
    }
}
