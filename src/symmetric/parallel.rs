use super::common::{
    create_header, derive_nonce, DEFAULT_CHUNK_SIZE,
};
use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, Result};
use rayon::prelude::*;

/// Encrypts in-memory data using parallel processing.
pub fn encrypt<'a, S>(key: &S::Key, plaintext: &[u8], key_id: String) -> Result<Vec<u8>>
where
    S: SymmetricAlgorithm,
    S::Key: Send + Sync + Clone,
{
    // 1. Setup Header
    let (header, base_nonce) = create_header::<S>(key_id)?;
    let header_bytes = header.encode_to_vec()?;

    // 2. Process chunks in parallel using Rayon
    let encrypted_chunks: Vec<Vec<u8>> = plaintext
        .par_chunks(DEFAULT_CHUNK_SIZE as usize)
        .enumerate()
        .map(|(i, chunk)| {
            // 3. Derive nonce and encrypt
            let nonce = derive_nonce(&base_nonce, i as u64);
            S::encrypt(&key.clone().into(), &nonce, chunk, None)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    // 4. Assemble the final output
    let mut final_output = Vec::with_capacity(
        4 + header_bytes.len() + encrypted_chunks.iter().map(Vec::len).sum::<usize>(),
    );
    final_output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    final_output.extend_from_slice(&header_bytes);
    final_output.extend_from_slice(&encrypted_chunks.concat());

    Ok(final_output)
}

/// Decrypts a ciphertext body in parallel using the provided key and header.
///
/// This function assumes `decode_header` has been called and its results are provided.
pub fn decrypt_body<S>(key: &S::Key, header: &Header, ciphertext_body: &[u8]) -> Result<Vec<u8>>
where
    S: SymmetricAlgorithm,
    S::Key: Send + Sync + Clone,
{
    // Extract stream info from Header
    let (chunk_size, base_nonce) = match &header.payload {
        HeaderPayload::Symmetric {
            stream_info: Some(info),
            ..
        } => (info.chunk_size, info.base_nonce),
        _ => return Err(Error::InvalidHeader),
    };

    let tag_len = S::TAG_SIZE;
    let encrypted_chunk_size = chunk_size as usize + tag_len;

    // Decrypt in parallel
    let decrypted_chunks: Vec<Vec<u8>> = ciphertext_body
        .par_chunks(encrypted_chunk_size)
        .enumerate()
        .map(|(i, encrypted_chunk)| {
            // Derive deterministic nonce
            let nonce = derive_nonce(&base_nonce, i as u64);

            // Decrypt the chunk
            S::decrypt(&key.clone().into(), &nonce, encrypted_chunk, None)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(decrypted_chunks.concat())
}

/// A pending decryptor for in-memory data that will be processed in parallel.
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
    pub fn into_plaintext<S: SymmetricAlgorithm>(self, key: &S::Key) -> Result<Vec<u8>>
    where
        S::Key: Clone + Send + Sync,
    {
        decrypt_body::<S>(key, &self.header, self.ciphertext_body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error as FlowError;
    use seal_crypto::errors::Error as CryptoError;
    use seal_crypto::prelude::SymmetricKeyGenerator;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;

    #[test]
    fn test_symmetric_parallel_roundtrip() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"This is a test message that is longer than one chunk to ensure the chunking logic works correctly. Let's add some more data to be sure.";

        let encrypted = encrypt::<Aes256Gcm>(&key, plaintext, "test_key_id".to_string()).unwrap();

        // Test the convenience function
        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending.into_plaintext::<Aes256Gcm>(&key).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Test the separated functions
        let (header, body) = Header::decode_from_prefixed_slice(&encrypted).unwrap();
        assert_eq!(header.payload.key_id(), Some("test_key_id"));
        let decrypted_body = decrypt_body::<Aes256Gcm>(&key, &header, body).unwrap();
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
        let result = pending.into_plaintext::<Aes256Gcm>(&key);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"";

        let encrypted = encrypt::<Aes256Gcm>(&key, plaintext, "test_key_id".to_string()).unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending.into_plaintext::<Aes256Gcm>(&key).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];

        let encrypted = encrypt::<Aes256Gcm>(&key, &plaintext, "test_key_id".to_string()).unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending.into_plaintext::<Aes256Gcm>(&key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = Aes256Gcm::generate_key().unwrap();
        let key2 = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some data";

        let encrypted =
            encrypt::<Aes256Gcm>(&key1, plaintext, "test_key_id_1".to_string()).unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result = pending.into_plaintext::<Aes256Gcm>(&key2);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FlowError::Crypto(CryptoError::Symmetric(_))
        ));
    }

    #[test]
    fn test_internal_functions() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some plaintext for parallel";
        let encrypted = encrypt::<Aes256Gcm>(&key, plaintext, "test_key_id".to_string()).unwrap();

        // Test the separated functions
        let (header, body) = Header::decode_from_prefixed_slice(&encrypted).unwrap();
        assert_eq!(header.payload.key_id(), Some("test_key_id"));
        let decrypted_body = decrypt_body::<Aes256Gcm>(&key, &header, body).unwrap();
        assert_eq!(plaintext, decrypted_body.as_slice());
    }
}
