use super::common::create_header;
use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::{derive_nonce, DEFAULT_CHUNK_SIZE};
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, Result};
use rayon::prelude::*;

/// Encrypts in-memory data using parallel processing.
pub fn encrypt<'a, S>(
    key: S::Key,
    plaintext: &[u8],
    key_id: String,
    aad: Option<&[u8]>,
) -> Result<Vec<u8>>
where
    S: SymmetricAlgorithm,
    S::Key: Send + Sync,
{
    // 1. Setup Header
    let (header, base_nonce) = create_header::<S>(key_id)?;
    let header_bytes = header.encode_to_vec()?;
    let key_material = key.into();
    let chunk_size = DEFAULT_CHUNK_SIZE as usize;
    let tag_size = S::TAG_SIZE;

    // 2. Pre-allocate output buffer
    let num_chunks = (plaintext.len() + chunk_size - 1) / chunk_size;
    let last_chunk_len = if plaintext.len() % chunk_size == 0 {
        if plaintext.is_empty() {
            0
        } else {
            chunk_size
        }
    } else {
        plaintext.len() % chunk_size
    };

    let total_body_size = if plaintext.is_empty() {
        0
    } else {
        (num_chunks.saturating_sub(1)) * (chunk_size + tag_size) + (last_chunk_len + tag_size)
    };
    let mut final_output = Vec::with_capacity(4 + header_bytes.len() + total_body_size);
    final_output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    final_output.extend_from_slice(&header_bytes);
    // The rest of the buffer is for the body, which we will fill in parallel
    let body_len = total_body_size;
    final_output.resize(4 + header_bytes.len() + body_len, 0);

    let (_header_part, body_part) = final_output.split_at_mut(4 + header_bytes.len());

    // 3. Process chunks in parallel using Rayon, writing directly to the output buffer
    if !plaintext.is_empty() {
        body_part
            .par_chunks_mut(chunk_size + tag_size)
            .zip(plaintext.par_chunks(chunk_size))
            .enumerate()
            .try_for_each(|(i, (output_chunk, input_chunk))| -> Result<()> {
                let nonce = derive_nonce(&base_nonce, i as u64);
                let expected_output_len = input_chunk.len() + tag_size;
                let buffer_slice = &mut output_chunk[..expected_output_len];

                S::encrypt_to_buffer(&key_material, &nonce, input_chunk, buffer_slice, aad)
                    .map(|_| ())
                    .map_err(Error::from)
            })?;
    }

    Ok(final_output)
}

/// Decrypts a ciphertext body in parallel using the provided key and header.
///
/// This function assumes `decode_header` has been called and its results are provided.
pub fn decrypt_body<S>(
    key: S::Key,
    header: &Header,
    ciphertext_body: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>>
where
    S: SymmetricAlgorithm,
    S::Key: Send + Sync,
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
    let key_material = key.into();

    // Pre-allocate plaintext buffer
    let num_chunks = (ciphertext_body.len() + encrypted_chunk_size - 1) / encrypted_chunk_size;
    let last_chunk_len = if ciphertext_body.len() % encrypted_chunk_size == 0 {
        if ciphertext_body.is_empty() {
            0
        } else {
            encrypted_chunk_size
        }
    } else {
        ciphertext_body.len() % encrypted_chunk_size
    };

    if last_chunk_len > 0 && last_chunk_len <= tag_len {
        return Err(Error::InvalidCiphertextFormat);
    }

    let total_size = (num_chunks.saturating_sub(1)) * chunk_size as usize
        + (if last_chunk_len > tag_len {
            last_chunk_len - tag_len
        } else {
            0
        });
    let mut plaintext = vec![0u8; total_size];

    // Decrypt in parallel, writing directly to the plaintext buffer
    let decrypted_chunk_lengths: Vec<usize> = plaintext
        .par_chunks_mut(chunk_size as usize)
        .zip(ciphertext_body.par_chunks(encrypted_chunk_size))
        .enumerate()
        .map(|(i, (plaintext_chunk, encrypted_chunk))| -> Result<usize> {
            let nonce = derive_nonce(&base_nonce, i as u64);

            // Decrypt the chunk
            S::decrypt_to_buffer(&key_material, &nonce, encrypted_chunk, plaintext_chunk, aad)
                .map_err(Error::from)
        })
        .collect::<Result<Vec<usize>>>()?;

    // Truncate the plaintext to the actual decrypted size
    let actual_size = decrypted_chunk_lengths.iter().sum();
    plaintext.truncate(actual_size);

    Ok(plaintext)
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
            FlowError::Crypto(CryptoError::Symmetric(_))
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
