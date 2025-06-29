//! Ordinary (single-threaded, in-memory) hybrid encryption and decryption.

use super::common::{create_header, derive_nonce, DEFAULT_CHUNK_SIZE};
use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, Result};
use seal_crypto::zeroize::Zeroizing;

/// Performs hybrid encryption on in-memory data.
pub fn encrypt<A, S>(
    pk: &A::PublicKey,
    plaintext: &[u8],
    kek_id: String,
    aad: Option<&[u8]>,
) -> Result<Vec<u8>>
where
    A: AsymmetricAlgorithm,
    A::EncapsulatedKey: Into<Vec<u8>> + Send,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>>,
{
    // 1. Create header, nonce, and DEK
    let (header, base_nonce, shared_secret) = create_header::<A, S>(pk, kek_id)?;

    // 2. Serialize the header.
    let header_bytes = header.encode_to_vec()?;
    let key_material = shared_secret.into();

    // 3. Encrypt data chunks sequentially.
    let mut encrypted_body = Vec::with_capacity(
        plaintext.len() + (plaintext.len() / DEFAULT_CHUNK_SIZE as usize + 1) * S::TAG_SIZE,
    );
    let mut temp_chunk_buffer = vec![0u8; DEFAULT_CHUNK_SIZE as usize + S::TAG_SIZE];

    for (i, chunk) in plaintext.chunks(DEFAULT_CHUNK_SIZE as usize).enumerate() {
        let nonce = derive_nonce(&base_nonce, i as u64);
        let bytes_written =
            S::encrypt_to_buffer(&key_material, &nonce, chunk, &mut temp_chunk_buffer, aad)?;
        encrypted_body.extend_from_slice(&temp_chunk_buffer[..bytes_written]);
    }

    // 4. Assemble the final output.
    let mut final_output =
        Vec::with_capacity(4 + header_bytes.len() + encrypted_body.len());
    final_output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    final_output.extend_from_slice(&header_bytes);
    final_output.extend_from_slice(&encrypted_body);

    Ok(final_output)
}

/// A pending decryptor for in-memory hybrid-encrypted data.
///
/// This state is entered after the header has been successfully parsed from
/// the ciphertext, allowing the user to inspect the header (e.g., to find
/// the `kek_id`) before supplying the appropriate private key to proceed with
/// decryption.
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
    pub fn into_plaintext<A, S>(self, sk: &A::PrivateKey, aad: Option<&[u8]>) -> Result<Vec<u8>>
    where
        A: AsymmetricAlgorithm,
        A::EncapsulatedKey: From<Vec<u8>> + Send,
        S: SymmetricAlgorithm,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        decrypt_body::<A, S>(sk, &self.header, self.ciphertext_body, aad)
    }
}

/// Performs hybrid decryption on an in-memory ciphertext body.
///
/// This function assumes `decode_header` has been called and its results are provided.
pub fn decrypt_body<A, S>(
    sk: &A::PrivateKey,
    header: &Header,
    ciphertext_body: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>>
where
    A: AsymmetricAlgorithm,
    A::EncapsulatedKey: From<Vec<u8>> + Send,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>>,
{
    // 1. Extract metadata and the encrypted DEK from the header.
    let (encapsulated_key, chunk_size, base_nonce) = match &header.payload {
        HeaderPayload::Hybrid {
            encrypted_dek,
            stream_info: Some(info),
            ..
        } => (
            encrypted_dek.clone().into(),
            info.chunk_size,
            info.base_nonce,
        ),
        _ => return Err(Error::InvalidHeader),
    };

    // 2. KEM Decapsulate to recover the DEK.
    let shared_secret = A::decapsulate(sk, &encapsulated_key)?;
    let key_material = shared_secret.into();

    let tag_len = S::TAG_SIZE;
    let encrypted_chunk_size = chunk_size as usize + tag_len;

    // 3. Decrypt data chunks sequentially.
    let mut plaintext = Vec::with_capacity(ciphertext_body.len());
    let mut decrypted_chunk_buffer = vec![0u8; chunk_size as usize];

    for (i, encrypted_chunk) in ciphertext_body.chunks(encrypted_chunk_size).enumerate() {
        let nonce = derive_nonce(&base_nonce, i as u64);
        let bytes_written = S::decrypt_to_buffer(
            &key_material,
            &nonce,
            encrypted_chunk,
            &mut decrypted_chunk_buffer,
            aad,
        )?;
        plaintext.extend_from_slice(&decrypted_chunk_buffer[..bytes_written]);
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::prelude::KeyGenerator;
    use seal_crypto::schemes::asymmetric::traditional::rsa::Rsa2048;
    use seal_crypto::schemes::hash::Sha256;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;

    #[test]
    fn test_hybrid_ordinary_roundtrip() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"This is a test message for hybrid ordinary encryption, which should be long enough to span multiple chunks to properly test the implementation.";

        let encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, plaintext, "test_kek_id".to_string(), None).unwrap();

        // Test convenience function
        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted_full = pending
            .into_plaintext::<Rsa2048, Aes256Gcm>(&sk, None)
            .unwrap();
        assert_eq!(plaintext, decrypted_full.as_slice());

        // Test separated functions
        let (header, body) = Header::decode_from_prefixed_slice(&encrypted).unwrap();
        assert_eq!(header.payload.kek_id(), Some("test_kek_id"));
        let decrypted_parts =
            decrypt_body::<Rsa2048, Aes256Gcm>(&sk, &header, body, None).unwrap();
        assert_eq!(plaintext, decrypted_parts.as_slice());
    }

    #[test]
    fn test_empty_plaintext() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"";

        let encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, plaintext, "test_kek_id".to_string(), None).unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending
            .into_plaintext::<Rsa2048, Aes256Gcm>(&sk, None)
            .unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];

        let encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, &plaintext, "test_kek_id".to_string(), None)
                .unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending
            .into_plaintext::<Rsa2048, Aes256Gcm>(&sk, None)
            .unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"some important data";

        let mut encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, plaintext, "test_kek_id".to_string(), None).unwrap();

        // Tamper with the ciphertext body
        if encrypted.len() > 300 {
            encrypted[300] ^= 1; // Tamper after the header
        }

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result = pending.into_plaintext::<Rsa2048, Aes256Gcm>(&sk, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let (pk, _) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let (_, sk2) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"some data";

        let encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, plaintext, "test_kek_id".to_string(), None).unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result = pending.into_plaintext::<Rsa2048, Aes256Gcm>(&sk2, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_aad_roundtrip() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"some important data with aad";
        let aad = b"some important context";

        let encrypted = encrypt::<Rsa2048, Aes256Gcm>(
            &pk,
            plaintext,
            "aad_kek_id".to_string(),
            Some(aad),
        )
        .unwrap();

        // Decrypt with correct AAD
        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending
            .into_plaintext::<Rsa2048, Aes256Gcm>(&sk, Some(aad))
            .unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Decrypt with wrong AAD fails
        let pending_fail = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result_fail =
            pending_fail.into_plaintext::<Rsa2048, Aes256Gcm>(&sk, Some(b"wrong aad"));
        assert!(result_fail.is_err());

        // Decrypt with no AAD fails
        let pending_fail2 = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result_fail2 = pending_fail2.into_plaintext::<Rsa2048, Aes256Gcm>(&sk, None);
        assert!(result_fail2.is_err());
    }
}
