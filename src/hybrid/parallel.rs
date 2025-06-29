use super::common::{create_header, derive_nonce, DEFAULT_CHUNK_SIZE};
use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, Result};
use rayon::prelude::*;
use seal_crypto::prelude::*;
use seal_crypto::zeroize::Zeroizing;

/// Performs parallel, in-memory hybrid encryption.
pub fn encrypt<A, S>(pk: &A::PublicKey, plaintext: &[u8], kek_id: String, aad: Option<&[u8]>) -> Result<Vec<u8>>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync,
    Vec<u8>: From<<A as Kem>::EncapsulatedKey>,
{
    // 1. Create header, nonce, and DEK
    let (header, base_nonce, shared_secret) = create_header::<A, S>(&pk.clone().into(), kek_id)?;

    // 2. Serialize the header and prepare for encryption
    let header_bytes = header.encode_to_vec()?;
    let key_material: S::Key = shared_secret.into();
    let chunk_size = DEFAULT_CHUNK_SIZE as usize;
    let tag_size = S::TAG_SIZE;

    // 3. Pre-allocate the exact size for the output buffer
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
    final_output.resize(4 + header_bytes.len() + total_body_size, 0);

    let (_header_part, body_part) = final_output.split_at_mut(4 + header_bytes.len());

    // 4. Process chunks in parallel, writing directly to the output buffer
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

/// A pending decryptor for in-memory hybrid-encrypted data that will be
/// processed in parallel.
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
        S: SymmetricAlgorithm,
        S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync,
        A::PrivateKey: Clone,
        A::EncapsulatedKey: From<Vec<u8>>,
    {
        decrypt_body::<A, S>(sk, &self.header, self.ciphertext_body, aad)
    }
}

/// Performs parallel, in-memory hybrid decryption on a ciphertext body.
pub fn decrypt_body<A, S>(
    sk: &A::PrivateKey,
    header: &Header,
    ciphertext_body: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync,
    A::PrivateKey: Clone,
    A::EncapsulatedKey: From<Vec<u8>>,
{
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

    let shared_secret = A::decapsulate(&sk.clone().into(), &encapsulated_key)?;
    let key_material: S::Key = shared_secret.into();
    let tag_len = S::TAG_SIZE;
    let encrypted_chunk_size = chunk_size as usize + tag_len;

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

            S::decrypt_to_buffer(&key_material, &nonce, encrypted_chunk, plaintext_chunk, aad)
                .map_err(Error::from)
        })
        .collect::<Result<Vec<usize>>>()?;

    let actual_size = decrypted_chunk_lengths.iter().sum();
    plaintext.truncate(actual_size);

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
    fn test_hybrid_parallel_roundtrip() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"This is a test message for hybrid parallel encryption, which should be long enough to span multiple chunks to properly test the implementation.";

        let encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, plaintext, "test_kek_id".to_string(), None).unwrap();

        // Test convenience function
        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending.into_plaintext::<Rsa2048, Aes256Gcm>(&sk, None).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Test separated functions
        let (header, body) = Header::decode_from_prefixed_slice(&encrypted).unwrap();
        assert_eq!(header.payload.kek_id(), Some("test_kek_id"));
        let decrypted_body = decrypt_body::<Rsa2048, Aes256Gcm>(&sk, &header, body, None).unwrap();
        assert_eq!(plaintext, decrypted_body.as_slice());

        // Tamper with the ciphertext body
        let mut encrypted_tampered = encrypted;
        encrypted_tampered[300] ^= 1;

        let pending = PendingDecryptor::from_ciphertext(&encrypted_tampered).unwrap();
        let result = pending.into_plaintext::<Rsa2048, Aes256Gcm>(&sk, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"";

        let encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, plaintext, "test_kek_id".to_string(), None).unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending.into_plaintext::<Rsa2048, Aes256Gcm>(&sk, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];

        let encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, &plaintext, "test_kek_id".to_string(), None).unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending.into_plaintext::<Rsa2048, Aes256Gcm>(&sk, None).unwrap();

        assert_eq!(plaintext, decrypted);
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
    fn test_internal_functions() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"some plaintext for parallel";
        let encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, plaintext, "test_kek_id".to_string(), None).unwrap();

        // Test the separated functions
        let (header, body) = Header::decode_from_prefixed_slice(&encrypted).unwrap();
        assert_eq!(header.payload.kek_id(), Some("test_kek_id"));
        let decrypted_body =
            decrypt_body::<Rsa2048, Aes256Gcm>(&sk, &header, body, None).unwrap();
        assert_eq!(plaintext, decrypted_body.as_slice());
    }

    #[test]
    fn test_aad_roundtrip() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"some parallel data to protect";
        let aad = b"some parallel context data";

        // Encrypt with AAD
        let encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, plaintext, "aad_key".to_string(), Some(aad)).unwrap();

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
