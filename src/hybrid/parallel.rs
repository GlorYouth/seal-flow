use super::common::{create_header, derive_nonce, DEFAULT_CHUNK_SIZE};
use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, Result};
use rayon::prelude::*;
use seal_crypto::prelude::*;
use seal_crypto::zeroize::Zeroizing;

/// Performs parallel, in-memory hybrid encryption.
pub fn encrypt<A, S>(pk: &A::PublicKey, plaintext: &[u8], kek_id: String) -> Result<Vec<u8>>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync + Clone,
    Vec<u8>: From<<A as Kem>::EncapsulatedKey>,
{
    // 1. Create header, nonce, and DEK
    let (header, base_nonce, shared_secret) = create_header::<A, S>(&pk.clone().into(), kek_id)?;

    // 2. Serialize the header.
    let header_bytes = header.encode_to_vec()?;
    let key_material = shared_secret.into();

    // 3. Encrypt data chunks in parallel using Rayon.
    let encrypted_chunks: Vec<Vec<u8>> = plaintext
        .par_chunks(DEFAULT_CHUNK_SIZE as usize)
        .enumerate()
        .map(|(i, chunk)| {
            let nonce = derive_nonce(&base_nonce, i as u64);
            S::encrypt(&key_material, &nonce, chunk, None)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    // 4. Assemble the final output.
    let final_output = {
        let body = encrypted_chunks.concat();
        let mut output = Vec::with_capacity(4 + header_bytes.len() + body.len());
        output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        output.extend_from_slice(&header_bytes);
        output.extend_from_slice(&body);
        output
    };

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
    pub fn into_plaintext<A, S>(self, sk: &A::PrivateKey) -> Result<Vec<u8>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
        S::Key: From<Zeroizing<Vec<u8>>>,
        A::PrivateKey: Clone,
        A::EncapsulatedKey: From<Vec<u8>>,
    {
        decrypt_body::<A, S>(sk, &self.header, self.ciphertext_body)
    }
}

/// Performs parallel, in-memory hybrid decryption on a ciphertext body.
pub fn decrypt_body<A, S>(
    sk: &A::PrivateKey,
    header: &Header,
    ciphertext_body: &[u8],
) -> Result<Vec<u8>>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>>,
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
    let tag_len = S::TAG_SIZE;
    let encrypted_chunk_size = chunk_size as usize + tag_len;

    let decrypted_chunks: Vec<Vec<u8>> = ciphertext_body
        .par_chunks(encrypted_chunk_size)
        .enumerate()
        .map(|(i, encrypted_chunk)| {
            let nonce = derive_nonce(&base_nonce, i as u64);
            S::decrypt(&shared_secret.clone().into(), &nonce, encrypted_chunk, None)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(decrypted_chunks.concat())
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
            encrypt::<Rsa2048, Aes256Gcm>(&pk, plaintext, "test_kek_id".to_string()).unwrap();

        // Test convenience function
        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending.into_plaintext::<Rsa2048, Aes256Gcm>(&sk).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Test separated functions
        let (header, body) = Header::decode_from_prefixed_slice(&encrypted).unwrap();
        assert_eq!(header.payload.kek_id(), Some("test_kek_id"));
        let decrypted_body = decrypt_body::<Rsa2048, Aes256Gcm>(&sk, &header, body).unwrap();
        assert_eq!(plaintext, decrypted_body.as_slice());
    }

    #[test]
    fn test_empty_plaintext() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"";

        let encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, plaintext, "test_kek_id".to_string()).unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending.into_plaintext::<Rsa2048, Aes256Gcm>(&sk).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];

        let encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, &plaintext, "test_kek_id".to_string()).unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending.into_plaintext::<Rsa2048, Aes256Gcm>(&sk).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"some important data";

        let mut encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, plaintext, "test_kek_id".to_string()).unwrap();

        if encrypted.len() > 300 {
            encrypted[300] ^= 1;
        }

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result = pending.into_plaintext::<Rsa2048, Aes256Gcm>(&sk);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Crypto(_)));
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let (pk, _) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let (_, sk2) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"some data";

        let encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, plaintext, "test_kek_id".to_string()).unwrap();

        let pending = PendingDecryptor::from_ciphertext(&encrypted).unwrap();
        let result = pending.into_plaintext::<Rsa2048, Aes256Gcm>(&sk2);
        assert!(result.is_err());
    }
}
