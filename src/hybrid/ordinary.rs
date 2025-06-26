//! Ordinary (single-threaded, in-memory) hybrid encryption and decryption.

use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::header::{Header, HeaderPayload, SealMode, StreamInfo};
use crate::error::{Error, Result};
use rand::{rngs::OsRng, TryRngCore};
use seal_crypto::zeroize::Zeroizing;

const DEFAULT_CHUNK_SIZE: u32 = 65536; // 64 KiB

/// Performs hybrid encryption on in-memory data.
pub fn encrypt<A, S>(pk: &A::PublicKey, plaintext: &[u8], kek_id: String) -> Result<Vec<u8>>
where
    A: AsymmetricAlgorithm,
    A::EncapsulatedKey: Into<Vec<u8>> + Send,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>>,
{
    // 1. KEM Encapsulate: Generate DEK and wrap it with the public key.
    let (shared_secret, encapsulated_key) = A::encapsulate(pk)?;

    // 2. Generate a base_nonce for deterministic nonce derivation for each chunk.
    let mut base_nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut base_nonce)?;

    // 3. Construct the header with stream info.
    let header = Header {
        version: 1,
        mode: SealMode::Hybrid,
        payload: HeaderPayload::Hybrid {
            kek_id,
            kek_algorithm: A::ALGORITHM,
            dek_algorithm: S::ALGORITHM,
            encrypted_dek: encapsulated_key.into(),
            stream_info: Some(StreamInfo {
                chunk_size: DEFAULT_CHUNK_SIZE,
                base_nonce,
            }),
        },
    };

    // 4. Serialize the header.
    let header_bytes = header.encode_to_vec()?;

    // 5. Encrypt data chunks sequentially.
    let mut encrypted_chunks = Vec::new();
    for (i, chunk) in plaintext.chunks(DEFAULT_CHUNK_SIZE as usize).enumerate() {
        let mut nonce = base_nonce;
        let counter_bytes = (i as u64).to_le_bytes();
        for j in 0..8 {
            nonce[4 + j] ^= counter_bytes[j];
        }
        let encrypted_chunk = S::encrypt(&shared_secret.clone().into(), &nonce, chunk, None)?;
        encrypted_chunks.push(encrypted_chunk);
    }

    // 6. Assemble the final output.
    let body = encrypted_chunks.concat();
    let capacity = 4 + header_bytes.len() + body.len();
    let mut final_output = Vec::with_capacity(capacity);
    final_output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    final_output.extend_from_slice(&header_bytes);
    final_output.extend_from_slice(&body);

    Ok(final_output)
}

/// Decodes the header from the beginning of a ciphertext slice.
///
/// Returns the parsed `Header` and a slice pointing to the remaining ciphertext body.
pub fn decode_header(ciphertext: &[u8]) -> Result<(Header, &[u8])> {
    if ciphertext.len() < 4 {
        return Err(Error::InvalidCiphertextFormat);
    }
    let header_len = u32::from_le_bytes(ciphertext[0..4].try_into().unwrap()) as usize;
    if ciphertext.len() < 4 + header_len {
        return Err(Error::InvalidCiphertextFormat);
    }
    let header_bytes = &ciphertext[4..4 + header_len];
    let ciphertext_body = &ciphertext[4 + header_len..];

    let (header, _) = Header::decode_from_slice(header_bytes)?;
    Ok((header, ciphertext_body))
}

/// A pending decryptor for in-memory hybrid-encrypted data.
///
/// This state is entered after the header has been successfully parsed from
/// the ciphertext, allowing the user to inspect the header (e.g., to find
/// the `kek_id`) before supplying the appropriate private key to proceed with
/// decryption.
pub struct PendingDecryptor<'a, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    header: Header,
    ciphertext_body: &'a [u8],
    _phantom: std::marker::PhantomData<(A, S)>,
}

impl<'a, A, S> PendingDecryptor<'a, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    /// Creates a new `PendingDecryptor` by parsing the header from the ciphertext.
    pub fn from_ciphertext(ciphertext: &'a [u8]) -> Result<Self> {
        let (header, ciphertext_body) = decode_header(ciphertext)?;
        Ok(Self {
            header,
            ciphertext_body,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Returns a reference to the header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Consumes the `PendingDecryptor` and returns the decrypted plaintext.
    pub fn into_plaintext(self, sk: &A::PrivateKey) -> Result<Vec<u8>>
    where
        A::EncapsulatedKey: From<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        decrypt_body::<A, S>(sk, &self.header, self.ciphertext_body)
    }
}

/// Performs hybrid decryption on an in-memory ciphertext body.
///
/// This function assumes `decode_header` has been called and its results are provided.
pub fn decrypt_body<A, S>(
    sk: &A::PrivateKey,
    header: &Header,
    ciphertext_body: &[u8],
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

    let tag_len = S::TAG_SIZE;
    let encrypted_chunk_size = chunk_size as usize + tag_len;

    // 3. Decrypt data chunks sequentially.
    let mut decrypted_chunks = Vec::new();
    for (i, encrypted_chunk) in ciphertext_body.chunks(encrypted_chunk_size).enumerate() {
        let mut nonce = base_nonce;
        let counter_bytes = (i as u64).to_le_bytes();
        for j in 0..8 {
            nonce[4 + j] ^= counter_bytes[j];
        }
        let decrypted_chunk =
            S::decrypt(&shared_secret.clone().into(), &nonce, encrypted_chunk, None)?;
        decrypted_chunks.push(decrypted_chunk);
    }

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
    fn test_hybrid_ordinary_roundtrip() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"This is a test message for hybrid ordinary encryption, which should be long enough to span multiple chunks to properly test the implementation.";

        let encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, plaintext, "test_kek_id".to_string()).unwrap();

        // Test convenience function
        let pending = PendingDecryptor::<Rsa2048, Aes256Gcm>::from_ciphertext(&encrypted).unwrap();
        let decrypted_full = pending.into_plaintext(&sk).unwrap();
        assert_eq!(plaintext, decrypted_full.as_slice());

        // Test separated functions
        let (header, body) = decode_header(&encrypted).unwrap();
        assert_eq!(header.payload.kek_id(), Some("test_kek_id"));
        let decrypted_parts =
            decrypt_body::<Rsa2048, Aes256Gcm>(&sk, &header, body).unwrap();
        assert_eq!(plaintext, decrypted_parts.as_slice());
    }

    #[test]
    fn test_empty_plaintext() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"";

        let encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, plaintext, "test_kek_id".to_string()).unwrap();

        let pending = PendingDecryptor::<Rsa2048, Aes256Gcm>::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending.into_plaintext(&sk).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];

        let encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, &plaintext, "test_kek_id".to_string()).unwrap();

        let pending = PendingDecryptor::<Rsa2048, Aes256Gcm>::from_ciphertext(&encrypted).unwrap();
        let decrypted = pending.into_plaintext(&sk).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"some important data";

        let mut encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, plaintext, "test_kek_id".to_string()).unwrap();

        // Tamper with the ciphertext body
        if encrypted.len() > 300 {
            encrypted[300] ^= 1; // Tamper after the header
        }

        let pending = PendingDecryptor::<Rsa2048, Aes256Gcm>::from_ciphertext(&encrypted).unwrap();
        let result = pending.into_plaintext(&sk);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let (pk, _) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let (_, sk2) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"some data";

        let encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, plaintext, "test_kek_id".to_string()).unwrap();

        let pending = PendingDecryptor::<Rsa2048, Aes256Gcm>::from_ciphertext(&encrypted).unwrap();
        let result = pending.into_plaintext(&sk2);
        assert!(result.is_err());
    }
}
