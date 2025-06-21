//! Ordinary (single-threaded, in-memory) hybrid encryption and decryption.

use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::header::{Header, HeaderPayload, SealMode, StreamInfo};
use crate::error::{Error, Result};
use rand::{rngs::OsRng, TryRngCore};
use seal_crypto::traits::{
    kem::Kem,
    symmetric::{SymmetricCipher, SymmetricDecryptor, SymmetricEncryptor},
};
use seal_crypto::zeroize::Zeroizing;

const DEFAULT_CHUNK_SIZE: u32 = 65536; // 64 KiB

/// Performs hybrid encryption on in-memory data.
pub fn encrypt<'a, A, S>(pk: &'a Vec<u8>, plaintext: &[u8], kek_id: String) -> Result<Vec<u8>>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm<Key = Zeroizing<Vec<u8>>>,
    &'a <A as AsymmetricAlgorithm>::PublicKey: From<&'a Vec<u8>>,
    Vec<u8>: From<<<A as AsymmetricAlgorithm>::Scheme as Kem>::EncapsulatedKey>,
{
    // 1. KEM Encapsulate: Generate DEK and wrap it with the public key.
    let (shared_secret, encapsulated_key) = A::Scheme::encapsulate(pk.into())?;

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
        let encrypted_chunk = S::Scheme::encrypt(&shared_secret, &nonce, chunk, None)?;
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

/// Performs hybrid decryption on in-memory data.
pub fn decrypt<A, S>(sk: &A::PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm<Key = Zeroizing<Vec<u8>>>,
    <A::Scheme as Kem>::EncapsulatedKey: From<Vec<u8>>,
{
    // 1. Parse the header.
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

    // 2. Extract metadata and the encrypted DEK from the header.
    let (encapsulated_key, chunk_size, base_nonce) = match header.payload {
        HeaderPayload::Hybrid {
            encrypted_dek,
            stream_info: Some(info),
            ..
        } => (encrypted_dek.into(), info.chunk_size, info.base_nonce),
        _ => return Err(Error::InvalidHeader),
    };

    // 3. KEM Decapsulate to recover the DEK.
    let shared_secret = A::Scheme::decapsulate(sk, &encapsulated_key)?;

    let tag_len = S::Scheme::TAG_SIZE;
    let encrypted_chunk_size = chunk_size as usize + tag_len;

    // 4. Decrypt data chunks sequentially.
    let mut decrypted_chunks = Vec::new();
    for (i, encrypted_chunk) in ciphertext_body.chunks(encrypted_chunk_size).enumerate() {
        let mut nonce = base_nonce;
        let counter_bytes = (i as u64).to_le_bytes();
        for j in 0..8 {
            nonce[4 + j] ^= counter_bytes[j];
        }
        let decrypted_chunk =
            S::Scheme::decrypt(&shared_secret.clone(), &nonce, encrypted_chunk, None)?;
        decrypted_chunks.push(decrypted_chunk);
    }

    Ok(decrypted_chunks.concat())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::definitions::{Aes256Gcm, Rsa2048};
    use crate::algorithms::traits::AsymmetricAlgorithm;
    use seal_crypto::traits::key::KeyGenerator;

    #[test]
    fn test_hybrid_ordinary_roundtrip() {
        let (pk, sk) = <Rsa2048 as AsymmetricAlgorithm>::Scheme::generate_keypair().unwrap();
        let plaintext = b"This is a test message for hybrid ordinary encryption, which should be long enough to span multiple chunks to properly test the implementation.";

        let encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, plaintext, "test_kek_id".to_string()).unwrap();

        let decrypted = decrypt::<Rsa2048, Aes256Gcm>(&sk, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_empty_plaintext() {
        let (pk, sk) = <Rsa2048 as AsymmetricAlgorithm>::Scheme::generate_keypair().unwrap();
        let plaintext = b"";

        let encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, plaintext, "test_kek_id".to_string()).unwrap();

        let decrypted = decrypt::<Rsa2048, Aes256Gcm>(&sk, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let (pk, sk) = <Rsa2048 as AsymmetricAlgorithm>::Scheme::generate_keypair().unwrap();
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];

        let encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, &plaintext, "test_kek_id".to_string()).unwrap();

        let decrypted = decrypt::<Rsa2048, Aes256Gcm>(&sk, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (pk, sk) = <Rsa2048 as AsymmetricAlgorithm>::Scheme::generate_keypair().unwrap();
        let plaintext = b"some important data";

        let mut encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, plaintext, "test_kek_id".to_string()).unwrap();

        // Tamper with the ciphertext body
        if encrypted.len() > 300 {
            encrypted[300] ^= 1; // Tamper after the header
        }

        let result = decrypt::<Rsa2048, Aes256Gcm>(&sk, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let (pk, _) = <Rsa2048 as AsymmetricAlgorithm>::Scheme::generate_keypair().unwrap();
        let (_, sk2) = <Rsa2048 as AsymmetricAlgorithm>::Scheme::generate_keypair().unwrap();
        let plaintext = b"some data";

        let encrypted =
            encrypt::<Rsa2048, Aes256Gcm>(&pk, plaintext, "test_kek_id".to_string()).unwrap();

        let result = decrypt::<Rsa2048, Aes256Gcm>(&sk2, &encrypted);
        assert!(result.is_err());
    }
}
