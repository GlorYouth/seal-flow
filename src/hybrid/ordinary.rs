//! Ordinary (single-threaded, in-memory) hybrid encryption and decryption.

use crate::common::algorithms::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::header::{Header, HeaderPayload, SealMode, StreamInfo};
use crate::error::{Error, Result};
use rand::{rngs::OsRng, TryRngCore};
use seal_crypto::{
    traits::{
        kem::{SharedSecret, Kem},
        symmetric::{SymmetricCipher, SymmetricDecryptor, SymmetricEncryptor},
    },
};

const DEFAULT_CHUNK_SIZE: u32 = 65536; // 64 KiB

/// Performs hybrid encryption on in-memory data using a single-threaded, chunk-based strategy.
pub fn hybrid_ordinary_encrypt<K, S>(
    pk: &K::PublicKey,
    plaintext: &[u8],
    // Metadata
    kek_id: String,
    kek_algorithm: AsymmetricAlgorithm,
    dek_algorithm: SymmetricAlgorithm,
) -> Result<Vec<u8>>
where
    K: Kem<EncapsulatedKey = Vec<u8>>,
    S: SymmetricEncryptor<Key = SharedSecret> + SymmetricCipher,
{
    // 1. KEM Encapsulate: Generate DEK and wrap it with the public key.
    let (shared_secret, encapsulated_key) = K::encapsulate(pk)?;

    // 2. Generate a base_nonce for deterministic nonce derivation for each chunk.
    let mut base_nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut base_nonce)?;

    // 3. Construct the header with stream info.
    let header = Header {
        version: 1,
        mode: SealMode::Hybrid,
        payload: HeaderPayload::Hybrid {
            kek_id,
            kek_algorithm,
            dek_algorithm,
            encrypted_dek: encapsulated_key,
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
        // 6. Derive a deterministic nonce for this chunk.
        let mut nonce = base_nonce;
        let counter_bytes = (i as u64).to_le_bytes();
        for j in 0..8 {
            nonce[4 + j] ^= counter_bytes[j];
        }

        // 7. Encrypt the chunk with the derived DEK.
        let encrypted_chunk = S::encrypt(&shared_secret, &nonce, chunk, None)?;
        encrypted_chunks.push(encrypted_chunk);
    }

    // 8. Assemble the final output.
    let final_output = {
        let body = encrypted_chunks.concat();
        let capacity = 4 + header_bytes.len() + body.len();
        let mut final_output = Vec::with_capacity(capacity);
        final_output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        final_output.extend_from_slice(&header_bytes);
        final_output.extend_from_slice(&body);
        final_output
    };

    Ok(final_output)
}

/// Performs hybrid decryption on in-memory data using a single-threaded, chunk-based strategy.
pub fn hybrid_ordinary_decrypt<K, S>(
    sk: &K::PrivateKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>>
where
    K: Kem,
    S: SymmetricDecryptor<Key = SharedSecret> + SymmetricCipher,
    <K as Kem>::EncapsulatedKey: From<Vec<u8>>,
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
    let shared_secret = K::decapsulate(sk, &encapsulated_key)?;

    let tag_len = S::TAG_SIZE;
    let encrypted_chunk_size = chunk_size as usize + tag_len;

    // 4. Decrypt data chunks sequentially.
    let mut decrypted_chunks = Vec::new();
    for (i, encrypted_chunk) in ciphertext_body.chunks(encrypted_chunk_size).enumerate() {
        // 5. Derive the deterministic nonce for this chunk.
        let mut nonce = base_nonce;
        let counter_bytes = (i as u64).to_le_bytes();
        for j in 0..8 {
            nonce[4 + j] ^= counter_bytes[j];
        }

        // 6. Decrypt the chunk with the recovered DEK.
        let decrypted_chunk = S::decrypt(&shared_secret, &nonce, encrypted_chunk, None)?;
        decrypted_chunks.push(decrypted_chunk);
    }

    Ok(decrypted_chunks.concat())
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::systems::{
        asymmetric::rsa::{Rsa2048, RsaScheme},
        symmetric::aes_gcm::{Aes256, AesGcmScheme},
    };
    use seal_crypto::traits::key::KeyGenerator;

    #[test]
    fn test_hybrid_ordinary_roundtrip() {
        let (pk, sk) = RsaScheme::<Rsa2048>::generate_keypair().unwrap();
        let plaintext = b"This is a test message for hybrid ordinary encryption, which should be long enough to span multiple chunks to properly test the implementation.";

        let encrypted = hybrid_ordinary_encrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(
            &pk,
            plaintext,
            "test_kek_id".to_string(),
            AsymmetricAlgorithm::Rsa2048,
            SymmetricAlgorithm::Aes256Gcm,
        )
        .unwrap();

        let decrypted =
            hybrid_ordinary_decrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(&sk, &encrypted)
                .unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_empty_plaintext() {
        let (pk, sk) = RsaScheme::<Rsa2048>::generate_keypair().unwrap();
        let plaintext = b"";

        let encrypted = hybrid_ordinary_encrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(
            &pk,
            plaintext,
            "test_kek_id".to_string(),
            AsymmetricAlgorithm::Rsa2048,
            SymmetricAlgorithm::Aes256Gcm,
        )
        .unwrap();

        let decrypted =
            hybrid_ordinary_decrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(&sk, &encrypted)
                .unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let (pk, sk) = RsaScheme::<Rsa2048>::generate_keypair().unwrap();
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];

        let encrypted = hybrid_ordinary_encrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(
            &pk,
            &plaintext,
            "test_kek_id".to_string(),
            AsymmetricAlgorithm::Rsa2048,
            SymmetricAlgorithm::Aes256Gcm,
        )
        .unwrap();

        let decrypted =
            hybrid_ordinary_decrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(&sk, &encrypted)
                .unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (pk, sk) = RsaScheme::<Rsa2048>::generate_keypair().unwrap();
        let plaintext = b"some important data";

        let mut encrypted = hybrid_ordinary_encrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(
            &pk,
            plaintext,
            "test_kek_id".to_string(),
            AsymmetricAlgorithm::Rsa2048,
            SymmetricAlgorithm::Aes256Gcm,
        )
        .unwrap();

        // Tamper with the ciphertext body
        if encrypted.len() > 300 {
            encrypted[300] ^= 1; // Tamper after the header
        }

        let result = hybrid_ordinary_decrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(&sk, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let (pk, _) = RsaScheme::<Rsa2048>::generate_keypair().unwrap();
        let (_, sk2) = RsaScheme::<Rsa2048>::generate_keypair().unwrap();
        let plaintext = b"some data";

        let encrypted = hybrid_ordinary_encrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(
            &pk,
            plaintext,
            "test_kek_id".to_string(),
            AsymmetricAlgorithm::Rsa2048,
            SymmetricAlgorithm::Aes256Gcm,
        )
        .unwrap();

        let result = hybrid_ordinary_decrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(&sk2, &encrypted);
        assert!(result.is_err());
    }
} 