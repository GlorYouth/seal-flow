use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::header::{Header, HeaderPayload, SealMode, StreamInfo};
use crate::error::{Error, Result};
use rand::{rngs::OsRng, TryRngCore};
use rayon::prelude::*;
use seal_crypto::prelude::*;
use seal_crypto::zeroize::Zeroizing;

const DEFAULT_CHUNK_SIZE: u32 = 65536; // 64 KiB

/// Performs parallel, in-memory hybrid encryption.
pub fn encrypt<A, S>(
    pk: &<A::Scheme as Algorithm>::PublicKey,
    plaintext: &[u8],
    kek_id: String,
) -> Result<Vec<u8>>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    Vec<u8>: From<<<A as AsymmetricAlgorithm>::Scheme as Kem>::EncapsulatedKey>,
    <S::Scheme as SymmetricKeyGenerator>::Key: From<Zeroizing<Vec<u8>>> + Sync,
{
    // 1. KEM Encapsulate: Generate DEK and wrap it with the public key.
    let (shared_secret, encapsulated_key) = A::Scheme::encapsulate(pk)?;

    // 2. Generate a base_nonce for deterministic nonce derivation.
    let mut base_nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut base_nonce)?;

    // 3. Construct the header.
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

    // 5. Encrypt data chunks in parallel using Rayon.
    let encrypted_chunks: Vec<Vec<u8>> = plaintext
        .par_chunks(DEFAULT_CHUNK_SIZE as usize)
        .enumerate()
        .map(|(i, chunk)| {
            let mut nonce = base_nonce;
            let counter_bytes = (i as u64).to_le_bytes();
            for j in 0..8 {
                nonce[4 + j] ^= counter_bytes[j];
            }
            S::Scheme::encrypt(&shared_secret.clone().into(), &nonce, chunk, None)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    // 6. Assemble the final output.
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

/// Performs parallel, in-memory hybrid decryption.
pub fn decrypt<A, S>(
    sk: &<A::Scheme as Algorithm>::PrivateKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    <A::Scheme as Kem>::EncapsulatedKey: From<Vec<u8>>,
    <S::Scheme as SymmetricKeyGenerator>::Key: From<Zeroizing<Vec<u8>>> + Sync,
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

    // 2. Extract info and encapsulated key from the header.
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

    // 4. Decrypt data chunks in parallel using Rayon.
    let decrypted_chunks: Vec<Vec<u8>> = ciphertext_body
        .par_chunks(encrypted_chunk_size)
        .enumerate()
        .map(|(i, encrypted_chunk)| {
            let mut nonce = base_nonce;
            let counter_bytes = (i as u64).to_le_bytes();
            for j in 0..8 {
                nonce[4 + j] ^= counter_bytes[j];
            }
            S::Scheme::decrypt(&shared_secret.clone().into(), &nonce, encrypted_chunk, None)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(decrypted_chunks.concat())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::definitions::{Aes256Gcm, Rsa2048};
    use crate::algorithms::traits::AsymmetricAlgorithm;

    #[test]
    fn test_hybrid_parallel_roundtrip() {
        let (pk, sk) = <Rsa2048 as AsymmetricAlgorithm>::Scheme::generate_keypair().unwrap();
        let plaintext = b"This is a test message for hybrid parallel encryption, which should be long enough to span multiple chunks to properly test the implementation.";

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

        if encrypted.len() > 300 {
            encrypted[300] ^= 1;
        }

        let result = decrypt::<Rsa2048, Aes256Gcm>(&sk, &encrypted);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Crypto(_)));
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
