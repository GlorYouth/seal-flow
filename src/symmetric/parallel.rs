use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::{Header, HeaderPayload, SealMode, StreamInfo};
use crate::error::{Error, Result};
use rand::{rngs::OsRng, TryRngCore};
use rayon::prelude::*;
use seal_crypto::traits::symmetric::{SymmetricCipher, SymmetricDecryptor, SymmetricEncryptor};

const DEFAULT_CHUNK_SIZE: u32 = 65536; // 64 KiB

/// Encrypts in-memory data using parallel processing.
pub fn encrypt<S>(
    key: &S::Key,
    plaintext: &[u8],
    key_id: String,
) -> Result<Vec<u8>>
where
    S: SymmetricAlgorithm,
    S::Key: Sync,
{
    // 1. Generate base_nonce, construct Header with chunk_size
    let mut base_nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut base_nonce)?;

    let header = Header {
        version: 1,
        mode: SealMode::Symmetric,
        payload: HeaderPayload::Symmetric {
            key_id,
            algorithm: S::ALGORITHM,
            stream_info: Some(StreamInfo {
                chunk_size: DEFAULT_CHUNK_SIZE,
                base_nonce,
            }),
        },
    };
    let header_bytes = header.encode_to_vec()?;

    // 2. Process chunks in parallel using Rayon
    let encrypted_chunks: Vec<Vec<u8>> = plaintext
        .par_chunks(DEFAULT_CHUNK_SIZE as usize)
        .enumerate()
        .map(|(i, chunk)| {
            // 3. Derive a deterministic nonce
            let mut nonce = base_nonce;
            let counter_bytes = (i as u64).to_le_bytes();
            for j in 0..8 {
                nonce[4 + j] ^= counter_bytes[j];
            }

            // 4. Encrypt the chunk
            S::Scheme::encrypt(key, &nonce, chunk, None)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    // 5. Assemble the final output
    let mut final_output = Vec::with_capacity(4 + header_bytes.len() + encrypted_chunks.iter().map(Vec::len).sum::<usize>());
    final_output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    final_output.extend_from_slice(&header_bytes);
    final_output.extend_from_slice(&encrypted_chunks.concat());

    Ok(final_output)
}

/// Decrypts in-memory data using parallel processing.
pub fn decrypt<S>(
    key: &S::Key,
    ciphertext: &[u8],
) -> Result<Vec<u8>>
where
    S: SymmetricAlgorithm,
    S::Key: Sync,
{
    // 1. Parse Header
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

    // 2. Extract stream info from Header
    let (chunk_size, base_nonce) = match header.payload {
        HeaderPayload::Symmetric {
            stream_info: Some(info),
            ..
        } => (info.chunk_size, info.base_nonce),
        _ => return Err(Error::InvalidHeader),
    };

    let tag_len = S::Scheme::TAG_SIZE;
    let encrypted_chunk_size = chunk_size as usize + tag_len;

    // 3. Decrypt in parallel
    let decrypted_chunks: Vec<Vec<u8>> = ciphertext_body
        .par_chunks(encrypted_chunk_size)
        .enumerate()
        .map(|(i, encrypted_chunk)| {
            // 4. Derive deterministic nonce
            let mut nonce = base_nonce;
            let counter_bytes = (i as u64).to_le_bytes();
            for j in 0..8 {
                nonce[4 + j] ^= counter_bytes[j];
            }

            // 5. Decrypt the chunk
            S::Scheme::decrypt(key, &nonce, encrypted_chunk, None)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(decrypted_chunks.concat())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::{definitions::Aes256Gcm, traits::SymmetricAlgorithm};
    use crate::error::Error as FlowError;
    use seal_crypto::errors::Error as CryptoError;
    use seal_crypto::traits::symmetric::SymmetricKeyGenerator;

    #[test]
    fn test_symmetric_parallel_roundtrip() {
        let key = <Aes256Gcm as SymmetricAlgorithm>::Scheme::generate_key().unwrap();
        let plaintext = b"This is a test message that is longer than one chunk to ensure the chunking logic works correctly. Let's add some more data to be sure.";

        let encrypted = encrypt::<Aes256Gcm>(
            &key,
            plaintext,
            "test_key_id".to_string(),
        )
        .unwrap();

        let decrypted = decrypt::<Aes256Gcm>(&key, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());

        // Tamper with the ciphertext body
        let header_len = u32::from_le_bytes(encrypted[0..4].try_into().unwrap()) as usize;
        let ciphertext_start_index = 4 + header_len;

        assert!(
            encrypted.len() > ciphertext_start_index,
            "Not enough data to tamper"
        );
        let mut encrypted = encrypted;
        encrypted[ciphertext_start_index] ^= 1;

        let result = decrypt::<Aes256Gcm>(&key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = <Aes256Gcm as SymmetricAlgorithm>::Scheme::generate_key().unwrap();
        let plaintext = b"";

        let encrypted = encrypt::<Aes256Gcm>(
            &key,
            plaintext,
            "test_key_id".to_string(),
        )
        .unwrap();

        let decrypted = decrypt::<Aes256Gcm>(&key, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let key = <Aes256Gcm as SymmetricAlgorithm>::Scheme::generate_key().unwrap();
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];

        let encrypted = encrypt::<Aes256Gcm>(
            &key,
            &plaintext,
            "test_key_id".to_string(),
        )
        .unwrap();

        let decrypted = decrypt::<Aes256Gcm>(&key, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = <Aes256Gcm as SymmetricAlgorithm>::Scheme::generate_key().unwrap();
        let key2 = <Aes256Gcm as SymmetricAlgorithm>::Scheme::generate_key().unwrap();
        let plaintext = b"some data";

        let encrypted = encrypt::<Aes256Gcm>(
            &key1,
            plaintext,
            "test_key_id_1".to_string(),
        )
        .unwrap();

        let result = decrypt::<Aes256Gcm>(&key2, &encrypted);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FlowError::Crypto(CryptoError::Symmetric(_))
        ));
    }
}

