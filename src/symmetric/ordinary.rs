//! Implements the ordinary (single-threaded, in-memory) symmetric encryption scheme.

use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::{Header, HeaderPayload, SealMode, StreamInfo};
use crate::error::{Error, Result};
use rand::{rngs::OsRng, TryRngCore};

const DEFAULT_CHUNK_SIZE: u32 = 65536; // 64 KiB

/// Derives a nonce for a specific chunk index.
fn derive_nonce(base_nonce: &[u8; 12], i: u64) -> [u8; 12] {
    let mut nonce_bytes = *base_nonce;
    let i_bytes = i.to_le_bytes(); // u64 -> 8 bytes, little-endian

    // XOR the chunk index into the last 8 bytes of the nonce
    for j in 0..8 {
        nonce_bytes[4 + j] ^= i_bytes[j];
    }

    nonce_bytes
}

/// Encrypts plaintext using a chunking mechanism.
pub fn encrypt<S: SymmetricAlgorithm>(
    key: &S::Key,
    plaintext: &[u8],
    key_id: String,
) -> Result<Vec<u8>>
where
    S::Key: Clone + Send + Sync,
{
    let mut base_nonce_bytes = [0u8; 12];
    OsRng.try_fill_bytes(&mut base_nonce_bytes)?;

    let header = Header {
        version: 1,
        mode: SealMode::Symmetric,
        payload: HeaderPayload::Symmetric {
            key_id,
            algorithm: S::ALGORITHM,
            stream_info: Some(StreamInfo {
                chunk_size: DEFAULT_CHUNK_SIZE,
                base_nonce: base_nonce_bytes,
            }),
        },
    };

    let header_bytes = header.encode_to_vec()?;

    let mut encrypted_body = Vec::with_capacity(
        plaintext.len() + (plaintext.len() / DEFAULT_CHUNK_SIZE as usize + 1) * S::TAG_SIZE,
    );

    for (i, chunk) in plaintext.chunks(DEFAULT_CHUNK_SIZE as usize).enumerate() {
        let nonce = derive_nonce(&base_nonce_bytes, i as u64);
        let encrypted_chunk = S::encrypt(&key.clone().into(), &nonce, chunk, None)?;
        encrypted_body.extend_from_slice(&encrypted_chunk);
    }

    let mut final_output = Vec::with_capacity(4 + header_bytes.len() + encrypted_body.len());
    final_output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    final_output.extend_from_slice(&header_bytes);
    final_output.extend_from_slice(&encrypted_body);

    Ok(final_output)
}

/// Decrypts ciphertext that was encrypted with the corresponding `encrypt` function.
pub fn decrypt<S: SymmetricAlgorithm>(key: &S::Key, ciphertext: &[u8]) -> Result<Vec<u8>>
where
    S::Key: Clone + Send + Sync,
{
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

    let (chunk_size, base_nonce_array) = match header.payload {
        HeaderPayload::Symmetric {
            stream_info: Some(info),
            ..
        } => (info.chunk_size, info.base_nonce),
        _ => return Err(Error::InvalidHeader),
    };

    let mut plaintext = Vec::with_capacity(ciphertext_body.len());
    let chunk_size_with_tag = chunk_size as usize + S::TAG_SIZE;
    let mut chunk_index = 0;

    let mut cursor = 0;
    while cursor < ciphertext_body.len() {
        let remaining_len = ciphertext_body.len() - cursor;
        let current_chunk_len = if remaining_len < chunk_size_with_tag {
            remaining_len
        } else {
            chunk_size_with_tag
        };

        if current_chunk_len == 0 {
            break;
        }

        let encrypted_chunk = &ciphertext_body[cursor..cursor + current_chunk_len];

        let nonce = derive_nonce(&base_nonce_array, chunk_index as u64);
        let decrypted_chunk = S::decrypt(&key.clone().into(), &nonce, encrypted_chunk, None)?;

        plaintext.extend_from_slice(&decrypted_chunk);

        cursor += current_chunk_len;
        chunk_index += 1;
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::prelude::SymmetricKeyGenerator;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;

    #[test]
    fn test_symmetric_ordinary_roundtrip() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"This is a test message that is longer than one chunk to ensure the chunking logic works correctly. Let's add some more data to be sure.";

        let encrypted = encrypt::<Aes256Gcm>(&key, plaintext, "test_key_id".to_string()).unwrap();
        let decrypted = decrypt::<Aes256Gcm>(&key, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"";

        let encrypted = encrypt::<Aes256Gcm>(&key, plaintext, "test_key_id".to_string()).unwrap();
        let decrypted = decrypt::<Aes256Gcm>(&key, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];

        let encrypted = encrypt::<Aes256Gcm>(&key, &plaintext, "test_key_id".to_string()).unwrap();
        let decrypted = decrypt::<Aes256Gcm>(&key, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some important data";

        let mut encrypted =
            encrypt::<Aes256Gcm>(&key, plaintext, "test_key_id".to_string()).unwrap();

        // Tamper with the ciphertext body
        if !encrypted.is_empty() {
            let len = encrypted.len();
            encrypted[len / 2] ^= 1;
        }

        let result = decrypt::<Aes256Gcm>(&key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = Aes256Gcm::generate_key().unwrap();
        let key2 = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some data";

        let encrypted =
            encrypt::<Aes256Gcm>(&key1, plaintext, "test_key_id_1".to_string()).unwrap();
        let result = decrypt::<Aes256Gcm>(&key2, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some data";

        let mut encrypted =
            encrypt::<Aes256Gcm>(&key, plaintext, "test_key_id".to_string()).unwrap();

        // Tamper with the nonce in the header
        if encrypted.len() > 20 {
            // Ensure there's a header to tamper with
            encrypted[20] ^= 1;
        }

        let result = decrypt::<Aes256Gcm>(&key, &encrypted);
        assert!(result.is_err());
    }
}
