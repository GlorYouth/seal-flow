use crate::common::algorithms::SymmetricAlgorithm;
use crate::common::header::{Header, HeaderPayload, SealMode, StreamInfo};
use crate::error::{Error, Result};
use rand::{rngs::OsRng, TryRngCore};
use rayon::prelude::*;
use seal_crypto::{
    traits::symmetric::{SymmetricCipher, SymmetricDecryptor, SymmetricEncryptor},
};

const DEFAULT_CHUNK_SIZE: u32 = 65536; // 64 KiB

/// 对内存中的数据执行并行对称加密。
pub fn symmetric_parallel_encrypt<S>(
    key: &S::Key,
    plaintext: &[u8],
    key_id: String,
    algorithm: SymmetricAlgorithm,
) -> Result<Vec<u8>>
where
    S: SymmetricEncryptor + SymmetricCipher + Sync,
    S::Key: Sync + Clone,
{
    // 1. 生成 base_nonce, 构建包含 chunk_size 的 Header
    let mut base_nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut base_nonce)?;

    let header = Header {
        version: 1,
        mode: SealMode::Symmetric,
        payload: HeaderPayload::Symmetric {
            key_id,
            algorithm,
            stream_info: Some(StreamInfo {
                chunk_size: DEFAULT_CHUNK_SIZE,
                base_nonce,
            }),
        },
    };
    let header_bytes = header.encode_to_vec()?;

    // 2. 使用 Rayon 并行处理
    let encrypted_chunks: Vec<Vec<u8>> = plaintext
        .par_chunks(DEFAULT_CHUNK_SIZE as usize)
        .enumerate()
        .map(|(i, chunk)| {
            // 3. 派生确定性 Nonce
            let mut nonce = base_nonce;
            let counter_bytes = (i as u64).to_le_bytes();
            for j in 0..8 {
                nonce[4 + j] ^= counter_bytes[j];
            }

            // 4. 加密块
            S::encrypt(key, &nonce, chunk, None)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    // 5. 组装最终输出
    let mut final_output = Vec::with_capacity(4 + header_bytes.len() + encrypted_chunks.iter().map(Vec::len).sum::<usize>());
    final_output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    final_output.extend_from_slice(&header_bytes);
    final_output.extend_from_slice(&encrypted_chunks.concat());

    Ok(final_output)
}

/// 对内存中的数据执行并行对称解密。
pub fn symmetric_parallel_decrypt<S>(
    key: &S::Key,
    ciphertext: &[u8],
) -> Result<Vec<u8>>
where
    S: SymmetricDecryptor + SymmetricCipher + Sync,
    S::Key: Sync,
{
    // 1. 解析 Header
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

    // 2. 从 Header 提取流信息
    let (chunk_size, base_nonce) = match header.payload {
        HeaderPayload::Symmetric {
            stream_info: Some(info),
            ..
        } => (info.chunk_size, info.base_nonce),
        _ => return Err(Error::InvalidHeader),
    };

    let tag_len = S::TAG_SIZE;
    let encrypted_chunk_size = chunk_size as usize + tag_len;

    // 3. 并行解密
    let decrypted_chunks: Vec<Vec<u8>> = ciphertext_body
        .par_chunks(encrypted_chunk_size)
        .enumerate()
        .map(|(i, encrypted_chunk)| {
            // 4. 派生确定性 Nonce
            let mut nonce = base_nonce;
            let counter_bytes = (i as u64).to_le_bytes();
            for j in 0..8 {
                nonce[4 + j] ^= counter_bytes[j];
            }

            // 5. 解密块
            S::decrypt(key, &nonce, encrypted_chunk, None)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(decrypted_chunks.concat())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::algorithms::SymmetricAlgorithm;
    use crate::error::Error as FlowError;
    use seal_crypto::errors::Error as CryptoError;
    use seal_crypto::{
        systems::symmetric::aes_gcm::{Aes256, AesGcmScheme},
        traits::symmetric::SymmetricKeyGenerator,
    };

    #[test]
    fn test_symmetric_parallel_roundtrip() {
        let key = AesGcmScheme::<Aes256>::generate_key().unwrap();
        let plaintext = b"This is a test message that is longer than one chunk to ensure the chunking logic works correctly. Let's add some more data to be sure.";

        let encrypted = symmetric_parallel_encrypt::<AesGcmScheme<Aes256>>(
            &key,
            plaintext,
            "test_key_id".to_string(),
            SymmetricAlgorithm::Aes256Gcm,
        )
        .unwrap();

        let decrypted = symmetric_parallel_decrypt::<AesGcmScheme<Aes256>>(&key, &encrypted).unwrap();

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

        let result = symmetric_parallel_decrypt::<AesGcmScheme<Aes256>>(&key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = AesGcmScheme::<Aes256>::generate_key().unwrap();
        let plaintext = b"";

        let encrypted = symmetric_parallel_encrypt::<AesGcmScheme<Aes256>>(
            &key,
            plaintext,
            "test_key_id".to_string(),
            SymmetricAlgorithm::Aes256Gcm,
        )
        .unwrap();

        let decrypted = symmetric_parallel_decrypt::<AesGcmScheme<Aes256>>(&key, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let key = AesGcmScheme::<Aes256>::generate_key().unwrap();
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];

        let encrypted = symmetric_parallel_encrypt::<AesGcmScheme<Aes256>>(
            &key,
            &plaintext,
            "test_key_id".to_string(),
            SymmetricAlgorithm::Aes256Gcm,
        )
        .unwrap();

        let decrypted = symmetric_parallel_decrypt::<AesGcmScheme<Aes256>>(&key, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = AesGcmScheme::<Aes256>::generate_key().unwrap();
        let key2 = AesGcmScheme::<Aes256>::generate_key().unwrap();
        let plaintext = b"some data";

        let encrypted = symmetric_parallel_encrypt::<AesGcmScheme<Aes256>>(
            &key1,
            plaintext,
            "test_key_id_1".to_string(),
            SymmetricAlgorithm::Aes256Gcm,
        )
        .unwrap();

        let result = symmetric_parallel_decrypt::<AesGcmScheme<Aes256>>(&key2, &encrypted);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FlowError::Crypto(CryptoError::Symmetric(_))
        ));
    }
}

