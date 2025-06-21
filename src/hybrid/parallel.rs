use rayon::iter::ParallelIterator;
use rayon::iter::IndexedParallelIterator;
use rand::{rngs::OsRng, TryRngCore};
use rayon::prelude::ParallelSlice;
use crate::common::header::{Header, HeaderPayload, SealMode, StreamInfo};
use crate::error::{Result, Error, BincodeError};

use seal_crypto::traits::{
    kem::{SharedSecret, Kem},
    symmetric::{SymmetricCipher, SymmetricDecryptor, SymmetricEncryptor},
};
use crate::common::algorithms::{AsymmetricAlgorithm, SymmetricAlgorithm};

const DEFAULT_CHUNK_SIZE: u32 = 65536; // 64 KiB

/// 使用并行的、基于块的策略对内存中的数据执行混合加密。
pub fn hybrid_parallel_encrypt<K, S>(
    pk: &K::PublicKey,
    plaintext: &[u8],
    // 元数据
    kek_id: String,
    kek_algorithm: AsymmetricAlgorithm,
    dek_algorithm: SymmetricAlgorithm,
) -> Result<Vec<u8>>
where
    K: Kem<EncapsulatedKey = Vec<u8>>,
    S: SymmetricEncryptor<Key = SharedSecret> + SymmetricCipher + Sync,
    S::Key: Sync,
{
    // 1. KEM 封装：生成DEK并用公钥包裹
    let (shared_secret, encapsulated_key) = K::encapsulate(pk)?;

    // 2. 为每个块的确定性 Nonce 派生生成一个 base_nonce
    let mut base_nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut base_nonce)?;

    // 3. 构建包含 stream_info 的 Header
    let header = Header {
        version: 1,
        mode: SealMode::Hybrid,
        payload: HeaderPayload::Hybrid {
            kek_id,
            kek_algorithm,
            dek_algorithm,
            encrypted_dek: encapsulated_key,
            stream_info: Some(StreamInfo { // 已更改：现在包含流信息
                chunk_size: DEFAULT_CHUNK_SIZE,
                base_nonce,
            }),
        },
    };

    // 4. 序列化 Header
    let header_bytes = header.encode_to_vec()?;

    // 5. 使用 Rayon 并行加密数据块
    let encrypted_chunks: Vec<Vec<u8>> = plaintext
        .par_chunks(DEFAULT_CHUNK_SIZE as usize)
        .enumerate()
        .map(|(i, chunk)| {
            // 6. 为此块派生确定性 Nonce
            let mut nonce = base_nonce;
            let counter_bytes = (i as u64).to_le_bytes();
            for j in 0..8 {
                nonce[4 + j] ^= counter_bytes[j];
            }

            // 7. 使用派生的 DEK 加密块
            S::encrypt(&shared_secret, &nonce, chunk, None)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    // 8. 组装最终输出
    let mut final_output = Vec::with_capacity(
        4 + header_bytes.len()
            + encrypted_chunks
                .iter()
                .map(Vec::len)
                .sum::<usize>(),
    );
    final_output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    final_output.extend_from_slice(&header_bytes);
    final_output.extend_from_slice(&encrypted_chunks.concat());

    Ok(final_output)
}

/// 使用并行的、基于块的策略对内存中的数据执行混合解密。
pub fn hybrid_parallel_decrypt<K, S>(
    sk: &K::PrivateKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>>
where
    K: Kem,
    S: SymmetricDecryptor<Key = SharedSecret> + SymmetricCipher + Sync,
    <K as Kem>::EncapsulatedKey: From<Vec<u8>>,
    S::Key: Sync,
{
    // 1. 解析头部
    if ciphertext.len() < 4 {
        return Err(Error::InvalidCiphertextFormat);
    }
    let header_len = u32::from_le_bytes(ciphertext[0..4].try_into().unwrap()) as usize;
    if ciphertext.len() < 4 + header_len {
        return Err(Error::InvalidCiphertextFormat);
    }
    let header_bytes = &ciphertext[4..4 + header_len];
    let ciphertext_body = &ciphertext[4 + header_len..];

    let (header, _) = Header::decode_from_slice(header_bytes).map_err(BincodeError::from)?;

    // 2. 从 Header 提取元数据和加密的 DEK
    let (encapsulated_key, chunk_size, base_nonce) = match header.payload {
        HeaderPayload::Hybrid {
            encrypted_dek,
            stream_info: Some(info),
            ..
        } => (encrypted_dek.into(), info.chunk_size, info.base_nonce),
        _ => return Err(Error::InvalidHeader), // 现在需要 stream_info
    };

    // 3. KEM 解封装，恢复 DEK
    let shared_secret = K::decapsulate(sk, &encapsulated_key)?;

    let tag_len = S::TAG_SIZE;
    let encrypted_chunk_size = chunk_size as usize + tag_len;

    // 4. 使用 Rayon 并行解密数据块
    let decrypted_chunks: Vec<Vec<u8>> = ciphertext_body
        .par_chunks(encrypted_chunk_size)
        .enumerate()
        .map(|(i, encrypted_chunk)| {
            // 5. 为此块派生确定性 Nonce
            let mut nonce = base_nonce;
            let counter_bytes = (i as u64).to_le_bytes();
            for j in 0..8 {
                nonce[4 + j] ^= counter_bytes[j];
            }

            // 6. 使用恢复的 DEK 解密块
            S::decrypt(&shared_secret, &nonce, encrypted_chunk, None)
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Error::from)?;

    Ok(decrypted_chunks.concat())
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::prelude::*;
    use seal_crypto::systems::{
        asymmetric::rsa::{Rsa2048, RsaScheme},
        symmetric::aes_gcm::{Aes256, AesGcmScheme},
    };

    #[test]
    fn test_hybrid_parallel_roundtrip() {
        let (pk, sk) = RsaScheme::<Rsa2048>::generate_keypair().unwrap();
        let plaintext = b"This is a test message for hybrid parallel encryption, which should be long enough to span multiple chunks to properly test the implementation.";

        let encrypted = hybrid_parallel_encrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(
            &pk,
            plaintext,
            "test_kek_id".to_string(),
            AsymmetricAlgorithm::Rsa2048,
            SymmetricAlgorithm::Aes256Gcm,
        )
        .unwrap();

        let decrypted =
            hybrid_parallel_decrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(&sk, &encrypted)
                .unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_empty_plaintext() {
        let (pk, sk) = RsaScheme::<Rsa2048>::generate_keypair().unwrap();
        let plaintext = b"";

        let encrypted = hybrid_parallel_encrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(
            &pk,
            plaintext,
            "test_kek_id".to_string(),
            AsymmetricAlgorithm::Rsa2048,
            SymmetricAlgorithm::Aes256Gcm,
        )
        .unwrap();

        let decrypted =
            hybrid_parallel_decrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(&sk, &encrypted)
                .unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_exact_chunk_size() {
        let (pk, sk) = RsaScheme::<Rsa2048>::generate_keypair().unwrap();
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];

        let encrypted = hybrid_parallel_encrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(
            &pk,
            &plaintext,
            "test_kek_id".to_string(),
            AsymmetricAlgorithm::Rsa2048,
            SymmetricAlgorithm::Aes256Gcm,
        )
        .unwrap();

        let decrypted =
            hybrid_parallel_decrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(&sk, &encrypted)
                .unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (pk, sk) = RsaScheme::<Rsa2048>::generate_keypair().unwrap();
        let plaintext = b"some important data";

        let mut encrypted = hybrid_parallel_encrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(
            &pk,
            plaintext,
            "test_kek_id".to_string(),
            AsymmetricAlgorithm::Rsa2048,
            SymmetricAlgorithm::Aes256Gcm,
        )
        .unwrap();

        if encrypted.len() > 300 {
            encrypted[300] ^= 1;
        }

        let result = hybrid_parallel_decrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(&sk, &encrypted);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Crypto(_)));
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let (pk, _) = RsaScheme::<Rsa2048>::generate_keypair().unwrap();
        let (_, sk2) = RsaScheme::<Rsa2048>::generate_keypair().unwrap();
        let plaintext = b"some data";

        let encrypted = hybrid_parallel_encrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(
            &pk,
            plaintext,
            "test_kek_id".to_string(),
            AsymmetricAlgorithm::Rsa2048,
            SymmetricAlgorithm::Aes256Gcm,
        )
        .unwrap();

        let result = hybrid_parallel_decrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(&sk2, &encrypted);
        assert!(result.is_err());
    }
}