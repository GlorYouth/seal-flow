//! Implements a parallel streaming hybrid encryption/decryption scheme.

use rayon::iter::ParallelIterator;
use rayon::iter::IndexedParallelIterator;
use rand::{rngs::OsRng, TryRngCore};
use rayon::prelude::*;
use crate::common::header::{Header, HeaderPayload, SealMode, StreamInfo};
use crate::error::{Result, Error, BincodeError};

use seal_crypto::traits::{
    kem::{SharedSecret, Kem},
    symmetric::{SymmetricCipher, SymmetricDecryptor, SymmetricEncryptor},
};
use crate::common::algorithms::{AsymmetricAlgorithm, SymmetricAlgorithm};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::thread;

const DEFAULT_CHUNK_SIZE: u32 = 65536; // 64 KiB
const CHANNEL_BOUND: usize = 16;

fn derive_nonce(base_nonce: &[u8; 12], i: u64) -> [u8; 12] {
    let mut nonce_bytes = *base_nonce;
    let i_bytes = i.to_le_bytes();
    for j in 0..8 {
        nonce_bytes[4 + j] ^= i_bytes[j];
    }
    nonce_bytes
}

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

pub fn encrypt<S, K, R, W>(
    public_key: &K::PublicKey,
    mut reader: R,
    mut writer: W,
    kek_id: String,
    kek_algorithm: AsymmetricAlgorithm,
    dek_algorithm: SymmetricAlgorithm,
) -> Result<()>
where
    S: SymmetricEncryptor<Key = SharedSecret> + SymmetricCipher + Sync,
    S::Key: Sync,
    K: Kem<EncapsulatedKey = Vec<u8>>,
    R: Read + Send,
    W: Write,
{
    let (shared_secret, encapsulated_key) = K::encapsulate(public_key)?;

    let mut base_nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut base_nonce)?;

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

    let header_bytes = header.encode_to_vec()?;
    writer.write_all(&(header_bytes.len() as u32).to_le_bytes()).map_err(Error::Io)?;
    writer.write_all(&header_bytes).map_err(Error::Io)?;

    let (raw_chunk_tx, raw_chunk_rx) = mpsc::sync_channel::<(u64, Vec<u8>)>(CHANNEL_BOUND);
    let (enc_chunk_tx, enc_chunk_rx) = mpsc::sync_channel::<(u64, Result<Vec<u8>>)>(CHANNEL_BOUND);
    let (io_error_tx, io_error_rx) = mpsc::channel::<std::io::Error>();

    thread::scope(|s| {
        s.spawn(move || {
            let mut chunk_index = 0u64;
            loop {
                let mut chunk = vec![0; DEFAULT_CHUNK_SIZE as usize];
                let mut bytes_read = 0;
                while bytes_read < chunk.len() {
                    match reader.read(&mut chunk[bytes_read..]) {
                        Ok(0) => break,
                        Ok(n) => bytes_read += n,
                        Err(e) => {
                            let _ = io_error_tx.send(e);
                            return;
                        }
                    }
                }
                if bytes_read > 0 {
                    chunk.truncate(bytes_read);
                    if raw_chunk_tx.send((chunk_index, chunk)).is_err() {
                        break;
                    }
                    chunk_index += 1;
                }
                if bytes_read < DEFAULT_CHUNK_SIZE as usize {
                    break;
                }
            }
        });

        let enc_chunk_tx_clone = enc_chunk_tx.clone();
        s.spawn(move || {
            let chunks: Vec<_> = raw_chunk_rx.into_iter().collect();
            chunks
                .into_par_iter()
                .for_each(|(index, chunk)| {
                    let nonce = derive_nonce(&base_nonce, index);
                    let encrypted = S::encrypt(&shared_secret, &nonce, &chunk, None).map_err(Error::from);
                    if enc_chunk_tx_clone.send((index, encrypted)).is_err() {
                        return;
                    }
                });
        });

        let mut next_chunk_to_write = 0u64;
        let mut out_of_order_buffer = BTreeMap::new();
        drop(enc_chunk_tx);

        loop {
            if let Ok(io_err) = io_error_rx.try_recv() {
                return Err(Error::Io(io_err));
            }
            match enc_chunk_rx.recv() {
                Ok((index, encrypted_result)) => {
                    let encrypted_chunk = encrypted_result?;
                    out_of_order_buffer.insert(index, encrypted_chunk);
                    while let Some(chunk_to_write) = out_of_order_buffer.remove(&next_chunk_to_write) {
                        writer.write_all(&chunk_to_write).map_err(Error::Io)?;
                        next_chunk_to_write += 1;
                    }
                }
                Err(_) => break,
            }
        }
        while let Some(chunk_to_write) = out_of_order_buffer.remove(&next_chunk_to_write) {
            writer.write_all(&chunk_to_write).map_err(Error::Io)?;
            next_chunk_to_write += 1;
        }
        Ok(())
    })
}

pub fn decrypt<S, K, R, W>(
    private_key: &K::PrivateKey,
    mut reader: R,
    mut writer: W,
) -> Result<()>
where
    S: SymmetricDecryptor<Key = SharedSecret> + SymmetricCipher + Sync,
    S::Key: Sync,
    K: Kem,
    <K as Kem>::EncapsulatedKey: From<Vec<u8>>,
    R: Read + Send,
    W: Write,
{
    let mut header_len_bytes = [0u8; 4];
    reader.read_exact(&mut header_len_bytes).map_err(Error::Io)?;
    let header_len = u32::from_le_bytes(header_len_bytes);

    let mut header_bytes = vec![0; header_len as usize];
    reader.read_exact(&mut header_bytes).map_err(Error::Io)?;
    let (header, _) = Header::decode_from_slice(&header_bytes).map_err(Error::from)?;

    let (chunk_size, base_nonce, encapsulated_key) = match header.payload {
        HeaderPayload::Hybrid {
            stream_info: Some(info),
            encrypted_dek,
            ..
        } => (info.chunk_size, info.base_nonce, encrypted_dek.into()),
        _ => return Err(Error::InvalidHeader),
    };

    let shared_secret = K::decapsulate(private_key, &encapsulated_key)?;

    let encrypted_chunk_size = (chunk_size as usize) + S::TAG_SIZE;

    let (enc_chunk_tx, enc_chunk_rx) = mpsc::sync_channel::<(u64, Vec<u8>)>(CHANNEL_BOUND);
    let (dec_chunk_tx, dec_chunk_rx) = mpsc::sync_channel::<(u64, Result<Vec<u8>>)>(CHANNEL_BOUND);
    let (io_error_tx, io_error_rx) = mpsc::channel::<std::io::Error>();

    thread::scope(|s| {
        s.spawn(move || {
            let mut chunk_index = 0u64;
            loop {
                let mut chunk = vec![0; encrypted_chunk_size];
                let mut bytes_read = 0;
                while bytes_read < chunk.len() {
                    match reader.read(&mut chunk[bytes_read..]) {
                        Ok(0) => break,
                        Ok(n) => bytes_read += n,
                        Err(e) => {
                            let _ = io_error_tx.send(e);
                            return;
                        }
                    }
                }
                if bytes_read > 0 {
                    chunk.truncate(bytes_read);
                    if enc_chunk_tx.send((chunk_index, chunk)).is_err() {
                        break;
                    }
                    chunk_index += 1;
                }
                if bytes_read < encrypted_chunk_size {
                    break;
                }
            }
        });

        let dec_chunk_tx_clone = dec_chunk_tx.clone();
        s.spawn(move || {
            let chunks: Vec<_> = enc_chunk_rx.into_iter().collect();
            chunks
                .into_par_iter()
                .for_each(|(index, chunk)| {
                    let nonce = derive_nonce(&base_nonce, index);
                    let decrypted = S::decrypt(&shared_secret, &nonce, &chunk, None).map_err(Error::from);
                    if dec_chunk_tx_clone.send((index, decrypted)).is_err() {
                        return;
                    }
                });
        });

        let mut next_chunk_to_write = 0u64;
        let mut out_of_order_buffer = BTreeMap::new();
        drop(dec_chunk_tx);

        loop {
            if let Ok(io_err) = io_error_rx.try_recv() {
                return Err(Error::Io(io_err));
            }
            match dec_chunk_rx.recv() {
                Ok((index, decrypted_result)) => {
                    let decrypted_chunk = decrypted_result?;
                    out_of_order_buffer.insert(index, decrypted_chunk);
                    while let Some(chunk_to_write) = out_of_order_buffer.remove(&next_chunk_to_write) {
                        writer.write_all(&chunk_to_write).map_err(Error::Io)?;
                        next_chunk_to_write += 1;
                    }
                }
                Err(_) => break,
            }
        }
        
        while let Some(chunk_to_write) = out_of_order_buffer.remove(&next_chunk_to_write) {
            writer.write_all(&chunk_to_write).map_err(Error::Io)?;
            next_chunk_to_write += 1;
        }

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::{
        systems::{
            asymmetric::rsa::{Rsa2048, RsaScheme},
            symmetric::aes_gcm::{Aes256, AesGcmScheme},
        },
        traits::key::KeyGenerator,
    };
    use std::io::Cursor;

    fn get_test_data(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 256) as u8).collect()
    }

    #[test]
    fn test_hybrid_parallel_streaming_roundtrip() {
        let (pk, sk) = RsaScheme::<Rsa2048>::generate_keypair().unwrap();
        let plaintext = get_test_data(DEFAULT_CHUNK_SIZE as usize * 3 + 100);
        let mut source = Cursor::new(&plaintext);
        let mut encrypted_dest = Vec::new();

        encrypt::<AesGcmScheme<Aes256>, RsaScheme<Rsa2048>, _, _>(
            &pk,
            &mut source,
            &mut encrypted_dest,
            "test_kek_id".to_string(),
            AsymmetricAlgorithm::Rsa2048,
            SymmetricAlgorithm::Aes256Gcm,
        )
        .unwrap();

        let mut encrypted_source = Cursor::new(&encrypted_dest);
        let mut decrypted_dest = Vec::new();
        decrypt::<AesGcmScheme<Aes256>, RsaScheme<Rsa2048>, _, _>(
            &sk,
            &mut encrypted_source,
            &mut decrypted_dest,
        )
        .unwrap();

        assert_eq!(plaintext, decrypted_dest);
    }

    #[test]
    fn test_empty_input() {
        let (pk, sk) = RsaScheme::<Rsa2048>::generate_keypair().unwrap();
        let plaintext: Vec<u8> = Vec::new();
        let mut source = Cursor::new(&plaintext);
        let mut encrypted_dest = Vec::new();

        encrypt::<AesGcmScheme<Aes256>, RsaScheme<Rsa2048>, _, _>(
            &pk,
            &mut source,
            &mut encrypted_dest,
            "test_kek_id".to_string(),
            AsymmetricAlgorithm::Rsa2048,
            SymmetricAlgorithm::Aes256Gcm,
        )
        .unwrap();

        let mut encrypted_source = Cursor::new(&encrypted_dest);
        let mut decrypted_dest = Vec::new();
        decrypt::<AesGcmScheme<Aes256>, RsaScheme<Rsa2048>, _, _>(
            &sk,
            &mut encrypted_source,
            &mut decrypted_dest,
        )
        .unwrap();

        assert_eq!(plaintext, decrypted_dest);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (pk, sk) = RsaScheme::<Rsa2048>::generate_keypair().unwrap();
        let plaintext = b"some important data";
        let mut source = Cursor::new(plaintext);
        let mut encrypted_dest = Vec::new();

        encrypt::<AesGcmScheme<Aes256>, RsaScheme<Rsa2048>, _, _>(
            &pk,
            &mut source,
            &mut encrypted_dest,
            "test_kek_id".to_string(),
            AsymmetricAlgorithm::Rsa2048,
            SymmetricAlgorithm::Aes256Gcm,
        )
        .unwrap();

        // Tamper with the ciphertext body
        if encrypted_dest.len() > 100 { // Tamper after the header
            encrypted_dest[100] ^= 1;
        }

        let mut encrypted_source = Cursor::new(&encrypted_dest);
        let mut decrypted_dest = Vec::new();
        let result = decrypt::<AesGcmScheme<Aes256>, RsaScheme<Rsa2048>, _, _>(
            &sk,
            &mut encrypted_source,
            &mut decrypted_dest,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let (pk1, _) = RsaScheme::<Rsa2048>::generate_keypair().unwrap();
        let (_, sk2) = RsaScheme::<Rsa2048>::generate_keypair().unwrap();
        let plaintext = b"some data";
        let mut source = Cursor::new(plaintext);
        let mut encrypted_dest = Vec::new();

        encrypt::<AesGcmScheme<Aes256>, RsaScheme<Rsa2048>, _, _>(
            &pk1,
            &mut source,
            &mut encrypted_dest,
            "test_kek_id".to_string(),
            AsymmetricAlgorithm::Rsa2048,
            SymmetricAlgorithm::Aes256Gcm,
        )
        .unwrap();
        
        let mut encrypted_source = Cursor::new(&encrypted_dest);
        let mut decrypted_dest = Vec::new();
        let result = decrypt::<AesGcmScheme<Aes256>, RsaScheme<Rsa2048>, _, _>(
            &sk2,
            &mut encrypted_source,
            &mut decrypted_dest,
        );
        assert!(result.is_err());
    }
}