//! Implements an asynchronous streaming symmetric encryption/decryption scheme.
//! This mode is designed for high-performance processing of large files or data streams
//! by overlapping asynchronous I/O with parallel computation.
//!
//! 实现异步流式对称加解密方案。
//! 此模式通过将异步 I/O 与并行计算重叠，专为高性能处理大文件或数据流而设计。

#![cfg(feature = "async")]

use crate::body::config::BodyDecryptConfig;
use crate::body::traits::AsynchronousBodyProcessor;
use crate::common::config::{ArcConfig, DecryptorConfig};
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, FormatError, Result};
use crate::keys::TypedSymmetricKey;
use crate::symmetric::config::SymmetricConfig;
use crate::symmetric::pending::PendingDecryptor;
use crate::symmetric::traits::{
    SymmetricAsynchronousPendingDecryptor, SymmetricAsynchronousProcessor,
};
use async_trait::async_trait;
use std::borrow::Cow;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

#[async_trait]
impl<'decr> SymmetricAsynchronousPendingDecryptor<'decr>
    for PendingDecryptor<Box<dyn AsyncRead + Unpin + Send + 'decr>>
{
    async fn into_decryptor<'a>(
        self: Box<Self>,
        key: &'a TypedSymmetricKey,
        aad: Option<Vec<u8>>,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin + 'decr>> {
        let HeaderPayload {
            base_nonce,
            chunk_size,
            ..
        } = self.header.payload;

        let config = BodyDecryptConfig {
            key: Cow::Owned(key.clone()),
            nonce: base_nonce,
            aad,
            config: DecryptorConfig {
                chunk_size,
                arc_config: self.config,
            },
        };

        self.algorithm.decrypt_body_async(self.source, config)
    }

    fn header(&self) -> &Header {
        &self.header
    }
}

pub struct Asynchronous;

impl Asynchronous {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl SymmetricAsynchronousProcessor for Asynchronous {
    async fn encrypt_symmetric_async<'a>(
        &self,
        mut writer: Box<dyn AsyncWrite + Send + Unpin + 'a>,
        config: SymmetricConfig<'a>,
    ) -> Result<Box<dyn AsyncWrite + Send + Unpin + 'a>> {
        let algo = config.algorithm.clone();
        let (config, header_bytes) = config.into_body_config_and_header()?;
        writer
            .write_all(&(header_bytes.len() as u32).to_le_bytes())
            .await?;
        writer.write_all(&header_bytes).await?;
        algo.as_ref().encrypt_body_async(writer, config)
    }

    async fn begin_decrypt_symmetric_async<'a>(
        &self,
        mut reader: Box<dyn tokio::io::AsyncRead + Send + Unpin + 'a>,
        config: ArcConfig,
    ) -> Result<Box<dyn SymmetricAsynchronousPendingDecryptor<'a> + Send + 'a>> {
        let header = Header::decode_from_prefixed_async_reader(&mut reader).await?;
        if !header.is_symmetric() {
            return Err(Error::Format(FormatError::InvalidHeader));
        }
        let algorithm = header
            .payload
            .symmetric_algorithm()
            .into_symmetric_wrapper();
        let pending = PendingDecryptor {
            source: reader,
            header,
            algorithm,
            config,
        };
        Ok(Box::new(pending))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::DEFAULT_CHUNK_SIZE;
    use crate::{
        algorithms::symmetric::SymmetricAlgorithmWrapper, prelude::SymmetricAlgorithmEnum,
    };
    use std::io::Cursor;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn get_wrapper() -> SymmetricAlgorithmWrapper {
        SymmetricAlgorithmEnum::Aes256Gcm.into_symmetric_wrapper()
    }

    async fn test_roundtrip(plaintext: &[u8], aad: Option<Vec<u8>>) {
        let wrapper = get_wrapper();
        let processor = Asynchronous::new();
        let key_id = "test_key_id".to_string();
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        // Encrypt
        let mut encrypted_data = Vec::new();
        {
            let mut encryptor = processor
                .encrypt_symmetric_async(
                    Box::new(&mut encrypted_data),
                    SymmetricConfig {
                        algorithm: Cow::Borrowed(&wrapper),
                        key_id: key_id.clone(),
                        config: config.clone(),
                        key: Cow::Owned(key.clone()),
                        aad: aad.clone(),
                    },
                )
                .await
                .unwrap();
            encryptor.write_all(plaintext).await.unwrap();
            encryptor.shutdown().await.unwrap();
        }

        // Decrypt
        let mut decryptor = processor
            .begin_decrypt_symmetric_async(Box::new(Cursor::new(encrypted_data)), config.clone())
            .await
            .unwrap()
            .into_decryptor(&key, aad)
            .await
            .unwrap();
        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).await.unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[tokio::test]
    async fn test_processor_roundtrip_async() {
        let wrapper = get_wrapper();
        let processor = Asynchronous::new();
        let plaintext = b"This is an async processor test.";
        let untyped = wrapper.generate_typed_key().unwrap();
        let aad = Some(b"async processor aad".to_vec());
        let config = ArcConfig::default();
        // Encrypt
        let mut encrypted_data = Vec::new();
        {
            let mut encrypt_stream = processor
                .encrypt_symmetric_async(
                    Box::new(&mut encrypted_data),
                    SymmetricConfig {
                        algorithm: Cow::Borrowed(&wrapper),
                        key_id: "proc_key".to_string(),
                        config: config.clone(),
                        key: Cow::Borrowed(&untyped),
                        aad: aad.clone(),
                    },
                )
                .await
                .unwrap();
            encrypt_stream.write_all(plaintext).await.unwrap();
            encrypt_stream.shutdown().await.unwrap();
        }

        // Decrypt
        let pending_decryptor = processor
            .begin_decrypt_symmetric_async(Box::new(Cursor::new(&encrypted_data)), config.clone())
            .await
            .unwrap();

        assert_eq!(
            pending_decryptor.header().payload.key_id(),
            Some("proc_key")
        );

        let mut decrypt_stream = pending_decryptor
            .into_decryptor(&untyped, aad)
            .await
            .unwrap();
        let mut decrypted_data = Vec::new();
        decrypt_stream
            .read_to_end(&mut decrypted_data)
            .await
            .unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[tokio::test]
    async fn test_roundtrip_long_message_async() {
        let plaintext = b"This is a very long test message to test the async streaming encryption and decryption. It should be longer than a single chunk to ensure that the chunking logic is working correctly. Let's add more data to make sure it spans multiple chunks. Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        test_roundtrip(plaintext, None).await;
    }

    #[tokio::test]
    async fn test_roundtrip_empty_message_async() {
        test_roundtrip(b"", None).await;
    }

    #[tokio::test]
    async fn test_roundtrip_exact_chunk_size_async() {
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];
        test_roundtrip(&plaintext, None).await;
    }

    #[tokio::test]
    async fn test_aad_roundtrip_async() {
        let plaintext = b"secret async message";
        let aad = Some(b"public async context".to_vec());
        test_roundtrip(plaintext, aad).await;
    }

    #[tokio::test]
    async fn test_tampered_ciphertext_fails_async() {
        let wrapper = get_wrapper();
        let processor = Asynchronous::new();
        let plaintext = b"some important data";
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        let mut encrypted_data = Vec::new();
        {
            let mut encryptor = processor
                .encrypt_symmetric_async(
                    Box::new(&mut encrypted_data),
                    SymmetricConfig {
                        algorithm: Cow::Borrowed(&wrapper),
                        key_id: "test_key_id".to_string(),
                        config: config.clone(),
                        key: Cow::Borrowed(&key),
                        aad: None,
                    },
                )
                .await
                .unwrap();
            encryptor.write_all(plaintext).await.unwrap();
            encryptor.shutdown().await.unwrap();
        }

        // Tamper with the ciphertext body, after the header
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        if encrypted_data.len() > header_len {
            encrypted_data[header_len] ^= 1;
        }

        let decryptor_result = processor
            .begin_decrypt_symmetric_async(Box::new(Cursor::new(&encrypted_data)), config.clone())
            .await
            .unwrap()
            .into_decryptor(&key, None)
            .await;

        let mut decryptor = decryptor_result.unwrap();
        let result = decryptor.read_to_end(&mut Vec::new()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_wrong_key_fails_async() {
        let wrapper = get_wrapper();
        let processor = Asynchronous::new();
        let plaintext = b"some data";
        let correct_key = wrapper.generate_typed_key().unwrap();
        let wrong_key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        let mut encrypted_data = Vec::new();
        {
            let mut encryptor = processor
                .encrypt_symmetric_async(
                    Box::new(&mut encrypted_data),
                    SymmetricConfig {
                        algorithm: Cow::Borrowed(&wrapper),
                        key_id: "key1".to_string(),
                        config: config.clone(),
                        key: Cow::Borrowed(&correct_key),
                        aad: None,
                    },
                )
                .await
                .unwrap();
            encryptor.write_all(plaintext).await.unwrap();
            encryptor.shutdown().await.unwrap();
        }

        // Decrypt with the wrong key
        let decryptor_result = processor
            .begin_decrypt_symmetric_async(Box::new(Cursor::new(&encrypted_data)), config.clone())
            .await
            .unwrap()
            .into_decryptor(&wrong_key, None)
            .await;

        assert!(decryptor_result.is_err());
    }

    #[tokio::test]
    async fn test_wrong_aad_fails_async() {
        let wrapper = get_wrapper();
        let processor = Asynchronous::new();
        let plaintext = b"some data to protect";
        let aad = Some(b"correct aad".to_vec());
        let wrong_aad = Some(b"wrong aad".to_vec());
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        // Encrypt with AAD
        let mut encrypted_data = Vec::new();
        {
            let mut encryptor = processor
                .encrypt_symmetric_async(
                    Box::new(&mut encrypted_data),
                    SymmetricConfig {
                        algorithm: Cow::Borrowed(&wrapper),
                        key_id: "key1".to_string(),
                        config: config.clone(),
                        key: Cow::Borrowed(&key),
                        aad: aad.clone(),
                    },
                )
                .await
                .unwrap();
            encryptor.write_all(plaintext).await.unwrap();
            encryptor.shutdown().await.unwrap();
        }

        // Decrypt with correct AAD
        let mut decryptor = processor
            .begin_decrypt_symmetric_async(
                Box::new(Cursor::new(encrypted_data.clone())),
                config.clone(),
            )
            .await
            .unwrap()
            .into_decryptor(&key, aad)
            .await
            .unwrap();
        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).await.unwrap();
        assert_eq!(decrypted_data, plaintext);

        // Decrypt with wrong AAD should fail
        let decryptor_result_fail = processor
            .begin_decrypt_symmetric_async(
                Box::new(Cursor::new(encrypted_data.clone())),
                config.clone(),
            )
            .await
            .unwrap()
            .into_decryptor(&key, wrong_aad)
            .await;
        assert!(decryptor_result_fail.is_err());

        // Decrypt with no AAD should fail
        let decryptor_result_fail2 = processor
            .begin_decrypt_symmetric_async(Box::new(Cursor::new(encrypted_data)), config.clone())
            .await
            .unwrap()
            .into_decryptor(&key, None)
            .await;
        assert!(decryptor_result_fail2.is_err());
    }
}
