//! Implements a parallel streaming symmetric encryption/decryption scheme.
//! This mode is designed for high-performance processing of large files or data streams
//! by overlapping I/O with parallel computation.
//!
//! 实现并行流式对称加解密方案。
//! 此模式通过将 I/O 与并行计算重叠，专为高性能处理大文件或数据流而设计。

use crate::body::config::BodyDecryptConfig;
use crate::body::traits::ParallelStreamingBodyProcessor;
use crate::common::config::{ArcConfig, DecryptorConfig};
use crate::common::header::{Header, HeaderPayload};
use crate::error::Result;
use crate::error::{Error, FormatError};
use crate::keys::TypedSymmetricKey;
use crate::symmetric::config::SymmetricConfig;
use crate::symmetric::pending::PendingDecryptor;
use crate::symmetric::traits::{
    SymmetricParallelStreamingPendingDecryptor, SymmetricParallelStreamingProcessor,
};
use std::borrow::Cow;
use std::io::{Read, Write};

impl<'a> SymmetricParallelStreamingPendingDecryptor<'a>
    for PendingDecryptor<Box<dyn Read + Send + 'a>>
{
    fn decrypt_to_writer(
        self: Box<Self>,
        key: &TypedSymmetricKey,
        writer: Box<dyn Write + Send + 'a>,
        aad: Option<Vec<u8>>,
    ) -> Result<()> {
        let HeaderPayload {
            base_nonce,
            chunk_size,
            ..
        } = self.header.payload;

        let config = BodyDecryptConfig {
            key: Cow::Borrowed(key),
            nonce: base_nonce,
            aad,
            config: DecryptorConfig {
                chunk_size,
                arc_config: self.config,
            },
        };
        self.algorithm
            .algorithm
            .decrypt_body_pipeline(self.source, writer, config)
    }

    fn header(&self) -> &Header {
        &self.header
    }
}

pub struct ParallelStreaming;

impl ParallelStreaming {
    pub fn new() -> Self {
        Self
    }
}

impl SymmetricParallelStreamingProcessor for ParallelStreaming {
    fn encrypt_symmetric_pipeline<'a>(
        &self,
        reader: Box<dyn Read + Send + 'a>,
        mut writer: Box<dyn Write + Send + 'a>,
        config: SymmetricConfig<'a>,
    ) -> Result<()> {
        let algo = config.algorithm.clone();
        let config = config.into_encrypt_config()?;
        let header_bytes = config.header_bytes();
        writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(header_bytes)?;
        algo.as_ref().encrypt_body_pipeline(reader, writer, config)
    }

    fn begin_decrypt_symmetric_pipeline<'a>(
        &self,
        mut reader: Box<dyn Read + Send + 'a>,
        config: ArcConfig,
    ) -> Result<Box<dyn SymmetricParallelStreamingPendingDecryptor<'a> + 'a>> {
        let header = Header::decode_from_prefixed_reader(&mut reader)?;
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
    use crate::algorithms::symmetric::SymmetricAlgorithmWrapper;
    use crate::common::DEFAULT_CHUNK_SIZE;
    use crate::prelude::SymmetricAlgorithmEnum;
    use std::io::Cursor;

    fn get_wrapper() -> SymmetricAlgorithmWrapper {
        SymmetricAlgorithmEnum::Aes256Gcm.into_symmetric_wrapper()
    }

    fn get_test_data(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 256) as u8).collect()
    }

    #[test]
    fn test_parallel_streaming_roundtrip() {
        let wrapper = get_wrapper();
        let processor = ParallelStreaming::new();
        let plaintext = get_test_data(1024 * 1024); // 1 MiB
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        let mut encrypted_data = Vec::new();
        let mut plaintext_cursor = Cursor::new(plaintext);
        processor
            .encrypt_symmetric_pipeline(
                Box::new(&mut plaintext_cursor),
                Box::new(&mut encrypted_data),
                SymmetricConfig {
                    algorithm: Cow::Borrowed(&wrapper),
                    key_id: "test_key".to_string(),
                    config: config.clone(),
                    key: Cow::Borrowed(&key),
                    aad: None,
                },
            )
            .unwrap();

        let mut decrypted_data = Vec::new();
        let mut encrypted_cursor = Cursor::new(&encrypted_data);
        processor
            .begin_decrypt_symmetric_pipeline(Box::new(&mut encrypted_cursor), config.clone())
            .unwrap()
            .decrypt_to_writer(&key, Box::new(&mut decrypted_data), None)
            .unwrap();

        assert_eq!(plaintext_cursor.into_inner(), decrypted_data.as_slice());
    }

    #[test]
    fn test_processor_roundtrip() {
        let wrapper = get_wrapper();
        let processor = ParallelStreaming::new();
        let plaintext = get_test_data(1024 * 512); // 512 KiB
        let key = wrapper.generate_typed_key().unwrap();
        let aad = Some(b"parallel streaming processor aad".to_vec());
        let config = ArcConfig::default();
        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut plaintext_cursor = Cursor::new(plaintext);
        processor
            .encrypt_symmetric_pipeline(
                Box::new(&mut plaintext_cursor),
                Box::new(&mut encrypted_data),
                SymmetricConfig {
                    algorithm: Cow::Borrowed(&wrapper),
                    key_id: "proc_key".to_string(),
                    config: config.clone(),
                    key: Cow::Borrowed(&key),
                    aad: aad.clone(),
                },
            )
            .unwrap();

        // Decrypt
        let mut decrypted_data = Vec::new();
        let mut encrypted_cursor = Cursor::new(&encrypted_data);
        processor
            .begin_decrypt_symmetric_pipeline(Box::new(&mut encrypted_cursor), config.clone())
            .unwrap()
            .decrypt_to_writer(&key, Box::new(&mut decrypted_data), aad)
            .unwrap();

        assert_eq!(plaintext_cursor.into_inner(), decrypted_data.as_slice());
    }

    #[test]
    fn test_empty_input() {
        let wrapper = get_wrapper();
        let processor = ParallelStreaming::new();
        let plaintext = b"";
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        let mut encrypted_data = Vec::new();
        let mut plaintext_cursor = Cursor::new(plaintext);
        processor
            .encrypt_symmetric_pipeline(
                Box::new(&mut plaintext_cursor),
                Box::new(&mut encrypted_data),
                SymmetricConfig {
                    algorithm: Cow::Borrowed(&wrapper),
                    key_id: "test_key".to_string(),
                    config: config.clone(),
                    key: Cow::Borrowed(&key),
                    aad: None,
                },
            )
            .unwrap();

        let mut decrypted_data = Vec::new();
        let mut encrypted_cursor = Cursor::new(&encrypted_data);
        processor
            .begin_decrypt_symmetric_pipeline(Box::new(&mut encrypted_cursor), config.clone())
            .unwrap()
            .decrypt_to_writer(&key, Box::new(&mut decrypted_data), None)
            .unwrap();

        assert_eq!(plaintext_cursor.into_inner(), decrypted_data.as_slice());
    }

    #[test]
    fn test_exact_chunk_multiple() {
        let wrapper = get_wrapper();
        let processor = ParallelStreaming::new();
        let plaintext = get_test_data((DEFAULT_CHUNK_SIZE * 3) as usize);
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        let mut encrypted_data = Vec::new();
        let mut plaintext_cursor = Cursor::new(plaintext);
        processor
            .encrypt_symmetric_pipeline(
                Box::new(&mut plaintext_cursor),
                Box::new(&mut encrypted_data),
                SymmetricConfig {
                    algorithm: Cow::Borrowed(&wrapper),
                    key_id: "test_key".to_string(),
                    config: config.clone(),
                    key: Cow::Borrowed(&key),
                    aad: None,
                },
            )
            .unwrap();

        let mut decrypted_data = Vec::new();
        let mut encrypted_cursor = Cursor::new(&encrypted_data);
        processor
            .begin_decrypt_symmetric_pipeline(Box::new(&mut encrypted_cursor), config.clone())
            .unwrap()
            .decrypt_to_writer(&key, Box::new(&mut decrypted_data), None)
            .unwrap();

        assert_eq!(plaintext_cursor.into_inner(), decrypted_data.as_slice());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let wrapper = get_wrapper();
        let processor = ParallelStreaming::new();
        let plaintext = get_test_data(1024);
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        let mut encrypted_data = Vec::new();
        let mut plaintext_cursor = Cursor::new(plaintext);
        processor
            .encrypt_symmetric_pipeline(
                Box::new(&mut plaintext_cursor),
                Box::new(&mut encrypted_data),
                SymmetricConfig {
                    algorithm: Cow::Borrowed(&wrapper),
                    key_id: "test_key".to_string(),
                    config: config.clone(),
                    key: Cow::Borrowed(&key),
                    aad: None,
                },
            )
            .unwrap();

        // Tamper
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        encrypted_data[header_len + 10] ^= 1;

        let mut decrypted_data = Vec::new();
        let mut encrypted_cursor = Cursor::new(&encrypted_data);
        let result = processor
            .begin_decrypt_symmetric_pipeline(Box::new(&mut encrypted_cursor), config.clone())
            .unwrap()
            .decrypt_to_writer(&key, Box::new(&mut decrypted_data), None);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let wrapper = get_wrapper();
        let processor = ParallelStreaming::new();
        let plaintext = get_test_data(1024);
        let correct_key = wrapper.generate_typed_key().unwrap();
        let wrong_key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        let mut encrypted_data = Vec::new();
        let mut plaintext_cursor = Cursor::new(plaintext);
        processor
            .encrypt_symmetric_pipeline(
                Box::new(&mut plaintext_cursor),
                Box::new(&mut encrypted_data),
                SymmetricConfig {
                    algorithm: Cow::Borrowed(&wrapper),
                    key_id: "test_key".to_string(),
                    config: config.clone(),
                    key: Cow::Borrowed(&correct_key),
                    aad: None,
                },
            )
            .unwrap();

        let mut decrypted_data = Vec::new();
        let mut encrypted_cursor = Cursor::new(&encrypted_data);
        let result = processor
            .begin_decrypt_symmetric_pipeline(Box::new(&mut encrypted_cursor), config.clone())
            .unwrap()
            .decrypt_to_writer(&wrong_key, Box::new(&mut decrypted_data), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_aad_roundtrip() {
        let wrapper = get_wrapper();
        let processor = ParallelStreaming::new();
        let plaintext = get_test_data(1024 * 256); // 256 KiB
        let aad = b"parallel streaming aad".to_vec();
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();

        // Encrypt with AAD
        let mut encrypted_data = Vec::new();
        let mut plaintext_cursor = Cursor::new(plaintext);
        processor
            .encrypt_symmetric_pipeline(
                Box::new(&mut plaintext_cursor),
                Box::new(&mut encrypted_data),
                SymmetricConfig {
                    algorithm: Cow::Borrowed(&wrapper),
                    key_id: "test_key_aad".to_string(),
                    config: config.clone(),
                    key: Cow::Borrowed(&key),
                    aad: Some(aad.clone()),
                },
            )
            .unwrap();

        // Decrypt with correct AAD
        let mut decrypted_data = Vec::new();
        let mut encrypted_cursor = Cursor::new(&encrypted_data);
        processor
            .begin_decrypt_symmetric_pipeline(Box::new(&mut encrypted_cursor), config.clone())
            .unwrap()
            .decrypt_to_writer(&key, Box::new(&mut decrypted_data), Some(aad.clone()))
            .unwrap();
        assert_eq!(
            plaintext_cursor.into_inner().as_slice(),
            decrypted_data.as_slice()
        );

        // Decrypt with wrong AAD should fail
        let mut decrypted_data_fail = Vec::new();
        let mut encrypted_cursor_fail = Cursor::new(&encrypted_data);
        let result_fail = processor
            .begin_decrypt_symmetric_pipeline(Box::new(&mut encrypted_cursor_fail), config.clone())
            .unwrap()
            .decrypt_to_writer(
                &key,
                Box::new(&mut decrypted_data_fail),
                Some(b"wrong aad".to_vec()),
            );
        assert!(result_fail.is_err());

        // Decrypt with no AAD should fail
        let mut decrypted_data_fail2 = Vec::new();
        let mut encrypted_cursor_fail2 = Cursor::new(&encrypted_data);
        let result_fail2 = processor
            .begin_decrypt_symmetric_pipeline(Box::new(&mut encrypted_cursor_fail2), config.clone())
            .unwrap()
            .decrypt_to_writer(&key, Box::new(&mut decrypted_data_fail2), None);
        assert!(result_fail2.is_err());
    }
}
