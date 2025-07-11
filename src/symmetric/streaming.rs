//! Implements `std::io` traits for synchronous, streaming symmetric encryption.
//!
//! 为同步、流式对称加密实现 `std::io` trait。

use crate::body::config::BodyDecryptConfig;
use crate::body::traits::StreamingBodyProcessor;
use crate::common::config::{ArcConfig, DecryptorConfig};
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, FormatError, Result};
use crate::keys::TypedSymmetricKey;
use crate::symmetric::config::SymmetricConfig;
use crate::symmetric::pending::PendingDecryptor;
use crate::symmetric::traits::{SymmetricStreamingPendingDecryptor, SymmetricStreamingProcessor};
use std::borrow::Cow;
use std::io::{Read, Write};

impl<'a> SymmetricStreamingPendingDecryptor<'a> for PendingDecryptor<Box<dyn Read + 'a>> {
    fn into_decryptor(
        self: Box<Self>,
        key: &TypedSymmetricKey,
        aad: Option<Vec<u8>>,
    ) -> Result<Box<dyn Read + 'a>> {
        let (nonce, &chunk_size) = match &self.header.payload {
            HeaderPayload::Symmetric {
                stream_info: Some(info),
                chunk_size,
                ..
            } => (info.base_nonce, chunk_size),
            _ => return Err(Error::Format(FormatError::InvalidHeader)),
        };

        let config = BodyDecryptConfig {
            key: Cow::Owned(key.clone()),
            nonce,
            aad,
            config: DecryptorConfig {
                chunk_size,
                arc_config: self.config,
            },
        };
        self.algorithm.decrypt_body_from_stream(self.source, config)
    }

    fn header(&self) -> &Header {
        &self.header
    }
}

pub struct Streaming;

impl Streaming {
    pub fn new() -> Self {
        Self {}
    }
}

impl SymmetricStreamingProcessor for Streaming {
    fn encrypt_symmetric_to_stream<'a>(
        &self,
        mut writer: Box<dyn Write + 'a>,
        config: SymmetricConfig<'a>,
    ) -> Result<Box<dyn Write + 'a>> {
        let algo = config.algorithm.clone();
        let config = config.into_encrypt_config()?;

        let header_bytes = config.header_bytes();
        writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&header_bytes)?;
        algo.as_ref().encrypt_body_to_stream(writer, config)
    }

    fn begin_decrypt_symmetric_from_stream<'a>(
        &self,
        mut reader: Box<dyn Read + 'a>,
        config: ArcConfig,
    ) -> Result<Box<dyn SymmetricStreamingPendingDecryptor<'a> + 'a>> {
        let header = Header::decode_from_prefixed_reader(&mut reader)?;
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
    use crate::prelude::SymmetricAlgorithmEnum;
    use std::io::Cursor;
    use std::io::Write;

    fn get_wrapper() -> SymmetricAlgorithmWrapper {
        SymmetricAlgorithmEnum::Aes256Gcm.into_symmetric_wrapper()
    }

    fn test_streaming_roundtrip(plaintext: &[u8], aad: Option<Vec<u8>>) {
        let wrapper = get_wrapper();
        let processor = Streaming::new();
        let key_id = "test_key_id".to_string();
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        // Encrypt
        let mut encrypted_data = Vec::new();
        {
            let mut encryptor = processor
                .encrypt_symmetric_to_stream(
                    Box::new(&mut encrypted_data),
                    SymmetricConfig {
                        algorithm: Cow::Borrowed(&wrapper),
                        key_id: key_id.clone(),
                        config: config.clone(),
                        key: Cow::Borrowed(&key),
                        aad: aad.clone(),
                    },
                )
                .unwrap();
            encryptor.write_all(plaintext).unwrap();
            encryptor.flush().unwrap();
        }

        // Decrypt using the new two-step process
        let pending_decryptor = processor
            .begin_decrypt_symmetric_from_stream(
                Box::new(Cursor::new(&encrypted_data)),
                config.clone(),
            )
            .unwrap();
        assert_eq!(
            pending_decryptor.header().payload.key_id(),
            Some(key_id.as_str())
        );

        let mut decryptor = pending_decryptor.into_decryptor(&key, aad).unwrap();
        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[test]
    fn test_processor_roundtrip() {
        let wrapper = get_wrapper();
        let processor = Streaming::new();
        let plaintext = b"This is a processor test for streaming.";
        let key = wrapper.generate_typed_key().unwrap();
        let aad = Some(b"streaming aad".to_vec());
        let config = ArcConfig::default();
        // Encrypt
        let mut encrypted_data = Vec::new();
        {
            let mut encrypt_stream = processor
                .encrypt_symmetric_to_stream(
                    Box::new(&mut encrypted_data),
                    SymmetricConfig {
                        algorithm: Cow::Borrowed(&wrapper),
                        key_id: "proc_key".to_string(),
                        config: ArcConfig::default(),
                        key: Cow::Borrowed(&key),
                        aad: None,
                    },
                )
                .unwrap();
            encrypt_stream.write_all(plaintext).unwrap();
            encrypt_stream.flush().unwrap();
        }

        // Decrypt
        let pending = processor
            .begin_decrypt_symmetric_from_stream(
                Box::new(Cursor::new(&encrypted_data)),
                config.clone(),
            )
            .unwrap();
        let mut decrypt_stream = pending.into_decryptor(&key, aad).unwrap();
        let mut decrypted_data = Vec::new();
        decrypt_stream.read_to_end(&mut decrypted_data).unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[test]
    fn test_roundtrip_long_message() {
        let plaintext = b"This is a very long test message to test the streaming encryption and decryption. It should be longer than a single chunk to ensure that the chunking logic is working correctly. Let's add more data to make sure it spans multiple chunks. Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        test_streaming_roundtrip(plaintext, None);
    }

    #[test]
    fn test_roundtrip_empty_message() {
        test_streaming_roundtrip(b"", None);
    }

    #[test]
    fn test_roundtrip_exact_chunk_size() {
        let plaintext = vec![42u8; crate::common::DEFAULT_CHUNK_SIZE as usize];
        test_streaming_roundtrip(&plaintext, None);
    }

    #[test]
    fn test_aad_roundtrip() {
        let plaintext = b"streaming data with aad";
        let aad = b"streaming context";
        test_streaming_roundtrip(plaintext, Some(aad.to_vec()));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let wrapper = get_wrapper();
        let processor = Streaming::new();
        let plaintext = b"some important data";
        let key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        let mut encrypted_data = Vec::new();
        {
            let mut encryptor = processor
                .encrypt_symmetric_to_stream(
                    Box::new(&mut encrypted_data),
                    SymmetricConfig {
                        algorithm: Cow::Borrowed(&wrapper),
                        key_id: "test_key_id".to_string(),
                        config: ArcConfig::default(),
                        key: Cow::Borrowed(&key),
                        aad: None,
                    },
                )
                .unwrap();
            encryptor.write_all(plaintext).unwrap();
            encryptor.flush().unwrap();
        }

        // Tamper with the ciphertext body, after the header
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        if encrypted_data.len() > header_len {
            encrypted_data[header_len] ^= 1;
        }

        let pending = processor
            .begin_decrypt_symmetric_from_stream(
                Box::new(Cursor::new(&encrypted_data)),
                config.clone(),
            )
            .unwrap();
        let mut decryptor = pending.into_decryptor(&key, None).unwrap();
        let result = decryptor.read_to_end(&mut Vec::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let wrapper = get_wrapper();
        let processor = Streaming::new();
        let key_id = "test_key_id".to_string();

        let correct_key = wrapper.generate_typed_key().unwrap();
        let wrong_key = wrapper.generate_typed_key().unwrap();
        let config = ArcConfig::default();
        let plaintext = b"some data";

        // Encrypt with the correct key
        let mut encrypted_data = Vec::new();
        {
            let mut encryptor = processor
                .encrypt_symmetric_to_stream(
                    Box::new(&mut encrypted_data),
                    SymmetricConfig {
                        algorithm: Cow::Borrowed(&wrapper),
                        key_id: key_id.clone(),
                        config: ArcConfig::default(),
                        key: Cow::Borrowed(&correct_key),
                        aad: None,
                    },
                )
                .unwrap();
            encryptor.write_all(plaintext).unwrap();
            encryptor.flush().unwrap();
        }

        // Attempt to decrypt with the wrong key
        let pending_decryptor = processor
            .begin_decrypt_symmetric_from_stream(
                Box::new(Cursor::new(&encrypted_data)),
                config.clone(),
            )
            .unwrap();

        let decryptor_result = pending_decryptor.into_decryptor(&wrong_key, None);

        // We expect an error during the creation of the decryptor,
        // or on the first read.
        if let Ok(mut decryptor) = decryptor_result {
            let mut buf = Vec::new();
            let read_result = decryptor.read_to_end(&mut buf);
            assert!(read_result.is_err(), "Decryption should fail on read");
        }
        // If into_decryptor itself fails, the test passes as well.
    }

    #[test]
    fn test_wrong_aad_fails() {
        let wrapper = get_wrapper();
        let processor = Streaming::new();
        let key_id = "test_key_id".to_string();
        let key = wrapper.generate_typed_key().unwrap();
        let plaintext = b"some data";
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";
        let config = ArcConfig::default();

        // Encrypt with AAD
        let mut encrypted_data = Vec::new();
        {
            let mut encryptor = processor
                .encrypt_symmetric_to_stream(
                    Box::new(&mut encrypted_data),
                    SymmetricConfig {
                        algorithm: Cow::Borrowed(&wrapper),
                        key_id: key_id.clone(),
                        config: ArcConfig::default(),
                        key: Cow::Borrowed(&key),
                        aad: Some(aad.to_vec()),
                    },
                )
                .unwrap();
            encryptor.write_all(plaintext).unwrap();
            encryptor.flush().unwrap();
        }

        // Decrypt with correct AAD
        let pending = processor
            .begin_decrypt_symmetric_from_stream(
                Box::new(Cursor::new(&encrypted_data)),
                config.clone(),
            )
            .unwrap();
        let mut decryptor = pending.into_decryptor(&key, Some(aad.to_vec())).unwrap();
        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).unwrap();
        assert_eq!(decrypted_data, plaintext);

        // Decrypt with wrong AAD should fail
        let pending_fail = processor
            .begin_decrypt_symmetric_from_stream(
                Box::new(Cursor::new(&encrypted_data)),
                config.clone(),
            )
            .unwrap();
        let decryptor_result = pending_fail.into_decryptor(&key, Some(wrong_aad.to_vec()));
        assert!(
            decryptor_result.is_err()
                || decryptor_result
                    .unwrap()
                    .read_to_end(&mut Vec::new())
                    .is_err()
        );

        // Decrypt with no AAD should also fail
        let pending_fail2 = processor
            .begin_decrypt_symmetric_from_stream(
                Box::new(Cursor::new(&encrypted_data)),
                config.clone(),
            )
            .unwrap();
        let decryptor_result2 = pending_fail2.into_decryptor(&key, None);
        assert!(
            decryptor_result2.is_err()
                || decryptor_result2
                    .unwrap()
                    .read_to_end(&mut Vec::new())
                    .is_err()
        );
    }
}
