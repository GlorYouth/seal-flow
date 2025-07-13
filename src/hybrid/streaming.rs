//! Synchronous, streaming hybrid encryption and decryption implementation.
//!
//! 同步、流式混合加密和解密实现。
use super::traits::{HybridStreamingPendingDecryptor, HybridStreamingProcessor};
use crate::algorithms::hybrid::HybridAlgorithmWrapper;
use crate::algorithms::traits::HybridAlgorithm;
use crate::body::traits::{FinishingWrite, StreamingBodyProcessor};
use crate::common::config::ArcConfig;
use crate::common::header::Header;
use crate::error::{FormatError, Result};
use crate::hybrid::config::HybridConfig;
use crate::hybrid::pending::PendingDecryptor;
use crate::keys::TypedAsymmetricPrivateKey;
use std::io::{Read, Write};

pub struct Streaming;

impl Streaming {
    pub fn new() -> Self {
        Self
    }
}

impl HybridStreamingProcessor for Streaming {
    fn encrypt_hybrid_to_stream<'a>(
        &self,
        mut writer: Box<dyn Write + 'a>,
        config: HybridConfig<'a>,
    ) -> Result<Box<dyn FinishingWrite + 'a>> {
        let algo = config.algorithm.clone();
        let (body_config, header_bytes) = config.into_body_config_and_header()?;
        writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&header_bytes)?;
        algo.as_ref()
            .symmetric_algorithm()
            .encrypt_body_to_stream(writer, body_config)
    }

    fn begin_decrypt_hybrid_from_stream<'a>(
        &self,
        mut reader: Box<dyn Read + 'a>,
        config: ArcConfig,
    ) -> Result<Box<dyn HybridStreamingPendingDecryptor<'a> + 'a>> {
        let header = Header::decode_from_prefixed_reader(&mut reader)?;
        let asym_algo = header
            .payload
            .asymmetric_algorithm()
            .ok_or(FormatError::InvalidHeader)?
            .into_asymmetric_wrapper();
        let sym_algo = header
            .payload
            .symmetric_algorithm()
            .into_symmetric_wrapper();
        let algorithm = HybridAlgorithmWrapper::new(asym_algo, sym_algo);

        let pending = PendingDecryptor {
            source: reader,
            header,
            algorithm,
            config,
        };

        Ok(Box::new(pending))
    }
}

impl<'a> HybridStreamingPendingDecryptor<'a> for PendingDecryptor<Box<dyn Read + 'a>> {
    fn into_decryptor(
        self: Box<Self>,
        sk: &TypedAsymmetricPrivateKey,
        aad: Option<Vec<u8>>,
    ) -> Result<Box<dyn Read + 'a>> {
        let reader = self.source;
        let body_config = super::common::prepare_body_decrypt_config(
            self.header,
            &self.algorithm,
            sk,
            aad,
            self.config,
        )?;

        self.algorithm
            .symmetric_algorithm()
            .decrypt_body_from_stream(reader, body_config)
    }

    fn header(&self) -> &Header {
        &self.header
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::asymmetric::Rsa2048Sha256Wrapper;
    use crate::algorithms::symmetric::Aes256GcmWrapper;
    use crate::algorithms::traits::AsymmetricAlgorithm;
    use crate::common::header::{DerivationInfo, KdfInfo};
    use crate::common::DerivationSet;
    use crate::keys::TypedAsymmetricPublicKey;
    use std::borrow::Cow;
    use std::io::Cursor;

    fn get_test_algorithm() -> HybridAlgorithmWrapper {
        HybridAlgorithmWrapper::new(Rsa2048Sha256Wrapper::new(), Aes256GcmWrapper::new())
    }

    fn generate_test_keys() -> (TypedAsymmetricPublicKey, TypedAsymmetricPrivateKey) {
        let wrapper = Rsa2048Sha256Wrapper::new();
        let keypair = wrapper.generate_keypair().unwrap();
        keypair.into_keypair()
    }

    fn test_hybrid_streaming_roundtrip(plaintext: &[u8], aad: Option<Vec<u8>>, use_kdf: bool) {
        let algorithm = get_test_algorithm();
        let processor = Streaming::new();
        let (pk, sk) = generate_test_keys();
        let kek_id = "test_kek_id".to_string();

        let derivation_config = if use_kdf {
            let salt = b"salt-stream";
            let info = b"info-stream";

            let kdf_info = KdfInfo {
                kdf_algorithm: crate::common::algorithms::KdfKeyAlgorithm::HkdfSha256,
                salt: Some(salt.to_vec()),
                info: Some(info.to_vec()),
            };

            let kdf_algorithm = crate::common::algorithms::KdfKeyAlgorithm::HkdfSha256;

            use crate::common::DerivationWrapper;
            Some(DerivationSet {
                derivation_info: DerivationInfo::Kdf(kdf_info),
                wrapper: DerivationWrapper::Kdf(kdf_algorithm.into_kdf_key_wrapper()),
            })
        } else {
            None
        };

        let config = HybridConfig {
            algorithm: Cow::Borrowed(&algorithm),
            public_key: Cow::Borrowed(&pk),
            kek_id,
            signer: None,
            aad: aad.clone(),
            derivation_config,
            config: ArcConfig::default(),
        };

        // Encrypt
        let mut encrypted_data = Vec::new();
        let writer = Box::new(&mut encrypted_data);
        let mut encryptor = processor.encrypt_hybrid_to_stream(writer, config).unwrap();

        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt
        let pending_decryptor = processor
            .begin_decrypt_hybrid_from_stream(
                Box::new(Cursor::new(&encrypted_data)),
                ArcConfig::default(),
            )
            .unwrap();
        assert_eq!(
            pending_decryptor.header().payload.kek_id(),
            Some("test_kek_id")
        );

        let mut decryptor = pending_decryptor.into_decryptor(&sk, aad).unwrap();
        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[test]
    fn test_roundtrip_long_message() {
        let plaintext = b"This is a very long test message to test the streaming encryption and decryption. It should be longer than a single chunk to ensure that the chunking logic is working correctly. Let's add more data to make sure it spans multiple chunks. Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        test_hybrid_streaming_roundtrip(plaintext, None, false);
    }

    #[test]
    fn test_roundtrip_long_message_with_kdf() {
        let plaintext = b"This is a very long test message to test the streaming encryption and decryption with a KDF. It should be longer than a single chunk to ensure that the chunking logic is working correctly. Let's add more data to make sure it spans multiple chunks. Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        test_hybrid_streaming_roundtrip(plaintext, None, true);
    }

    #[test]
    fn test_roundtrip_empty_message() {
        test_hybrid_streaming_roundtrip(b"", None, false);
    }

    #[test]
    fn test_roundtrip_empty_message_with_kdf() {
        test_hybrid_streaming_roundtrip(b"", None, true);
    }

    #[test]
    fn test_roundtrip_exact_chunk_size() {
        let plaintext = vec![42u8; crate::common::DEFAULT_CHUNK_SIZE as usize];
        test_hybrid_streaming_roundtrip(&plaintext, None, false);
    }

    #[test]
    fn test_aad_roundtrip() {
        let plaintext = b"streaming hybrid data with aad";
        let aad = b"streaming hybrid context".to_vec();
        test_hybrid_streaming_roundtrip(plaintext, Some(aad), false);
    }

    #[test]
    fn test_aad_roundtrip_with_kdf() {
        let plaintext = b"streaming hybrid data with aad and kdf";
        let aad = b"streaming hybrid context with kdf".to_vec();
        test_hybrid_streaming_roundtrip(plaintext, Some(aad), true);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let algorithm = get_test_algorithm();
        let processor = Streaming::new();
        let (pk, sk) = generate_test_keys();
        let plaintext = b"some important data";

        let config = HybridConfig {
            algorithm: Cow::Borrowed(&algorithm),
            public_key: Cow::Borrowed(&pk),
            kek_id: "test_kek_id".to_string(),
            signer: None,
            aad: None,
            derivation_config: None,
            config: ArcConfig::default(),
        };

        let mut encrypted_data = Vec::new();
        let writer = Box::new(&mut encrypted_data);
        let mut encryptor = processor.encrypt_hybrid_to_stream(writer, config).unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Tamper with the ciphertext body
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        if encrypted_data.len() > header_len {
            encrypted_data[header_len] ^= 1;
        }

        let pending = processor
            .begin_decrypt_hybrid_from_stream(
                Box::new(Cursor::new(&encrypted_data)),
                ArcConfig::default(),
            )
            .unwrap();
        let mut decryptor = pending.into_decryptor(&sk, None).unwrap();

        let result = decryptor.read_to_end(&mut Vec::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let algorithm = get_test_algorithm();
        let processor = Streaming::new();
        let (pk, _) = generate_test_keys();
        let plaintext = b"some important data";

        let config = HybridConfig {
            algorithm: Cow::Borrowed(&algorithm),
            public_key: Cow::Borrowed(&pk),
            kek_id: "test_kek_id".to_string(),
            signer: None,
            aad: None,
            derivation_config: None,
            config: ArcConfig::default(),
        };

        let mut encrypted_data = Vec::new();
        let writer = Box::new(&mut encrypted_data);
        let mut encryptor = processor.encrypt_hybrid_to_stream(writer, config).unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        let (_, sk2) = generate_test_keys();
        let pending = processor
            .begin_decrypt_hybrid_from_stream(
                Box::new(Cursor::new(&encrypted_data)),
                ArcConfig::default(),
            )
            .unwrap();
        let result = pending.into_decryptor(&sk2, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let algorithm = get_test_algorithm();
        let processor = Streaming::new();
        let (pk, sk) = generate_test_keys();
        let plaintext = b"some important data";
        let aad = b"some aad".to_vec();
        let wrong_aad = b"wrong aad".to_vec();

        let config = HybridConfig {
            algorithm: Cow::Borrowed(&algorithm),
            public_key: Cow::Borrowed(&pk),
            kek_id: "test_kek_id".to_string(),
            signer: None,
            aad: Some(aad),
            derivation_config: None,
            config: ArcConfig::default(),
        };

        let mut encrypted_data = Vec::new();
        let writer = Box::new(&mut encrypted_data);
        let mut encryptor = processor.encrypt_hybrid_to_stream(writer, config).unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        let pending = processor
            .begin_decrypt_hybrid_from_stream(
                Box::new(Cursor::new(&encrypted_data)),
                ArcConfig::default(),
            )
            .unwrap();
        let mut decryptor = pending.into_decryptor(&sk, Some(wrong_aad)).unwrap();

        let result = decryptor.read_to_end(&mut Vec::new());
        assert!(result.is_err());
    }
}
