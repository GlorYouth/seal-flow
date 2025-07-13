//! Implements a parallel streaming hybrid encryption/decryption scheme.
//!
//! 实现并行流式混合加解密方案。

use super::traits::{HybridParallelStreamingPendingDecryptor, HybridParallelStreamingProcessor};
use crate::algorithms::hybrid::HybridAlgorithmWrapper;
use crate::algorithms::traits::HybridAlgorithm;
use crate::body::traits::ParallelStreamingBodyProcessor;
use crate::common::config::ArcConfig;
use crate::common::header::Header;
use crate::error::{FormatError, Result};
use crate::hybrid::config::HybridConfig;
use crate::hybrid::pending::PendingDecryptor;
use crate::keys::TypedAsymmetricPrivateKey;
use std::io::{Read, Write};

pub struct ParallelStreaming;

impl ParallelStreaming {
    pub fn new() -> Self {
        Self
    }
}

impl HybridParallelStreamingProcessor for ParallelStreaming {
    fn encrypt_hybrid_pipeline<'a>(
        &self,
        reader: Box<dyn Read + Send + 'a>,
        mut writer: Box<dyn Write + Send + 'a>,
        config: HybridConfig<'a>,
    ) -> Result<()> {
        let algo = config
            .algorithm
            .as_ref()
            .symmetric_algorithm()
            .clone_box_symmetric();
        let (body_config, header_bytes) = config.into_body_config_and_header()?;
        writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&header_bytes)?;

        algo.encrypt_body_pipeline(reader, writer, body_config)
    }

    fn begin_decrypt_hybrid_pipeline<'a>(
        &self,
        mut reader: Box<dyn Read + Send + 'a>,
        config: ArcConfig,
    ) -> Result<Box<dyn HybridParallelStreamingPendingDecryptor<'a> + 'a>> {
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

impl<'a> HybridParallelStreamingPendingDecryptor<'a>
    for PendingDecryptor<Box<dyn Read + Send + 'a>>
{
    fn decrypt_to_writer(
        self: Box<Self>,
        sk: &TypedAsymmetricPrivateKey,
        writer: Box<dyn Write + Send + 'a>,
        aad: Option<Vec<u8>>,
    ) -> Result<()> {
        let reader = self.source;
        let body_config = super::common::prepare_body_decrypt_config(
            self.header,
            &self.algorithm,
            sk,
            aad,
            self.config,
        )?;

        let algo = self.algorithm.symmetric_algorithm().clone_box_symmetric();
        algo.decrypt_body_pipeline(reader, writer, body_config)
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
    fn get_test_data(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 256) as u8).collect()
    }

    fn get_test_algorithm() -> HybridAlgorithmWrapper {
        HybridAlgorithmWrapper::new(Rsa2048Sha256Wrapper::new(), Aes256GcmWrapper::new())
    }

    fn generate_test_keys() -> (TypedAsymmetricPublicKey, TypedAsymmetricPrivateKey) {
        Rsa2048Sha256Wrapper::new()
            .generate_keypair()
            .unwrap()
            .into_keypair()
    }

    #[test]
    fn test_hybrid_parallel_streaming_roundtrip() {
        let algorithm = get_test_algorithm();
        let processor = ParallelStreaming::new();
        let (pk, sk) = generate_test_keys();
        let kek_id = "test-kek-id".to_string();
        let plaintext = get_test_data(1024 * 1024); // 1 MiB

        let mut encrypted_data = Vec::new();
        let reader = Box::new(Cursor::new(&plaintext));
        let writer = Box::new(&mut encrypted_data);

        let config = HybridConfig {
            algorithm: Cow::Borrowed(&algorithm),
            public_key: Cow::Borrowed(&pk),
            kek_id: kek_id.clone(),
            signer: None,
            aad: None,
            derivation_config: None,
            config: ArcConfig::default(),
        };

        processor
            .encrypt_hybrid_pipeline(reader, writer, config)
            .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = processor
            .begin_decrypt_hybrid_pipeline(
                Box::new(Cursor::new(&encrypted_data)),
                ArcConfig::default(),
            )
            .unwrap();
        assert_eq!(pending.header().payload.kek_id(), Some(kek_id.as_str()));
        pending
            .decrypt_to_writer(&sk, Box::new(&mut decrypted_data), None)
            .unwrap();

        assert_eq!(plaintext, decrypted_data);
    }

    #[test]
    fn test_empty_input() {
        let algorithm = get_test_algorithm();
        let processor = ParallelStreaming::new();
        let (pk, sk) = generate_test_keys();
        let kek_id = "test-kek-id".to_string();
        let plaintext = get_test_data(0);

        let mut encrypted_data = Vec::new();
        let reader = Box::new(Cursor::new(&plaintext));
        let writer = Box::new(&mut encrypted_data);

        let config = HybridConfig {
            algorithm: Cow::Borrowed(&algorithm),
            public_key: Cow::Borrowed(&pk),
            kek_id: kek_id.clone(),
            signer: None,
            aad: None,
            derivation_config: None,
            config: ArcConfig::default(),
        };
        processor
            .encrypt_hybrid_pipeline(reader, writer, config)
            .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = processor
            .begin_decrypt_hybrid_pipeline(
                Box::new(Cursor::new(&encrypted_data)),
                ArcConfig::default(),
            )
            .unwrap();
        assert_eq!(pending.header().payload.kek_id(), Some(kek_id.as_str()));
        pending
            .decrypt_to_writer(&sk, Box::new(&mut decrypted_data), None)
            .unwrap();

        assert_eq!(plaintext, decrypted_data);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let algorithm = get_test_algorithm();
        let processor = ParallelStreaming::new();
        let (pk, sk) = generate_test_keys();
        let kek_id = "test-kek-id".to_string();
        let plaintext = get_test_data(1024);

        let mut encrypted_data = Vec::new();
        let reader = Box::new(Cursor::new(&plaintext));
        let writer = Box::new(&mut encrypted_data);

        let config = HybridConfig {
            algorithm: Cow::Borrowed(&algorithm),
            public_key: Cow::Borrowed(&pk),
            kek_id: kek_id.clone(),
            signer: None,
            aad: None,
            derivation_config: None,
            config: ArcConfig::default(),
        };

        processor
            .encrypt_hybrid_pipeline(reader, writer, config)
            .unwrap();

        // Tamper
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        encrypted_data[header_len + 10] ^= 1;

        let mut decrypted_data = Vec::new();
        let pending = processor
            .begin_decrypt_hybrid_pipeline(
                Box::new(Cursor::new(&encrypted_data)),
                ArcConfig::default(),
            )
            .unwrap();
        let result = pending.decrypt_to_writer(&sk, Box::new(&mut decrypted_data), None);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let algorithm = get_test_algorithm();
        let processor = ParallelStreaming::new();
        let (pk, _) = generate_test_keys();
        let (_, sk2) = generate_test_keys();
        let kek_id = "test-kek-id".to_string();
        let plaintext = get_test_data(1024);

        let mut encrypted_data = Vec::new();
        let reader = Box::new(Cursor::new(&plaintext));
        let writer = Box::new(&mut encrypted_data);

        let config = HybridConfig {
            algorithm: Cow::Borrowed(&algorithm),
            public_key: Cow::Borrowed(&pk),
            kek_id: kek_id.clone(),
            signer: None,
            aad: None,
            derivation_config: None,
            config: ArcConfig::default(),
        };

        processor
            .encrypt_hybrid_pipeline(reader, writer, config)
            .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = processor
            .begin_decrypt_hybrid_pipeline(
                Box::new(Cursor::new(&encrypted_data)),
                ArcConfig::default(),
            )
            .unwrap();
        let result = pending.decrypt_to_writer(&sk2, Box::new(&mut decrypted_data), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_aad_roundtrip() {
        let algorithm = get_test_algorithm();
        let processor = ParallelStreaming::new();
        let (pk, sk) = generate_test_keys();
        let plaintext = get_test_data(1024 * 256); // 256 KiB
        let aad = b"parallel streaming aad".to_vec();

        let mut encrypted_data = Vec::new();
        let reader = Box::new(Cursor::new(&plaintext));
        let writer = Box::new(&mut encrypted_data);

        let config = HybridConfig {
            algorithm: Cow::Borrowed(&algorithm),
            public_key: Cow::Borrowed(&pk),
            kek_id: "test_kek_id_aad".to_string(),
            signer: None,
            aad: Some(aad.clone()),
            derivation_config: None,
            config: ArcConfig::default(),
        };

        processor
            .encrypt_hybrid_pipeline(reader, writer, config)
            .unwrap();

        // Decrypt with correct AAD
        let mut decrypted_data = Vec::new();
        let pending = processor
            .begin_decrypt_hybrid_pipeline(
                Box::new(Cursor::new(&encrypted_data)),
                ArcConfig::default(),
            )
            .unwrap();
        assert_eq!(pending.header().payload.kek_id(), Some("test_kek_id_aad"));
        pending
            .decrypt_to_writer(&sk, Box::new(&mut decrypted_data), Some(aad))
            .unwrap();
        assert_eq!(plaintext, decrypted_data);

        // Decrypt with wrong AAD fails
        let mut decrypted_data_fail = Vec::new();
        let pending_fail = processor
            .begin_decrypt_hybrid_pipeline(
                Box::new(Cursor::new(&encrypted_data)),
                ArcConfig::default(),
            )
            .unwrap();
        let result = pending_fail.decrypt_to_writer(
            &sk,
            Box::new(&mut decrypted_data_fail),
            Some(b"wrong aad".to_vec()),
        );
        assert!(result.is_err());

        // Decrypt with no AAD fails
        let mut decrypted_data_fail2 = Vec::new();
        let pending_fail2 = processor
            .begin_decrypt_hybrid_pipeline(
                Box::new(Cursor::new(&encrypted_data)),
                ArcConfig::default(),
            )
            .unwrap();
        let result2 =
            pending_fail2.decrypt_to_writer(&sk, Box::new(&mut decrypted_data_fail2), None);
        assert!(result2.is_err());
    }

    #[test]
    fn test_hybrid_parallel_streaming_roundtrip_with_kdf() {
        let algorithm = get_test_algorithm();
        let processor = ParallelStreaming::new();
        let (pk, sk) = generate_test_keys();
        let kek_id = "test-kek-id-kdf".to_string();
        let plaintext = get_test_data(1024 * 1024); // 1 MiB

        let salt = b"salt-parallel-streaming";
        let info = b"info-parallel-streaming";

        let kdf_info = KdfInfo {
            kdf_algorithm: crate::common::algorithms::KdfKeyAlgorithm::HkdfSha256,
            salt: Some(salt.to_vec()),
            info: Some(info.to_vec()),
        };

        let kdf_algorithm = crate::common::algorithms::KdfKeyAlgorithm::HkdfSha256;

        use crate::common::DerivationWrapper;
        let mut encrypted_data = Vec::new();
        let reader = Box::new(Cursor::new(&plaintext));
        let writer = Box::new(&mut encrypted_data);

        let config = HybridConfig {
            algorithm: Cow::Borrowed(&algorithm),
            public_key: Cow::Borrowed(&pk),
            kek_id: kek_id.clone(),
            signer: None,
            aad: None,
            derivation_config: Some(DerivationSet {
                derivation_info: DerivationInfo::Kdf(kdf_info),
                wrapper: DerivationWrapper::Kdf(kdf_algorithm.into_kdf_key_wrapper()),
            }),
            config: ArcConfig::default(),
        };

        processor
            .encrypt_hybrid_pipeline(reader, writer, config)
            .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = processor
            .begin_decrypt_hybrid_pipeline(
                Box::new(Cursor::new(&encrypted_data)),
                ArcConfig::default(),
            )
            .unwrap();
        assert_eq!(pending.header().payload.kek_id(), Some(kek_id.as_str()));
        pending
            .decrypt_to_writer(&sk, Box::new(&mut decrypted_data), None)
            .unwrap();

        assert_eq!(plaintext, decrypted_data);
    }
}
