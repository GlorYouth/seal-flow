//! Implements a parallel streaming hybrid encryption/decryption scheme.
//!
//! 实现并行流式混合加解密方案。

use super::common::create_header;
use super::traits::{HybridParallelStreamingPendingDecryptor, HybridParallelStreamingProcessor};
use crate::algorithms::definitions::hybrid::HybridAlgorithmWrapper;
use crate::algorithms::traits::HybridAlgorithm as HybridAlgorithmTrait;
use crate::body::traits::ParallelStreamingBodyProcessor;
use crate::common::header::{Header, HeaderPayload};
use crate::common::{DerivationSet, SignerSet};
use crate::error::{Error, FormatError, Result};
use crate::hybrid::pending::PendingDecryptor;
use crate::keys::{TypedAsymmetricPrivateKey, TypedAsymmetricPublicKey, TypedSymmetricKey};
use seal_crypto::zeroize::Zeroizing;
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
        algorithm: &HybridAlgorithmWrapper,
        public_key: &TypedAsymmetricPublicKey,
        reader: Box<dyn Read + Send + 'a>,
        mut writer: Box<dyn Write + Send + 'a>,
        kek_id: String,
        signer: Option<SignerSet>,
        aad: Option<&[u8]>,
        derivation_config: Option<DerivationSet>,
    ) -> Result<()> {
        let (info, deriver_fn) = derivation_config
            .map(|d| (d.derivation_info, d.deriver_fn))
            .unzip();

        let (header, base_nonce, shared_secret) =
            create_header(algorithm, public_key, kek_id, signer, aad, info)?;

        let dek = if let Some(f) = deriver_fn {
            f(&shared_secret)?
        } else {
            shared_secret
        };

        let header_bytes = header.encode_to_vec()?;
        writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&header_bytes)?;

        let algo = algorithm.symmetric_algorithm().clone_box_symmetric();
        ParallelStreamingBodyProcessor::encrypt_body_pipeline(
            &algo, dek, base_nonce, reader, writer, aad,
        )
    }

    fn begin_decrypt_hybrid_pipeline<'a>(
        &self,
        mut reader: Box<dyn Read + Send + 'a>,
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
        aad: Option<&[u8]>,
    ) -> Result<()> {
        let reader = self.source;
        let (encapsulated_key, base_nonce, derivation_info) = match &self.header.payload {
            HeaderPayload::Hybrid {
                stream_info: Some(info),
                encrypted_dek,
                derivation_info,
                ..
            } => (
                Zeroizing::new(encrypted_dek.clone()),
                info.base_nonce,
                derivation_info.clone(),
            ),
            _ => return Err(Error::Format(FormatError::InvalidHeader)),
        };

        let shared_secret = self
            .algorithm
            .asymmetric_algorithm()
            .decapsulate_key(sk, &encapsulated_key)?;

        // Derive key if a deriver function is specified
        // 如果指定了派生器，则派生密钥
        let dek = if let Some(info) = derivation_info {
            info.derive_key(&shared_secret)?
        } else {
            shared_secret
        };

        let dek = TypedSymmetricKey::from_bytes(
            dek.as_slice(),
            self.algorithm.symmetric_algorithm().algorithm(),
        )?;

        let algo = self.algorithm.symmetric_algorithm().clone_box_symmetric();
        ParallelStreamingBodyProcessor::decrypt_body_pipeline(
            &algo, dek, base_nonce, reader, writer, aad,
        )
    }

    fn header(&self) -> &Header {
        &self.header
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::definitions::{
        asymmetric::Rsa2048Sha256Wrapper, hybrid::HybridAlgorithmWrapper,
        symmetric::Aes256GcmWrapper,
    };
    use crate::algorithms::traits::AsymmetricAlgorithm;
    use crate::common::header::{DerivationInfo, KdfInfo};
    use crate::common::DerivationSet;
    use crate::keys::{TypedAsymmetricPublicKey, TypedSymmetricKey};
    use seal_crypto::prelude::KeyBasedDerivation;
    use seal_crypto::schemes::kdf::hkdf::HkdfSha256;
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
        processor
            .encrypt_hybrid_pipeline(
                &algorithm,
                &pk,
                reader,
                writer,
                kek_id.clone(),
                None,
                None,
                None,
            )
            .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = processor
            .begin_decrypt_hybrid_pipeline(Box::new(Cursor::new(&encrypted_data)))
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
        processor
            .encrypt_hybrid_pipeline(
                &algorithm,
                &pk,
                reader,
                writer,
                kek_id.clone(),
                None,
                None,
                None,
            )
            .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = processor
            .begin_decrypt_hybrid_pipeline(Box::new(Cursor::new(&encrypted_data)))
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
        processor
            .encrypt_hybrid_pipeline(
                &algorithm,
                &pk,
                reader,
                writer,
                kek_id.clone(),
                None,
                None,
                None,
            )
            .unwrap();

        // Tamper
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        encrypted_data[header_len + 10] ^= 1;

        let mut decrypted_data = Vec::new();
        let pending = processor
            .begin_decrypt_hybrid_pipeline(Box::new(Cursor::new(&encrypted_data)))
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
        processor
            .encrypt_hybrid_pipeline(
                &algorithm,
                &pk,
                reader,
                writer,
                kek_id.clone(),
                None,
                None,
                None,
            )
            .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = processor
            .begin_decrypt_hybrid_pipeline(Box::new(Cursor::new(&encrypted_data)))
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
        let aad = b"parallel streaming aad";

        let mut encrypted_data = Vec::new();
        let reader = Box::new(Cursor::new(&plaintext));
        let writer = Box::new(&mut encrypted_data);
        processor
            .encrypt_hybrid_pipeline(
                &algorithm,
                &pk,
                reader,
                writer,
                "test_kek_id_aad".to_string(),
                None,
                Some(aad),
                None,
            )
            .unwrap();

        // Decrypt with correct AAD
        let mut decrypted_data = Vec::new();
        let pending = processor
            .begin_decrypt_hybrid_pipeline(Box::new(Cursor::new(&encrypted_data)))
            .unwrap();
        assert_eq!(pending.header().payload.kek_id(), Some("test_kek_id_aad"));
        pending
            .decrypt_to_writer(&sk, Box::new(&mut decrypted_data), Some(aad))
            .unwrap();
        assert_eq!(plaintext, decrypted_data);

        // Decrypt with wrong AAD fails
        let mut decrypted_data_fail = Vec::new();
        let pending_fail = processor
            .begin_decrypt_hybrid_pipeline(Box::new(Cursor::new(&encrypted_data)))
            .unwrap();
        let result = pending_fail.decrypt_to_writer(
            &sk,
            Box::new(&mut decrypted_data_fail),
            Some(b"wrong aad"),
        );
        assert!(result.is_err());

        // Decrypt with no AAD fails
        let mut decrypted_data_fail2 = Vec::new();
        let pending_fail2 = processor
            .begin_decrypt_hybrid_pipeline(Box::new(Cursor::new(&encrypted_data)))
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
        let output_len = 32;

        let kdf_info = KdfInfo {
            kdf_algorithm: crate::common::algorithms::KdfAlgorithm::HkdfSha256,
            salt: Some(salt.to_vec()),
            info: Some(info.to_vec()),
            output_len,
        };

        let deriver = HkdfSha256::default();
        let kdf_fn = Box::new(move |ikm: &TypedSymmetricKey| {
            let dk = deriver.derive(ikm.as_ref(), Some(salt), Some(info), output_len as usize)?;
            TypedSymmetricKey::from_bytes(dk.as_bytes(), ikm.algorithm())
        });

        let mut encrypted_data = Vec::new();
        let reader = Box::new(Cursor::new(&plaintext));
        let writer = Box::new(&mut encrypted_data);
        processor
            .encrypt_hybrid_pipeline(
                &algorithm,
                &pk,
                reader,
                writer,
                kek_id.clone(),
                None,
                None,
                Some(DerivationSet {
                    derivation_info: DerivationInfo::Kdf(kdf_info),
                    deriver_fn: kdf_fn,
                }),
            )
            .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = processor
            .begin_decrypt_hybrid_pipeline(Box::new(Cursor::new(&encrypted_data)))
            .unwrap();
        assert_eq!(pending.header().payload.kek_id(), Some(kek_id.as_str()));
        pending
            .decrypt_to_writer(&sk, Box::new(&mut decrypted_data), None)
            .unwrap();

        assert_eq!(plaintext, decrypted_data);
    }
}
