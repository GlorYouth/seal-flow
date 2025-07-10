//! Synchronous, streaming hybrid encryption and decryption implementation.
//!
//! 同步、流式混合加密和解密实现。
use super::common::create_header;
use super::traits::{HybridStreamingPendingDecryptor, HybridStreamingProcessor};
use crate::algorithms::traits::HybridAlgorithm as HybridAlgorithmTrait;
use crate::body::streaming::{DecryptorImpl, EncryptorImpl};
use crate::common::header::{Header, HeaderPayload};
use crate::common::{DerivationSet, SignerSet};
use crate::error::{Error, FormatError, Result};
use crate::hybrid::pending::PendingDecryptor;
use crate::keys::{AsymmetricPrivateKey, TypedAsymmetricPublicKey, TypedSymmetricKey};
use seal_crypto::zeroize::Zeroizing;
use std::io::{Read, Write};

/// Implements `std::io::Write` for synchronous, streaming hybrid encryption.
pub struct Encryptor<W: Write> {
    inner: EncryptorImpl<W>,
}

impl<W: Write> Encryptor<W> {
    pub fn new<H: HybridAlgorithmTrait>(
        mut writer: W,
        algorithm: &H,
        public_key: &TypedAsymmetricPublicKey,
        kek_id: String,
        signer: Option<SignerSet>,
        aad: Option<&[u8]>,
        derivation_config: Option<DerivationSet>,
    ) -> Result<Self> {
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

        let algo = algorithm.symmetric_algorithm();
        let inner = EncryptorImpl::new(writer, algo.clone_box_symmetric(), dek, base_nonce, aad)?;
        Ok(Self { inner })
    }

    pub fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    pub fn finish(self) -> Result<()> {
        self.inner.finish()
    }
}

/// Implements `std::io::Read` for synchronous, streaming hybrid decryption.
pub struct Decryptor<R: Read> {
    inner: DecryptorImpl<R>,
}

impl<R: Read> Read for Decryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

pub struct Streaming<'h, H: HybridAlgorithmTrait> {
    algorithm: &'h H,
}

impl<'h, H: HybridAlgorithmTrait> Streaming<'h, H> {
    pub fn new(algorithm: &'h H) -> Self {
        Self { algorithm }
    }
}

impl<'h, H: HybridAlgorithmTrait> HybridStreamingProcessor for Streaming<'h, H> {
    fn encrypt_hybrid_to_stream<'a>(
        &self,
        public_key: &TypedAsymmetricPublicKey,
        writer: Box<dyn Write + 'a>,
        kek_id: String,
        signer: Option<SignerSet>,
        aad: Option<&'a [u8]>,
        derivation_config: Option<DerivationSet>,
    ) -> Result<Box<dyn Write + 'a>> {
        let encryptor = Encryptor::new(
            writer,
            self.algorithm,
            public_key,
            kek_id,
            signer,
            aad,
            derivation_config,
        )?;
        Ok(Box::new(StreamEncryptor {
            encryptor: Some(encryptor),
            _marker: std::marker::PhantomData,
        }))
    }

    fn begin_decrypt_hybrid_from_stream<'a>(
        &self,
        mut reader: Box<dyn Read + 'a>,
    ) -> Result<Box<dyn HybridStreamingPendingDecryptor<'a> + 'a>> {
        let header = Header::decode_from_prefixed_reader(&mut reader)?;

        let pending = PendingDecryptor {
            source: reader,
            header,
            algorithm: self.algorithm.clone(),
        };

        Ok(Box::new(pending))
    }
}

impl<'a, H> HybridStreamingPendingDecryptor<'a> for PendingDecryptor<Box<dyn Read + 'a>, H>
where
    H: HybridAlgorithmTrait,
{
    fn into_decryptor(
        self: Box<Self>,
        sk: &AsymmetricPrivateKey,
        aad: Option<&'a [u8]>,
    ) -> Result<Box<dyn Read + 'a>> {
        let reader = self.source;

        let (encapsulated_key, base_nonce, derivation_info) = match self.header.payload {
            HeaderPayload::Hybrid {
                encrypted_dek,
                stream_info: Some(info),
                derivation_info,
                ..
            } => (
                Zeroizing::new(encrypted_dek.clone()),
                info.base_nonce,
                derivation_info,
            ),
            _ => return Err(Error::Format(FormatError::InvalidHeader)),
        };

        let shared_secret = self
            .algorithm
            .asymmetric_algorithm()
            .decapsulate_key(sk, &encapsulated_key)?;

        let dek = if let Some(info) = derivation_info {
            info.derive_key(&shared_secret)?
        } else {
            shared_secret
        };

        let dek = TypedSymmetricKey::from_bytes(
            dek.as_slice(),
            self.algorithm.symmetric_algorithm().algorithm(),
        )?;

        let algo = self.algorithm.symmetric_algorithm();
        let inner = DecryptorImpl::new(reader, algo.clone_box_symmetric(), dek, base_nonce, aad);
        Ok(Box::new(Decryptor { inner }))
    }

    fn header(&self) -> &Header {
        &self.header
    }
}

struct StreamEncryptor<'a, W: Write> {
    encryptor: Option<Encryptor<W>>,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<W: Write> Write for StreamEncryptor<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.encryptor
            .as_mut()
            .unwrap()
            .write(buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<W: Write> Drop for StreamEncryptor<'_, W> {
    fn drop(&mut self) {
        if let Some(encryptor) = self.encryptor.take() {
            encryptor.finish().unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::definitions::{
        asymmetric::Rsa2048Sha256Wrapper, hybrid::HybridAlgorithm, symmetric::Aes256GcmWrapper,
    };
    use crate::algorithms::traits::AsymmetricAlgorithm;
    use crate::common::header::{DerivationInfo, KdfInfo};
    use crate::common::DerivationSet;
    use crate::keys::{AsymmetricPrivateKey, TypedAsymmetricPublicKey, TypedSymmetricKey};
    use seal_crypto::prelude::KeyBasedDerivation;
    use seal_crypto::schemes::kdf::hkdf::HkdfSha256;
    use std::io::Cursor;

    fn get_test_algorithm() -> HybridAlgorithm {
        HybridAlgorithm::new(
            Box::new(Rsa2048Sha256Wrapper::new()),
            Box::new(Aes256GcmWrapper::new()),
        )
    }

    fn generate_test_keys() -> (TypedAsymmetricPublicKey, AsymmetricPrivateKey) {
        Rsa2048Sha256Wrapper::new()
            .generate_keypair()
            .unwrap()
            .into_keypair()
    }

    fn test_hybrid_streaming_roundtrip(plaintext: &[u8], aad: Option<&[u8]>, use_kdf: bool) {
        let algorithm = get_test_algorithm();
        let processor = Streaming::new(&algorithm);
        let (pk, sk) = generate_test_keys();
        let kek_id = "test_kek_id".to_string();

        let derivation_config = if use_kdf {
            let salt = b"salt-stream";
            let info = b"info-stream";
            let output_len = 32;

            let kdf_info = KdfInfo {
                kdf_algorithm: crate::common::algorithms::KdfAlgorithm::HkdfSha256,
                salt: Some(salt.to_vec()),
                info: Some(info.to_vec()),
                output_len,
            };

            let deriver = HkdfSha256::default();
            let deriver_fn = Box::new(move |ikm: &TypedSymmetricKey| {
                deriver
                    .derive(ikm.as_ref(), Some(salt), Some(info), output_len as usize)
                    .map(|dk| TypedSymmetricKey::from_bytes(dk.as_bytes(), ikm.algorithm()))?
            });

            Some(DerivationSet {
                derivation_info: DerivationInfo::Kdf(kdf_info),
                deriver_fn,
            })
        } else {
            None
        };

        // Encrypt
        let mut encrypted_data = Vec::new();
        let writer = Box::new(&mut encrypted_data);
        let mut encryptor = processor
            .encrypt_hybrid_to_stream(
                &pk,
                writer,
                kek_id.clone(),
                None,
                aad,
                derivation_config,
            )
            .unwrap();

        encryptor.write_all(plaintext).unwrap();

        // Drop the encryptor to ensure finish is called via Drop trait.
        std::mem::drop(encryptor);

        // Decrypt
        let pending_decryptor = processor
            .begin_decrypt_hybrid_from_stream(Box::new(Cursor::new(&encrypted_data)))
            .unwrap();
        assert_eq!(
            pending_decryptor.header().payload.kek_id(),
            Some(kek_id.as_str())
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
        let aad = b"streaming hybrid context";
        test_hybrid_streaming_roundtrip(plaintext, Some(aad), false);
    }

    #[test]
    fn test_aad_roundtrip_with_kdf() {
        let plaintext = b"streaming hybrid data with aad and kdf";
        let aad = b"streaming hybrid context with kdf";
        test_hybrid_streaming_roundtrip(plaintext, Some(aad), true);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let algorithm = get_test_algorithm();
        let processor = Streaming::new(&algorithm);
        let (pk, sk) = generate_test_keys();
        let plaintext = b"some important data";

        let mut encrypted_data = Vec::new();
        let writer = Box::new(&mut encrypted_data);
        let mut encryptor = processor
            .encrypt_hybrid_to_stream(
                &pk,
                writer,
                "test_kek_id".to_string(),
                None,
                None,
                None,
            )
            .unwrap();
        encryptor.write_all(plaintext).unwrap();
        std::mem::drop(encryptor);

        // Tamper with the ciphertext body
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        if encrypted_data.len() > header_len {
            encrypted_data[header_len] ^= 1;
        }

        let pending = processor
            .begin_decrypt_hybrid_from_stream(Box::new(Cursor::new(&encrypted_data)))
            .unwrap();
        let mut decryptor = pending.into_decryptor(&sk, None).unwrap();

        let result = decryptor.read_to_end(&mut Vec::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let algorithm = get_test_algorithm();
        let processor = Streaming::new(&algorithm);
        let (pk, _) = generate_test_keys();
        let plaintext = b"some important data";

        let mut encrypted_data = Vec::new();
        let writer = Box::new(&mut encrypted_data);
        let mut encryptor = processor
            .encrypt_hybrid_to_stream(
                &pk,
                writer,
                "test_kek_id".to_string(),
                None,
                None,
                None,
            )
            .unwrap();
        encryptor.write_all(plaintext).unwrap();
        std::mem::drop(encryptor);

        let (_, sk2) = generate_test_keys();
        let pending = processor
            .begin_decrypt_hybrid_from_stream(Box::new(Cursor::new(&encrypted_data)))
            .unwrap();
        let result = pending.into_decryptor(&sk2, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let algorithm = get_test_algorithm();
        let processor = Streaming::new(&algorithm);
        let (pk, sk) = generate_test_keys();
        let plaintext = b"some important data";
        let aad = b"some aad";
        let wrong_aad = b"wrong aad";

        let mut encrypted_data = Vec::new();
        let writer = Box::new(&mut encrypted_data);
        let mut encryptor = processor
            .encrypt_hybrid_to_stream(
                &pk,
                writer,
                "test_kek_id".to_string(),
                None,
                Some(aad),
                None,
            )
            .unwrap();
        encryptor.write_all(plaintext).unwrap();
        std::mem::drop(encryptor);

        let pending = processor
            .begin_decrypt_hybrid_from_stream(Box::new(Cursor::new(&encrypted_data)))
            .unwrap();
        let mut decryptor = pending.into_decryptor(&sk, Some(wrong_aad)).unwrap();

        let result = decryptor.read_to_end(&mut Vec::new());
        assert!(result.is_err());
    }
}
