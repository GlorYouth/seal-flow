//! Synchronous, streaming hybrid encryption and decryption implementation.
//!
//! 同步、流式混合加密和解密实现。
use super::common::create_header;
use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::header::{Header, HeaderPayload};
use crate::common::{DerivationSet, PendingImpl, SignerSet};
use crate::error::{Error, FormatError, Result};
use crate::impls::streaming::{DecryptorImpl, EncryptorImpl};
use seal_crypto::prelude::Key;
use std::io::{self, Read, Write};

/// An `std::io::Write` adapter for streaming hybrid encryption.
///
/// 用于流式混合加密的 `std::io::Write` 适配器。
pub struct Encryptor<W: Write, A, S: SymmetricAlgorithm> {
    inner: EncryptorImpl<W, S>,
    _phantom: std::marker::PhantomData<(A, S)>,
}

impl<W, A, S> Encryptor<W, A, S>
where
    W: Write,
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    /// Creates a new streaming encryptor.
    ///
    /// This will perform the KEM encapsulate operation immediately to generate the DEK,
    /// and write the complete header to the underlying writer.
    ///
    /// 创建一个新的流式加密器。
    ///
    /// 这将立即执行 KEM 封装操作以生成 DEK，
    /// 并将完整的标头写入底层的 writer。
    pub fn new(
        mut writer: W,
        pk: &A::PublicKey,
        kek_id: String,
        signer: Option<SignerSet>,
        aad: Option<&[u8]>,
        derivation_config: Option<DerivationSet>,
    ) -> Result<Self> {
        let (info, deriver_fn) = derivation_config
            .map(|d| (d.derivation_info, d.deriver_fn))
            .unzip();

        // 1. Create header, nonce, and shared secret
        // 1. 创建标头、nonce 和共享密钥
        let (header, base_nonce, shared_secret) =
            create_header::<A, S>(pk, kek_id, signer, aad, info)?;

        // 2. Derive key if a deriver is specified
        // 2. 如果指定了派生器，则派生密钥
        let dek = if let Some(f) = deriver_fn {
            f(&shared_secret)?
        } else {
            shared_secret
        };

        // 3. Write header length and header to the writer
        // 3. 将标头长度和标头写入 writer
        let header_bytes = header.encode_to_vec()?;
        writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&header_bytes)?;

        let inner = EncryptorImpl::new(writer, Key::from_bytes(dek.as_slice())?, base_nonce, aad)?;

        Ok(Self {
            inner,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Finalizes the encryption stream.
    ///
    /// This method must be called to ensure that the last partial chunk of data is
    /// encrypted and the authentication tag is written to the underlying writer.
    ///
    /// 完成加密流。
    ///
    /// 必须调用此方法以确保最后的数据块被加密，
    /// 并且认证标签被写入底层的 writer。
    pub fn finish(self) -> Result<()> {
        self.inner.finish()
    }
}

impl<W: Write, A, S: SymmetricAlgorithm> Write for Encryptor<W, A, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A pending hybrid decryptor that has read the header and is waiting for the private key.
///
/// 一个已读取标头并等待私钥的待定混合解密器。
pub struct PendingDecryptor<R: Read> {
    reader: R,
    header: Header,
}

impl<R: Read> PendingDecryptor<R> {
    /// Creates a new `PendingDecryptor` by reading the header from the stream.
    ///
    /// 通过从流中读取标头来创建一个新的 `PendingDecryptor`。
    pub fn from_reader(mut reader: R) -> Result<Self> {
        let header = Header::decode_from_prefixed_reader(&mut reader)?;

        Ok(Self { reader, header })
    }

    /// Consumes the pending decryptor and returns a full `Decryptor` by providing the private key.
    ///
    /// 通过提供私钥来消费待定解密器并返回一个完整的 `Decryptor`。
    pub fn into_decryptor<A, S>(
        self,
        sk: &A::PrivateKey,
        aad: Option<&[u8]>,
    ) -> Result<Decryptor<R, A, S>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
    {
        let (encapsulated_key, chunk_size, base_nonce, derivation_info) = match self.header.payload
        {
            HeaderPayload::Hybrid {
                encrypted_dek,
                stream_info: Some(info),
                derivation_info,
                ..
            } => (
                encrypted_dek.clone(),
                info.chunk_size,
                info.base_nonce,
                derivation_info,
            ),
            _ => return Err(Error::Format(FormatError::InvalidHeader)),
        };

        let shared_secret = A::decapsulate(
            sk,
            &A::EncapsulatedKey::from_bytes(encapsulated_key.as_slice())?,
        )?;

        let dek = if let Some(info) = derivation_info {
            info.derive_key(&shared_secret)?
        } else {
            shared_secret
        };

        let key_material: S::Key = Key::from_bytes(dek.as_slice())?;
        let tag_len = S::TAG_SIZE;
        let encrypted_chunk_size = chunk_size as usize + tag_len;

        let inner = DecryptorImpl::new(
            self.reader,
            key_material,
            base_nonce,
            encrypted_chunk_size,
            aad,
        );

        Ok(Decryptor {
            inner,
            _phantom: std::marker::PhantomData,
        })
    }
}

/// Implements `std::io::Read` for synchronous, streaming hybrid decryption.
///
/// 为同步、流式混合解密实现 `std::io::Read`。
pub struct Decryptor<R: Read, A: AsymmetricAlgorithm, S: SymmetricAlgorithm> {
    inner: DecryptorImpl<R, S>,
    _phantom: std::marker::PhantomData<(A, S)>,
}

impl<R: Read, A, S> Read for Decryptor<R, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Read> PendingImpl for PendingDecryptor<R> {
    fn header(&self) -> &Header {
        &self.header
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::header::{DerivationInfo, KdfInfo};
    use crate::common::DerivationSet;
    use seal_crypto::prelude::{KeyBasedDerivation, KeyGenerator};
    use seal_crypto::schemes::asymmetric::traditional::rsa::Rsa2048;
    use seal_crypto::schemes::hash::Sha256;
    use seal_crypto::schemes::kdf::hkdf::HkdfSha256;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
    use seal_crypto::zeroize::Zeroizing;
    use std::io::Cursor;

    type TestKem = Rsa2048<Sha256>;
    type TestDek = Aes256Gcm;

    fn test_hybrid_streaming_roundtrip(plaintext: &[u8], aad: Option<&[u8]>, use_kdf: bool) {
        let (pk, sk) = TestKem::generate_keypair().unwrap();
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
            let deriver_fn = Box::new(move |ikm: &[u8]| {
                deriver
                    .derive(ikm, Some(salt), Some(info), output_len as usize)
                    .map(|dk| Zeroizing::new(dk.as_bytes().to_vec()))
                    .map_err(|e| e.into())
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
        let mut encryptor = Encryptor::<_, TestKem, TestDek>::new(
            &mut encrypted_data,
            &pk,
            kek_id.clone(),
            None,
            aad,
            derivation_config,
        )
        .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt
        let pending_decryptor =
            PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        assert_eq!(
            pending_decryptor.header().payload.kek_id(),
            Some(kek_id.as_str())
        );

        let mut decryptor = pending_decryptor
            .into_decryptor::<TestKem, TestDek>(&sk, aad)
            .unwrap();
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
        let (pk, sk) = TestKem::generate_keypair().unwrap();
        let plaintext = b"some important data";

        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, TestKem, TestDek>::new(
            &mut encrypted_data,
            &pk,
            "test_kek_id".to_string(),
            None,
            None,
            None,
        )
        .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Tamper with the ciphertext body
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        if encrypted_data.len() > header_len {
            encrypted_data[header_len] ^= 1;
        }

        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let mut decryptor = pending
            .into_decryptor::<TestKem, TestDek>(&sk, None)
            .unwrap();

        let result = decryptor.read_to_end(&mut Vec::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let (pk, _) = TestKem::generate_keypair().unwrap();
        let plaintext = b"some important data";

        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, TestKem, TestDek>::new(
            &mut encrypted_data,
            &pk,
            "test_kek_id".to_string(),
            None,
            None,
            None,
        )
        .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        let (_, sk2) = TestKem::generate_keypair().unwrap();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let result = pending.into_decryptor::<TestKem, TestDek>(&sk2, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let (pk, sk) = TestKem::generate_keypair().unwrap();
        let plaintext = b"some important data";
        let aad = b"some aad";
        let wrong_aad = b"wrong aad";

        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, TestKem, TestDek>::new(
            &mut encrypted_data,
            &pk,
            "test_kek_id".to_string(),
            None,
            Some(aad),
            None,
        )
        .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let mut decryptor = pending
            .into_decryptor::<TestKem, TestDek>(&sk, Some(wrong_aad))
            .unwrap();

        let result = decryptor.read_to_end(&mut Vec::new());
        assert!(result.is_err());
    }
}
