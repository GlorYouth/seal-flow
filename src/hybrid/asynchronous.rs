//! Asynchronous, streaming hybrid encryption and decryption implementation.
//!
//! 异步、流式混合加密和解密实现。
#![cfg(feature = "async")]

use super::common::create_header;
use crate::algorithms::traits::{
    HybridAlgorithm as HybridAlgorithmTrait, SymmetricAlgorithm as SymmetricAlgorithmTrait,
};
use crate::body::asynchronous::{DecryptorImpl, EncryptorImpl};
use crate::common::header::{Header, HeaderPayload};
use crate::common::{DerivationSet, SignerSet};
use crate::error::{Error, FormatError, Result};
use crate::hybrid::pending::PendingDecryptor;
use crate::hybrid::traits::{HybridAsynchronousPendingDecryptor, HybridAsynchronousProcessor};
use crate::keys::{AsymmetricPrivateKey, TypedAsymmetricPublicKey, TypedSymmetricKey};
use async_trait::async_trait;
use pin_project_lite::pin_project;
use seal_crypto::zeroize::Zeroizing;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

// --- Encryptor ---

pin_project! {
    /// An asynchronous, streaming hybrid encryptor.
    ///
    /// 一个异步的、流式的混合加密器。
    pub struct Encryptor<W: AsyncWrite> {
        #[pin]
        inner: EncryptorImpl<W>,
    }
}

impl<W: AsyncWrite + Unpin> Encryptor<W> {
    /// Creates a new `Encryptor`.
    ///
    /// This is not meant to be called directly. Use the `HybridAsynchronousProcessor` trait.
    /// The `new` function is not async because the trait method that returns this is not async.
    /// All async setup must be done before calling this.
    ///
    /// 创建一个新的 `Encryptor`。
    ///
    /// 这不应该被直接调用。请使用 `HybridAsynchronousProcessor` trait。
    /// `new` 函数不是异步的，因为返回此实例的 trait 方法不是异步的。
    /// 所有的异步设置必须在此之前完成。
    fn new(
        writer: W,
        key: TypedSymmetricKey,
        algorithm: Arc<dyn SymmetricAlgorithmTrait>,
        base_nonce: [u8; 12],
        aad: Option<&[u8]>,
    ) -> Self {
        let inner = EncryptorImpl::new(writer, Arc::new(key), algorithm, base_nonce, aad);
        Self { inner }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Encryptor<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

// --- Decryptor ---

pin_project! {
    /// An asynchronous, streaming hybrid decryptor.
    ///
    /// 一个异步的、流式的混合解密器。
    pub struct Decryptor<R: AsyncRead> {
        #[pin]
        inner: DecryptorImpl<R>,
    }
}

impl<R: AsyncRead + Unpin> Decryptor<R> {
    /// Creates a new `Decryptor`.
    ///
    /// This should not be called directly. Use `PendingDecryptor`.
    ///
    /// 创建一个新的 `Decryptor`。
    ///
    /// 不应直接调用此函数。请使用 `PendingDecryptor`。
    fn new(
        reader: R,
        key: TypedSymmetricKey,
        algorithm: Arc<dyn SymmetricAlgorithmTrait>,
        base_nonce: [u8; 12],
        aad: Option<&[u8]>,
    ) -> Self {
        let inner = DecryptorImpl::new(reader, Arc::new(key), algorithm, base_nonce, aad);
        Self { inner }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Decryptor<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl<'a, R, H> HybridAsynchronousPendingDecryptor<'a, R> for PendingDecryptor<R, H>
where
    R: AsyncRead + Send + Unpin + 'a,
    H: HybridAlgorithmTrait + Send + Sync,
{
    fn into_decryptor(
        self: Box<Self>,
        sk: &AsymmetricPrivateKey,
        aad: Option<&[u8]>,
    ) -> Result<Box<dyn AsyncRead + Send + Unpin + 'a>> {
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

        let dek = if let Some(info) = derivation_info {
            info.derive_key(&shared_secret)?
        } else {
            shared_secret
        };

        let dek = TypedSymmetricKey::from_bytes(
            dek.as_ref(),
            self.algorithm.symmetric_algorithm().algorithm(),
        )?;

        let algo = Arc::from(self.algorithm.symmetric_algorithm().clone_box_symmetric());
        let decryptor = Decryptor::new(self.source, dek, algo, base_nonce, aad);

        Ok(Box::new(decryptor))
    }

    fn header(&self) -> &Header {
        &self.header
    }
}

pub struct Asynchronous<'h, H: HybridAlgorithmTrait> {
    algorithm: &'h H,
}

impl<'h, H: HybridAlgorithmTrait> Asynchronous<'h, H> {
    pub fn new(algorithm: &'h H) -> Self {
        Self { algorithm }
    }
}

#[async_trait]
impl<'h, H: HybridAlgorithmTrait + Send + Sync> HybridAsynchronousProcessor
    for Asynchronous<'h, H>
{
    async fn encrypt_hybrid_async<'a>(
        &self,
        public_key: &TypedAsymmetricPublicKey,
        mut writer: Box<dyn AsyncWrite + Send + Unpin + 'a>,
        kek_id: String,
        signer: Option<SignerSet>,
        aad: Option<&'a [u8]>,
        derivation_config: Option<DerivationSet>,
    ) -> Result<Box<dyn AsyncWrite + Send + Unpin + 'a>> {
        let (info, deriver_fn) = derivation_config
            .map(|d| (d.derivation_info, d.deriver_fn))
            .unzip();

        let (header, base_nonce, shared_secret) =
            create_header(self.algorithm, public_key, kek_id, signer, aad, info)?;

        let dek = if let Some(f) = deriver_fn {
            f(&shared_secret)?
        } else {
            shared_secret
        };

        let dek = TypedSymmetricKey::from_bytes(
            dek.as_ref(),
            self.algorithm.symmetric_algorithm().algorithm(),
        )?;

        let header_bytes = header.encode_to_vec()?;

        writer
            .write_all(&(header_bytes.len() as u32).to_le_bytes())
            .await?;
        writer.write_all(&header_bytes).await?;
        writer.flush().await?;

        let algo = Arc::from(self.algorithm.symmetric_algorithm().clone_box_symmetric());
        Ok(Box::new(Encryptor::new(
            writer, dek, algo, base_nonce, aad,
        )))
    }

    async fn begin_decrypt_hybrid_async<'a, R>(
        &self,
        mut reader: R,
    ) -> Result<Box<dyn HybridAsynchronousPendingDecryptor<'a, R> + 'a>>
    where
        R: AsyncRead + Send + Unpin + 'a,
    {
        let header = Header::decode_from_prefixed_async_reader(&mut reader).await?;
        let pending = PendingDecryptor {
            source: reader,
            header,
            algorithm: self.algorithm.clone(),
        };
        Ok(Box::new(pending) as Box<dyn HybridAsynchronousPendingDecryptor<'a, R> + 'a>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::definitions::{
        asymmetric::Rsa2048Sha256Wrapper, hybrid::HybridAlgorithm,
        symmetric::Aes256GcmWrapper as SymAlgo,
    };
    use crate::algorithms::traits::AsymmetricAlgorithm;
    use crate::common::header::{DerivationInfo, KdfInfo};
    use crate::common::DEFAULT_CHUNK_SIZE;
    use crate::keys::{AsymmetricPrivateKey, TypedAsymmetricPublicKey};
    use seal_crypto::prelude::KeyBasedDerivation;
    use seal_crypto::schemes::kdf::hkdf::HkdfSha256;
    use std::io::Cursor;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn get_test_algorithm() -> HybridAlgorithm {
        HybridAlgorithm::new(
            Box::new(Rsa2048Sha256Wrapper::new()),
            Box::new(SymAlgo::new()),
        )
    }

    fn generate_test_keys() -> (TypedAsymmetricPublicKey, AsymmetricPrivateKey) {
        Rsa2048Sha256Wrapper::new()
            .generate_keypair()
            .unwrap()
            .into_keypair()
    }

    async fn test_hybrid_async_streaming_roundtrip(
        algorithm: &HybridAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) {
        let processor = Asynchronous::new(algorithm);
        let (pk, sk) = generate_test_keys();
        let kek_id = "test-rsa-key".to_string();

        // Encrypt
        let mut encrypted_data = Vec::new();
        {
            let writer = Box::new(&mut encrypted_data);
            let mut encryptor = processor
                .encrypt_hybrid_async(&pk, writer, kek_id.clone(), None, aad, None)
                .await
                .unwrap();

            encryptor.write_all(plaintext).await.unwrap();
            encryptor.shutdown().await.unwrap();
        }

        // Decrypt
        let reader = Box::new(Cursor::new(encrypted_data));
        let mut decryptor = {
            let pending = processor.begin_decrypt_hybrid_async(reader).await.unwrap();
            assert_eq!(pending.header().payload.kek_id(), Some(kek_id.as_str()));
            pending.into_decryptor(&sk, aad).unwrap()
        };

        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).await.unwrap();
        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[tokio::test]
    async fn test_roundtrip_long_message_async() {
        let algorithm = get_test_algorithm();
        let plaintext = b"This is a very long test message to test the async hybrid streaming encryption and decryption. It needs to be longer than a single chunk to ensure the chunking logic is working correctly.";
        test_hybrid_async_streaming_roundtrip(&algorithm, plaintext, None).await;
    }

    #[tokio::test]
    async fn test_roundtrip_empty_message_async() {
        let algorithm = get_test_algorithm();
        test_hybrid_async_streaming_roundtrip(&algorithm, b"", None).await;
    }

    #[tokio::test]
    async fn test_roundtrip_exact_chunk_size_async() {
        let algorithm = get_test_algorithm();
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];
        test_hybrid_async_streaming_roundtrip(&algorithm, &plaintext, None).await;
    }

    #[tokio::test]
    async fn test_aad_roundtrip_async() {
        let algorithm = get_test_algorithm();
        let plaintext = b"secret async hybrid message";
        let aad = b"public async hybrid context";
        test_hybrid_async_streaming_roundtrip(&algorithm, plaintext, Some(aad)).await;
    }

    #[tokio::test]
    async fn test_tampered_ciphertext_fails_async() {
        let algorithm = get_test_algorithm();
        let processor = Asynchronous::new(&algorithm);
        let (pk, sk) = generate_test_keys();
        let plaintext = b"some important data";

        // Encrypt
        let mut encrypted_data = Vec::new();
        {
            let writer = Box::new(&mut encrypted_data);
            let mut encryptor = processor
                .encrypt_hybrid_async(&pk, writer, "test-kek-id".to_string(), None, None, None)
                .await
                .unwrap();

            encryptor.write_all(plaintext).await.unwrap();
            encryptor.shutdown().await.unwrap();
        }

        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        if encrypted_data.len() > header_len {
            encrypted_data[header_len] ^= 1;
        }

        let reader = Box::new(Cursor::new(encrypted_data));
        let decryptor_result = {
            let pending = processor.begin_decrypt_hybrid_async(reader).await.unwrap();
            pending.into_decryptor(&sk, None)
        };

        let mut decryptor = decryptor_result.unwrap();
        let result = decryptor.read_to_end(&mut Vec::new()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_wrong_private_key_fails_async() {
        let algorithm = get_test_algorithm();
        let processor = Asynchronous::new(&algorithm);
        let (pk, _sk) = generate_test_keys();
        let (_pk2, sk2) = generate_test_keys();
        let plaintext = b"some data";

        // Encrypt
        let mut encrypted_data = Vec::new();
        {
            let writer = Box::new(&mut encrypted_data);
            let mut encryptor = processor
                .encrypt_hybrid_async(&pk, writer, "test_kek_id".to_string(), None, None, None)
                .await
                .unwrap();

            encryptor.write_all(plaintext).await.unwrap();
            encryptor.shutdown().await.unwrap();
        }

        let reader = Box::new(Cursor::new(encrypted_data));
        let decryptor_result = {
            let pending = processor.begin_decrypt_hybrid_async(reader).await.unwrap();
            pending.into_decryptor(&sk2, None)
        };

        assert!(
            decryptor_result.is_err(),
            "Decapsulation should fail with the wrong private key"
        );
    }

    #[tokio::test]
    async fn test_wrong_aad_fails_async() {
        let algorithm = get_test_algorithm();
        let processor = Asynchronous::new(&algorithm);
        let (pk, sk) = generate_test_keys();
        let plaintext = b"some data";
        let aad1 = b"correct async aad";
        let aad2 = b"wrong async aad";

        // Encrypt
        let mut encrypted_data = Vec::new();
        {
            let writer = Box::new(&mut encrypted_data);
            let mut encryptor = processor
                .encrypt_hybrid_async(&pk, writer, "key1".to_string(), None, Some(aad1), None)
                .await
                .unwrap();

            encryptor.write_all(plaintext).await.unwrap();
            encryptor.shutdown().await.unwrap();
        }

        // Decrypt with the wrong aad
        let reader1 = Box::new(Cursor::new(encrypted_data.clone()));
        let mut decryptor = {
            let pending = processor.begin_decrypt_hybrid_async(reader1).await.unwrap();
            pending.into_decryptor(&sk, Some(aad2)).unwrap()
        };
        let result = decryptor.read_to_end(&mut Vec::new()).await;
        assert!(result.is_err());

        // Decrypt with no aad
        let reader2 = Box::new(Cursor::new(encrypted_data));
        let mut decryptor2 = {
            let pending2 = processor.begin_decrypt_hybrid_async(reader2).await.unwrap();
            pending2.into_decryptor(&sk, None).unwrap()
        };
        let result2 = decryptor2.read_to_end(&mut Vec::new()).await;
        assert!(result2.is_err());
    }

    #[tokio::test]
    async fn test_roundtrip_with_kdf_async() {
        let algorithm = get_test_algorithm();
        let processor = Asynchronous::new(&algorithm);
        let (pk, sk) = generate_test_keys();
        let kek_id = "test-rsa-key-kdf".to_string();
        let plaintext = b"This is a test message with KDF in async streaming.";

        let salt = b"salt-async";
        let info = b"info-async";
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

        let derivation_set = DerivationSet {
            derivation_info: DerivationInfo::Kdf(kdf_info),
            deriver_fn: kdf_fn,
        };

        // Encrypt
        let mut encrypted_data = Vec::new();
        {
            let writer = Box::new(&mut encrypted_data);
            let mut encryptor = processor
                .encrypt_hybrid_async(&pk, writer, kek_id.clone(), None, None, Some(derivation_set))
                .await
                .unwrap();
            encryptor.write_all(plaintext).await.unwrap();
            encryptor.shutdown().await.unwrap();
        }

        // Decrypt
        let reader = Box::new(Cursor::new(encrypted_data));
        let mut decryptor = {
            let pending = processor.begin_decrypt_hybrid_async(reader).await.unwrap();
            pending.into_decryptor(&sk, None).unwrap()
        };
        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).await.unwrap();
        assert_eq!(plaintext.as_slice(), decrypted_data.as_slice());
    }
}
