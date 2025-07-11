use crate::common::header::Header;
use crate::error::{FormatError, KeyManagementError};
use crate::hybrid::traits::{HybridAsynchronousPendingDecryptor, HybridOrdinaryPendingDecryptor, HybridOrdinaryProcessor, HybridParallelPendingDecryptor, HybridParallelProcessor, HybridParallelStreamingPendingDecryptor, HybridParallelStreamingProcessor, HybridStreamingPendingDecryptor, HybridStreamingProcessor};
use crate::keys::provider::KeyProvider;
use crate::keys::{AsymmetricPrivateKey, SignaturePublicKey};
use crate::seal::traits::{WithAad, WithVerificationKey};
use std::io::{Read, Write};
use std::sync::Arc;
use tokio::io::AsyncRead;
use crate::hybrid::traits::HybridAsynchronousProcessor;

/// A generic pending hybrid decryptor, waiting for configuration and private key.
/// This struct unifies the logic for various decryption modes (in-memory, streaming, etc.).
///
/// 一个通用的、等待配置和私钥的待处理混合解密器。
/// 该结构统一了各种解密模式（内存中、流式等）的逻辑。
pub struct PendingDecryptor<T> {
    inner: T,
    aad: Option<Vec<u8>>,
    verification_key: Option<SignaturePublicKey>,
    key_provider: Option<Arc<dyn KeyProvider>>,
}

impl<T> WithAad for PendingDecryptor<T> {
    fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }
}

impl<T> WithVerificationKey for PendingDecryptor<T> {
    fn with_verification_key(mut self, verification_key: SignaturePublicKey) -> Self {
        self.verification_key = Some(verification_key);
        self
    }
}

impl<T> PendingDecryptor<T>
where
    T: PendingDecryptorTrait,
{
    /// Creates a new `PendingDecryptor` with the given inner implementation.
    ///
    /// 使用给定的内部实现创建一个新的 `PendingDecryptor`。
    fn new(inner: T, key_provider: Option<Arc<dyn KeyProvider>>) -> Self {
        Self {
            inner,
            aad: None,
            verification_key: None,
            key_provider,
        }
    }

    /// Returns a reference to the header.
    ///
    /// 返回对标头的引用。
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the Key-Encrypting-Key ID from the header.
    ///
    /// 从标头返回密钥加密密钥 (KEK) 的 ID。
    pub fn kek_id(&self) -> Option<&str> {
        self.header().payload.kek_id()
    }

    /// Returns the Signer-Key-ID from the header.
    ///
    /// 从标头返回签名者密钥的 ID。
    pub fn signer_key_id(&self) -> Option<&str> {
        self.header().payload.signer_key_id()
    }
}

pub trait PendingDecryptorTrait {
    fn header(&self) -> &Header;
}

impl<'a> PendingDecryptorTrait for Box<dyn HybridOrdinaryPendingDecryptor + 'a> {
    fn header(&self) -> &Header {
        self.as_ref().header()
    }
}

impl<'a> PendingDecryptorTrait for Box<dyn HybridParallelPendingDecryptor + 'a> {
    fn header(&self) -> &Header {
        self.as_ref().header()
    }
}

impl<'a> PendingDecryptorTrait for Box<dyn HybridStreamingPendingDecryptor<'a> + 'a> {
    fn header(&self) -> &Header {
        self.as_ref().header()
    }
}

impl<'a> PendingDecryptorTrait for Box<dyn HybridParallelStreamingPendingDecryptor<'a> + 'a> {
    fn header(&self) -> &Header {
        self.as_ref().header()
    }
}

#[cfg(feature = "async")]
impl<'a> PendingDecryptorTrait for Box<dyn HybridAsynchronousPendingDecryptor<'a> + Send + 'a> {
    fn header(&self) -> &Header {
        self.as_ref().header()
    }
}

/// A type alias for a pending in-memory hybrid decryptor.
///
/// 待处理内存混合解密器的类型别名。
pub type PendingInMemoryDecryptor<'a> =
    PendingDecryptor<Box<dyn HybridOrdinaryPendingDecryptor + 'a>>;

/// A type alias for a pending parallel in-memory hybrid decryptor.
///
/// 待处理并行内存混合解密器的类型别名。
pub type PendingInMemoryParallelDecryptor<'a> =
    PendingDecryptor<Box<dyn HybridParallelPendingDecryptor + 'a>>;
/// A type alias for a pending synchronous streaming hybrid decryptor.
///
/// 待处理同步流混合解密器的类型别名。
pub type PendingStreamingDecryptor<'a> =
    PendingDecryptor<Box<dyn HybridStreamingPendingDecryptor<'a> + 'a>>;
/// A type alias for a pending parallel streaming hybrid decryptor.
///
/// 待处理并行流混合解密器的类型别名。
pub type PendingParallelStreamingDecryptor<'a> =
    PendingDecryptor<Box<dyn HybridParallelStreamingPendingDecryptor<'a> + 'a>>;
/// A type alias for a pending asynchronous streaming hybrid decryptor.
///
/// 待处理异步流混合解密器的类型别名。
#[cfg(feature = "async")]
pub type PendingAsyncStreamingDecryptor<'a> =
    PendingDecryptor<Box<dyn HybridAsynchronousPendingDecryptor<'a> + Send + 'a>>;

/// A builder for hybrid decryption operations.
///
/// 混合解密操作的构建器。
#[derive(Default)]
pub struct HybridDecryptorBuilder {
    key_provider: Option<Arc<dyn KeyProvider>>,
}

impl HybridDecryptorBuilder {
    /// Creates a new `HybridDecryptorBuilder`.
    ///
    /// 创建一个新的 `HybridDecryptorBuilder`。
    pub fn new() -> Self {
        Self { key_provider: None }
    }

    /// Attaches a `KeyProvider` to the builder.
    ///
    /// When a `KeyProvider` is set, you can use the `resolve_and_decrypt`
    /// method on the pending decryptor to automatically handle key lookup.
    ///
    /// 将一个 `KeyProvider` 附加到构建器上。
    ///
    /// 设置 `KeyProvider` 后，您可以在待处理解密器上使用 `resolve_and_decrypt`
    /// 方法来自动处理密钥查找。
    pub fn with_key_provider(mut self, provider: Arc<dyn KeyProvider>) -> Self {
        self.key_provider = Some(provider);
        self
    }

    /// Configures decryption from an in-memory byte slice.
    ///
    /// 从内存中的字节切片配置解密。
    pub fn slice(self, ciphertext: &[u8]) -> crate::Result<PendingInMemoryDecryptor> {
        let processor = crate::hybrid::ordinary::Ordinary::new();
        let mid_level_pending = processor.begin_decrypt_hybrid_in_memory(ciphertext)?;
        Ok(PendingDecryptor::new(mid_level_pending, self.key_provider))
    }

    /// Configures parallel decryption from an in-memory byte slice.
    ///
    /// 从内存中的字节切片配置并行解密。
    pub fn slice_parallel(
        self,
        ciphertext: &[u8],
    ) -> crate::Result<PendingInMemoryParallelDecryptor> {
        let processor = crate::hybrid::parallel::Parallel::new();
        let mid_level_pending = processor.begin_decrypt_hybrid_parallel(ciphertext)?;
        Ok(PendingDecryptor::new(mid_level_pending, self.key_provider))
    }

    /// Configures decryption from a synchronous `Read` stream.
    ///
    /// 从同步 `Read` 流配置解密。
    pub fn reader<'a, R: Read + 'a>(
        self,
        reader: R,
    ) -> crate::Result<PendingStreamingDecryptor<'a>> {
        let processor = crate::hybrid::streaming::Streaming::new();
        let mid_level_pending =
            processor.begin_decrypt_hybrid_from_stream(Box::new(reader))?;
        Ok(PendingDecryptor::new(mid_level_pending, self.key_provider))
    }

    /// Configures parallel decryption from a synchronous `Read` stream.
    ///
    /// 从同步 `Read` 流配置并行解密。
    pub fn reader_parallel<'a, R: Read + Send + 'a>(
        self,
        reader: R,
    ) -> crate::Result<PendingParallelStreamingDecryptor<'a>> {
        let processor =
            crate::hybrid::parallel_streaming::ParallelStreaming::new();
        let mid_level_pending =
            processor.begin_decrypt_hybrid_pipeline(Box::new(reader))?;
        Ok(PendingDecryptor::new(mid_level_pending, self.key_provider))
    }

    /// [Async] Configures decryption from an asynchronous `Read` stream.
    ///
    /// [异步] 从异步 `Read` 流配置解密。
    #[cfg(feature = "async")]
    pub async fn async_reader<'a, R: AsyncRead + Unpin + Send + 'a>(
        self,
        reader: R,
    ) -> crate::Result<PendingAsyncStreamingDecryptor<'a>> {
        let processor = crate::hybrid::asynchronous::Asynchronous::new();

        let mid_level_pending = processor
            .begin_decrypt_hybrid_async(Box::new(reader))
            .await?;
        Ok(PendingDecryptor::new(mid_level_pending, self.key_provider))
    }
}

impl<'a> PendingInMemoryDecryptor<'a> {
    /// Automatically resolves keys using the attached `KeyProvider` and completes decryption.
    ///
    /// 使用附加的 `KeyProvider` 自动解析密钥并完成解密。
    pub fn resolve_and_decrypt(mut self) -> crate::Result<Vec<u8>> {
        let provider = self
            .key_provider
            .as_ref()
            .ok_or(KeyManagementError::ProviderMissing)?;

        if let Some(signer_key_id) = self.signer_key_id() {
            let verification_key = provider.get_signature_public_key(signer_key_id)?;
            self.verification_key = Some(verification_key);
        }

        let kek_id = self.kek_id().ok_or(KeyManagementError::KekIdNotFound)?;
        let private_key = provider.get_asymmetric_private_key(kek_id)?;

        self.with_key(private_key)
    }

    /// Supplies a private key directly from its wrapper for decryption
    ///
    /// 提供包装好的私钥以进行解密。
    pub fn with_key(self, key: AsymmetricPrivateKey) -> crate::Result<Vec<u8>> {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
        let typed_key = key.into_typed(self.header().payload.asymmetric_algorithm().ok_or(FormatError::InvalidHeader)?)?;
        self.inner.into_plaintext(&typed_key, self.aad.as_deref())
    }
}

impl<'a> PendingInMemoryParallelDecryptor<'a> {
    /// Automatically resolves keys using the attached `KeyProvider` and completes decryption.
    ///
    /// 使用附加的 `KeyProvider` 自动解析密钥并完成解密。
    pub fn resolve_and_decrypt(mut self) -> crate::Result<Vec<u8>> {
        let provider = self
            .key_provider
            .as_ref()
            .ok_or(KeyManagementError::ProviderMissing)?;

        if let Some(signer_key_id) = self.signer_key_id() {
            let verification_key = provider.get_signature_public_key(signer_key_id)?;
            self.verification_key = Some(verification_key);
        }

        let kek_id = self.kek_id().ok_or(KeyManagementError::KekIdNotFound)?;
        let private_key = provider.get_asymmetric_private_key(kek_id)?;

        self.with_key(private_key)
    }

    /// Supplies a private key directly from its wrapper for decryption
    ///
    /// 提供包装好的私钥以进行解密。
    pub fn with_key(self, key: AsymmetricPrivateKey) -> crate::Result<Vec<u8>> {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
        let typed_key = key.into_typed(self.header().payload.asymmetric_algorithm().ok_or(FormatError::InvalidHeader)?)?;
        self.inner.into_plaintext(&typed_key, self.aad.as_deref())
    }
}

impl<'a> PendingStreamingDecryptor<'a> {
    /// Automatically resolves keys using the attached `KeyProvider` and completes decryption.
    ///
    /// 使用附加的 `KeyProvider` 自动解析密钥并完成解密。
    pub fn resolve_and_decrypt(mut self) -> crate::Result<Box<dyn Read + 'a>> {
        let provider = self
            .key_provider
            .as_ref()
            .ok_or(KeyManagementError::ProviderMissing)?;

        if let Some(signer_key_id) = self.signer_key_id() {
            let verification_key = provider.get_signature_public_key(signer_key_id)?;
            self.verification_key = Some(verification_key);
        }

        let kek_id = self.kek_id().ok_or(KeyManagementError::KekIdNotFound)?;
        let private_key = provider.get_asymmetric_private_key(kek_id)?;

        self.with_key(private_key)
    }

    /// Supplies a private key directly from its wrapper for decryption
    ///
    /// 提供包装好的私钥以进行解密。
    pub fn with_key(self, key: AsymmetricPrivateKey) -> crate::Result<Box<dyn Read + 'a>> {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
        let typed_key = key.into_typed(self.header().payload.asymmetric_algorithm().ok_or(FormatError::InvalidHeader)?)?;
        self.inner.into_decryptor(&typed_key, self.aad.as_deref())
    }
}

impl<'a> PendingParallelStreamingDecryptor<'a> {
    /// Automatically resolves keys and decrypts the stream to the provided writer.
    ///
    /// 自动解析密钥并将流解密到提供的写入器。
    pub fn resolve_and_decrypt_to_writer<W: Write + Send + 'a>(
        mut self,
        writer: W,
    ) -> crate::Result<()> {
        let provider = self
            .key_provider
            .as_ref()
            .ok_or(KeyManagementError::ProviderMissing)?;

        if let Some(signer_key_id) = self.signer_key_id() {
            let verification_key = provider.get_signature_public_key(signer_key_id)?;
            self.verification_key = Some(verification_key);
        }

        let kek_id = self.kek_id().ok_or(KeyManagementError::KekIdNotFound)?;
        let private_key = provider.get_asymmetric_private_key(kek_id)?;

        self.with_key_to_writer(private_key, writer)
    }

    /// Supplies a private key directly from its wrapper for decryption
    ///
    /// 提供包装好的私钥以进行解密。
    pub fn with_key_to_writer<W: Write + Send + 'a>(
        self,
        key: AsymmetricPrivateKey,
        writer: W,
    ) -> crate::Result<()> {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
        let typed_key = key.into_typed(self.header().payload.asymmetric_algorithm().ok_or(FormatError::InvalidHeader)?)?;
        self.inner
            .decrypt_to_writer(&typed_key, Box::new(writer), self.aad.as_deref())
    }
}

#[cfg(feature = "async")]
impl<'a> PendingAsyncStreamingDecryptor<'a> {
    /// Automatically resolves keys and returns a decrypting async reader.
    ///
    /// 自动解析密钥并返回一个解密的异步读取器。
    pub async fn resolve_and_decrypt(
        mut self,
    ) -> crate::Result<Box<dyn AsyncRead + Unpin + Send + 'a>> {
        let provider = self
            .key_provider
            .as_ref()
            .ok_or(KeyManagementError::ProviderMissing)?;

        if let Some(signer_key_id) = self.signer_key_id() {
            let verification_key = provider.get_signature_public_key(signer_key_id)?;
            self.verification_key = Some(verification_key);
        }

        let kek_id = self.kek_id().ok_or(KeyManagementError::KekIdNotFound)?;
        let private_key = provider.get_asymmetric_private_key(kek_id)?;

        self.with_key(private_key).await
    }

    /// Supplies a private key directly from its wrapper for decryption
    ///
    /// 提供包装好的私钥以进行解密。
    pub async fn with_key(
        self,
        key: AsymmetricPrivateKey,
    ) -> crate::Result<Box<dyn AsyncRead + Unpin + Send + 'a>> {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
        
        let typed_key = key.into_typed(self.header().payload.asymmetric_algorithm().ok_or(FormatError::InvalidHeader)?)?;
        self.inner
            .into_decryptor(&typed_key, self.aad)
            .await
    }
}
