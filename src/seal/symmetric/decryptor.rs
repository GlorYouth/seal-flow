//! High-level API for building and executing symmetric decryption operations.
//!
//! 用于构建和执行对称解密操作的高级 API。

use crate::common::{config::ArcConfig, header::Header};
use crate::error::KeyManagementError;
use crate::keys::provider::KeyProvider;
use crate::keys::{SymmetricKey, TypedSymmetricKey};
use crate::seal::traits::{
    AsyncStreamingDecryptor, InMemoryDecryptor, ParallelStreamingDecryptor, StreamingDecryptor,
    WithAad,
};
use crate::symmetric::traits::{
    SymmetricAsynchronousPendingDecryptor, SymmetricAsynchronousProcessor,
    SymmetricOrdinaryPendingDecryptor, SymmetricOrdinaryProcessor,
    SymmetricParallelPendingDecryptor, SymmetricParallelProcessor,
    SymmetricParallelStreamingPendingDecryptor, SymmetricParallelStreamingProcessor,
    SymmetricStreamingPendingDecryptor, SymmetricStreamingProcessor,
};
use std::io::{Read, Write};
use std::sync::Arc;

// --- Builder ---

/// A builder for symmetric decryption operations.
///
/// 对称解密操作的构建器。
#[derive(Default)]
pub struct SymmetricDecryptorBuilder {
    config: ArcConfig,
    key_provider: Option<Arc<dyn KeyProvider>>,
    aad: Option<Vec<u8>>,
}

impl SymmetricDecryptorBuilder {
    /// Creates a new `SymmetricDecryptorBuilder`.
    ///
    /// 创建一个新的 `SymmetricDecryptorBuilder`。
    pub fn new(config: ArcConfig) -> Self {
        Self {
            config,
            key_provider: None,
            aad: None,
        }
    }

    /// Attaches a `KeyProvider` to the builder.
    ///
    /// 将一个 `KeyProvider` 附加到构建器上。
    pub fn with_key_provider(mut self, provider: Arc<dyn KeyProvider>) -> Self {
        self.key_provider = Some(provider);
        self
    }

    /// Sets the Associated Data (AAD) for this decryption operation.
    ///
    /// 为此解密操作设置关联数据 (AAD)。
    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }

    /// Configures decryption from an in-memory byte slice.
    ///
    /// 从内存中的字节切片配置解密。
    pub fn slice(self, ciphertext: &[u8]) -> crate::Result<PendingOrdinaryDecryptor> {
        let processor = crate::symmetric::ordinary::Ordinary::new();
        let mid_level_pending =
            processor.begin_decrypt_symmetric_in_memory(ciphertext, self.config)?;
        Ok(PendingOrdinaryDecryptor::new(
            mid_level_pending,
            self.key_provider,
            self.aad,
        ))
    }

    /// Configures parallel decryption from an in-memory byte slice.
    ///
    /// 从内存中的字节切片配置并行解密。
    pub fn slice_parallel(self, ciphertext: &[u8]) -> crate::Result<PendingParallelDecryptor> {
        let processor = crate::symmetric::parallel::Parallel::new();
        let mid_level_pending =
            processor.begin_decrypt_symmetric_parallel(ciphertext, self.config)?;
        Ok(PendingParallelDecryptor::new(
            mid_level_pending,
            self.key_provider,
            self.aad,
        ))
    }

    /// Configures decryption from a synchronous `Read` stream.
    ///
    /// 从同步 `Read` 流配置解密。
    pub fn reader<'a, R>(self, reader: R) -> crate::Result<PendingStreamingDecryptor<'a>>
    where
        R: Read + 'a,
    {
        let processor = crate::symmetric::streaming::Streaming::new();
        let mid_level_pending =
            processor.begin_decrypt_symmetric_from_stream(Box::new(reader), self.config)?;
        Ok(PendingStreamingDecryptor::new(
            mid_level_pending,
            self.key_provider,
            self.aad,
        ))
    }

    /// Configures parallel decryption from a synchronous `Read` stream.
    ///
    /// 从同步 `Read` 流配置并行解密。
    pub fn reader_parallel<'a, R>(
        self,
        reader: R,
    ) -> crate::Result<PendingParallelStreamingDecryptor<'a>>
    where
        R: Read + Send + 'a,
    {
        let processor = crate::symmetric::parallel_streaming::ParallelStreaming::new();
        let mid_level_pending =
            processor.begin_decrypt_symmetric_pipeline(Box::new(reader), self.config)?;
        Ok(PendingParallelStreamingDecryptor::new(
            mid_level_pending,
            self.key_provider,
            self.aad,
        ))
    }

    /// Begins an asynchronous streaming decryption operation.
    ///
    /// 开始一个异步流式解密操作。
    #[cfg(feature = "async")]
    pub async fn async_reader<'a, R>(
        self,
        reader: R,
    ) -> crate::Result<PendingAsyncStreamingDecryptor<'a>>
    where
        R: tokio::io::AsyncRead + Unpin + Send + 'a,
    {
        let processor = crate::symmetric::asynchronous::Asynchronous::new();
        let mid_level_pending = processor
            .begin_decrypt_symmetric_async(Box::new(reader), self.config)
            .await?;
        Ok(PendingAsyncStreamingDecryptor::new(
            mid_level_pending,
            self.key_provider,
            self.aad,
        ))
    }
}

// --- Pending Decryptors ---

pub trait PendingDecryptorTrait {
    fn header(&self) -> &Header;
}

impl<'a> PendingDecryptorTrait for Box<dyn SymmetricOrdinaryPendingDecryptor<'a> + 'a> {
    fn header(&self) -> &Header {
        self.as_ref().header()
    }
}

impl<'a> PendingDecryptorTrait for Box<dyn SymmetricParallelPendingDecryptor<'a> + 'a> {
    fn header(&self) -> &Header {
        self.as_ref().header()
    }
}

impl<'a> PendingDecryptorTrait for Box<dyn SymmetricStreamingPendingDecryptor<'a> + 'a> {
    fn header(&self) -> &Header {
        self.as_ref().header()
    }
}

impl<'a> PendingDecryptorTrait for Box<dyn SymmetricParallelStreamingPendingDecryptor<'a> + 'a> {
    fn header(&self) -> &Header {
        self.as_ref().header()
    }
}

#[cfg(feature = "async")]
impl<'a> PendingDecryptorTrait for Box<dyn SymmetricAsynchronousPendingDecryptor<'a> + Send + 'a> {
    fn header(&self) -> &Header {
        self.as_ref().header()
    }
}

pub struct PendingDecryptor<T> {
    inner: T,
    aad: Option<Vec<u8>>,
    key_provider: Option<Arc<dyn KeyProvider>>,
}

impl<T> PendingDecryptor<T>
where
    T: PendingDecryptorTrait,
{
    fn new(inner: T, key_provider: Option<Arc<dyn KeyProvider>>, aad: Option<Vec<u8>>) -> Self {
        Self {
            inner,
            aad,
            key_provider,
        }
    }

    fn resolve_symmetric_key(&self) -> crate::Result<TypedSymmetricKey> {
        let provider = self
            .key_provider
            .as_ref()
            .ok_or(KeyManagementError::ProviderMissing)?;
        let key_id = self.key_id().ok_or(KeyManagementError::KeyIdMissing)?;
        provider.get_symmetric_key(key_id).map_err(Into::into)
    }

    /// Returns the key ID from the header.
    ///
    /// 从标头返回密钥 ID。
    pub fn key_id(&self) -> Option<&str> {
        self.header().payload.key_id()
    }

    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    pub fn extra_data(&self) -> Option<&[u8]> {
        self.header().extra_data()
    }
}

impl<T> WithAad for PendingDecryptor<T> {
    fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }
}

/// A pending ordinary symmetric decryptor.
pub type PendingOrdinaryDecryptor<'a> =
    PendingDecryptor<Box<dyn SymmetricOrdinaryPendingDecryptor<'a> + 'a>>;

impl<'a> PendingOrdinaryDecryptor<'a> {
    /// Decrypts in-memory data using an automatically resolved key.
    ///
    /// 使用自动解析的密钥解密内存中的数据。
    pub fn resolve_and_decrypt_to_vec(self) -> crate::Result<Vec<u8>> {
        let key = self.resolve_symmetric_key()?;
        self.with_key_to_vec(&key)
    }

    /// Decrypts in-memory data using the provided typed key.
    ///
    /// 使用提供的类型化密钥解密内存中的数据。
    pub fn with_key_to_vec(self, key: &TypedSymmetricKey) -> crate::Result<Vec<u8>> {
        self.inner.into_plaintext(key, self.aad)
    }

    /// Decrypts in-memory data using the provided key.
    ///
    /// 使用提供的密钥解密内存中的数据。
    pub fn with_untyped_key_to_vec(self, key: &SymmetricKey) -> crate::Result<Vec<u8>> {
        let key = key
            .clone()
            .into_typed(self.header().payload.symmetric_algorithm())?;
        self.with_key_to_vec(&key)
    }
}

impl<'a> InMemoryDecryptor for PendingOrdinaryDecryptor<'a> {
    type TypedKey = TypedSymmetricKey;
    type UntypedKey = SymmetricKey;

    fn resolve_and_decrypt_to_vec(self) -> crate::Result<Vec<u8>> {
        PendingOrdinaryDecryptor::resolve_and_decrypt_to_vec(self)
    }

    fn with_key_to_vec(self, key: &Self::TypedKey) -> crate::Result<Vec<u8>> {
        PendingOrdinaryDecryptor::with_key_to_vec(self, key)
    }

    fn with_untyped_key_to_vec(self, key: &Self::UntypedKey) -> crate::Result<Vec<u8>> {
        PendingOrdinaryDecryptor::with_untyped_key_to_vec(self, key)
    }
}

/// A pending parallel symmetric decryptor.
pub type PendingParallelDecryptor<'a> =
    PendingDecryptor<Box<dyn SymmetricParallelPendingDecryptor<'a> + 'a>>;

impl<'a> PendingParallelDecryptor<'a> {
    /// Decrypts in-memory data using an automatically resolved key.
    ///
    /// 使用自动解析的密钥解密内存中的数据。
    pub fn resolve_and_decrypt_to_vec(self) -> crate::Result<Vec<u8>> {
        let key = self.resolve_symmetric_key()?;
        self.with_key_to_vec(&key)
    }

    /// Decrypts in-memory data using the provided typed key.
    ///
    /// 使用提供的类型化密钥解密内存中的数据。
    pub fn with_key_to_vec(self, key: &TypedSymmetricKey) -> crate::Result<Vec<u8>> {
        self.inner.into_plaintext(key, self.aad)
    }

    /// Decrypts in-memory data using the provided key.
    ///
    /// 使用提供的密钥解密内存中的数据。
    pub fn with_untyped_key_to_vec(self, key: &SymmetricKey) -> crate::Result<Vec<u8>> {
        let key = key
            .clone()
            .into_typed(self.header().payload.symmetric_algorithm())?;
        self.with_key_to_vec(&key)
    }
}

impl<'a> InMemoryDecryptor for PendingParallelDecryptor<'a> {
    type TypedKey = TypedSymmetricKey;
    type UntypedKey = SymmetricKey;

    fn resolve_and_decrypt_to_vec(self) -> crate::Result<Vec<u8>> {
        PendingParallelDecryptor::resolve_and_decrypt_to_vec(self)
    }

    fn with_key_to_vec(self, key: &Self::TypedKey) -> crate::Result<Vec<u8>> {
        PendingParallelDecryptor::with_key_to_vec(self, key)
    }

    fn with_untyped_key_to_vec(self, key: &Self::UntypedKey) -> crate::Result<Vec<u8>> {
        PendingParallelDecryptor::with_untyped_key_to_vec(self, key)
    }
}

/// A pending streaming symmetric decryptor.
pub type PendingStreamingDecryptor<'a> =
    PendingDecryptor<Box<dyn SymmetricStreamingPendingDecryptor<'a> + 'a>>;

impl<'a> PendingStreamingDecryptor<'a> {
    /// Returns a decrypting reader using an automatically resolved key.
    ///
    /// 使用自动解析的密钥返回解密读取器。
    pub fn resolve_and_decrypt_to_reader<'s>(self) -> crate::Result<Box<dyn Read + 's>>
    where
        Self: 's,
    {
        let key = self.resolve_symmetric_key()?;
        self.with_key_to_reader(&key)
    }

    /// Returns a decrypting reader using the provided typed key.
    ///
    /// 使用提供的类型化密钥返回解密读取器。
    pub fn with_key_to_reader<'s>(
        self,
        key: &TypedSymmetricKey,
    ) -> crate::Result<Box<dyn Read + 's>>
    where
        Self: 's,
    {
        self.inner.into_decryptor(key, self.aad)
    }

    /// Returns a decrypting reader using the provided key.
    ///
    /// 使用提供的密钥返回解密读取器。
    pub fn with_untyped_key_to_reader<'s>(
        self,
        key: &SymmetricKey,
    ) -> crate::Result<Box<dyn Read + 's>>
    where
        Self: 's,
    {
        let key = key
            .clone()
            .into_typed(self.header().payload.symmetric_algorithm())?;
        self.with_key_to_reader(&key)
    }
}

impl<'a> StreamingDecryptor for PendingStreamingDecryptor<'a> {
    type TypedKey = TypedSymmetricKey;
    type UntypedKey = SymmetricKey;

    fn resolve_and_decrypt_to_reader<'s>(self) -> crate::Result<Box<dyn Read + 's>>
    where
        Self: 's,
    {
        PendingStreamingDecryptor::resolve_and_decrypt_to_reader(self)
    }

    fn with_key_to_reader<'s>(
        self,
        key: &Self::TypedKey,
    ) -> crate::Result<Box<dyn Read + 's>>
    where
        Self: 's,
    {
        PendingStreamingDecryptor::with_key_to_reader(self, key)
    }

    fn with_untyped_key_to_reader<'s>(
        self,
        key: &Self::UntypedKey,
    ) -> crate::Result<Box<dyn Read + 's>>
    where
        Self: 's,
    {
        PendingStreamingDecryptor::with_untyped_key_to_reader(self, key)
    }
}

/// A pending parallel streaming symmetric decryptor.
pub type PendingParallelStreamingDecryptor<'a> =
    PendingDecryptor<Box<dyn SymmetricParallelStreamingPendingDecryptor<'a> + 'a>>;

impl<'a> PendingParallelStreamingDecryptor<'a> {
    /// Decrypts to a writer using an automatically resolved key.
    ///
    /// 使用自动解析的密钥解密到写入器。
    pub fn resolve_and_decrypt_to_writer<W: Write + Send + 'a>(
        self,
        writer: W,
    ) -> crate::Result<()> {
        let key = self.resolve_symmetric_key()?;
        self.with_key_to_writer(&key, writer)
    }

    /// Decrypts to a writer using the provided typed key.
    ///
    /// 使用提供的类型化密钥解密到写入器。
    pub fn with_key_to_writer<W: Write + Send + 'a>(
        self,
        key: &TypedSymmetricKey,
        writer: W,
    ) -> crate::Result<()> {
        self.inner
            .decrypt_to_writer(key, Box::new(writer), self.aad)
    }

    /// Decrypts to a writer using the provided key.
    ///
    /// 使用提供的密钥解密到写入器。
    pub fn with_untyped_key_to_writer<W: Write + Send + 'a>(
        self,
        key: &SymmetricKey,
        writer: W,
    ) -> crate::Result<()> {
        let key = key
            .clone()
            .into_typed(self.header().payload.symmetric_algorithm())?;
        self.with_key_to_writer(&key, writer)
    }
}

impl<'a> ParallelStreamingDecryptor for PendingParallelStreamingDecryptor<'a> {
    type TypedKey = TypedSymmetricKey;
    type UntypedKey = SymmetricKey;

    fn resolve_and_decrypt_to_writer<W: Write + Send + 'static>(
        self,
        writer: W,
    ) -> crate::Result<()> {
        PendingParallelStreamingDecryptor::resolve_and_decrypt_to_writer(self, writer)
    }

    fn with_key_to_writer<W: Write + Send + 'static>(
        self,
        key: &Self::TypedKey,
        writer: W,
    ) -> crate::Result<()> {
        PendingParallelStreamingDecryptor::with_key_to_writer(self, key, writer)
    }

    fn with_untyped_key_to_writer<W: Write + Send + 'static>(
        self,
        key: &Self::UntypedKey,
        writer: W,
    ) -> crate::Result<()> {
        PendingParallelStreamingDecryptor::with_untyped_key_to_writer(self, key, writer)
    }
}

/// A pending asynchronous streaming symmetric decryptor.
#[cfg(feature = "async")]
pub type PendingAsyncStreamingDecryptor<'a> =
    PendingDecryptor<Box<dyn SymmetricAsynchronousPendingDecryptor<'a> + Send + 'a>>;

#[cfg(feature = "async")]
impl<'a> PendingAsyncStreamingDecryptor<'a> {
    /// [Async] Returns a decrypting reader using an automatically resolved key.
    ///
    /// [异步] 使用自动解析的密钥返回解密读取器。
    pub async fn resolve_and_decrypt_to_async_reader<'s>(
        self,
    ) -> crate::Result<Box<dyn tokio::io::AsyncRead + Unpin + Send + 's>>
    where
        Self: 's,
    {
        let key = self.resolve_symmetric_key()?;
        self.with_key_to_async_reader(&key).await
    }

    /// [Async] Returns a decrypting reader using the provided typed key.
    ///
    /// [异步] 使用提供的类型化密钥返回解密读取器。
    pub async fn with_key_to_async_reader<'s>(
        self,
        key: &TypedSymmetricKey,
    ) -> crate::Result<Box<dyn tokio::io::AsyncRead + Unpin + Send + 's>>
    where
        Self: 's,
    {
        self.inner.into_decryptor(key, self.aad).await
    }

    /// [异步] 使用提供的密钥返回解密读取器。
    pub async fn with_untyped_key_to_async_reader<'s>(
        self,
        key: &SymmetricKey,
    ) -> crate::Result<Box<dyn tokio::io::AsyncRead + Unpin + Send + 's>>
    where
        Self: 's,
    {
        let key = key
            .clone()
            .into_typed(self.header().payload.symmetric_algorithm())?;
        self.with_key_to_async_reader(&key).await
    }
}

#[cfg(feature = "async")]
#[async_trait::async_trait]
impl<'a> AsyncStreamingDecryptor for PendingAsyncStreamingDecryptor<'a> {
    type TypedKey = TypedSymmetricKey;
    type UntypedKey = SymmetricKey;

    async fn resolve_and_decrypt_to_reader<'s>(
        self,
    ) -> crate::Result<Box<dyn tokio::io::AsyncRead + Unpin + Send + 's>>
    where
        Self: 's,
    {
        self.resolve_and_decrypt_to_async_reader().await
    }

    async fn with_key_to_reader<'s>(
        self,
        key: &Self::TypedKey,
    ) -> crate::Result<Box<dyn tokio::io::AsyncRead + Unpin + Send + 's>>
    where
        Self: 's,
    {
        self.with_key_to_async_reader(key).await
    }

    async fn with_untyped_key_to_reader<'s>(
        self,
        key: &Self::UntypedKey,
    ) -> crate::Result<Box<dyn tokio::io::AsyncRead + Unpin + Send + 's>>
    where
        Self: 's,
    {
        self.with_untyped_key_to_async_reader(key).await
    }
}
