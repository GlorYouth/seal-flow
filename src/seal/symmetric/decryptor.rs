//! High-level API for building and executing symmetric decryption operations.
//!
//! 用于构建和执行对称解密操作的高级 API。

use crate::common::header::Header;
use crate::error::KeyManagementError;
use crate::keys::provider::KeyProvider;
use crate::keys::SymmetricKey;
use crate::seal::traits::{PendingDecryptor as PendingDecryptorTrait, WithAad};
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
    key_provider: Option<Arc<dyn KeyProvider>>,
    aad: Option<Vec<u8>>,
}

impl SymmetricDecryptorBuilder {
    /// Creates a new `SymmetricDecryptorBuilder`.
    ///
    /// 创建一个新的 `SymmetricDecryptorBuilder`。
    pub fn new() -> Self {
        Self {
            ..Default::default()
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
        let mid_level_pending = processor.begin_decrypt_symmetric_in_memory(ciphertext)?;
        Ok(PendingOrdinaryDecryptor::new(
            mid_level_pending,
            self.key_provider,
            self.aad,
        ))
    }

    /// Configures parallel decryption from an in-memory byte slice.
    ///
    /// 从内存中的字节切片配置并行解密。
    pub fn slice_parallel(
        self,
        ciphertext: &[u8],
    ) -> crate::Result<PendingParallelDecryptor> {
        let processor = crate::symmetric::parallel::Parallel::new();
        let mid_level_pending = processor.begin_decrypt_symmetric_parallel(ciphertext)?;
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
            processor.begin_decrypt_symmetric_from_stream(Box::new(reader))?;
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
        let mid_level_pending = processor.begin_decrypt_symmetric_pipeline(Box::new(reader))?;
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
    pub async fn async_reader<'a, R>(self, reader: R) -> crate::Result<PendingAsyncStreamingDecryptor<'a>>
    where
        R: tokio::io::AsyncRead + Unpin + Send + 'a,
    {
        let processor = crate::symmetric::asynchronous::Asynchronous::new();
        let mid_level_pending = processor.begin_decrypt_symmetric_async(Box::new(reader)).await?;
        Ok(PendingAsyncStreamingDecryptor::new(
            mid_level_pending,
            self.key_provider,
            self.aad,
        ))
    }
}

// --- Pending Decryptors ---

/// A pending ordinary symmetric decryptor.
pub struct PendingOrdinaryDecryptor<'a> {
    inner: Box<dyn SymmetricOrdinaryPendingDecryptor + 'a>,
    aad: Option<Vec<u8>>,
    key_provider: Option<Arc<dyn KeyProvider>>,
}

impl<'a> PendingOrdinaryDecryptor<'a> {
    fn new(
        inner: Box<dyn SymmetricOrdinaryPendingDecryptor + 'a>,
        key_provider: Option<Arc<dyn KeyProvider>>,
        aad: Option<Vec<u8>>,
    ) -> Self {
        Self {
            inner,
            aad,
            key_provider,
        }
    }

    /// Returns the key ID from the header.
    ///
    /// 从标头返回密钥 ID。
    pub fn key_id(&self) -> Option<&str> {
        self.header().payload.key_id()
    }

    /// Decrypts in-memory data using an automatically resolved key.
    ///
    /// 使用自动解析的密钥解密内存中的数据。
    pub fn resolve_and_decrypt_to_vec(self) -> crate::Result<Vec<u8>> {
        let provider = self
            .key_provider
            .as_ref()
            .ok_or(KeyManagementError::ProviderMissing)?;
        let key_id = self.key_id().ok_or(KeyManagementError::KeyIdMissing)?;
        let key = provider.get_symmetric_key(key_id)?;
        self.with_key_to_vec(key)
    }

    /// Decrypts in-memory data using the provided key.
    ///
    /// 使用提供的密钥解密内存中的数据。
    pub fn with_key_to_vec(self, key: SymmetricKey) -> crate::Result<Vec<u8>> {
        let aad = self.aad.as_deref();
        let key = key.into_typed(self.inner.header().payload.symmetric_algorithm())?;
        self.inner.into_plaintext(key, aad)
    }
}

impl<'a> PendingDecryptorTrait for PendingOrdinaryDecryptor<'a> {
    fn header(&self) -> &Header {
        self.inner.header()
    }
}

impl<'a> WithAad for PendingOrdinaryDecryptor<'a> {
    fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }
}

/// A pending parallel symmetric decryptor.
pub struct PendingParallelDecryptor<'a> {
    inner: Box<dyn SymmetricParallelPendingDecryptor + 'a>,
    aad: Option<Vec<u8>>,
    key_provider: Option<Arc<dyn KeyProvider>>,
}

impl<'a> PendingParallelDecryptor<'a> {
    fn new(
        inner: Box<dyn SymmetricParallelPendingDecryptor + 'a>,
        key_provider: Option<Arc<dyn KeyProvider>>,
        aad: Option<Vec<u8>>,
    ) -> Self {
        Self {
            inner,
            aad,
            key_provider,
        }
    }

    /// Returns the key ID from the header.
    ///
    /// 从标头返回密钥 ID。
    pub fn key_id(&self) -> Option<&str> {
        self.header().payload.key_id()
    }

    /// Decrypts in-memory data using an automatically resolved key.
    ///
    /// 使用自动解析的密钥解密内存中的数据。
    pub fn resolve_and_decrypt_to_vec(self) -> crate::Result<Vec<u8>> {
        let provider = self
            .key_provider
            .as_ref()
            .ok_or(KeyManagementError::ProviderMissing)?;
        let key_id = self.key_id().ok_or(KeyManagementError::KeyIdMissing)?;
        let key = provider.get_symmetric_key(key_id)?;
        self.with_key_to_vec(key)
    }

    /// Decrypts in-memory data using the provided key.
    ///
    /// 使用提供的密钥解密内存中的数据。
    pub fn with_key_to_vec(self, key: SymmetricKey) -> crate::Result<Vec<u8>> {
        let aad = self.aad.as_deref();
        let key = key.into_typed(self.inner.header().payload.symmetric_algorithm())?;
        self.inner.into_plaintext(key, aad)
    }
}

impl<'a> PendingDecryptorTrait for PendingParallelDecryptor<'a> {
    fn header(&self) -> &Header {
        self.inner.header()
    }
}

impl<'a> WithAad for PendingParallelDecryptor<'a> {
    fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }
}

/// A pending streaming symmetric decryptor.
pub struct PendingStreamingDecryptor<'a> {
    inner: Box<dyn SymmetricStreamingPendingDecryptor + 'a>,
    aad: Option<Vec<u8>>,
    key_provider: Option<Arc<dyn KeyProvider>>,
}

impl<'a> PendingStreamingDecryptor<'a> {
    fn new(
        inner: Box<dyn SymmetricStreamingPendingDecryptor + 'a>,
        key_provider: Option<Arc<dyn KeyProvider>>,
        aad: Option<Vec<u8>>,
    ) -> Self {
        Self {
            inner,
            aad,
            key_provider,
        }
    }

    /// Returns the key ID from the header.
    ///
    /// 从标头返回密钥 ID。
    pub fn key_id(&self) -> Option<&str> {
        self.header().payload.key_id()
    }

    /// Returns a decrypting reader using an automatically resolved key.
    ///
    /// 使用自动解析的密钥返回解密读取器。
    pub fn resolve_and_decrypt_to_reader<'s>(self) -> crate::Result<Box<dyn Read + 's>>
    where
        Self: 's,
    {
        let provider = self
            .key_provider
            .as_ref()
            .ok_or(KeyManagementError::ProviderMissing)?;
        let key_id = self.key_id().ok_or(KeyManagementError::KeyIdMissing)?;
        let key = provider.get_symmetric_key(key_id)?;
        self.with_key_to_reader(key)
    }

    /// Returns a decrypting reader using the provided key.
    ///
    /// 使用提供的密钥返回解密读取器。
    pub fn with_key_to_reader<'s>(self, key: SymmetricKey) -> crate::Result<Box<dyn Read + 's>>
    where
        Self: 's,
    {
        let aad = self.aad.as_deref();
        let key = key.into_typed(self.inner.header().payload.symmetric_algorithm())?;
        self.inner.into_decryptor(key, aad)
    }
}

impl<'a> PendingDecryptorTrait for PendingStreamingDecryptor<'a> {
    fn header(&self) -> &Header {
        self.inner.header()
    }
}

impl<'a> WithAad for PendingStreamingDecryptor<'a> {
    fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }
}

/// A pending parallel streaming symmetric decryptor.
pub struct PendingParallelStreamingDecryptor<'a> {
    inner: Box<dyn SymmetricParallelStreamingPendingDecryptor + 'a>,
    aad: Option<Vec<u8>>,
    key_provider: Option<Arc<dyn KeyProvider>>,
}

impl<'a> PendingParallelStreamingDecryptor<'a> {
    fn new(
        inner: Box<dyn SymmetricParallelStreamingPendingDecryptor + 'a>,
        key_provider: Option<Arc<dyn KeyProvider>>,
        aad: Option<Vec<u8>>,
    ) -> Self {
        Self {
            inner,
            aad,
            key_provider,
        }
    }

    /// Returns the key ID from the header.
    ///
    /// 从标头返回密钥 ID。
    pub fn key_id(&self) -> Option<&str> {
        self.header().payload.key_id()
    }

    /// Decrypts to a writer using an automatically resolved key.
    ///
    /// 使用自动解析的密钥解密到写入器。
    pub fn resolve_and_decrypt_to_writer<W: Write + Send + 'a>(
        self,
        writer: W,
    ) -> crate::Result<()> {
        let provider = self
            .key_provider
            .as_ref()
            .ok_or(KeyManagementError::ProviderMissing)?;
        let key_id = self.key_id().ok_or(KeyManagementError::KeyIdMissing)?;
        let key = provider.get_symmetric_key(key_id)?;
        self.with_key_to_writer(key, writer)
    }

    /// Decrypts to a writer using the provided key.
    ///
    /// 使用提供的密钥解密到写入器。
    pub fn with_key_to_writer<W: Write + Send + 'a>(
        self,
        key: SymmetricKey,
        writer: W,
    ) -> crate::Result<()> {
        let aad = self.aad.as_deref();
        let key = key.into_typed(self.inner.header().payload.symmetric_algorithm())?;
        self.inner.decrypt_to_writer(key, Box::new(writer), aad)
    }
}

impl<'a> PendingDecryptorTrait for PendingParallelStreamingDecryptor<'a> {
    fn header(&self) -> &Header {
        self.inner.header()
    }
}

impl<'a> WithAad for PendingParallelStreamingDecryptor<'a> {
    fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }
}

/// A pending asynchronous streaming symmetric decryptor.
#[cfg(feature = "async")]
pub struct PendingAsyncStreamingDecryptor<'a> {
    inner: Box<dyn SymmetricAsynchronousPendingDecryptor<'a> + Send>,
    aad: Option<Vec<u8>>,
    key_provider: Option<Arc<dyn KeyProvider>>,
}

#[cfg(feature = "async")]
impl<'a> PendingAsyncStreamingDecryptor<'a> {
    fn new(
        inner: Box<dyn SymmetricAsynchronousPendingDecryptor<'a> + Send + 'a>,
        key_provider: Option<Arc<dyn KeyProvider>>,
        aad: Option<Vec<u8>>,
    ) -> Self {
        Self {
            inner,
            aad,
            key_provider,
        }
    }

    /// Returns the key ID from the header.
    ///
    /// 从标头返回密钥 ID。
    pub fn key_id(&self) -> Option<&str> {
        self.header().payload.key_id()
    }

    /// [Async] Returns a decrypting reader using an automatically resolved key.
    ///
    /// [异步] 使用自动解析的密钥返回解密读取器。
    pub async fn resolve_and_decrypt_to_async_reader<'s>(
        self,
    ) -> crate::Result<Box<dyn tokio::io::AsyncRead + Unpin + Send + 's>>
    where
        Self: 's,
    {
        let provider = self
            .key_provider
            .as_ref()
            .ok_or(KeyManagementError::ProviderMissing)?;
        let key_id = self.key_id().ok_or(KeyManagementError::KeyIdMissing)?;
        let key = provider.get_symmetric_key(key_id)?;
        self.with_key_to_async_reader(key).await
    }

    /// [Async] Returns a decrypting reader using the provided key.
    ///
    /// [异步] 使用提供的密钥返回解密读取器。
    pub async fn with_key_to_async_reader<'s>(
        self,
        key: SymmetricKey,
    ) -> crate::Result<Box<dyn tokio::io::AsyncRead + Unpin + Send + 's>>
    where
        Self: 's,
    {
        let aad = self.aad; // Must be owned for async call
        let key = key.into_typed(self.inner.header().payload.symmetric_algorithm())?;
        self.inner.into_decryptor(key, aad.as_deref()).await
    }
}

#[cfg(feature = "async")]
impl<'a> PendingDecryptorTrait for PendingAsyncStreamingDecryptor<'a> {
    fn header(&self) -> &Header {
        self.inner.header()
    }
}

#[cfg(feature = "async")]
impl<'a> WithAad for PendingAsyncStreamingDecryptor<'a> {
    fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }
}
