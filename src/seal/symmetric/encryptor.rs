use crate::body::traits::FinishingWrite;
use crate::common::config::ArcConfig;
use crate::keys::TypedSymmetricKey;
use crate::seal::traits::{
    AsyncStreamingEncryptor, InMemoryEncryptor, StreamingEncryptor, WithAad, WithExtraData,
};
#[cfg(feature = "async")]
use crate::symmetric::asynchronous::Asynchronous;
use crate::symmetric::config::SymmetricConfig;
use crate::symmetric::ordinary::Ordinary;
use crate::symmetric::parallel::Parallel;
use crate::symmetric::parallel_streaming::ParallelStreaming;
use crate::symmetric::streaming::Streaming;
use crate::symmetric::traits::*;
#[cfg(feature = "async")]
use async_trait::async_trait;
use std::borrow::Cow;
use std::io::{Read, Write};
#[cfg(feature = "async")]
use tokio::io::AsyncWrite;

/// A context for symmetric encryption operations, allowing selection of execution mode.
///
/// 对称加密操作的上下文，允许选择执行模式。
pub struct SymmetricEncryptor {
    pub(crate) key: TypedSymmetricKey,
    pub(crate) key_id: String,
    pub(crate) aad: Option<Vec<u8>>,
    pub(crate) extra_data: Option<Vec<u8>>,
    pub(crate) config: ArcConfig,
}

impl WithAad for SymmetricEncryptor {
    /// Sets the Associated Data (AAD) for this encryption operation.
    ///
    /// 为此加密操作设置关联数据 (AAD)。
    fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }
}

impl WithExtraData for SymmetricEncryptor {

    /// Sets the extra data for this encryption operation.
    ///
    /// 为此加密操作设置额外数据。
    fn with_extra_data(mut self, extra_data: impl Into<Vec<u8>>) -> Self {
        self.extra_data = Some(extra_data.into());
        self
    }
}

impl InMemoryEncryptor for SymmetricEncryptor {
    /// Encrypts the given plaintext in-memory.
    ///
    /// 在内存中加密给定的明文。
    fn to_vec(self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        let processor = Ordinary::new();
        processor.encrypt_symmetric_in_memory(
            plaintext,
            SymmetricConfig {
                algorithm: Cow::Owned(self.key.algorithm().into_symmetric_wrapper()),
                key: Cow::Borrowed(&self.key),
                key_id: self.key_id,
                aad: self.aad,
                config: self.config,
                extra_data: self.extra_data,
            },
        )
    }

    /// Encrypts the given plaintext in-memory using parallel processing.
    ///
    /// 使用并行处理在内存中加密给定的明文。
    fn to_vec_parallel(self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        let processor = Parallel::new();
        processor.encrypt_symmetric_parallel(
            plaintext,
            SymmetricConfig {
                algorithm: Cow::Owned(self.key.algorithm().into_symmetric_wrapper()),
                key: Cow::Borrowed(&self.key),
                key_id: self.key_id,
                aad: self.aad,
                config: self.config,
                extra_data: self.extra_data,
            },
        )
    }
}

impl StreamingEncryptor for SymmetricEncryptor {
    /// Creates a streaming encryptor that wraps the given `Write` implementation.
    ///
    /// 创建一个包装了给定 `Write` 实现的流式加密器。
    fn into_writer<'a, W: Write + 'a>(
        self,
        writer: W,
    ) -> crate::Result<Box<dyn FinishingWrite + 'a>> {
        let processor = Streaming::new();
        processor.encrypt_symmetric_to_stream(
            Box::new(writer),
            SymmetricConfig {
                algorithm: Cow::Owned(self.key.algorithm().into_symmetric_wrapper()),
                key: Cow::Owned(self.key),
                key_id: self.key_id,
                aad: self.aad,
                config: self.config,
                extra_data: self.extra_data,
            },
        )
    }

    /// Encrypts data from a reader and writes to a writer using parallel processing.
    ///
    /// 使用并行处理从 reader 加密数据并写入 writer。
    fn pipe_parallel<R, W>(self, reader: R, writer: W) -> crate::Result<()>
    where
        R: Read + Send,
        W: Write + Send,
    {
        let processor = ParallelStreaming::new();
        processor.encrypt_symmetric_pipeline(
            Box::new(reader),
            Box::new(writer),
            SymmetricConfig {
                algorithm: Cow::Owned(self.key.algorithm().into_symmetric_wrapper()),
                key: Cow::Borrowed(&self.key),
                key_id: self.key_id,
                aad: self.aad,
                config: self.config,
                extra_data: self.extra_data,
            },
        )
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl AsyncStreamingEncryptor for SymmetricEncryptor {
    /// Creates an asynchronous streaming encryptor that wraps the given `AsyncWrite` implementation.
    ///
    /// 创建一个包装了给定 `AsyncWrite` 实现的异步流式加密器。
    async fn into_async_writer<'a, W: AsyncWrite + Unpin + Send + 'a>(
        self,
        writer: W,
    ) -> crate::Result<Box<dyn AsyncWrite + Unpin + Send + 'a>> {
        let processor = Asynchronous::new();
        processor
            .encrypt_symmetric_async(
                Box::new(writer),
                SymmetricConfig {
                    algorithm: Cow::Owned(self.key.algorithm().into_symmetric_wrapper()),
                    key: Cow::Owned(self.key),
                    key_id: self.key_id,
                    aad: self.aad,
                    config: self.config,
                    extra_data: self.extra_data,
                },
            )
            .await
    }
}
