use crate::algorithms::traits::SymmetricAlgorithm;
use crate::body::traits::{
    OrdinaryBodyProcessor, ParallelBodyProcessor, ParallelStreamingBodyProcessor,
};
use crate::keys::SymmetricKey;
use crate::seal::traits::{
    AsyncStreamingEncryptor, InMemoryEncryptor, StreamingEncryptor, WithAad,
};
#[cfg(feature = "async")]
use crate::symmetric::asynchronous::Asynchronous;
use crate::symmetric::ordinary::Ordinary;
use crate::symmetric::parallel::Parallel;
use crate::symmetric::parallel_streaming::ParallelStreaming;
use crate::symmetric::streaming::Streaming;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::sync::Arc;
#[cfg(feature = "async")]
use tokio::io::AsyncWrite;

/// A context for symmetric encryption operations, allowing selection of execution mode.
///
/// 对称加密操作的上下文，允许选择执行模式。
pub struct SymmetricEncryptor {
    pub(crate) key: SymmetricKey,
    pub(crate) key_id: String,
    pub(crate) aad: Option<Vec<u8>>,
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

impl SymmetricEncryptor {
    /// Configures the encryptor to use a specific symmetric algorithm.
    ///
    /// This returns a new encryptor instance that is specialized for the given
    /// algorithm, which can then be used to perform the actual encryption.
    ///
    /// 配置加密器以使用特定的对称算法。
    ///
    /// 这将返回一个为给定算法特化的新加密器实例，
    /// 然后可用于执行实际的加密操作。
    pub fn execute_with<S: SymmetricAlgorithm + 'static>(
        self,
    ) -> SymmetricEncryptorWithAlgorithm<S> {
        SymmetricEncryptorWithAlgorithm {
            inner: self,
            _phantom: PhantomData,
        }
    }
}

/// A symmetric encryptor that has been configured with a specific algorithm.
///
/// This struct provides the final encryption methods (`to_vec`, `into_writer`, etc.)
/// without requiring further generic algorithm specification.
///
/// 已配置特定算法的对称加密器。
///
/// 该结构提供了最终的加密方法（`to_vec`、`into_writer`等），
/// 无需进一步指定泛型算法。
pub struct SymmetricEncryptorWithAlgorithm<S: SymmetricAlgorithm> {
    inner: SymmetricEncryptor,
    _phantom: PhantomData<S>,
}

impl<S> InMemoryEncryptor for SymmetricEncryptorWithAlgorithm<S>
where
    S: SymmetricAlgorithm + OrdinaryBodyProcessor + Default,
{
    /// Encrypts the given plaintext in-memory.
    ///
    /// 在内存中加密给定的明文。
    fn to_vec(self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        let algorithm = S::default();
        let processor = Ordinary::new(&algorithm);
        let typed_key = self.inner.key.into_typed(algorithm.algorithm())?;
        processor.encrypt_symmetric_in_memory(
            typed_key,
            self.inner.key_id,
            plaintext,
            self.inner.aad.as_deref(),
        )
    }

    /// Encrypts the given plaintext in-memory using parallel processing.
    ///
    /// 使用并行处理在内存中加密给定的明文。
    fn to_vec_parallel(self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        let algorithm = S::default();
        let processor = Parallel::new(&algorithm);
        let typed_key = self.inner.key.into_typed(algorithm.algorithm())?;
        processor.encrypt_symmetric_parallel(
            typed_key,
            self.inner.key_id,
            plaintext,
            self.inner.aad.as_deref(),
        )
    }
}

impl<S> StreamingEncryptor for SymmetricEncryptorWithAlgorithm<S>
where
    S: SymmetricAlgorithm + Default + ParallelStreamingBodyProcessor,
{
    /// Creates a streaming encryptor that wraps the given `Write` implementation.
    ///
    /// 创建一个包装了给定 `Write` 实现的流式加密器。
    fn into_writer<'a, W: Write + 'a>(self, writer: W) -> crate::Result<Box<dyn Write + 'a>> {
        let algorithm = S::default();
        let processor = Streaming::new(&algorithm);
        let typed_key = self.inner.key.into_typed(algorithm.algorithm())?;
        processor.encrypt_symmetric_to_stream(
            typed_key,
            self.inner.key_id,
            Box::new(writer),
            self.inner.aad.as_deref(),
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
        let algorithm = Arc::new(S::default());
        let processor = ParallelStreaming::new(algorithm.clone());
        let typed_key = self.inner.key.into_typed(algorithm.algorithm())?;
        processor.encrypt_symmetric_pipeline(
            typed_key,
            self.inner.key_id,
            Box::new(reader),
            Box::new(writer),
            self.inner.aad.as_deref(),
        )
    }
}

#[cfg(feature = "async")]
impl<S> AsyncStreamingEncryptor for SymmetricEncryptorWithAlgorithm<S>
where
    S: SymmetricAlgorithm + Default + Send + Sync,
{
    /// Creates an asynchronous streaming encryptor that wraps the given `AsyncWrite` implementation.
    ///
    /// 创建一个包装了给定 `AsyncWrite` 实现的异步流式加密器。
    async fn into_async_writer<'a, W: AsyncWrite + Unpin + Send + 'a>(
        self,
        writer: W,
    ) -> crate::Result<Box<dyn AsyncWrite + Unpin + Send + 'a>> {
        let algorithm = S::default();
        let processor = Asynchronous::new(&algorithm);
        let typed_key = self.inner.key.into_typed(algorithm.algorithm())?;
        processor
            .encrypt_symmetric_async(
                typed_key,
                self.inner.key_id,
                Box::new(writer),
                self.inner.aad.as_deref(),
            )
            .await
    }
}
