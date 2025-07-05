use crate::algorithms::traits::SymmetricAlgorithm;
use crate::keys::SymmetricKey;
use seal_crypto::zeroize::Zeroizing;
use std::io::{Read, Write};
use tokio::io::AsyncWrite;

/// A context for symmetric encryption operations, allowing selection of execution mode.
///
/// 对称加密操作的上下文，允许选择执行模式。
pub struct SymmetricEncryptor {
    pub(crate) key: SymmetricKey,
    pub(crate) key_id: String,
    pub(crate) aad: Option<Vec<u8>>,
}

impl SymmetricEncryptor {
    /// Sets the Associated Data (AAD) for this encryption operation.
    ///
    /// 为此加密操作设置关联数据 (AAD)。
    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }

    /// Encrypts the given plaintext in-memory.
    ///
    /// 在内存中加密给定的明文。
    pub fn to_vec<S: SymmetricAlgorithm>(self, plaintext: &[u8]) -> crate::Result<Vec<u8>>
    where
        S::Key: From<Zeroizing<Vec<u8>>> + Clone + Send + Sync,
    {
        crate::symmetric::ordinary::encrypt::<S>(
            S::Key::from(self.key.into_bytes()),
            plaintext,
            self.key_id,
            self.aad.as_deref(),
        )
    }

    /// Encrypts the given plaintext in-memory using parallel processing.
    ///
    /// 使用并行处理在内存中加密给定的明文。
    pub fn to_vec_parallel<S: SymmetricAlgorithm>(self, plaintext: &[u8]) -> crate::Result<Vec<u8>>
    where
        S::Key: From<Zeroizing<Vec<u8>>> + Clone + Send + Sync,
    {
        crate::symmetric::parallel::encrypt::<S>(
            S::Key::from(self.key.into_bytes()),
            plaintext,
            self.key_id,
            self.aad.as_deref(),
        )
    }

    /// Creates a streaming encryptor that writes to the given `Write` implementation.
    ///
    /// 创建一个流式加密器，写入给定的 `Write` 实现。
    pub fn into_writer<S: SymmetricAlgorithm, W: Write>(
        self,
        writer: W,
    ) -> crate::Result<crate::symmetric::streaming::Encryptor<W, S>>
    where
        S::Key: From<Zeroizing<Vec<u8>>> + Clone + Send + Sync,
    {
        crate::symmetric::streaming::Encryptor::new(
            writer,
            S::Key::from(self.key.into_bytes()),
            self.key_id,
            self.aad.as_deref(),
        )
    }

    /// [Async] Creates an asynchronous streaming encryptor.
    ///
    /// [异步] 创建一个异步流式加密器。
    #[cfg(feature = "async")]
    pub async fn into_async_writer<S: SymmetricAlgorithm, W: AsyncWrite + Unpin>(
        self,
        writer: W,
    ) -> crate::Result<crate::symmetric::asynchronous::Encryptor<W, S>>
    where
        S::Key: From<Zeroizing<Vec<u8>>> + Clone + Send + Sync,
    {
        crate::symmetric::asynchronous::Encryptor::new(
            writer,
            S::Key::from(self.key.into_bytes()),
            self.key_id,
            self.aad.as_deref(),
        )
        .await
    }

    /// Encrypts data from a reader and writes to a writer using parallel processing.
    ///
    /// 使用并行处理从 reader 加密数据并写入 writer。
    pub fn pipe_parallel<S: SymmetricAlgorithm, R, W>(
        self,
        reader: R,
        writer: W,
    ) -> crate::Result<()>
    where
        R: Read + Send,
        W: Write,
        S::Key: From<Zeroizing<Vec<u8>>> + Clone + Send + Sync,
    {
        crate::symmetric::parallel_streaming::encrypt::<S, R, W>(
            S::Key::from(self.key.into_bytes()),
            reader,
            writer,
            self.key_id,
            self.aad.as_deref(),
        )
    }
}
