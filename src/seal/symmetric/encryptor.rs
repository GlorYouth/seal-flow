use crate::algorithms::traits::SymmetricAlgorithm;
use crate::keys::SymmetricKey;
use crate::seal::traits::{
    InMemoryEncryptor, IntoAsyncWriter, IntoWriter, StreamingEncryptor as StreamingEncryptorTrait,
};
use seal_crypto::prelude::Key;
use std::io::{Read, Write};
use std::marker::PhantomData;
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

    /// Configures the encryptor to use a specific symmetric algorithm.
    ///
    /// This returns a new encryptor instance that is specialized for the given
    /// algorithm, which can then be used to perform the actual encryption.
    ///
    /// 配置加密器以使用特定的对称算法。
    ///
    /// 这将返回一个为给定算法特化的新加密器实例，
    /// 然后可用于执行实际的加密操作。
    pub fn with_algorithm<S: SymmetricAlgorithm>(self) -> SymmetricEncryptorWithAlgorithm<S> {
        SymmetricEncryptorWithAlgorithm {
            inner: self,
            _phantom: PhantomData,
        }
    }

    /// Encrypts the given plaintext in-memory.
    ///
    /// 在内存中加密给定的明文。
    pub fn to_vec<S: SymmetricAlgorithm>(self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        crate::symmetric::ordinary::encrypt::<S>(
            Key::from_bytes(self.key.as_bytes())?,
            plaintext,
            self.key_id,
            self.aad.as_deref(),
        )
    }

    /// Encrypts the given plaintext in-memory using parallel processing.
    ///
    /// 使用并行处理在内存中加密给定的明文。
    pub fn to_vec_parallel<S: SymmetricAlgorithm>(
        self,
        plaintext: &[u8],
    ) -> crate::Result<Vec<u8>> {
        crate::symmetric::parallel::encrypt::<S>(
            Key::from_bytes(self.key.as_bytes())?,
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
    ) -> crate::Result<crate::symmetric::streaming::Encryptor<W, S>> {
        crate::symmetric::streaming::Encryptor::new(
            writer,
            Key::from_bytes(self.key.as_bytes())?,
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
    ) -> crate::Result<crate::symmetric::asynchronous::Encryptor<W, S>> {
        crate::symmetric::asynchronous::Encryptor::new(
            writer,
            Key::from_bytes(self.key.as_bytes())?,
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
    {
        crate::symmetric::parallel_streaming::encrypt::<S, R, W>(
            Key::from_bytes(self.key.as_bytes())?,
            reader,
            writer,
            self.key_id,
            self.aad.as_deref(),
        )
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

impl<S: SymmetricAlgorithm> InMemoryEncryptor for SymmetricEncryptorWithAlgorithm<S> {
    /// Encrypts the given plaintext in-memory.
    ///
    /// 在内存中加密给定的明文。
    fn to_vec(self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        crate::symmetric::ordinary::encrypt::<S>(
            Key::from_bytes(self.inner.key.as_bytes())?,
            plaintext,
            self.inner.key_id,
            self.inner.aad.as_deref(),
        )
    }

    /// Encrypts the given plaintext in-memory using parallel processing.
    ///
    /// 使用并行处理在内存中加密给定的明文。
    fn to_vec_parallel(self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        crate::symmetric::parallel::encrypt::<S>(
            Key::from_bytes(self.inner.key.as_bytes())?,
            plaintext,
            self.inner.key_id,
            self.inner.aad.as_deref(),
        )
    }
}

impl<S: SymmetricAlgorithm> StreamingEncryptorTrait for SymmetricEncryptorWithAlgorithm<S> {
    /// Encrypts data from a reader and writes to a writer using parallel processing.
    ///
    /// 使用并行处理从 reader 加密数据并写入 writer。
    fn pipe_parallel<R, W>(self, reader: R, writer: W) -> crate::Result<()>
    where
        R: Read + Send,
        W: Write,
    {
        crate::symmetric::parallel_streaming::encrypt::<S, R, W>(
            Key::from_bytes(self.inner.key.as_bytes())?,
            reader,
            writer,
            self.inner.key_id,
            self.inner.aad.as_deref(),
        )
    }
}

impl<S: SymmetricAlgorithm> IntoWriter for SymmetricEncryptorWithAlgorithm<S> {
    type Encryptor<W: Write> = crate::symmetric::streaming::Encryptor<W, S>;
    fn into_writer<W: Write>(
        self,
        writer: W,
    ) -> crate::Result<crate::symmetric::streaming::Encryptor<W, S>> {
        crate::symmetric::streaming::Encryptor::new(
            writer,
            Key::from_bytes(self.inner.key.as_bytes())?,
            self.inner.key_id,
            self.inner.aad.as_deref(),
        )
    }
}

#[cfg(feature = "async")]
impl<S: SymmetricAlgorithm> IntoAsyncWriter for SymmetricEncryptorWithAlgorithm<S> {
    type AsyncEncryptor<W: AsyncWrite + Unpin + Send> =
        crate::symmetric::asynchronous::Encryptor<W, S>;
    fn into_async_writer<W: AsyncWrite + Unpin + Send>(
        self,
        writer: W,
    ) -> impl std::future::Future<Output = crate::Result<Self::AsyncEncryptor<W>>> + Send {
        let key_bytes = self.inner.key;
        let key_id = self.inner.key_id;
        let aad = self.inner.aad;

        async move {
            crate::symmetric::asynchronous::Encryptor::new(
                writer,
                Key::from_bytes(key_bytes.as_bytes())?,
                key_id,
                aad.as_deref(),
            )
            .await
        }
    }
}
