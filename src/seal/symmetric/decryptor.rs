use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::algorithms::SymmetricAlgorithm as SymmetricAlgorithmEnum;
use crate::common::header::Header;
use crate::common::PendingImpl;
use crate::error::{KeyManagementError};
use crate::keys::provider::KeyProvider;
use crate::keys::SymmetricKey;
use std::io::{Read, Write};
use tokio::io::AsyncRead;

use seal_crypto::prelude::*;
use seal_crypto::schemes::symmetric::aes_gcm::{Aes128Gcm, Aes256Gcm};
use seal_crypto::schemes::symmetric::chacha20_poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};

/// 创建一个宏来处理从原始字节转换为特定算法密钥的过程
/// 这个宏替代了旧的枚举类型调度方式，直接从字节转换到密钥
macro_rules! dispatch_symmetric_key_bytes {
    // 内部规则，处理算法列表
    (@internal $algorithm:expr, $key_bytes:expr, $callback:ident, $extra_args:tt,
     $(($algo_enum:path, $algo_type:ty)),*
    ) => {
        {
            match $algorithm {
                $(
                    $algo_enum => {
                        let key = <$algo_type as SymmetricKeySet>::Key::from_bytes($key_bytes)?;
                        $callback!(key, $algo_type, $extra_args)
                    },
                )*
            }
        }
    };

    // 宏的公共入口点
    ($algorithm:expr, $key_bytes:expr, $callback:ident, $($extra_args:tt)*) => {
        dispatch_symmetric_key_bytes!(@internal $algorithm, $key_bytes, $callback, ($($extra_args)*),
            (SymmetricAlgorithmEnum::Aes128Gcm, Aes128Gcm),
            (SymmetricAlgorithmEnum::Aes256Gcm, Aes256Gcm),
            (SymmetricAlgorithmEnum::ChaCha20Poly1305, ChaCha20Poly1305),
            (SymmetricAlgorithmEnum::XChaCha20Poly1305, XChaCha20Poly1305)
        )
    };
}

/// A generic pending symmetric decryptor, waiting for configuration and key.
/// This struct unifies the logic for various decryption modes (in-memory, streaming, etc.).
///
/// 一个通用的、等待配置和密钥的待处理对称解密器。
/// 该结构统一了各种解密模式（内存中、流式等）的逻辑。
pub struct PendingDecryptor<'a, T> {
    inner: T,
    aad: Option<Vec<u8>>,
    key_provider: Option<&'a dyn KeyProvider>,
}

impl<'a, T: PendingImpl> PendingDecryptor<'a, T> {
    /// Creates a new `PendingDecryptor` with the given inner implementation.
    ///
    /// 使用给定的内部实现创建一个新的 `PendingDecryptor`。
    fn new(inner: T, key_provider: Option<&'a dyn KeyProvider>) -> Self {
        Self { inner, aad: None, key_provider }
    }

    /// Returns a reference to the header.
    ///
    /// 返回对标头的引用。
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the key ID from the header.
    ///
    /// 从标头返回密钥 ID。
    pub fn key_id(&self) -> Option<&str> {
        self.header().payload.key_id()
    }

    /// Sets the Associated Data (AAD) for this decryption operation.
    /// The AAD must match the value provided during encryption.
    ///
    /// 为此解密操作设置关联数据 (AAD)。
    /// AAD 必须与加密时提供的值匹配。
    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }
}

/// A type alias for a pending in-memory symmetric decryptor.
///
/// 待处理内存对称解密器的类型别名。
pub type PendingInMemoryDecryptor<'a> =
    PendingDecryptor<'a, crate::symmetric::ordinary::PendingDecryptor<'a>>;
/// A type alias for a pending parallel in-memory symmetric decryptor.
///
/// 待处理并行内存对称解密器的类型别名。
pub type PendingInMemoryParallelDecryptor<'a> =
    PendingDecryptor<'a, crate::symmetric::parallel::PendingDecryptor<'a>>;
/// A type alias for a pending synchronous streaming symmetric decryptor.
///
/// 待处理同步流对称解密器的类型别名。
pub type PendingStreamingDecryptor<'a, R> =
    PendingDecryptor<'a, crate::symmetric::streaming::PendingDecryptor<R>>;
/// A type alias for a pending parallel streaming symmetric decryptor.
///
/// 待处理并行流对称解密器的类型别名。
pub type PendingParallelStreamingDecryptor<'a, R> =
    PendingDecryptor<'a, crate::symmetric::parallel_streaming::PendingDecryptor<R>>;
/// A type alias for a pending asynchronous streaming symmetric decryptor.
///
/// 待处理异步流对称解密器的类型别名。
#[cfg(feature = "async")]
pub type PendingAsyncStreamingDecryptor<'a, R> =
    PendingDecryptor<'a, crate::symmetric::asynchronous::PendingDecryptor<R>>;

/// A builder for symmetric decryption operations.
///
/// 对称解密操作的构建器。
#[derive(Default)]
pub struct SymmetricDecryptorBuilder<'a> {
    key_provider: Option<&'a dyn KeyProvider>,
}

impl<'a> SymmetricDecryptorBuilder<'a> {
    /// Creates a new `SymmetricDecryptorBuilder`.
    ///
    /// 创建一个新的 `SymmetricDecryptorBuilder`。
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
    pub fn with_key_provider(mut self, provider: &'a dyn KeyProvider) -> Self {
        self.key_provider = Some(provider);
        self
    }

    /// Configures decryption from an in-memory byte slice.
    ///
    /// Returns a `PendingInMemoryDecryptor` that allows inspecting the header
    /// before providing the key.
    ///
    /// 从内存中的字节切片配置解密。
    ///
    /// 返回一个 `PendingInMemoryDecryptor`，允许在提供密钥之前检查标头。
    pub fn slice(self, ciphertext: &'a [u8]) -> crate::Result<PendingInMemoryDecryptor<'a>> {
        let mid_level_pending =
            crate::symmetric::ordinary::PendingDecryptor::from_ciphertext(ciphertext)?;
        Ok(PendingDecryptor::new(
            mid_level_pending,
            self.key_provider,
        ))
    }

    /// Configures parallel decryption from an in-memory byte slice.
    ///
    /// 从内存中的字节切片配置并行解密。
    pub fn slice_parallel(
        self,
        ciphertext: &'a [u8],
    ) -> crate::Result<PendingInMemoryParallelDecryptor<'a>> {
        let mid_level_pending =
            crate::symmetric::parallel::PendingDecryptor::from_ciphertext(ciphertext)?;
        Ok(PendingDecryptor::new(
            mid_level_pending,
            self.key_provider,
        ))
    }

    /// Configures decryption from a synchronous `Read` stream.
    ///
    /// 从同步 `Read` 流配置解密。
    pub fn reader<R: Read>(self, reader: R) -> crate::Result<PendingStreamingDecryptor<'a, R>> {
        let mid_level_pending = crate::symmetric::streaming::PendingDecryptor::from_reader(reader)?;
        Ok(PendingDecryptor::new(
            mid_level_pending,
            self.key_provider,
        ))
    }

    /// Configures parallel decryption from a synchronous `Read` stream.
    ///
    /// 从同步 `Read` 流配置并行解密。
    pub fn reader_parallel<R: Read + Send>(
        self,
        reader: R,
    ) -> crate::Result<PendingParallelStreamingDecryptor<'a, R>> {
        let mid_level_pending =
            crate::symmetric::parallel_streaming::PendingDecryptor::from_reader(reader)?;
        Ok(PendingDecryptor::new(
            mid_level_pending,
            self.key_provider,
        ))
    }

    /// Begins an asynchronous streaming decryption operation.
    ///
    /// 开始一个异步流式解密操作。
    #[cfg(feature = "async")]
    pub async fn async_reader<R: AsyncRead + Unpin>(
        self,
        reader: R,
    ) -> crate::Result<PendingAsyncStreamingDecryptor<'a, R>> {
        let mid_level_pending =
            crate::symmetric::asynchronous::PendingDecryptor::from_reader(reader).await?;
        Ok(PendingDecryptor::new(
            mid_level_pending,
            self.key_provider,
        ))
    }
}

impl<'a> PendingInMemoryDecryptor<'a> {
    /// Automatically resolves the key using the attached `KeyProvider` and
    /// completes the decryption.
    ///
    /// # Errors
    ///
    /// This method will return an error if no `KeyProvider` was set on the
    /// `SymmetricDecryptorBuilder`, or if the key ID from the ciphertext
    /// cannot be found by the provider.
    ///
    /// 使用附加的 `KeyProvider` 自动解析密钥并完成解密。
    ///
    /// # 错误
    ///
    /// 如果 `SymmetricDecryptorBuilder` 上未设置 `KeyProvider`，或者
    /// 提供者找不到密文中的密钥 ID，此方法将返回错误。
    pub fn resolve_and_decrypt(self) -> crate::Result<Vec<u8>> {
        let provider = self
            .key_provider
            .ok_or(KeyManagementError::ProviderMissing)?;
        let key_id = self
            .key_id()
            .ok_or(KeyManagementError::KeyIdMissing)?;
        let key = provider.get_symmetric_key(key_id)?;
        self.with_key(key)
    }

    /// Supplies a key from its raw bytes for decryption.
    ///
    /// 提供原始字节形式的密钥以进行解密。
    pub fn with_key(self, key: SymmetricKey) -> crate::Result<Vec<u8>> {
        let algorithm = self.inner.header().payload.symmetric_algorithm();

        // 使用新的宏来替换重复的match语句
        macro_rules! do_decrypt {
            ($k:ident, $S:ty, ()) => {
                self.inner.into_plaintext::<$S>($k, self.aad.as_deref())
            };
        }

        dispatch_symmetric_key_bytes!(algorithm, key.as_bytes(), do_decrypt,)
    }

    /// Supplies the typed key and returns the decrypted plaintext.
    ///
    /// 提供类型化的密钥并返回解密的明文。
    pub fn with_typed_key<S: SymmetricAlgorithm>(self, key: S::Key) -> crate::Result<Vec<u8>>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner
            .into_plaintext::<S>(key.clone(), self.aad.as_deref())
    }
}

impl<'a> PendingInMemoryParallelDecryptor<'a> {
    /// Automatically resolves the key using the attached `KeyProvider` and
    /// completes the decryption.
    ///
    /// 使用附加的 `KeyProvider` 自动解析密钥并完成解密。
    pub fn resolve_and_decrypt(self) -> crate::Result<Vec<u8>> {
        let provider = self
            .key_provider
            .ok_or(KeyManagementError::ProviderMissing)?;
        let key_id = self
            .key_id()
            .ok_or(KeyManagementError::KeyIdMissing)?;
        let key = provider.get_symmetric_key(key_id)?;
        self.with_key(key)
    }

    /// Supplies a key from its raw bytes for decryption.
    ///
    /// 提供原始字节形式的密钥以进行解密。
    pub fn with_key(self, key: SymmetricKey) -> crate::Result<Vec<u8>> {
        let algorithm = self.inner.header().payload.symmetric_algorithm();

        // 使用新的宏来替换重复的match语句
        macro_rules! do_decrypt {
            ($k:ident, $S:ty, ()) => {
                self.inner.into_plaintext::<$S>($k, self.aad.as_deref())
            };
        }

        dispatch_symmetric_key_bytes!(algorithm, key.as_bytes(), do_decrypt,)
    }

    /// Supplies the typed key and returns the decrypted plaintext.
    ///
    /// 提供类型化的密钥并返回解密的明文。
    pub fn with_typed_key<S: SymmetricAlgorithm>(self, key: S::Key) -> crate::Result<Vec<u8>>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner
            .into_plaintext::<S>(key.clone(), self.aad.as_deref())
    }
}

impl<'a, R: Read> PendingStreamingDecryptor<'a, R> {
    /// Automatically resolves the key using the attached `KeyProvider` and
    /// returns a decrypting reader.
    ///
    /// 使用附加的 `KeyProvider` 自动解析密钥并返回一个解密读取器。
    pub fn resolve_and_decrypt<'s>(self) -> crate::Result<Box<dyn Read + 's>>
    where
        R: 's,
    {
        let provider = self
            .key_provider
            .ok_or(KeyManagementError::ProviderMissing)?;
        let key_id = self
            .key_id()
            .ok_or(KeyManagementError::KeyIdMissing)?;
        let key = provider.get_symmetric_key(key_id)?;
        self.with_key(key)
    }

    /// Supplies a key from its raw bytes for decryption.
    ///
    /// 提供原始字节形式的密钥以进行解密。
    pub fn with_key<'s>(self, key: SymmetricKey) -> crate::Result<Box<dyn Read + 's>>
    where
        R: 's,
    {
        let algorithm = self.inner.header().payload.symmetric_algorithm();

        // 使用新的宏来替换重复的match语句
        macro_rules! do_decrypt {
            ($k:ident, $S:ty, ()) => {
                self.inner
                    .into_decryptor::<$S>($k, self.aad.as_deref())
                    .map(|d| Box::new(d) as Box<dyn Read>)
            };
        }

        dispatch_symmetric_key_bytes!(algorithm, key.as_bytes(), do_decrypt,)
    }

    /// Supplies the typed key and returns a fully initialized `Decryptor`.
    ///
    /// 提供类型化的密钥并返回一个完全初始化的 `Decryptor`。
    pub fn with_typed_key<S: SymmetricAlgorithm>(
        self,
        key: S::Key,
    ) -> crate::Result<crate::symmetric::streaming::Decryptor<R, S>>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner.into_decryptor(key.clone(), self.aad.as_deref())
    }
}

impl<'a, R> PendingParallelStreamingDecryptor<'a, R>
where
    R: Read + Send,
{
    /// Automatically resolves the key using the attached `KeyProvider` and
    /// decrypts the stream to the provided writer.
    ///
    /// 使用附加的 `KeyProvider` 自动解析密钥，并将流解密到提供的写入器。
    pub fn resolve_and_decrypt_to_writer<W: Write>(self, writer: W) -> crate::Result<()> {
        let provider = self
            .key_provider
            .ok_or(KeyManagementError::ProviderMissing)?;
        let key_id = self
            .key_id()
            .ok_or(KeyManagementError::KeyIdMissing)?;
        let key = provider.get_symmetric_key(key_id)?;
        self.with_key_to_writer(key, writer)
    }

    /// Supplies a key from its raw bytes and decrypts to the provided writer.
    ///
    /// 提供原始字节形式的密钥，并将解密后的数据写入提供的写入器。
    pub fn with_key_to_writer<W: Write>(self, key: SymmetricKey, writer: W) -> crate::Result<()> {
        let algorithm = self.inner.header().payload.symmetric_algorithm();

        // 使用新的宏来替换重复的match语句
        macro_rules! do_decrypt {
            ($k:ident, $S:ty, ($writer:ident)) => {
                self.inner
                    .decrypt_to_writer::<$S, W>($k, $writer, self.aad.as_deref())
            };
        }

        dispatch_symmetric_key_bytes!(algorithm, key.as_bytes(), do_decrypt, writer)
    }

    /// Supplies the typed key and decrypts the stream, writing to the provided writer.
    ///
    /// 提供类型化的密钥，解密流，并将结果写入提供的写入器。
    pub fn with_typed_key_to_writer<S: SymmetricAlgorithm, W: Write>(
        self,
        key: S::Key,
        writer: W,
    ) -> crate::Result<()>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner
            .decrypt_to_writer::<S, W>(key.clone(), writer, self.aad.as_deref())
    }
}

#[cfg(feature = "async")]
impl<'a, R: AsyncRead + Unpin> PendingAsyncStreamingDecryptor<'a, R> {
    /// Automatically resolves the key using the attached `KeyProvider` and
    /// returns a decrypting async reader.
    ///
    /// 使用附加的 `KeyProvider` 自动解析密钥，并返回一个解密的异步读取器。
    pub fn resolve_and_decrypt<'s>(self) -> crate::Result<Box<dyn AsyncRead + Unpin + 's>>
    where
        R: 's,
    {
        let provider = self
            .key_provider
            .ok_or(KeyManagementError::ProviderMissing)?;
        let key_id = self
            .key_id()
            .ok_or(KeyManagementError::KeyIdMissing)?;
        let key = provider.get_symmetric_key(key_id)?;
        self.with_key(key)
    }

    /// Supplies a key from its raw bytes for decryption.
    ///
    /// 提供原始字节形式的密钥以进行解密。
    pub fn with_key<'s>(self, key: SymmetricKey) -> crate::Result<Box<dyn AsyncRead + Unpin + 's>>
    where
        R: 's,
    {
        let algorithm = self.inner.header().payload.symmetric_algorithm();

        // 使用新的宏来替换重复的match语句
        macro_rules! do_decrypt {
            ($k:ident, $S:ty, ()) => {
                self.inner
                    .into_decryptor::<$S>($k, self.aad.as_deref())
                    .map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin>)
            };
        }

        dispatch_symmetric_key_bytes!(algorithm, key.as_bytes(), do_decrypt,)
    }

    /// Supplies the typed key and returns a fully initialized `Decryptor`.
    ///
    /// 提供类型化的密钥并返回一个完全初始化的 `Decryptor`。
    pub fn with_typed_key<S: SymmetricAlgorithm>(
        self,
        key: S::Key,
    ) -> crate::Result<crate::symmetric::asynchronous::Decryptor<R, S>>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner.into_decryptor(key.clone(), self.aad.as_deref())
    }
}
