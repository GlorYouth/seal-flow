//! This module defines a set of traits to unify the decryption APIs for both symmetric and hybrid encryption.
//! These traits provide a consistent interface for various decryption modes, such as in-memory and streaming.
//!
//! 该模块定义了一组 trait，用于统一对称加密和混合加密的解密 API。
//! 这些 trait 为各种解密模式（如内存解密和流式解密）提供了一致的接口。

use crate::common::header::Header;
use crate::error::Result;
use std::io::{Read, Write};
#[cfg(feature = "async")]
use tokio::io::AsyncRead;
#[cfg(feature = "async")]
use tokio::io::AsyncWrite;

/// A common trait for all pending decryptors, providing access to header information.
///
/// 所有待处理解密器的通用 trait，提供对标头信息的访问。
pub trait PendingDecryptor {
    /// Returns a reference to the header.
    ///
    /// 返回对标头的引用。
    fn header(&self) -> &Header;
}

/// A trait for decryptors that can be configured with Associated Authenticated Data (AAD).
///
/// 用于可以通过关联验证数据 (AAD) 进行配置的解密器的 trait。
pub trait WithAad<T> {
    /// Sets the Associated Data (AAD) for this decryption operation.
    ///
    /// 为此解密操作设置关联数据 (AAD)。
    fn with_aad(self, aad: impl Into<Vec<u8>>) -> T;
}

/// A trait for in-memory decryption operations.
///
/// 用于内存中解密操作的 trait。
pub trait InMemoryDecryptor {
    /// The specific key type required for decryption (e.g., `SymmetricKey` or `AsymmetricPrivateKey`).
    ///
    /// 解密所需的特定密钥类型（例如 `SymmetricKey` 或 `AsymmetricPrivateKey`）。
    type Key;

    /// Automatically resolves the key using a `KeyProvider` and completes decryption.
    ///
    /// 使用 `KeyProvider` 自动解析密钥并完成解密。
    fn resolve_and_decrypt(self) -> Result<Vec<u8>>;

    /// Supplies a key directly to complete decryption.
    ///
    /// 直接提供密钥以完成解密。
    fn with_key(self, key: Self::Key) -> Result<Vec<u8>>;
}

/// A trait for synchronous streaming decryption operations.
///
/// 用于同步流式解密操作的 trait。
pub trait StreamingDecryptor: Sized {
    /// The specific key type required for decryption.
    ///
    /// 解密所需的特定密钥类型。
    type Key;

    /// Automatically resolves the key and returns a decrypting reader.
    ///
    /// 自动解析密钥并返回一个解密读取器。
    fn resolve_and_decrypt<'s>(self) -> Result<Box<dyn Read + 's>>
    where
        Self: 's;

    /// Supplies a key and returns a decrypting reader.
    ///
    /// 提供密钥并返回一个解密读取器。
    fn with_key<'s>(self, key: Self::Key) -> Result<Box<dyn Read + 's>>
    where
        Self: 's;
}

/// A trait for parallel streaming decryption operations.
///
/// 用于并行流式解密操作的 trait。
pub trait ParallelStreamingDecryptor {
    /// The specific key type required for decryption.
    ///
    /// 解密所需的特定密钥类型。
    type Key;

    /// Automatically resolves the key and decrypts the stream to the provided writer.
    ///
    /// 自动解析密钥并将流解密到提供的写入器。
    fn resolve_and_decrypt_to_writer<W: Write>(self, writer: W) -> Result<()>;

    /// Supplies a key and decrypts the stream to the provided writer.
    ///
    /// 提供密钥并将流解密到提供的写入器。
    fn with_key_to_writer<W: Write>(self, key: Self::Key, writer: W) -> Result<()>;
}

/// A trait for asynchronous streaming decryption operations.
///
/// 用于异步流式解密操作的 trait。
#[cfg(feature = "async")]
pub trait AsyncStreamingDecryptor: Sized {
    /// The specific key type required for decryption.
    ///
    /// 解密所需的特定密钥类型。
    type Key;

    /// Automatically resolves the key and returns a decrypting async reader.
    ///
    /// 自动解析密钥并返回一个解密的异步读取器。
    fn resolve_and_decrypt<'s>(self) -> Result<Box<dyn AsyncRead + Unpin + 's>>
    where
        Self: 's;

    /// Supplies a key and returns a decrypting async reader.
    ///
    /// 提供密钥并返回一个解密的异步读取器。
    fn with_key<'s>(self, key: Self::Key) -> Result<Box<dyn AsyncRead + Unpin + 's>>
    where
        Self: 's;
}

// --- Encryptor Traits ---

/// A trait for in-memory encryption operations on a pre-configured encryptor.
///
/// 用于预配置加密器上的内存加密操作的 trait。
pub trait InMemoryEncryptor: Sized {
    /// Encrypts the given plaintext in-memory.
    ///
    /// 在内存中加密给定的明文。
    fn to_vec(self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Encrypts the given plaintext in-memory using parallel processing.
    ///
    /// 使用并行处理在内存中加密给定的明文。
    fn to_vec_parallel(self, plaintext: &[u8]) -> Result<Vec<u8>>;
}

/// A trait for synchronous streaming encryption operations on a pre-configured encryptor.
///
/// 用于预配置加密器上的同步流加密操作的 trait。
pub trait StreamingEncryptor: Sized {
    /// Encrypts data from a reader and writes to a writer using parallel processing.
    ///
    /// 使用并行处理从 reader 加密数据并写入 writer。
    fn pipe_parallel<R: Read + Send, W: Write>(self, reader: R, writer: W) -> Result<()>;
}

/// A trait for creating a synchronous streaming encryptor.
///
/// 用于创建同步流式加密器的 trait。
pub trait IntoWriter: Sized {
    /// The concrete `Write` encryptor type produced.
    ///
    /// 生成的具体 `Write` 加密器类型。
    type Encryptor<W: Write>: Write;

    /// Creates a streaming encryptor that wraps the given `Write` implementation.
    ///
    /// 创建一个包装了给定 `Write` 实现的流式加密器。
    fn into_writer<W: Write>(self, writer: W) -> Result<Self::Encryptor<W>>;
}

/// A trait for creating an asynchronous streaming encryptor.
///
/// 用于创建异步流式加密器的 trait。
#[cfg(feature = "async")]
pub trait IntoAsyncWriter: Sized {
    /// The concrete `AsyncWrite` encryptor type produced.
    ///
    /// 生成的具体 `AsyncWrite` 加密器类型。
    type AsyncEncryptor<W: AsyncWrite + Unpin + Send>: AsyncWrite;

    /// Creates an asynchronous streaming encryptor that wraps the given `AsyncWrite` implementation.
    ///
    /// 创建一个包装了给定 `AsyncWrite` 实现的异步流式加密器。
    fn into_async_writer<W: AsyncWrite + Unpin + Send>(
        self,
        writer: W,
    ) -> impl std::future::Future<Output = Result<Self::AsyncEncryptor<W>>> + Send;
}
