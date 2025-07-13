//! This module defines a set of traits to unify the decryption APIs for both symmetric and hybrid encryption.
//! These traits provide a consistent interface for various decryption modes, such as in-memory and streaming.
//!
//! 该模块定义了一组 trait，用于统一对称加密和混合加密的解密 API。
//! 这些 trait 为各种解密模式（如内存解密和流式解密）提供了一致的接口。

use crate::body::traits::FinishingWrite;
use crate::common::header::Header;
use crate::error::Result;
use crate::keys::TypedSignaturePublicKey;
#[cfg(feature = "async")]
use async_trait::async_trait;
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
pub trait WithAad {
    /// Sets the Associated Data (AAD) for this decryption operation.
    ///
    /// 为此解密操作设置关联数据 (AAD)。
    fn with_aad(self, aad: impl Into<Vec<u8>>) -> Self;
}

/// A trait for decryptors that can be configured with a verification key.
///
/// 用于可以通过验证密钥进行配置的解密器的 trait。
pub trait WithVerificationKey {
    /// Supplies a verification key.
    ///
    /// 提供验证密钥。
    fn with_verification_key(self, verification_key: TypedSignaturePublicKey) -> Self;
}

/// A trait for in-memory decryption operations.
///
/// 用于内存中解密操作的 trait。
pub trait InMemoryDecryptor: Sized {
    /// The specific key type required for decryption (e.g., `SymmetricKey` or `AsymmetricPrivateKey`).
    ///
    /// 解密所需的特定密钥类型（例如 `SymmetricKey` 或 `AsymmetricPrivateKey`）。
    type TypedKey;
    type UntypedKey;

    /// Automatically resolves the key using a `KeyProvider` and completes decryption.
    ///
    /// 使用 `KeyProvider` 自动解析密钥并完成解密。
    fn resolve_and_decrypt_to_vec(self) -> Result<Vec<u8>>;

    /// Supplies a key directly to complete decryption.
    ///
    /// 直接提供密钥以完成解密。
    fn with_key_to_vec(self, key: &Self::TypedKey) -> Result<Vec<u8>>;

    fn with_untyped_key_to_vec(self, key: &Self::UntypedKey) -> Result<Vec<u8>>;
}

/// A trait for synchronous streaming decryption operations.
///
/// 用于同步流式解密操作的 trait。
pub trait StreamingDecryptor: Sized {
    /// The specific key type required for decryption.
    ///
    /// 解密所需的特定密钥类型。
    type TypedKey;
    type UntypedKey;

    /// Automatically resolves the key and returns a decrypting reader.
    ///
    /// 自动解析密钥并返回一个解密读取器。
    fn resolve_and_decrypt_to_reader<'s>(self) -> Result<Box<dyn Read + 's>>
    where
        Self: 's;

    /// Supplies a key and returns a decrypting reader.
    ///
    /// 提供密钥并返回一个解密读取器。
    fn with_key_to_reader<'s>(self, key: &Self::TypedKey) -> Result<Box<dyn Read + 's>>
    where
        Self: 's;

    fn with_untyped_key_to_reader<'s>(self, key: &Self::UntypedKey) -> Result<Box<dyn Read + 's>>
    where
        Self: 's;
}

/// A trait for parallel streaming decryption operations.
///
/// 用于并行流式解密操作的 trait。
pub trait ParallelStreamingDecryptor: Sized {
    /// The specific key type required for decryption.
    ///
    /// 解密所需的特定密钥类型。
    type TypedKey;
    type UntypedKey;

    /// Automatically resolves the key and decrypts the stream to the provided writer.
    ///
    /// 自动解析密钥并将流解密到提供的写入器。
    fn resolve_and_decrypt_to_writer<W: Write + Send + 'static>(self, writer: W) -> Result<()>;

    /// Supplies a key and decrypts the stream to the provided writer.
    ///
    /// 提供密钥并将流解密到提供的写入器。
    fn with_key_to_writer<W: Write + Send + 'static>(
        self,
        key: &Self::TypedKey,
        writer: W,
    ) -> Result<()>;

    fn with_untyped_key_to_writer<W: Write + Send + 'static>(
        self,
        key: &Self::UntypedKey,
        writer: W,
    ) -> Result<()>;
}

/// A trait for asynchronous streaming decryption operations.
///
/// 用于异步流式解密操作的 trait。
#[cfg(feature = "async")]
#[async_trait]
pub trait AsyncStreamingDecryptor: Sized + Send {
    /// The specific key type required for decryption.
    ///
    /// 解密所需的特定密钥类型。
    type TypedKey: Send + Sync;
    type UntypedKey: Send + Sync;

    /// Automatically resolves the key and returns a decrypting async reader.
    ///
    /// 自动解析密钥并返回一个解密的异步读取器。
    async fn resolve_and_decrypt_to_reader<'s>(
        self,
    ) -> Result<Box<dyn AsyncRead + Unpin + Send + 's>>
    where
        Self: 's;

    /// Supplies a key and returns a decrypting async reader.
    ///
    /// 提供密钥并返回一个解密的异步读取器。
    async fn with_key_to_reader<'s>(
        self,
        key: &Self::TypedKey,
    ) -> Result<Box<dyn AsyncRead + Unpin + Send + 's>>
    where
        Self: 's;

    async fn with_untyped_key_to_reader<'s>(
        self,
        key: &Self::UntypedKey,
    ) -> Result<Box<dyn AsyncRead + Unpin + Send + 's>>
    where
        Self: 's;
}

// --- Encryptor Traits ---

/// A trait for in-memory encryption operations on a pre-configured encryptor.
///
/// 用于预配置加密器上的内存加密操作的 trait。
pub trait InMemoryEncryptor {
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
pub trait StreamingEncryptor {
    /// Creates a streaming encryptor that wraps the given `Write` implementation.
    ///
    /// 创建一个包装了给定 `Write` 实现的流式加密器。
    fn into_writer<'a, W: Write + 'a>(self, writer: W) -> Result<Box<dyn FinishingWrite + 'a>>;

    /// Encrypts data from a reader and writes to a writer using parallel processing.
    ///
    /// 使用并行处理从 reader 加密数据并写入 writer。
    fn pipe_parallel<R: Read + Send, W: Write + Send>(self, reader: R, writer: W) -> Result<()>;
}

/// A trait for creating an asynchronous streaming encryptor.
///
/// 用于创建异步流式加密器的 trait。
#[cfg(feature = "async")]
#[async_trait]
pub trait AsyncStreamingEncryptor {
    /// Creates an asynchronous streaming encryptor that wraps the given `AsyncWrite` implementation.
    ///
    /// 创建一个包装了给定 `AsyncWrite` 实现的异步流式加密器。
    async fn into_async_writer<'a, W: AsyncWrite + Unpin + Send + 'a>(
        self,
        writer: W,
    ) -> Result<Box<dyn AsyncWrite + Unpin + Send + 'a>>;
}
