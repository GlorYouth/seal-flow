//! Defines the primary error type and result alias for the entire crate.
//!
//! 定义了整个 crate 的主要错误类型和结果别名。
use crate::provider::KeyProviderError;
use thiserror::Error;
use seal_crypto_wrapper::bincode;

/// An error related to `bincode` serialization or deserialization.
///
/// This is a wrapper around `bincode`'s own error types to provide a more
/// consistent error handling experience within this crate.
///
/// 与 `bincode` 序列化或反序列化相关的错误。
///
/// 这是对 `bincode` 自身错误类型的包装，以便在此 crate 中提供更一致的错误处理体验。
#[derive(Error, Debug)]
pub enum BincodeError {
    /// An error occurred during serialization (encoding).
    ///
    /// 在序列化（编码）过程中发生错误。
    #[error("Encode error: {0}")]
    Enc(#[source] Box<bincode::error::EncodeError>),
    /// An error occurred during deserialization (decoding).
    ///
    /// 在反序列化（解码）过程中发生错误。
    #[error("Decode error: {0}")]
    Dec(#[source] Box<bincode::error::DecodeError>),
}

impl From<bincode::error::EncodeError> for BincodeError {
    fn from(err: bincode::error::EncodeError) -> Self {
        BincodeError::Enc(Box::from(err))
    }
}

impl From<bincode::error::DecodeError> for BincodeError {
    fn from(err: bincode::error::DecodeError) -> Self {
        BincodeError::Dec(Box::from(err))
    }
}

/// Errors related to the external environment, such as I/O or system services.
///
/// 与外部环境相关的错误，例如 I/O 或系统服务。
#[derive(Debug, Error)]
pub enum EnvironmentError {
    /// An I/O operation failed.
    ///
    /// I/O 操作失败。
    #[error("I/O 操作失败: {0}")]
    Io(#[from] std::io::Error),

    /// The operating system's random number generator failed.
    /// This is a critical error as it compromises cryptographic security.
    ///
    /// 操作系统的随机数生成器失败。
    /// 这是一个严重错误，因为它会危及加密安全。
    #[error("操作系统随机数生成器失败: {0}")]
    OsRng(#[from] rand::rand_core::OsError),

    /// An asynchronous task failed to execute.
    /// This typically wraps errors from `tokio::task::JoinError`.
    ///
    /// 异步任务执行失败。
    /// 通常包装来自 `tokio::task::JoinError` 的错误。
    #[error("异步任务执行失败: {0}")]
    Async(String),
}

/// Errors related to data formatting and serialization.
///
/// 与数据格式和序列化相关的错误。
#[derive(Debug, Error)]
pub enum FormatError {
    /// A failure during `bincode` serialization or deserialization.
    ///
    /// `bincode` 序列化或反序列化期间的失败。
    #[error("序列化/反序列化失败: {0}")]
    Serialization(#[from] BincodeError),

    /// The ciphertext header is invalid, missing, or malformed.
    /// This prevents the decryptor from reading necessary metadata.
    ///
    /// 密文头部无效、缺失或格式不正确。
    /// 这会阻止解密器读取必要的元数据。
    #[error("头部信息无效、缺失或格式不正确")]
    InvalidHeader,

    /// The ciphertext stream is incomplete or its format is incorrect.
    /// This often indicates data corruption or truncation.
    ///
    /// 密文流不完整或其格式不正确。
    /// 这通常表示数据损坏或被截断。
    #[error("密文格式不正确或流不完整")]
    InvalidCiphertext,

    /// The key type is invalid.
    ///
    /// 密钥类型无效。
    #[error("密钥类型无效")]
    InvalidKeyType,

    /// The key is invalid.
    ///
    /// 密钥无效。
    #[error("密钥无效")]
    InvalidKey,

    /// The signature is invalid.
    ///
    /// 签名无效。
    #[error("签名无效")]
    InvalidSignature,
}

/// Errors related to key lookup and management.
///
/// 与密钥查找和管理相关的错误。
#[derive(Debug, Error)]
pub enum KeyManagementError {
    /// The requested key ID was not found in the `KeyProvider`.
    ///
    /// 在 `KeyProvider` 中未找到请求的密钥 ID。
    #[error("在密钥提供者中未找到ID为 '{0}' 的密钥")]
    KeyNotFound(String),

    /// An operation required a `KeyProvider` to resolve a key, but none was supplied.
    ///
    /// 操作需要 `KeyProvider` 来解析密钥，但没有提供。
    #[error("此操作需要一个密钥提供者，但未提供")]
    ProviderMissing,

    /// The ciphertext header is missing the symmetric key ID, making decryption impossible.
    ///
    /// 密文头部缺少对称密钥 ID，导致无法解密。
    #[error("密文头部缺少对称密钥ID")]
    KeyIdMissing,

    /// The ciphertext header is missing the Key-Encrypting-Key (KEK) ID in a hybrid scheme.
    ///
    /// 在混合方案中，密文头部缺少密钥加密密钥 (KEK) ID。
    #[error("密文头部缺少密钥加密密钥 (KEK) ID")]
    KekIdNotFound,
}

/// Errors related to cryptographic operations.
///
/// 与密码学操作相关的错误。
#[derive(Debug, Error)]
pub enum CryptoError {
    /// A signature was expected in the message header but was not found.
    ///
    /// 消息头部预期有签名但未找到。
    #[error("消息头部缺少预期的数字签名")]
    MissingSignature,

    /// The combination of algorithms or operations is not supported or invalid.
    ///
    /// 算法或操作的组合不受支持或无效。
    #[error("不支持的操作或算法组合")]
    UnsupportedOperation,

    /// An error originating from the underlying `seal-crypto` backend.
    ///
    /// 源自底层 `seal-crypto` 后端的错误。
    #[error("底层密码学库错误: {0}")]
    Backend(#[from] seal_crypto_wrapper::error::Error),
}

/// The main error type for the `seal-flow` crate.
///
/// This enum consolidates all possible errors into a single, comprehensive type,
/// categorized for easier matching and handling.
///
/// `seal-flow` crate 的主要错误类型。
///
/// 该枚举将所有可能的错误整合为一个单一、全面的类型，并进行分类以便于匹配和处理。
#[derive(Debug, Error)]
pub enum Error {
    /// An error related to the external environment (I/O, OS services).
    ///
    /// 与外部环境相关的错误（I/O、操作系统服务）。
    #[error("外部环境错误: {0}")]
    Environment(#[from] EnvironmentError),

    /// An error related to data formatting or serialization.
    ///
    /// 与数据格式或序列化相关的错误。
    #[error("数据格式错误: {0}")]
    Format(#[from] FormatError),

    /// An error during a cryptographic computation.
    ///
    /// 密码学计算期间的错误。
    #[error("密码学操作失败: {0}")]
    Crypto(#[from] CryptoError),

    /// An error related to key lookup or management.
    ///
    /// 与密钥查找或管理相关的错误。
    #[error("密钥管理错误: {0}")]
    KeyManagement(#[from] KeyManagementError),

    /// An error related to key provider.
    ///
    /// 与密钥提供者相关的错误。
    #[error("密钥提供者错误: {0}")]
    KeyProvider(#[from] KeyProviderError),

    /// An error indicating invalid configuration or API misuse.
    ///
    /// 表示无效配置或 API 滥用的错误。
    #[error("无效的配置或用法: {0}")]
    Configuration(String),

    /// An error that should never occur, indicating a logic bug.
    ///
    /// 永不应发生的错误，表示逻辑错误。
    #[error("Infallible Error: {0:?}")]
    Infallible(#[from] core::convert::Infallible),
}

impl From<tokio::task::JoinError> for Error {
    fn from(e: tokio::task::JoinError) -> Self {
        Error::Environment(EnvironmentError::Async(e.to_string()))
    }
}

impl From<seal_crypto_wrapper::error::Error> for Error {
    fn from(e: seal_crypto_wrapper::error::Error) -> Self {
        Error::Crypto(CryptoError::Backend(e))
    }
}

impl From<bincode::error::EncodeError> for Error {
    fn from(e: bincode::error::EncodeError) -> Self {
        Error::Format(FormatError::Serialization(BincodeError::Enc(Box::from(e))))
    }
}

impl From<bincode::error::DecodeError> for Error {
    fn from(e: bincode::error::DecodeError) -> Self {
        Error::Format(FormatError::Serialization(BincodeError::Dec(Box::from(e))))
    }
}

impl From<rand::rand_core::OsError> for Error {
    fn from(e: rand::rand_core::OsError) -> Self {
        Error::Environment(EnvironmentError::OsRng(e))
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Environment(EnvironmentError::Io(e))
    }
}

// Defines a unified Result type for the crate.
// 为 crate 定义一个统一的 Result 类型。
pub type Result<T> = std::result::Result<T, Error>;
