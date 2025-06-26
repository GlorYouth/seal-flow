use rand::rand_core::OsError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BincodeError {
    #[error("Encode error: {0}")]
    Enc(#[source] Box<bincode::error::EncodeError>),
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

#[derive(Debug, Error)]
pub enum Error {
    #[error("OS-level random number generation failed: {0}")]
    OsRngError(#[from] OsError),

    #[error("Infallible Error: {0:?}")]
    Infallible(#[from] core::convert::Infallible),

    #[error("底层I/O操作失败: {0}")]
    Io(#[from] std::io::Error),

    #[error("数据序列化或反序列化失败: {0}")]
    BincodeError(#[from] BincodeError),

    #[error("底层密码学库 seal-crypto 返回错误: {0}")]
    Crypto(#[from] seal_crypto::errors::Error),

    #[error("头部信息无效、缺失或已被篡改")]
    InvalidHeader,

    #[error("密文格式不正确或不完整")]
    InvalidCiphertextFormat,

    #[error("解密失败：数据可能已被篡改或密钥不匹配")]
    DecryptionFailed,

    #[error("不支持的操作或算法组合")]
    UnsupportedOperation,

    #[error("提供了错误的密钥类型（例如，需要私钥但提供了公钥）")]
    WrongKeyType,

    #[error("异步任务错误")]
    AsyncTaskError(#[from] tokio::task::JoinError),
}

impl From<bincode::error::EncodeError> for Error {
    fn from(err: bincode::error::EncodeError) -> Self {
        Error::from(BincodeError::Enc(Box::from(err)))
    }
}

impl From<bincode::error::DecodeError> for Error {
    fn from(err: bincode::error::DecodeError) -> Self {
        Error::from(BincodeError::Dec(Box::from(err)))
    }
}

// 定义一个统一的 Result 类型
pub type Result<T> = std::result::Result<T, Error>;
