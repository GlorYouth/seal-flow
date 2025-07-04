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
pub enum EnvironmentError {
    #[error("I/O 操作失败: {0}")]
    Io(#[from] std::io::Error),

    #[error("操作系统随机数生成器失败: {0}")]
    OsRng(#[from] rand::rand_core::OsError),

    #[error("异步任务执行失败: {0}")]
    Async(String),
}

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("序列化/反序列化失败: {0}")]
    Serialization(#[from] BincodeError),

    #[error("头部信息无效、缺失或格式不正确")]
    InvalidHeader,

    #[error("密文格式不正确或流不完整")]
    InvalidCiphertext,
}

#[derive(Debug, Error)]
pub enum KeyManagementError {
    #[error("在密钥提供者中未找到ID为 '{0}' 的密钥")]
    KeyNotFound(String),

    #[error("此操作需要一个密钥提供者，但未提供")]
    ProviderMissing,

    #[error("密文头部缺少对称密钥ID")]
    KeyIdMissing,

    #[error("密文头部缺少密钥加密密钥 (KEK) ID")]
    KekIdNotFound,
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("消息头部缺少预期的数字签名")]
    MissingSignature,

    #[error("不支持的操作或算法组合")]
    UnsupportedOperation,

    #[error("底层密码学库错误: {0}")]
    Backend(#[from] seal_crypto::errors::Error),
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("外部环境错误: {0}")]
    Environment(#[from] EnvironmentError),

    #[error("数据格式错误: {0}")]
    Format(#[from] FormatError),

    #[error("密码学操作失败: {0}")]
    Crypto(#[from] CryptoError),

    #[error("密钥管理错误: {0}")]
    KeyManagement(#[from] KeyManagementError),

    #[error("无效的配置或用法: {0}")]
    Configuration(String),

    #[error("Infallible Error: {0:?}")]
    Infallible(#[from] core::convert::Infallible),
}

impl From<tokio::task::JoinError> for Error {
    fn from(e: tokio::task::JoinError) -> Self {
        Error::Environment(EnvironmentError::Async(e.to_string()))
    }
}

impl From<seal_crypto::errors::Error> for Error {
    fn from(e: seal_crypto::errors::Error) -> Self {
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



// 定义一个统一的 Result 类型
pub type Result<T> = std::result::Result<T, Error>;
