use bincode::{Decode, Encode};

/// 对称加密算法枚举
#[derive(Clone, Debug, PartialEq, Eq, Hash, Decode, Encode)]
pub enum SymmetricAlgorithm {
    Aes256Gcm,
}

/// 非对称加密算法枚举
#[derive(Clone, Debug, PartialEq, Eq, Hash, Decode, Encode)]
pub enum AsymmetricAlgorithm {
    Rsa2048,
}
