use bincode::{Decode, Encode};

/// 对称加密算法枚举
#[derive(Clone, Debug, PartialEq, Eq, Hash, Decode, Encode)]
pub enum SymmetricAlgorithm {
    Aes128Gcm,
    Aes256Gcm,
}

/// 非对称加密算法枚举
#[derive(Clone, Debug, PartialEq, Eq, Hash, Decode, Encode)]
pub enum AsymmetricAlgorithm {
    Rsa2048,
    Rsa4096,
    Kyber512,
    Kyber768,
    Kyber1024,
}
