use bincode::{Decode, Encode};

/// 对称加密算法枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
pub enum SymmetricAlgorithm {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

/// 非对称加密算法枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
pub enum AsymmetricAlgorithm {
    Rsa2048,
    Rsa4096,
    Kyber512,
    Kyber768,
    Kyber1024,
}

/// 数字签名算法枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
pub enum SignatureAlgorithm {
    Dilithium2,
    Dilithium3,
    Dilithium5,
}
