use bincode::{Decode, Encode};

/// Symmetric encryption algorithm enum.
///
/// 对称加密算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
pub enum SymmetricAlgorithm {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

/// Asymmetric encryption algorithm enum.
///
/// 非对称加密算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
pub enum AsymmetricAlgorithm {
    Rsa2048,
    Rsa4096,
    Kyber512,
    Kyber768,
    Kyber1024,
}

/// Digital signature algorithm enum.
///
/// 数字签名算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
pub enum SignatureAlgorithm {
    Dilithium2,
    Dilithium3,
    Dilithium5,
    Ed25519,
    EcdsaP256,
}

/// Key Derivation Function (KDF) algorithm enum.
///
/// 密钥派生函数 (KDF) 算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
pub enum KdfAlgorithm {
    HkdfSha256,
    HkdfSha384,
    HkdfSha512,
}

/// Extendable-Output Function (XOF) algorithm enum.
///
/// 可扩展输出函数 (XOF) 算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
pub enum XofAlgorithm {
    Shake128,
    Shake256,
}
