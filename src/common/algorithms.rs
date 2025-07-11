use bincode::{Decode, Encode};


/// Symmetric encryption algorithm enum.
///
/// 对称加密算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SymmetricAlgorithm {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

use crate::algorithms::symmetric::SymmetricAlgorithmWrapper;
impl SymmetricAlgorithm {
    pub fn into_symmetric_wrapper(self) -> SymmetricAlgorithmWrapper {
        use crate::algorithms::symmetric::{Aes128GcmWrapper, Aes256GcmWrapper, ChaCha20Poly1305Wrapper, XChaCha20Poly1305Wrapper};
        match self {
            SymmetricAlgorithm::Aes128Gcm => SymmetricAlgorithmWrapper::new(Box::new(Aes128GcmWrapper::default())),
            SymmetricAlgorithm::Aes256Gcm => SymmetricAlgorithmWrapper::new(Box::new(Aes256GcmWrapper::default())),
            SymmetricAlgorithm::ChaCha20Poly1305 => SymmetricAlgorithmWrapper::new(Box::new(ChaCha20Poly1305Wrapper::default())),
            SymmetricAlgorithm::XChaCha20Poly1305 => SymmetricAlgorithmWrapper::new(Box::new(XChaCha20Poly1305Wrapper::default())),
        }
    }
}

/// Asymmetric encryption algorithm enum.
///
/// 非对称加密算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AsymmetricAlgorithm {
    Rsa2048Sha256,
    Rsa4096Sha256,
    Kyber512,
    Kyber768,
    Kyber1024,
}

use crate::algorithms::asymmetric::AsymmetricAlgorithmWrapper;
impl AsymmetricAlgorithm {
    pub fn into_asymmetric_wrapper(self) -> AsymmetricAlgorithmWrapper {
        use crate::algorithms::definitions::asymmetric::{Rsa2048Sha256Wrapper, Rsa4096Sha256Wrapper, Kyber512Wrapper, Kyber768Wrapper, Kyber1024Wrapper};
        match self {
            AsymmetricAlgorithm::Rsa2048Sha256 => AsymmetricAlgorithmWrapper::new(Box::new(Rsa2048Sha256Wrapper::default())),
            AsymmetricAlgorithm::Rsa4096Sha256 => AsymmetricAlgorithmWrapper::new(Box::new(Rsa4096Sha256Wrapper::default())),
            AsymmetricAlgorithm::Kyber512 => AsymmetricAlgorithmWrapper::new(Box::new(Kyber512Wrapper::default())),
            AsymmetricAlgorithm::Kyber768 => AsymmetricAlgorithmWrapper::new(Box::new(Kyber768Wrapper::default())),
            AsymmetricAlgorithm::Kyber1024 => AsymmetricAlgorithmWrapper::new(Box::new(Kyber1024Wrapper::default())),
        }
    }
}

/// Digital signature algorithm enum.
///
/// 数字签名算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum KdfAlgorithm {
    HkdfSha256,
    HkdfSha384,
    HkdfSha512,
}

/// Extendable-Output Function (XOF) algorithm enum.
///
/// 可扩展输出函数 (XOF) 算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum XofAlgorithm {
    Shake128,
    Shake256,
}
