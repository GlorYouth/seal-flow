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
        use crate::algorithms::symmetric::{
            Aes128GcmWrapper, Aes256GcmWrapper, ChaCha20Poly1305Wrapper, XChaCha20Poly1305Wrapper,
        };
        match self {
            SymmetricAlgorithm::Aes128Gcm => {
                SymmetricAlgorithmWrapper::new(Box::new(Aes128GcmWrapper::default()))
            }
            SymmetricAlgorithm::Aes256Gcm => {
                SymmetricAlgorithmWrapper::new(Box::new(Aes256GcmWrapper::default()))
            }
            SymmetricAlgorithm::ChaCha20Poly1305 => {
                SymmetricAlgorithmWrapper::new(Box::new(ChaCha20Poly1305Wrapper::default()))
            }
            SymmetricAlgorithm::XChaCha20Poly1305 => {
                SymmetricAlgorithmWrapper::new(Box::new(XChaCha20Poly1305Wrapper::default()))
            }
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
        use crate::algorithms::asymmetric::{
            Kyber1024Wrapper, Kyber512Wrapper, Kyber768Wrapper, Rsa2048Sha256Wrapper,
            Rsa4096Sha256Wrapper,
        };
        match self {
            AsymmetricAlgorithm::Rsa2048Sha256 => {
                AsymmetricAlgorithmWrapper::new(Box::new(Rsa2048Sha256Wrapper::default()))
            }
            AsymmetricAlgorithm::Rsa4096Sha256 => {
                AsymmetricAlgorithmWrapper::new(Box::new(Rsa4096Sha256Wrapper::default()))
            }
            AsymmetricAlgorithm::Kyber512 => {
                AsymmetricAlgorithmWrapper::new(Box::new(Kyber512Wrapper::default()))
            }
            AsymmetricAlgorithm::Kyber768 => {
                AsymmetricAlgorithmWrapper::new(Box::new(Kyber768Wrapper::default()))
            }
            AsymmetricAlgorithm::Kyber1024 => {
                AsymmetricAlgorithmWrapper::new(Box::new(Kyber1024Wrapper::default()))
            }
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

use crate::algorithms::signature::SignatureAlgorithmWrapper;

impl SignatureAlgorithm {
    pub fn into_signature_wrapper(self) -> SignatureAlgorithmWrapper {
        use crate::algorithms::signature::{
            Dilithium2Wrapper, Dilithium3Wrapper, Dilithium5Wrapper, EcdsaP256Wrapper,
            Ed25519Wrapper,
        };
        match self {
            SignatureAlgorithm::Dilithium2 => {
                SignatureAlgorithmWrapper::new(Box::new(Dilithium2Wrapper::default()))
            }
            SignatureAlgorithm::Dilithium3 => {
                SignatureAlgorithmWrapper::new(Box::new(Dilithium3Wrapper::default()))
            }
            SignatureAlgorithm::Dilithium5 => {
                SignatureAlgorithmWrapper::new(Box::new(Dilithium5Wrapper::default()))
            }
            SignatureAlgorithm::Ed25519 => {
                SignatureAlgorithmWrapper::new(Box::new(Ed25519Wrapper::default()))
            }
            SignatureAlgorithm::EcdsaP256 => {
                SignatureAlgorithmWrapper::new(Box::new(EcdsaP256Wrapper::default()))
            }
        }
    }
}

/// Key Derivation Function (KDF) algorithm enum.
///
/// 密钥派生函数 (KDF) 算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum KdfKeyAlgorithm {
    HkdfSha256,
    HkdfSha384,
    HkdfSha512,
}

use crate::algorithms::kdf::key::KdfKeyWrapper;

impl KdfKeyAlgorithm {
    pub fn into_kdf_key_wrapper(self) -> KdfKeyWrapper {
        use crate::algorithms::kdf::key::{
            HkdfSha256Wrapper, HkdfSha384Wrapper, HkdfSha512Wrapper,
        };
        match self {
            KdfKeyAlgorithm::HkdfSha256 => {
                KdfKeyWrapper::new(Box::new(HkdfSha256Wrapper::default()))
            }
            KdfKeyAlgorithm::HkdfSha384 => {
                KdfKeyWrapper::new(Box::new(HkdfSha384Wrapper::default()))
            }
            KdfKeyAlgorithm::HkdfSha512 => {
                KdfKeyWrapper::new(Box::new(HkdfSha512Wrapper::default()))
            }
        }
    }
}

/// Password-based KDF algorithm enum.
///
/// 基于密码的 KDF 算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum KdfPasswordAlgorithm {
    Argon2,
    Pbkdf2Sha256,
    Pbkdf2Sha384,
    Pbkdf2Sha512,
}

use crate::algorithms::kdf::passwd::KdfPasswordWrapper;

impl KdfPasswordAlgorithm {
    pub fn into_kdf_password_wrapper(self) -> KdfPasswordWrapper {
        use crate::algorithms::kdf::passwd::{
            Argon2Wrapper, Pbkdf2Sha256Wrapper, Pbkdf2Sha384Wrapper, Pbkdf2Sha512Wrapper,
        };
        match self {
            KdfPasswordAlgorithm::Argon2 => {
                KdfPasswordWrapper::new(Box::new(Argon2Wrapper::default()))
            }
            KdfPasswordAlgorithm::Pbkdf2Sha256 => {
                KdfPasswordWrapper::new(Box::new(Pbkdf2Sha256Wrapper::default()))
            }
            KdfPasswordAlgorithm::Pbkdf2Sha384 => {
                KdfPasswordWrapper::new(Box::new(Pbkdf2Sha384Wrapper::default()))
            }
            KdfPasswordAlgorithm::Pbkdf2Sha512 => {
                KdfPasswordWrapper::new(Box::new(Pbkdf2Sha512Wrapper::default()))
            }
        }
    }
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

use crate::algorithms::xof::XofWrapper;

impl XofAlgorithm {
    pub fn into_xof_wrapper(self) -> XofWrapper {
        use crate::algorithms::xof::{Shake128Wrapper, Shake256Wrapper};
        match self {
            XofAlgorithm::Shake128 => XofWrapper::new(Box::new(Shake128Wrapper::default())),
            XofAlgorithm::Shake256 => XofWrapper::new(Box::new(Shake256Wrapper::default())),
        }
    }
}
