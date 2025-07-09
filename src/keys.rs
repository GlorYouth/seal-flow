//! This module defines byte wrappers for cryptographic keys.
//!
//! 这个模块为加密密钥定义了字节包装器。
use crate::common::algorithms::{
    AsymmetricAlgorithm as AsymmetricAlgorithmEnum, SignatureAlgorithm as SignatureAlgorithmEnum,
    SymmetricAlgorithm as SymmetricAlgorithmEnum,
};
use crate::error::Error;
use seal_crypto::prelude::{AsymmetricKeySet, KeyGenerator, SymmetricKeySet};
use seal_crypto::schemes::asymmetric::{
    post_quantum::{
        dilithium::{Dilithium2, Dilithium3, Dilithium5},
        kyber::{Kyber1024, Kyber512, Kyber768},
    },
    traditional::{
        ecc::{EcdsaP256, Ed25519},
        rsa::{Rsa2048, Rsa4096},
    },
};
use seal_crypto::schemes::hash::Sha256;
use seal_crypto::schemes::symmetric::{
    aes_gcm::{Aes128Gcm, Aes256Gcm},
    chacha20_poly1305::{ChaCha20Poly1305, XChaCha20Poly1305},
};
use seal_crypto::{prelude::*, secrecy::SecretBox, zeroize};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub(crate) mod provider;

/// An enum wrapping a typed asymmetric key pair.
///
/// 包装了类型化非对称密钥对的枚举。
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub enum TypedAsymmetricKeyPair {
    Rsa2048Sha256(
        (
            <Rsa2048<Sha256> as AsymmetricKeySet>::PublicKey,
            <Rsa2048<Sha256> as AsymmetricKeySet>::PrivateKey,
        ),
    ),
    Rsa4096Sha256(
        (
            <Rsa4096<Sha256> as AsymmetricKeySet>::PublicKey,
            <Rsa4096<Sha256> as AsymmetricKeySet>::PrivateKey,
        ),
    ),
    Kyber512(
        (
            <Kyber512 as AsymmetricKeySet>::PublicKey,
            <Kyber512 as AsymmetricKeySet>::PrivateKey,
        ),
    ),
    Kyber768(
        (
            <Kyber768 as AsymmetricKeySet>::PublicKey,
            <Kyber768 as AsymmetricKeySet>::PrivateKey,
        ),
    ),
    Kyber1024(
        (
            <Kyber1024 as AsymmetricKeySet>::PublicKey,
            <Kyber1024 as AsymmetricKeySet>::PrivateKey,
        ),
    ),
}

impl TypedAsymmetricKeyPair {
    /// Generates a new key pair for the specified algorithm.
    ///
    /// 为指定的算法生成一个新的密钥对。
    pub fn generate(algorithm: AsymmetricAlgorithmEnum) -> Result<Self, Error> {
        match algorithm {
            AsymmetricAlgorithmEnum::Rsa2048Sha256 => {
                Ok(Rsa2048::<Sha256>::generate_keypair().map(Self::Rsa2048Sha256)?)
            }
            AsymmetricAlgorithmEnum::Rsa4096Sha256 => {
                Ok(Rsa4096::<Sha256>::generate_keypair().map(Self::Rsa4096Sha256)?)
            }
            AsymmetricAlgorithmEnum::Kyber512 => {
                Ok(Kyber512::generate_keypair().map(Self::Kyber512)?)
            }
            AsymmetricAlgorithmEnum::Kyber768 => {
                Ok(Kyber768::generate_keypair().map(Self::Kyber768)?)
            }
            AsymmetricAlgorithmEnum::Kyber1024 => {
                Ok(Kyber1024::generate_keypair().map(Self::Kyber1024)?)
            }
        }
    }

    pub fn into_keypair(self) -> (TypedAsymmetricPublicKey, TypedAsymmetricPrivateKey) {
        match self {
            Self::Rsa2048Sha256((pk, sk)) => {
                (TypedAsymmetricPublicKey::Rsa2048Sha256(pk), TypedAsymmetricPrivateKey::Rsa2048Sha256(sk))
            },
            Self::Rsa4096Sha256((pk, sk)) => {
                (TypedAsymmetricPublicKey::Rsa4096Sha256(pk), TypedAsymmetricPrivateKey::Rsa4096Sha256(sk))
            },
            Self::Kyber512((pk, sk)) => {
                (TypedAsymmetricPublicKey::Kyber512(pk), TypedAsymmetricPrivateKey::Kyber512(sk))
            },
            Self::Kyber768((pk, sk)) => {
                (TypedAsymmetricPublicKey::Kyber768(pk), TypedAsymmetricPrivateKey::Kyber768(sk))
            },
            Self::Kyber1024((pk, sk)) => {
                (TypedAsymmetricPublicKey::Kyber1024(pk), TypedAsymmetricPrivateKey::Kyber1024(sk))
            },
        }
    }

    /// Returns the public key as a generic byte wrapper.
    ///
    /// 以通用字节包装器形式返回公钥。
    pub fn public_key(&self) -> AsymmetricPublicKey {
        let bytes = match self {
            Self::Rsa2048Sha256((pk, _)) => pk.to_bytes(),
            Self::Rsa4096Sha256((pk, _)) => pk.to_bytes(),
            Self::Kyber512((pk, _)) => pk.to_bytes(),
            Self::Kyber768((pk, _)) => pk.to_bytes(),
            Self::Kyber1024((pk, _)) => pk.to_bytes(),
        };
        AsymmetricPublicKey::new(bytes)
    }

    /// Returns the private key as a generic byte wrapper.
    ///
    /// 以通用字节包装器形式返回私钥。
    pub fn private_key(&self) -> AsymmetricPrivateKey {
        let bytes = match self {
            Self::Rsa2048Sha256((_, sk)) => sk.to_bytes(),
            Self::Rsa4096Sha256((_, sk)) => sk.to_bytes(),
            Self::Kyber512((_, sk)) => sk.to_bytes(),
            Self::Kyber768((_, sk)) => sk.to_bytes(),
            Self::Kyber1024((_, sk)) => sk.to_bytes(),
        };
        AsymmetricPrivateKey::new(bytes)
    }

    /// Returns the algorithm of the key pair.
    ///
    /// 返回密钥对的算法。
    pub fn get_algorithm(&self) -> AsymmetricAlgorithmEnum {
        match self {
            Self::Rsa2048Sha256(_) => AsymmetricAlgorithmEnum::Rsa2048Sha256,
            Self::Rsa4096Sha256(_) => AsymmetricAlgorithmEnum::Rsa4096Sha256,
            Self::Kyber512(_) => AsymmetricAlgorithmEnum::Kyber512,
            Self::Kyber768(_) => AsymmetricAlgorithmEnum::Kyber768,
            Self::Kyber1024(_) => AsymmetricAlgorithmEnum::Kyber1024,
        }
    }
}

/// An enum wrapping a typed signature key pair.
///
/// 包装了类型化签名密钥对的枚举。
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub enum TypedSignatureKeyPair {
    Dilithium2(
        (
            <Dilithium2 as AsymmetricKeySet>::PublicKey,
            <Dilithium2 as AsymmetricKeySet>::PrivateKey,
        ),
    ),
    Dilithium3(
        (
            <Dilithium3 as AsymmetricKeySet>::PublicKey,
            <Dilithium3 as AsymmetricKeySet>::PrivateKey,
        ),
    ),
    Dilithium5(
        (
            <Dilithium5 as AsymmetricKeySet>::PublicKey,
            <Dilithium5 as AsymmetricKeySet>::PrivateKey,
        ),
    ),
    Ed25519(
        (
            <Ed25519 as AsymmetricKeySet>::PublicKey,
            <Ed25519 as AsymmetricKeySet>::PrivateKey,
        ),
    ),
    EcdsaP256(
        (
            <EcdsaP256 as AsymmetricKeySet>::PublicKey,
            <EcdsaP256 as AsymmetricKeySet>::PrivateKey,
        ),
    ),
}

impl TypedSignatureKeyPair {
    /// Generates a new key pair for the specified algorithm.
    ///
    /// 为指定的算法生成一个新的密钥对。
    pub fn generate(algorithm: SignatureAlgorithmEnum) -> Result<Self, Error> {
        match algorithm {
            SignatureAlgorithmEnum::Dilithium2 => {
                Ok(Dilithium2::generate_keypair().map(Self::Dilithium2)?)
            }
            SignatureAlgorithmEnum::Dilithium3 => {
                Ok(Dilithium3::generate_keypair().map(Self::Dilithium3)?)
            }
            SignatureAlgorithmEnum::Dilithium5 => {
                Ok(Dilithium5::generate_keypair().map(Self::Dilithium5)?)
            }
            SignatureAlgorithmEnum::Ed25519 => Ok(Ed25519::generate_keypair().map(Self::Ed25519)?),
            SignatureAlgorithmEnum::EcdsaP256 => {
                Ok(EcdsaP256::generate_keypair().map(Self::EcdsaP256)?)
            }
        }
    }

    /// Returns the public key as a generic byte wrapper.
    ///
    /// 以通用字节包装器形式返回公钥。
    pub fn public_key(&self) -> SignaturePublicKey {
        let bytes = match self {
            Self::Dilithium2((pk, _)) => pk.to_bytes(),
            Self::Dilithium3((pk, _)) => pk.to_bytes(),
            Self::Dilithium5((pk, _)) => pk.to_bytes(),
            Self::Ed25519((pk, _)) => pk.to_bytes(),
            Self::EcdsaP256((pk, _)) => pk.to_bytes(),
        };
        SignaturePublicKey::new(bytes)
    }

    /// Returns the private key as a generic byte wrapper.
    ///
    /// 以通用字节包装器形式返回私钥。
    pub fn private_key(&self) -> AsymmetricPrivateKey {
        let bytes = match self {
            Self::Dilithium2((_, sk)) => sk.to_bytes(),
            Self::Dilithium3((_, sk)) => sk.to_bytes(),
            Self::Dilithium5((_, sk)) => sk.to_bytes(),
            Self::Ed25519((_, sk)) => sk.to_bytes(),
            Self::EcdsaP256((_, sk)) => sk.to_bytes(),
        };
        AsymmetricPrivateKey::new(bytes)
    }

    /// Returns the algorithm of the key pair.
    ///
    /// 返回密钥对的算法。
    pub fn get_algorithm(&self) -> SignatureAlgorithmEnum {
        match self {
            Self::Dilithium2(_) => SignatureAlgorithmEnum::Dilithium2,
            Self::Dilithium3(_) => SignatureAlgorithmEnum::Dilithium3,
            Self::Dilithium5(_) => SignatureAlgorithmEnum::Dilithium5,
            Self::Ed25519(_) => SignatureAlgorithmEnum::Ed25519,
            Self::EcdsaP256(_) => SignatureAlgorithmEnum::EcdsaP256,
        }
    }
}

/// An enum wrapping a typed asymmetric private key.
///
/// 包装了类型化非对称私钥的枚举。
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub enum TypedAsymmetricPublicKey {
    Rsa2048Sha256(<Rsa2048<Sha256> as AsymmetricKeySet>::PublicKey),
    Rsa4096Sha256(<Rsa4096<Sha256> as AsymmetricKeySet>::PublicKey),
    Kyber512(<Kyber512 as AsymmetricKeySet>::PublicKey),
    Kyber768(<Kyber768 as AsymmetricKeySet>::PublicKey),
    Kyber1024(<Kyber1024 as AsymmetricKeySet>::PublicKey),
}

/// An enum wrapping a typed asymmetric private key.
///
/// 包装了类型化非对称私钥的枚举。
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub enum TypedAsymmetricPrivateKey {
    Rsa2048Sha256(<Rsa2048<Sha256> as AsymmetricKeySet>::PrivateKey),
    Rsa4096Sha256(<Rsa4096<Sha256> as AsymmetricKeySet>::PrivateKey),
    Kyber512(<Kyber512 as AsymmetricKeySet>::PrivateKey),
    Kyber768(<Kyber768 as AsymmetricKeySet>::PrivateKey),
    Kyber1024(<Kyber1024 as AsymmetricKeySet>::PrivateKey),
}

/// An enum wrapping a typed symmetric key.
///
/// 包装了类型化对称密钥的枚举。
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub enum TypedSymmetricKey {
    Aes128Gcm(<Aes128Gcm as SymmetricKeySet>::Key),
    Aes256Gcm(<Aes256Gcm as SymmetricKeySet>::Key),
    XChaCha20Poly1305(<XChaCha20Poly1305 as SymmetricKeySet>::Key),
    ChaCha20Poly1305(<ChaCha20Poly1305 as SymmetricKeySet>::Key),
}

impl TypedSymmetricKey {
    pub fn from_bytes(bytes: &[u8], algorithm: SymmetricAlgorithmEnum) -> Result<Self, Error> {
        match algorithm {
            SymmetricAlgorithmEnum::Aes128Gcm => {
                Ok(Self::Aes128Gcm(<Aes128Gcm as SymmetricKeySet>::Key::from_bytes(bytes)?))
            }
            SymmetricAlgorithmEnum::Aes256Gcm => {
                Ok(Self::Aes256Gcm(<Aes256Gcm as SymmetricKeySet>::Key::from_bytes(bytes)?))
            }
            SymmetricAlgorithmEnum::XChaCha20Poly1305 => {
                Ok(Self::XChaCha20Poly1305(<XChaCha20Poly1305 as SymmetricKeySet>::Key::from_bytes(bytes)?))
            }
            SymmetricAlgorithmEnum::ChaCha20Poly1305 => {
                Ok(Self::ChaCha20Poly1305(<ChaCha20Poly1305 as SymmetricKeySet>::Key::from_bytes(bytes)?))
            }
        }
    }

    pub fn algorithm(&self) -> SymmetricAlgorithmEnum {
        match self {
            Self::Aes128Gcm(_) => SymmetricAlgorithmEnum::Aes128Gcm,
            Self::Aes256Gcm(_) => SymmetricAlgorithmEnum::Aes256Gcm,
            Self::XChaCha20Poly1305(_) => SymmetricAlgorithmEnum::XChaCha20Poly1305,
            Self::ChaCha20Poly1305(_) => SymmetricAlgorithmEnum::ChaCha20Poly1305,
        }
    }
}


impl AsRef<[u8]> for TypedSymmetricKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Aes128Gcm(key) => key.as_ref(),
            Self::Aes256Gcm(key) => key.as_ref(),
            Self::XChaCha20Poly1305(key) => key.as_ref(),
            Self::ChaCha20Poly1305(key) => key.as_ref(),
        }
    }
}

/// A byte wrapper for a symmetric encryption key.
///
/// This struct stores raw key bytes that can be converted to specific algorithm keys
/// when needed. This simplifies key management while maintaining flexibility.
///
/// 对称加密密钥的字节包装器。
///
/// 这个结构体存储原始密钥字节，可以在需要时转换为特定算法的密钥。
/// 这在简化密钥管理的同时保持了灵活性的。
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SymmetricKey(pub zeroize::Zeroizing<Vec<u8>>);

impl SymmetricKey {
    /// Create a new symmetric key from bytes
    ///
    /// 从字节创建一个新的对称密钥
    pub fn new(bytes: impl Into<zeroize::Zeroizing<Vec<u8>>>) -> Self {
        Self(bytes.into())
    }

    /// Generates a new random symmetric key of the specified length.
    ///
    /// This is useful for creating new keys for encryption or for key rotation.
    /// It uses the operating system's cryptographically secure random number generator.
    ///
    /// 生成一个指定长度的新的随机对称密钥。
    ///
    /// 这对于为加密或密钥轮换创建新密钥很有用。
    /// 它使用操作系统的加密安全随机数生成器。
    ///
    /// # Arguments
    ///
    /// * `len` - The desired length of the key in bytes.
    ///
    /// * `len` - 所需的密钥长度（以字节为单位）。
    pub fn generate(len: usize) -> Result<Self, Error> {
        use rand::{rngs::OsRng, TryRngCore};
        let mut key_bytes = vec![0; len];
        OsRng.try_fill_bytes(&mut key_bytes)?;
        Ok(Self::new(key_bytes))
    }

    /// Get a reference to the raw bytes of the key
    ///
    /// 获取密钥原始字节的引用
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the key and return the inner bytes
    ///
    /// 消耗密钥并返回内部字节
    pub fn into_bytes(self) -> zeroize::Zeroizing<Vec<u8>> {
        self.0
    }

    /// Converts the raw key bytes into a typed symmetric key enum.
    ///
    /// 将原始密钥字节转换为类型化的对称密钥枚举。
    pub fn into_typed(self, algorithm: SymmetricAlgorithmEnum) -> Result<TypedSymmetricKey, Error> {
        match algorithm {
            SymmetricAlgorithmEnum::Aes128Gcm => {
                let key = <Aes128Gcm as SymmetricKeySet>::Key::from_bytes(self.as_bytes())?;
                Ok(TypedSymmetricKey::Aes128Gcm(key))
            }
            SymmetricAlgorithmEnum::Aes256Gcm => {
                let key = <Aes256Gcm as SymmetricKeySet>::Key::from_bytes(self.as_bytes())?;
                Ok(TypedSymmetricKey::Aes256Gcm(key))
            }
            SymmetricAlgorithmEnum::XChaCha20Poly1305 => {
                let key = <XChaCha20Poly1305 as SymmetricKeySet>::Key::from_bytes(self.as_bytes())?;
                Ok(TypedSymmetricKey::XChaCha20Poly1305(key))
            }
            SymmetricAlgorithmEnum::ChaCha20Poly1305 => {
                let key = <ChaCha20Poly1305 as SymmetricKeySet>::Key::from_bytes(self.as_bytes())?;
                Ok(TypedSymmetricKey::ChaCha20Poly1305(key))
            }
        }
    }

    /// Derives a new symmetric key from the current key using a specified key-based KDF.
    ///
    /// This is suitable for key rotation, where a master key is used to generate
    /// sub-keys for specific purposes.
    ///
    /// # Type Parameters
    ///
    /// * `K` - The type of the key-based derivation algorithm, which must implement `KeyBasedDerivation`.
    ///
    /// # Arguments
    ///
    /// * `deriver` - An instance of the key-based KDF scheme (e.g., `HkdfSha256`).
    /// * `salt` - An optional salt. While optional in HKDF, providing a salt is highly recommended.
    /// * `info` - Optional context-specific information.
    /// * `output_len` - The desired length of the derived key in bytes.
    pub fn derive_key<K>(
        &self,
        deriver: &K,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Self, Error>
    where
        K: KeyBasedDerivation,
    {
        let derived_key_bytes = deriver.derive(self.as_bytes(), salt, info, output_len)?;
        Ok(SymmetricKey::new(derived_key_bytes.as_bytes().to_vec()))
    }

    /// Derives a symmetric key from a password using a specified password-based KDF.
    ///
    /// This is ideal for generating a cryptographic key from a low-entropy user password.
    /// The concrete algorithm instance (e.g., `Pbkdf2Sha256`) should be configured
    /// with the desired number of iterations before being passed to this function.
    ///
    /// # Type Parameters
    ///
    /// * `P` - The type of the password-based derivation algorithm, which must implement `PasswordBasedDerivation`.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to derive the key from.
    /// * `deriver` - An instance of the password-based KDF scheme (e.g., `Pbkdf2Sha256::new(100_000)`).
    /// * `salt` - A salt. This is **required** for password-based derivation to be secure.
    /// * `output_len` - The desired length of the derived key in bytes.
    pub fn derive_from_password<P>(
        password: &SecretBox<[u8]>,
        deriver: &P,
        salt: &[u8],
        output_len: usize,
    ) -> Result<Self, Error>
    where
        P: PasswordBasedDerivation,
    {
        let derived_key_bytes = deriver.derive(password, salt, output_len)?;
        Ok(SymmetricKey::new(derived_key_bytes.as_bytes().to_vec()))
    }
}

/// A byte wrapper for an asymmetric private key.
///
/// 非对称私钥的字节包装器。
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AsymmetricPrivateKey(pub zeroize::Zeroizing<Vec<u8>>);

impl AsymmetricPrivateKey {
    /// Create a new asymmetric private key from bytes
    ///
    /// 从字节创建一个新的非对称私钥
    pub fn new(bytes: impl Into<zeroize::Zeroizing<Vec<u8>>>) -> Self {
        Self(bytes.into())
    }

    /// Get a reference to the raw bytes of the key
    ///
    /// 获取密钥原始字节的引用
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the key and return the inner bytes
    ///
    /// 消耗密钥并返回内部字节
    pub fn into_bytes(self) -> zeroize::Zeroizing<Vec<u8>> {
        self.0
    }

    /// Converts the raw key bytes into a typed private key enum.
    ///
    /// 将原始密钥字节转换为类型化的私钥枚举。
    pub fn into_typed(
        self,
        algorithm: AsymmetricAlgorithmEnum,
    ) -> Result<TypedAsymmetricPrivateKey, Error> {
        match algorithm {
            AsymmetricAlgorithmEnum::Rsa2048Sha256 => {
                let sk =
                    <Rsa2048<Sha256> as AsymmetricKeySet>::PrivateKey::from_bytes(self.as_bytes())?;
                Ok(TypedAsymmetricPrivateKey::Rsa2048Sha256(sk))
            }
            AsymmetricAlgorithmEnum::Rsa4096Sha256 => {
                let sk =
                    <Rsa4096<Sha256> as AsymmetricKeySet>::PrivateKey::from_bytes(self.as_bytes())?;
                Ok(TypedAsymmetricPrivateKey::Rsa4096Sha256(sk))
            }
            AsymmetricAlgorithmEnum::Kyber512 => {
                let sk = <Kyber512 as AsymmetricKeySet>::PrivateKey::from_bytes(self.as_bytes())?;
                Ok(TypedAsymmetricPrivateKey::Kyber512(sk))
            }
            AsymmetricAlgorithmEnum::Kyber768 => {
                let sk = <Kyber768 as AsymmetricKeySet>::PrivateKey::from_bytes(self.as_bytes())?;
                Ok(TypedAsymmetricPrivateKey::Kyber768(sk))
            }
            AsymmetricAlgorithmEnum::Kyber1024 => {
                let sk = <Kyber1024 as AsymmetricKeySet>::PrivateKey::from_bytes(self.as_bytes())?;
                Ok(TypedAsymmetricPrivateKey::Kyber1024(sk))
            }
        }
    }
}

/// A byte wrapper for an asymmetric public key.
///
/// 非对称公钥的字节包装器。
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AsymmetricPublicKey(pub zeroize::Zeroizing<Vec<u8>>);

impl AsymmetricPublicKey {
    /// Create a new asymmetric public key from bytes
    ///
    /// 从字节创建一个新的非对称公钥
    pub fn new(bytes: impl Into<zeroize::Zeroizing<Vec<u8>>>) -> Self {
        Self(bytes.into())
    }

    /// Get a reference to the raw bytes of the key
    ///
    /// 获取密钥原始字节的引用
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the key and return the inner bytes
    ///
    /// 消耗密钥并返回内部字节
    pub fn into_bytes(self) -> zeroize::Zeroizing<Vec<u8>> {
        self.0
    }
}

/// A byte wrapper for a signature public key.
///
/// 签名公钥的字节包装器。
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SignaturePublicKey(pub zeroize::Zeroizing<Vec<u8>>);

impl SignaturePublicKey {
    /// Create a new signature public key from bytes
    ///
    /// 从字节创建一个新的签名公钥
    pub fn new(bytes: impl Into<zeroize::Zeroizing<Vec<u8>>>) -> Self {
        Self(bytes.into())
    }

    /// Get a reference to the raw bytes of the key
    ///
    /// 获取密钥原始字节的引用
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the key and return the inner bytes
    ///
    /// 消耗密钥并返回内部字节
    pub fn into_bytes(self) -> zeroize::Zeroizing<Vec<u8>> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::schemes::kdf::{hkdf::HkdfSha256, pbkdf2::Pbkdf2Sha256};

    #[test]
    fn test_symmetric_key_generate() {
        use seal_crypto::{prelude::SymmetricCipher, schemes::symmetric::aes_gcm::Aes256Gcm};

        let key_len = <Aes256Gcm as SymmetricCipher>::KEY_SIZE;
        let key1 = SymmetricKey::generate(key_len).unwrap();
        let key2 = SymmetricKey::generate(key_len).unwrap();

        assert_eq!(key1.as_bytes().len(), key_len);
        assert_eq!(key2.as_bytes().len(), key_len);
        assert_ne!(
            key1.as_bytes(),
            key2.as_bytes(),
            "Generated keys should be unique"
        );
    }

    #[test]
    fn test_symmetric_key_from_bytes() {
        let key_bytes = vec![0u8; 32];
        let key = SymmetricKey::new(key_bytes.clone());

        assert_eq!(key.as_bytes(), key_bytes.as_slice());
    }

    #[test]
    fn test_symmetric_key_derive_key() {
        // 使用HKDF-SHA256进行密钥派生
        let master_key = SymmetricKey::new(vec![0u8; 32]);
        let deriver = HkdfSha256::default();

        // 使用不同的上下文信息派生出不同的子密钥
        let salt = b"salt_value";
        let info1 = b"encryption_key";
        let info2 = b"signing_key";

        let derived_key1 = master_key
            .derive_key(&deriver, Some(salt), Some(info1), 32)
            .unwrap();
        let derived_key2 = master_key
            .derive_key(&deriver, Some(salt), Some(info2), 32)
            .unwrap();

        // 相同的主密钥和参数应该产生相同的派生密钥
        let derived_key1_again = master_key
            .derive_key(&deriver, Some(salt), Some(info1), 32)
            .unwrap();

        // 不同的上下文信息应该产生不同的派生密钥
        assert_ne!(derived_key1.as_bytes(), derived_key2.as_bytes());

        // 相同的参数应该产生相同的派生密钥
        assert_eq!(derived_key1.as_bytes(), derived_key1_again.as_bytes());
    }

    #[test]
    fn test_symmetric_key_derive_from_password() {
        // 使用PBKDF2-SHA256从密码派生密钥
        let password = SecretBox::new(Box::from(b"my_secure_password".as_slice()));
        let salt = b"random_salt_value";

        // 设置较少的迭代次数以加速测试（实际应用中应使用更多迭代）
        let deriver = Pbkdf2Sha256::new(1000);

        let derived_key1 =
            SymmetricKey::derive_from_password(&password, &deriver, salt, 32).unwrap();

        // 相同的密码、盐和迭代次数应该产生相同的密钥
        let derived_key2 =
            SymmetricKey::derive_from_password(&password, &deriver, salt, 32).unwrap();

        assert_eq!(derived_key1.as_bytes(), derived_key2.as_bytes());

        // 不同的密码应该产生不同的密钥
        let different_password = SecretBox::new(Box::from(b"different_password".as_slice()));
        let derived_key3 =
            SymmetricKey::derive_from_password(&different_password, &deriver, salt, 32).unwrap();

        assert_ne!(derived_key1.as_bytes(), derived_key3.as_bytes());

        // 不同的盐应该产生不同的密钥
        let different_salt = b"different_salt_value";
        let derived_key4 =
            SymmetricKey::derive_from_password(&password, &deriver, different_salt, 32).unwrap();

        assert_ne!(derived_key1.as_bytes(), derived_key4.as_bytes());
    }

    #[test]
    fn test_key_derivation_output_length() {
        let master_key = SymmetricKey::new(vec![0u8; 32]);
        let deriver = HkdfSha256::default();
        let salt = b"salt";
        let info = b"info";

        // 测试不同长度的输出
        let key_16 = master_key
            .derive_key(&deriver, Some(salt), Some(info), 16)
            .unwrap();
        let key_32 = master_key
            .derive_key(&deriver, Some(salt), Some(info), 32)
            .unwrap();
        let key_64 = master_key
            .derive_key(&deriver, Some(salt), Some(info), 64)
            .unwrap();

        assert_eq!(key_16.as_bytes().len(), 16);
        assert_eq!(key_32.as_bytes().len(), 32);
        assert_eq!(key_64.as_bytes().len(), 64);
    }
}
