//! Defines the core traits for type-safe algorithm specification.
//!
//! 定义用于类型安全算法规范的核心 trait。

use crate::error::Result;
use crate::keys::{TypedAsymmetricPrivateKey, TypedAsymmetricPublicKey, TypedSymmetricKey};
use crate::{common, keys::TypedAsymmetricKeyPair};
use seal_crypto::prelude::*;
use seal_crypto::zeroize::Zeroizing;

macro_rules! impl_trait_for_box {
    ($trait:ident {
        $(fn $method:ident(&self, $($arg:ident: $ty:ty),*) -> $ret:ty;)*
    }) => {
        impl Clone for Box<dyn $trait> {
            fn clone(&self) -> Self {
                self.clone_box()
            }
        }

        impl $trait for Box<dyn $trait> {
            $(
                fn $method(&self, $($arg: $ty),*) -> $ret {
                    self.as_ref().$method($($arg),*)
                }
            )*
        }
    };
}

/// Represents a concrete symmetric encryption algorithm.
/// This is an object-safe trait that erases the concrete algorithm type.
///
/// 表示一个具体的对称加密算法。
/// 这是一个对象安全的 trait，它擦除了具体的算法类型。
pub trait SymmetricAlgorithm: Send + Sync + 'static {
    /// 克隆自身到一个 Box<dyn SymmetricAlgorithm>
    fn clone_box(&self) -> Box<dyn SymmetricAlgorithm>;

    /// Encrypts the given plaintext.
    fn encrypt(
        &self,
        key: TypedSymmetricKey,
        nonce: &[u8],
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    fn encrypt_to_buffer(
        &self,
        key: TypedSymmetricKey,
        nonce: &[u8],
        plaintext: &[u8],
        output: &mut [u8],
        aad: Option<&[u8]>,
    ) -> Result<usize>;

    /// Decrypts the given ciphertext.
    fn decrypt(
        &self,
        key: TypedSymmetricKey,
        nonce: &[u8],
        aad: Option<&[u8]>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>>;

    fn decrypt_to_buffer(
        &self,
        key: TypedSymmetricKey,
        nonce: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
        aad: Option<&[u8]>,
    ) -> Result<usize>;

    /// Returns the algorithm enum.
    fn algorithm(&self) -> common::algorithms::SymmetricAlgorithm;

    /// Returns the key size in bytes.
    fn key_size(&self) -> usize;

    /// Returns the nonce size in bytes.
    fn nonce_size(&self) -> usize;

    /// Returns the tag size in bytes.
    fn tag_size(&self) -> usize;
}

impl_trait_for_box!(SymmetricAlgorithm {
    fn clone_box(&self,) -> Box<dyn SymmetricAlgorithm>;
    fn encrypt(&self, key: TypedSymmetricKey, nonce: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>>;
    fn encrypt_to_buffer(&self, key: TypedSymmetricKey, nonce: &[u8], plaintext: &[u8], output: &mut [u8], aad: Option<&[u8]>) -> Result<usize>;
    fn decrypt(&self, key: TypedSymmetricKey, nonce: &[u8], aad: Option<&[u8]>, ciphertext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_to_buffer(&self, key: TypedSymmetricKey, nonce: &[u8], ciphertext: &[u8], output: &mut [u8], aad: Option<&[u8]>) -> Result<usize>;
    fn algorithm(&self,) -> common::algorithms::SymmetricAlgorithm;
    fn key_size(&self,) -> usize;
    fn nonce_size(&self,) -> usize;
    fn tag_size(&self,) -> usize;
});

/// Trait to provide the details for a specific key-based key derivation function (KDF).
/// The implementor of this trait is the scheme itself.
///
/// 用于提供特定基于密钥的密钥派生函数 (KDF) 详细信息的 trait。
/// 该 trait 的实现者是算法方案本身。
pub trait KdfAlgorithmDetails: KeyBasedDerivation + 'static {
    /// The corresponding algorithm enum.
    ///
    /// 对应的算法枚举。
    const ALGORITHM: common::algorithms::KdfAlgorithm;
}

/// Represents a concrete key-based key derivation function (KDF).
/// This is a marker trait that bundles `KdfAlgorithmDetails`.
///
/// 表示一个具体的基于密钥的密钥派生函数 (KDF)。
/// 这是一个标记 trait，它将 `KdfAlgorithmDetails` 捆绑在一起。
pub trait KdfAlgorithm: KdfAlgorithmDetails {}

impl<T: KdfAlgorithmDetails> KdfAlgorithm for T {}

/// Trait to provide the details for a specific asymmetric algorithm.
/// The implementor of this trait is the scheme itself.
///
/// 用于提供特定非对称算法详细信息的 trait。
/// 该 trait 的实现者是算法方案本身。
pub trait AsymmetricAlgorithm: Send + Sync + 'static {
    /// Returns the algorithm enum.
    ///
    /// 返回算法枚举。
    fn algorithm(&self) -> common::algorithms::AsymmetricAlgorithm;

    /// Encapsulates a key.
    ///
    /// 封装一个密钥。
    fn encapsulate_key(
        &self,
        public_key: &TypedAsymmetricPublicKey,
    ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)>;

    /// Decapsulates a key.
    ///
    /// 解封装一个密钥。
    fn decapsulate_key(
        &self,
        private_key: &TypedAsymmetricPrivateKey,
        encapsulated_key: &Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>>;

    fn generate_keypair(&self) -> Result<TypedAsymmetricKeyPair>;

    /// Clones the algorithm.
    ///
    /// 克隆算法。
    fn clone_box(&self) -> Box<dyn AsymmetricAlgorithm>;
}

impl_trait_for_box!(AsymmetricAlgorithm {
    fn clone_box(&self,) -> Box<dyn AsymmetricAlgorithm>;
    fn algorithm(&self,) -> common::algorithms::AsymmetricAlgorithm;
    fn encapsulate_key(&self, public_key: &TypedAsymmetricPublicKey) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)>;
    fn decapsulate_key(&self, private_key: &TypedAsymmetricPrivateKey, encapsulated_key: &Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>>;
    fn generate_keypair(&self,) -> Result<TypedAsymmetricKeyPair>;
});

pub trait HybridAlgorithm: AsymmetricAlgorithm + SymmetricAlgorithm {
    fn asymmetric_algorithm(&self) -> &dyn AsymmetricAlgorithm;
    fn symmetric_algorithm(&self) -> &dyn SymmetricAlgorithm;
    fn clone_box(&self) -> Box<dyn HybridAlgorithm>;
}

impl AsymmetricAlgorithm for Box<dyn HybridAlgorithm> {
    fn algorithm(&self) -> common::algorithms::AsymmetricAlgorithm {
        self.as_ref().asymmetric_algorithm().algorithm()
    }
    fn clone_box(&self) -> Box<dyn AsymmetricAlgorithm> {
        self.clone()
    }
    fn encapsulate_key(
        &self,
        public_key: &TypedAsymmetricPublicKey,
    ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        self.as_ref().encapsulate_key(public_key)
    }
    fn decapsulate_key(
        &self,
        private_key: &TypedAsymmetricPrivateKey,
        encapsulated_key: &Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.as_ref().decapsulate_key(private_key, encapsulated_key)
    }
    fn generate_keypair(&self) -> Result<TypedAsymmetricKeyPair> {
        self.as_ref().generate_keypair()
    }
}

impl SymmetricAlgorithm for Box<dyn HybridAlgorithm> {
    fn algorithm(&self) -> common::algorithms::SymmetricAlgorithm {
        self.as_ref().symmetric_algorithm().algorithm()
    }
    fn clone_box(&self) -> Box<dyn SymmetricAlgorithm> {
        self.clone()
    }
    fn key_size(&self) -> usize {
        self.as_ref().symmetric_algorithm().key_size()
    }
    fn nonce_size(&self) -> usize {
        self.as_ref().symmetric_algorithm().nonce_size()
    }
    fn tag_size(&self) -> usize {
        self.as_ref().symmetric_algorithm().tag_size()
    }
    fn encrypt(
        &self,
        key: TypedSymmetricKey,
        nonce: &[u8],
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.as_ref()
            .symmetric_algorithm()
            .encrypt(key, nonce, plaintext, aad)
    }
    fn encrypt_to_buffer(
        &self,
        key: TypedSymmetricKey,
        nonce: &[u8],
        plaintext: &[u8],
        output: &mut [u8],
        aad: Option<&[u8]>,
    ) -> Result<usize> {
        self.as_ref()
            .symmetric_algorithm()
            .encrypt_to_buffer(key, nonce, plaintext, output, aad)
    }
    fn decrypt(
        &self,
        key: TypedSymmetricKey,
        nonce: &[u8],
        aad: Option<&[u8]>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        self.as_ref()
            .symmetric_algorithm()
            .decrypt(key, nonce, aad, ciphertext)
    }
    fn decrypt_to_buffer(
        &self,
        key: TypedSymmetricKey,
        nonce: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
        aad: Option<&[u8]>,
    ) -> Result<usize> {
        self.as_ref()
            .symmetric_algorithm()
            .decrypt_to_buffer(key, nonce, ciphertext, output, aad)
    }
}

impl HybridAlgorithm for Box<dyn HybridAlgorithm> {
    fn asymmetric_algorithm(&self) -> &dyn AsymmetricAlgorithm {
        self.as_ref().asymmetric_algorithm()
    }
    fn symmetric_algorithm(&self) -> &dyn SymmetricAlgorithm {
        self.as_ref().symmetric_algorithm()
    }
    fn clone_box(&self) -> Box<dyn HybridAlgorithm> {
        self.clone()
    }
}

impl Clone for Box<dyn HybridAlgorithm> {
    fn clone(&self) -> Self {
        HybridAlgorithm::clone_box(self.as_ref())
    }
}

/// Trait to provide the details for a specific digital signature algorithm.
/// The implementor of this trait is the scheme itself.
///
/// 用于提供特定数字签名算法详细信息的 trait。
/// 该 trait 的实现者是算法方案本身。
pub trait SignatureAlgorithmDetails: SignatureScheme + 'static {
    /// The corresponding algorithm enum.
    ///
    /// 对应的算法枚举。
    const ALGORITHM: common::algorithms::SignatureAlgorithm;
}

/// Represents a concrete digital signature scheme.
/// This is a marker trait that bundles `SignatureAlgorithmDetails`.
///
/// 表示一个具体的数字签名方案。
/// 这是一个标记 trait，它将 `SignatureAlgorithmDetails` 捆绑在一起。
pub trait SignatureAlgorithm: SignatureAlgorithmDetails {}

impl<T: SignatureAlgorithmDetails> SignatureAlgorithm for T {}

/// Trait to provide the details for a specific extendable-output function (XOF).
/// The implementor of this trait is the scheme itself.
///
/// 用于提供特定可扩展输出函数 (XOF) 详细信息的 trait。
/// 该 trait 的实现者是算法方案本身。
pub trait XofAlgorithmDetails: XofDerivation + 'static {
    /// The corresponding algorithm enum.
    ///
    /// 对应的算法枚举。
    const ALGORITHM: common::algorithms::XofAlgorithm;
}

/// Represents a concrete extendable-output function (XOF).
/// This is a marker trait that bundles `XofAlgorithmDetails`.
///
/// 表示一个具体的可扩展输出函数 (XOF)。
/// 这是一个标记 trait，它将 `XofAlgorithmDetails` 捆绑在一起。
pub trait XofAlgorithm: XofAlgorithmDetails {}

impl<T: XofAlgorithmDetails> XofAlgorithm for T {}
