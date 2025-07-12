//! Defines the core traits for type-safe algorithm specification.
//!
//! 定义用于类型安全算法规范的核心 trait。

use crate::error::Result;
use crate::keys::{
    SymmetricKey as UntypedSymmetricKey, TypedAsymmetricPrivateKey, TypedAsymmetricPublicKey,
    TypedSignatureKeyPair, TypedSignaturePrivateKey, TypedSignaturePublicKey, TypedSymmetricKey,
};
use crate::prelude::{
    KdfKeyAlgorithmEnum, KdfPasswordAlgorithmEnum, XofAlgorithmEnum,
};
use crate::{common, keys::TypedAsymmetricKeyPair};
use seal_crypto::secrecy::SecretBox;
use seal_crypto::zeroize::Zeroizing;

macro_rules! impl_trait_for_box {
    // Internal recursive rules for TT muncher
    (
        @impl,
        $trait:ident,
        $clone_box_name:ident,
        { }, // no more methods
        { $($impls:tt)* } // accumulated impls
    ) => {
        impl Clone for Box<dyn $trait> {
            fn clone(&self) -> Self {
                self.$clone_box_name()
            }
        }

        impl $trait for Box<dyn $trait> {
            $($impls)*
        }
    };

    // Munch a `ref fn`
    (
        @impl,
        $trait:ident,
        $clone_box_name:ident,
        {
            ref fn $method:ident(&self, $($arg:ident: $ty:ty),*) -> $ret:ty;
            $($rest:tt)*
        },
        { $($impls:tt)* }
    ) => {
        impl_trait_for_box! {
            @impl,
            $trait,
            $clone_box_name,
            { $($rest)* },
            {
                $($impls)*
                fn $method(&self, $($arg: $ty),*) -> $ret {
                    self.as_ref().$method($($arg),*)
                }
            }
        }
    };

    // Munch a `self fn` with custom implementation
    (
        @impl,
        $trait:ident,
        $clone_box_name:ident,
        {
            self fn $method:ident(self, $($arg:ident: $ty:ty),*) -> $ret:ty { $($body:tt)+ };
            $($rest:tt)*
        },
        { $($impls:tt)* }
    ) => {
        impl_trait_for_box! {
            @impl,
            $trait,
            $clone_box_name,
            { $($rest)* },
            {
                $($impls)*
                fn $method(self, $($arg: $ty),*) -> $ret {
                    $($body)+
                }
            }
        }
    };

    // Munch a `self fn` with default `self` return
    (
        @impl,
        $trait:ident,
        $clone_box_name:ident,
        {
            self fn $method:ident(self, $($arg:ident: $ty:ty),*) -> $ret:ty;
            $($rest:tt)*
        },
        { $($impls:tt)* }
    ) => {
        impl_trait_for_box! {
            @impl,
            $trait,
            $clone_box_name,
            { $($rest)* },
            {
                $($impls)*
                fn $method(self, $($arg: $ty),*) -> $ret {
                    self
                }
            }
        }
    };

    // Public entry point
    ($trait:ident { $($methods:tt)* }, $clone_box_name:ident) => {
        impl_trait_for_box! {
            @impl,
            $trait,
            $clone_box_name,
            { $($methods)* },
            { }
        }
    };
}

/// Represents a concrete symmetric encryption algorithm.
/// This is an object-safe trait that erases the concrete algorithm type.
///
/// 表示一个具体的对称加密算法。
/// 这是一个对象安全的 trait，它擦除了具体的算法类型。
pub trait SymmetricAlgorithm: Send + Sync + 'static {
    /// Encrypts the given plaintext.
    fn encrypt(
        &self,
        key: &TypedSymmetricKey,
        nonce: &[u8],
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    fn encrypt_to_buffer(
        &self,
        key: &TypedSymmetricKey,
        nonce: &[u8],
        plaintext: &[u8],
        output: &mut [u8],
        aad: Option<&[u8]>,
    ) -> Result<usize>;

    /// Decrypts the given ciphertext.
    fn decrypt(
        &self,
        key: &TypedSymmetricKey,
        nonce: &[u8],
        aad: Option<&[u8]>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>>;

    fn decrypt_to_buffer(
        &self,
        key: &TypedSymmetricKey,
        nonce: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
        aad: Option<&[u8]>,
    ) -> Result<usize>;

    fn generate_typed_key(&self) -> Result<TypedSymmetricKey>;

    fn generate_untyped_key(&self) -> Result<UntypedSymmetricKey>;

    /// Returns the algorithm enum.
    fn algorithm(&self) -> common::algorithms::SymmetricAlgorithm;

    /// Returns the key size in bytes.
    fn key_size(&self) -> usize;

    /// Returns the nonce size in bytes.
    fn nonce_size(&self) -> usize;

    /// Returns the tag size in bytes.
    fn tag_size(&self) -> usize;

    /// Converts the algorithm into a boxed trait object.
    ///
    /// 将算法转换为 boxed trait 对象。
    fn into_symmetric_boxed(self) -> Box<dyn SymmetricAlgorithm>;

    /// 克隆自身到一个 Box<dyn SymmetricAlgorithm>
    fn clone_box_symmetric(&self) -> Box<dyn SymmetricAlgorithm>;
}

impl_trait_for_box!(SymmetricAlgorithm {
    ref fn encrypt(&self, key: &TypedSymmetricKey, nonce: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>>;
    ref fn encrypt_to_buffer(&self, key: &TypedSymmetricKey, nonce: &[u8], plaintext: &[u8], output: &mut [u8], aad: Option<&[u8]>) -> Result<usize>;
    ref fn decrypt(&self, key: &TypedSymmetricKey, nonce: &[u8], aad: Option<&[u8]>, ciphertext: &[u8]) -> Result<Vec<u8>>;
    ref fn decrypt_to_buffer(&self, key: &TypedSymmetricKey, nonce: &[u8], ciphertext: &[u8], output: &mut [u8], aad: Option<&[u8]>) -> Result<usize>;
    ref fn generate_typed_key(&self,) -> Result<TypedSymmetricKey>;
    ref fn generate_untyped_key(&self,) -> Result<UntypedSymmetricKey>;
    ref fn algorithm(&self,) -> common::algorithms::SymmetricAlgorithm;
    ref fn key_size(&self,) -> usize;
    ref fn nonce_size(&self,) -> usize;
    ref fn tag_size(&self,) -> usize;
    self fn into_symmetric_boxed(self,) -> Box<dyn SymmetricAlgorithm>;
    ref fn clone_box_symmetric(&self,) -> Box<dyn SymmetricAlgorithm>;
}, clone_box_symmetric);

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
    fn clone_box_asymmetric(&self) -> Box<dyn AsymmetricAlgorithm>;

    fn into_asymmetric_boxed(self) -> Box<dyn AsymmetricAlgorithm>;
}

impl_trait_for_box!(AsymmetricAlgorithm {
    ref fn clone_box_asymmetric(&self,) -> Box<dyn AsymmetricAlgorithm>;
    ref fn algorithm(&self,) -> common::algorithms::AsymmetricAlgorithm;
    ref fn encapsulate_key(&self, public_key: &TypedAsymmetricPublicKey) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)>;
    ref fn decapsulate_key(&self, private_key: &TypedAsymmetricPrivateKey, encapsulated_key: &Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>>;
    ref fn generate_keypair(&self,) -> Result<TypedAsymmetricKeyPair>;
    self fn into_asymmetric_boxed(self,) -> Box<dyn AsymmetricAlgorithm>;
}, clone_box_asymmetric);

pub trait HybridAlgorithm: AsymmetricAlgorithm + SymmetricAlgorithm {
    fn asymmetric_algorithm(&self) -> &dyn AsymmetricAlgorithm;
    fn symmetric_algorithm(&self) -> &dyn SymmetricAlgorithm;
    fn clone_box(&self) -> Box<dyn HybridAlgorithm>;
}

impl AsymmetricAlgorithm for Box<dyn HybridAlgorithm> {
    fn algorithm(&self) -> common::algorithms::AsymmetricAlgorithm {
        self.as_ref().asymmetric_algorithm().algorithm()
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
    fn clone_box_asymmetric(&self) -> Box<dyn AsymmetricAlgorithm> {
        self.clone()
    }
    fn into_asymmetric_boxed(self) -> Box<dyn AsymmetricAlgorithm> {
        Box::new(self)
    }
}

impl SymmetricAlgorithm for Box<dyn HybridAlgorithm> {
    fn encrypt(
        &self,
        key: &TypedSymmetricKey,
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
        key: &TypedSymmetricKey,
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
        key: &TypedSymmetricKey,
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
        key: &TypedSymmetricKey,
        nonce: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
        aad: Option<&[u8]>,
    ) -> Result<usize> {
        self.as_ref()
            .symmetric_algorithm()
            .decrypt_to_buffer(key, nonce, ciphertext, output, aad)
    }
    fn generate_typed_key(&self) -> Result<TypedSymmetricKey> {
        self.as_ref().symmetric_algorithm().generate_typed_key()
    }
    fn generate_untyped_key(&self) -> Result<UntypedSymmetricKey> {
        self.as_ref().symmetric_algorithm().generate_untyped_key()
    }
    fn algorithm(&self) -> common::algorithms::SymmetricAlgorithm {
        self.as_ref().symmetric_algorithm().algorithm()
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
    fn into_symmetric_boxed(self) -> Box<dyn SymmetricAlgorithm> {
        self
    }
    fn clone_box_symmetric(&self) -> Box<dyn SymmetricAlgorithm> {
        self.clone()
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

pub trait KdfKeyAlgorithm: Send + Sync + 'static {
    fn derive(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>>;

    fn algorithm(&self) -> KdfKeyAlgorithmEnum;

    fn clone_box(&self) -> Box<dyn KdfKeyAlgorithm>;
}

impl_trait_for_box!(KdfKeyAlgorithm {
    ref fn clone_box(&self,) -> Box<dyn KdfKeyAlgorithm>;
    ref fn derive(&self, ikm: &[u8], salt: Option<&[u8]>, info: Option<&[u8]>, output_len: usize) -> Result<Zeroizing<Vec<u8>>>;
    ref fn algorithm(&self,) -> KdfKeyAlgorithmEnum;
}, clone_box);

pub trait KdfPasswordAlgorithm {
    fn derive(
        &self,
        password: &SecretBox<[u8]>,
        salt: &[u8],
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>>;

    fn algorithm(&self) -> KdfPasswordAlgorithmEnum;

    fn clone_box(&self) -> Box<dyn KdfPasswordAlgorithm>;
}

impl_trait_for_box!(KdfPasswordAlgorithm {
    ref fn clone_box(&self,) -> Box<dyn KdfPasswordAlgorithm>;
    ref fn derive(&self, password: &SecretBox<[u8]>, salt: &[u8], output_len: usize) -> Result<Zeroizing<Vec<u8>>>;
    ref fn algorithm(&self,) -> KdfPasswordAlgorithmEnum;
}, clone_box);

pub trait XofAlgorithm: Send + Sync + 'static {
    fn derive(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>>;
    fn clone_box(&self) -> Box<dyn XofAlgorithm>;
    fn algorithm(&self) -> XofAlgorithmEnum;
}

impl_trait_for_box!(XofAlgorithm {
    ref fn derive(&self, ikm: &[u8], salt: Option<&[u8]>, info: Option<&[u8]>, output_len: usize) -> Result<Zeroizing<Vec<u8>>>;
    ref fn algorithm(&self,) -> XofAlgorithmEnum;
    ref fn clone_box(&self,) -> Box<dyn XofAlgorithm>;
}, clone_box);

pub trait SignatureAlgorithm: Send + Sync + 'static {
    fn sign(&self, message: &[u8], key: &TypedSignaturePrivateKey) -> Result<Vec<u8>>;
    fn verify(
        &self,
        message: &[u8],
        key: &TypedSignaturePublicKey,
        signature: Vec<u8>,
    ) -> Result<()>;
    fn generate_keypair(&self) -> Result<TypedSignatureKeyPair>;
    fn clone_box(&self) -> Box<dyn SignatureAlgorithm>;
    fn algorithm(&self) -> common::algorithms::SignatureAlgorithm;
}

impl_trait_for_box!(SignatureAlgorithm {
    ref fn sign(&self, message: &[u8], key: &TypedSignaturePrivateKey) -> Result<Vec<u8>>;
    ref fn verify(&self, message: &[u8], key: &TypedSignaturePublicKey, signature: Vec<u8>) -> Result<()>;
    ref fn generate_keypair(&self,) -> Result<TypedSignatureKeyPair>;
    ref fn clone_box(&self,) -> Box<dyn SignatureAlgorithm>;
    ref fn algorithm(&self,) -> common::algorithms::SignatureAlgorithm;
}, clone_box);
