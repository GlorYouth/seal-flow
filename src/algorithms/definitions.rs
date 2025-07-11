//! Defines the concrete algorithm types and implements the corresponding traits.

use super::traits::{
    AsymmetricAlgorithm, KdfAlgorithmDetails, SignatureAlgorithmDetails, SymmetricAlgorithm,
    XofAlgorithmDetails,
};
use crate::common;
use crate::error::{Error, FormatError, Result};
use crate::keys::SymmetricKey as UntypedSymmetricKey;

macro_rules! impl_symmetric_algorithm {
    ($wrapper:ident, $algo:ty, $key_variant:path, $algo_enum:path) => {
        #[derive(Clone)]
        pub struct $wrapper;

        impl $wrapper {
            pub fn new() -> Self {
                Self
            }
        }

        impl Default for $wrapper {
            fn default() -> Self {
                Self::new()
            }
        }

        impl Into<Box<dyn SymmetricAlgorithm>> for $wrapper {
            fn into(self) -> Box<dyn SymmetricAlgorithm> {
                self.clone_box_symmetric()
            }
        }

        impl SymmetricAlgorithm for $wrapper {
            fn encrypt(
                &self,
                key: TypedSymmetricKey,
                nonce: &[u8],
                plaintext: &[u8],
                aad: Option<&[u8]>,
            ) -> Result<Vec<u8>> {
                let key = match key {
                    $key_variant(key) => key,
                    _ => return Err(Error::Format(FormatError::InvalidKeyType)),
                };
                <$algo>::encrypt(&key, nonce, plaintext, aad).map_err(Error::from)
            }

            fn encrypt_to_buffer(
                &self,
                key: TypedSymmetricKey,
                nonce: &[u8],
                plaintext: &[u8],
                output: &mut [u8],
                aad: Option<&[u8]>,
            ) -> Result<usize> {
                let key = match key {
                    $key_variant(key) => key,
                    _ => return Err(Error::Format(FormatError::InvalidKeyType)),
                };
                <$algo>::encrypt_to_buffer(&key, nonce, plaintext, output, aad).map_err(Error::from)
            }

            fn decrypt(
                &self,
                key: TypedSymmetricKey,
                nonce: &[u8],
                aad: Option<&[u8]>,
                ciphertext: &[u8],
            ) -> Result<Vec<u8>> {
                let key = match key {
                    $key_variant(key) => key,
                    _ => return Err(Error::Format(FormatError::InvalidKeyType)),
                };
                <$algo>::decrypt(&key, nonce, ciphertext, aad).map_err(Error::from)
            }

            fn decrypt_to_buffer(
                &self,
                key: TypedSymmetricKey,
                nonce: &[u8],
                ciphertext: &[u8],
                output: &mut [u8],
                aad: Option<&[u8]>,
            ) -> Result<usize> {
                let key = match key {
                    $key_variant(key) => key,
                    _ => return Err(Error::Format(FormatError::InvalidKeyType)),
                };
                <$algo>::decrypt_to_buffer(&key, nonce, ciphertext, output, aad)
                    .map_err(Error::from)
            }

            fn clone_box_symmetric(&self) -> Box<dyn SymmetricAlgorithm> {
                Box::new(self.clone())
            }

            fn algorithm(&self) -> common::algorithms::SymmetricAlgorithm {
                $algo_enum
            }

            fn key_size(&self) -> usize {
                <$algo>::KEY_SIZE
            }

            fn nonce_size(&self) -> usize {
                <$algo>::NONCE_SIZE
            }

            fn tag_size(&self) -> usize {
                <$algo>::TAG_SIZE
            }

            fn generate_typed_key(&self) -> Result<TypedSymmetricKey> {
                use seal_crypto::prelude::SymmetricKeyGenerator;
                <$algo>::generate_key()
                    .map_err(Error::from)
                    .map(|k| $key_variant(k))
            }

            fn generate_untyped_key(&self) -> Result<UntypedSymmetricKey> {
                use seal_crypto::prelude::{Key, SymmetricKeyGenerator};
                <$algo>::generate_key()
                    .map_err(Error::from)
                    .map(|k| UntypedSymmetricKey::new(k.to_bytes()))
            }

            fn into_symmetric_boxed(self) -> Box<dyn SymmetricAlgorithm> {
                Box::new(self)
            }
        }
    };
}

pub mod symmetric {
    use super::*;
    use crate::keys::TypedSymmetricKey;
    use seal_crypto::prelude::{SymmetricCipher, SymmetricDecryptor, SymmetricEncryptor};
    pub use seal_crypto::schemes::symmetric::aes_gcm::{Aes128Gcm, Aes256Gcm};
    pub use seal_crypto::schemes::symmetric::chacha20_poly1305::{
        ChaCha20Poly1305, XChaCha20Poly1305,
    };
    use std::ops::Deref;

    #[derive(Clone)]
    pub struct SymmetricAlgorithmWrapper {
        pub(crate) algorithm: Box<dyn SymmetricAlgorithm>,
    }

    impl Deref for SymmetricAlgorithmWrapper {
        type Target = Box<dyn SymmetricAlgorithm>;

        fn deref(&self) -> &Self::Target {
            &self.algorithm
        }
    }

    impl Into<Box<dyn SymmetricAlgorithm>> for SymmetricAlgorithmWrapper {
        fn into(self) -> Box<dyn SymmetricAlgorithm> {
            self.algorithm
        }
    }

    impl SymmetricAlgorithmWrapper {
        pub fn new(algorithm: Box<dyn SymmetricAlgorithm>) -> Self {
            Self { algorithm }
        }

        pub fn from_enum(algorithm: common::algorithms::SymmetricAlgorithm) -> Self {
            match algorithm {
                common::algorithms::SymmetricAlgorithm::Aes128Gcm => {
                    Self::new(Box::new(Aes128GcmWrapper::new()))
                }
                common::algorithms::SymmetricAlgorithm::Aes256Gcm => {
                    Self::new(Box::new(Aes256GcmWrapper::new()))
                }
                common::algorithms::SymmetricAlgorithm::ChaCha20Poly1305 => {
                    Self::new(Box::new(ChaCha20Poly1305Wrapper::new()))
                }
                common::algorithms::SymmetricAlgorithm::XChaCha20Poly1305 => {
                    Self::new(Box::new(XChaCha20Poly1305Wrapper::new()))
                }
            }
        }

        pub fn generate_typed_key(&self) -> Result<TypedSymmetricKey> {
            self.algorithm.generate_typed_key()
        }

        pub fn generate_untyped_key(&self) -> Result<UntypedSymmetricKey> {
            self.algorithm.generate_untyped_key()
        }
    }

    impl SymmetricAlgorithm for SymmetricAlgorithmWrapper {
        fn clone_box_symmetric(&self) -> Box<dyn SymmetricAlgorithm> {
            Box::new(self.clone())
        }

        fn encrypt(
            &self,
            key: TypedSymmetricKey,
            nonce: &[u8],
            plaintext: &[u8],
            aad: Option<&[u8]>,
        ) -> Result<Vec<u8>> {
            self.algorithm.encrypt(key, nonce, plaintext, aad)
        }

        fn encrypt_to_buffer(
            &self,
            key: TypedSymmetricKey,
            nonce: &[u8],
            plaintext: &[u8],
            output: &mut [u8],
            aad: Option<&[u8]>,
        ) -> Result<usize> {
            self.algorithm
                .encrypt_to_buffer(key, nonce, plaintext, output, aad)
        }

        fn decrypt(
            &self,
            key: TypedSymmetricKey,
            nonce: &[u8],
            aad: Option<&[u8]>,
            ciphertext: &[u8],
        ) -> Result<Vec<u8>> {
            self.algorithm.decrypt(key, nonce, aad, ciphertext)
        }

        fn decrypt_to_buffer(
            &self,
            key: TypedSymmetricKey,
            nonce: &[u8],
            ciphertext: &[u8],
            output: &mut [u8],
            aad: Option<&[u8]>,
        ) -> Result<usize> {
            self.algorithm
                .decrypt_to_buffer(key, nonce, ciphertext, output, aad)
        }

        fn generate_typed_key(&self) -> Result<TypedSymmetricKey> {
            self.algorithm.generate_typed_key()
        }

        fn generate_untyped_key(&self) -> Result<UntypedSymmetricKey> {
            self.algorithm.generate_untyped_key()
        }

        fn algorithm(&self) -> common::algorithms::SymmetricAlgorithm {
            self.algorithm.algorithm()
        }

        fn key_size(&self) -> usize {
            self.algorithm.key_size()
        }

        fn nonce_size(&self) -> usize {
            self.algorithm.nonce_size()
        }

        fn tag_size(&self) -> usize {
            self.algorithm.tag_size()
        }

        fn into_symmetric_boxed(self) -> Box<dyn SymmetricAlgorithm> {
            Box::new(self)
        }
    }

    impl From<common::algorithms::SymmetricAlgorithm> for SymmetricAlgorithmWrapper {
        fn from(algorithm: common::algorithms::SymmetricAlgorithm) -> Self {
            Self::from_enum(algorithm)
        }
    }

    impl From<Box<dyn SymmetricAlgorithm>> for SymmetricAlgorithmWrapper {
        fn from(algorithm: Box<dyn SymmetricAlgorithm>) -> Self {
            Self::new(algorithm)
        }
    }

    impl_symmetric_algorithm!(
        Aes128GcmWrapper,
        Aes128Gcm,
        TypedSymmetricKey::Aes128Gcm,
        common::algorithms::SymmetricAlgorithm::Aes128Gcm
    );

    impl_symmetric_algorithm!(
        Aes256GcmWrapper,
        Aes256Gcm,
        TypedSymmetricKey::Aes256Gcm,
        common::algorithms::SymmetricAlgorithm::Aes256Gcm
    );

    impl_symmetric_algorithm!(
        ChaCha20Poly1305Wrapper,
        ChaCha20Poly1305,
        TypedSymmetricKey::ChaCha20Poly1305,
        common::algorithms::SymmetricAlgorithm::ChaCha20Poly1305
    );

    impl_symmetric_algorithm!(
        XChaCha20Poly1305Wrapper,
        XChaCha20Poly1305,
        TypedSymmetricKey::XChaCha20Poly1305,
        common::algorithms::SymmetricAlgorithm::XChaCha20Poly1305
    );
}

macro_rules! impl_asymmetric_algorithm {
    ($wrapper:ident, $algo:ty, $key_variant:ident, $algo_enum:path) => {
        #[derive(Clone)]
        pub struct $wrapper;

        impl $wrapper {
            pub fn new() -> Self {
                Self
            }
        }

        impl Default for $wrapper {
            fn default() -> Self {
                Self::new()
            }
        }

        impl Into<Box<dyn AsymmetricAlgorithm>> for $wrapper {
            fn into(self) -> Box<dyn AsymmetricAlgorithm> {
                self.clone_box_asymmetric()
            }
        }

        impl AsymmetricAlgorithm for $wrapper {
            fn algorithm(&self) -> common::algorithms::AsymmetricAlgorithm {
                $algo_enum
            }

            fn encapsulate_key(
                &self,
                public_key: &TypedAsymmetricPublicKey,
            ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
                let public_key = match public_key {
                    TypedAsymmetricPublicKey::$key_variant(pk) => pk,
                    _ => return Err(Error::Format(FormatError::InvalidKeyType)),
                };
                <$algo>::encapsulate(public_key).map_err(Error::from)
            }

            fn decapsulate_key(
                &self,
                private_key: &TypedAsymmetricPrivateKey,
                encapsulated_key: &Zeroizing<Vec<u8>>,
            ) -> Result<Zeroizing<Vec<u8>>> {
                let private_key = match private_key {
                    TypedAsymmetricPrivateKey::$key_variant(sk) => sk,
                    _ => return Err(Error::Format(FormatError::InvalidKeyType)),
                };
                <$algo>::decapsulate(private_key, encapsulated_key).map_err(Error::from)
            }

            fn generate_keypair(&self) -> Result<TypedAsymmetricKeyPair> {
                <$algo>::generate_keypair()
                    .map_err(Error::from)
                    .map(|(pk, sk)| TypedAsymmetricKeyPair::$key_variant((pk, sk)))
            }

            fn clone_box_asymmetric(&self) -> Box<dyn AsymmetricAlgorithm> {
                Box::new(self.clone())
            }

            fn into_asymmetric_boxed(self) -> Box<dyn AsymmetricAlgorithm> {
                Box::new(self)
            }
        }
    };
}

// --- Asymmetric Algorithms ---
pub mod asymmetric {
    use super::*;
    use crate::keys::{
        TypedAsymmetricKeyPair, TypedAsymmetricPrivateKey, TypedAsymmetricPublicKey,
    };
    use seal_crypto::prelude::{Kem, KeyGenerator};
    pub use seal_crypto::schemes::asymmetric::post_quantum::kyber::{
        Kyber1024, Kyber512, Kyber768,
    };
    pub use seal_crypto::schemes::asymmetric::traditional::rsa::{Rsa2048, Rsa4096};
    use seal_crypto::schemes::hash::Sha256;
    use seal_crypto::zeroize::Zeroizing;
    use std::ops::Deref;

    pub struct AsymmetricAlgorithmWrapper {
        pub(crate) algorithm: Box<dyn AsymmetricAlgorithm>,
    }

    impl Deref for AsymmetricAlgorithmWrapper {
        type Target = Box<dyn AsymmetricAlgorithm>;

        fn deref(&self) -> &Self::Target {
            &self.algorithm
        }
    }

    impl Into<Box<dyn AsymmetricAlgorithm>> for AsymmetricAlgorithmWrapper {
        fn into(self) -> Box<dyn AsymmetricAlgorithm> {
            self.algorithm
        }
    }

    impl AsymmetricAlgorithmWrapper {
        pub fn new(algorithm: Box<dyn AsymmetricAlgorithm>) -> Self {
            Self { algorithm }
        }

        pub fn from_enum(algorithm: common::algorithms::AsymmetricAlgorithm) -> Self {
            match algorithm {
                common::algorithms::AsymmetricAlgorithm::Rsa2048Sha256 => {
                    Self::new(Box::new(Rsa2048Sha256Wrapper::new()))
                }
                common::algorithms::AsymmetricAlgorithm::Rsa4096Sha256 => {
                    Self::new(Box::new(Rsa4096Sha256Wrapper::new()))
                }
                common::algorithms::AsymmetricAlgorithm::Kyber512 => {
                    Self::new(Box::new(Kyber512Wrapper::new()))
                }
                common::algorithms::AsymmetricAlgorithm::Kyber768 => {
                    Self::new(Box::new(Kyber768Wrapper::new()))
                }
                common::algorithms::AsymmetricAlgorithm::Kyber1024 => {
                    Self::new(Box::new(Kyber1024Wrapper::new()))
                }
            }
        }

        pub fn generate_keypair(&self) -> Result<TypedAsymmetricKeyPair> {
            self.algorithm.generate_keypair()
        }
    }

    impl AsymmetricAlgorithm for AsymmetricAlgorithmWrapper {
        fn algorithm(&self) -> common::algorithms::AsymmetricAlgorithm {
            self.algorithm.algorithm()
        }

        fn encapsulate_key(
            &self,
            public_key: &TypedAsymmetricPublicKey,
        ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
            self.algorithm.encapsulate_key(public_key)
        }

        fn decapsulate_key(
            &self,
            private_key: &TypedAsymmetricPrivateKey,
            encapsulated_key: &Zeroizing<Vec<u8>>,
        ) -> Result<Zeroizing<Vec<u8>>> {
            self.algorithm
                .decapsulate_key(private_key, encapsulated_key)
        }

        fn generate_keypair(&self) -> Result<TypedAsymmetricKeyPair> {
            self.algorithm.generate_keypair()
        }

        fn clone_box_asymmetric(&self) -> Box<dyn AsymmetricAlgorithm> {
            self.algorithm.clone()
        }

        fn into_asymmetric_boxed(self) -> Box<dyn AsymmetricAlgorithm> {
            Box::new(self.algorithm)
        }
    }

    impl From<common::algorithms::AsymmetricAlgorithm> for AsymmetricAlgorithmWrapper {
        fn from(algorithm: common::algorithms::AsymmetricAlgorithm) -> Self {
            Self::from_enum(algorithm)
        }
    }

    impl From<Box<dyn AsymmetricAlgorithm>> for AsymmetricAlgorithmWrapper {
        fn from(algorithm: Box<dyn AsymmetricAlgorithm>) -> Self {
            Self::new(algorithm)
        }
    }

    impl_asymmetric_algorithm!(
        Rsa2048Sha256Wrapper,
        Rsa2048<Sha256>,
        Rsa2048Sha256,
        common::algorithms::AsymmetricAlgorithm::Rsa2048Sha256
    );

    impl_asymmetric_algorithm!(
        Rsa4096Sha256Wrapper,
        Rsa4096<Sha256>,
        Rsa4096Sha256,
        common::algorithms::AsymmetricAlgorithm::Rsa4096Sha256
    );

    impl_asymmetric_algorithm!(
        Kyber512Wrapper,
        Kyber512,
        Kyber512,
        common::algorithms::AsymmetricAlgorithm::Kyber512
    );

    impl_asymmetric_algorithm!(
        Kyber768Wrapper,
        Kyber768,
        Kyber768,
        common::algorithms::AsymmetricAlgorithm::Kyber768
    );

    impl_asymmetric_algorithm!(
        Kyber1024Wrapper,
        Kyber1024,
        Kyber1024,
        common::algorithms::AsymmetricAlgorithm::Kyber1024
    );
}

pub mod hybrid {
    use crate::algorithms::traits::{
        AsymmetricAlgorithm, HybridAlgorithm as HybridAlgorithmTrait, SymmetricAlgorithm,
    };
    use crate::keys::{
        SymmetricKey as UntypedSymmetricKey, TypedAsymmetricKeyPair, TypedSymmetricKey,
    };
    use crate::keys::{TypedAsymmetricPrivateKey, TypedAsymmetricPublicKey};
    use seal_crypto::zeroize::Zeroizing;

    #[derive(Clone)]
    pub struct HybridAlgorithmWrapper {
        asymmetric_algorithm: Box<dyn AsymmetricAlgorithm>,
        symmetric_algorithm: Box<dyn SymmetricAlgorithm>,
    }

    impl HybridAlgorithmWrapper {
        pub fn new(
            asymmetric_algorithm: impl Into<Box<dyn AsymmetricAlgorithm>>,
            symmetric_algorithm: impl Into<Box<dyn SymmetricAlgorithm>>,
        ) -> Self {
            Self {
                asymmetric_algorithm: asymmetric_algorithm.into(),
                symmetric_algorithm: symmetric_algorithm.into(),
            }
        }
    }

    impl HybridAlgorithmTrait for HybridAlgorithmWrapper {
        fn asymmetric_algorithm(&self) -> &dyn AsymmetricAlgorithm {
            self.asymmetric_algorithm.as_ref()
        }

        fn symmetric_algorithm(&self) -> &dyn SymmetricAlgorithm {
            self.symmetric_algorithm.as_ref()
        }

        fn clone_box(&self) -> Box<dyn HybridAlgorithmTrait> {
            Box::new(self.clone())
        }
    }

    impl AsymmetricAlgorithm for HybridAlgorithmWrapper {
        fn algorithm(&self) -> crate::common::algorithms::AsymmetricAlgorithm {
            self.asymmetric_algorithm.algorithm()
        }

        fn encapsulate_key(
            &self,
            public_key: &TypedAsymmetricPublicKey,
        ) -> crate::Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
            self.asymmetric_algorithm.encapsulate_key(public_key)
        }

        fn decapsulate_key(
            &self,
            private_key: &TypedAsymmetricPrivateKey,
            encapsulated_key: &Zeroizing<Vec<u8>>,
        ) -> crate::Result<Zeroizing<Vec<u8>>> {
            self.asymmetric_algorithm
                .decapsulate_key(private_key, encapsulated_key)
        }

        fn clone_box_asymmetric(&self) -> Box<dyn AsymmetricAlgorithm> {
            Box::new(self.clone())
        }

        fn generate_keypair(&self) -> crate::Result<TypedAsymmetricKeyPair> {
            self.asymmetric_algorithm.generate_keypair()
        }

        fn into_asymmetric_boxed(self) -> Box<dyn AsymmetricAlgorithm> {
            Box::new(self.asymmetric_algorithm)
        }
    }

    impl SymmetricAlgorithm for HybridAlgorithmWrapper {
        fn algorithm(&self) -> crate::common::algorithms::SymmetricAlgorithm {
            self.symmetric_algorithm.algorithm()
        }

        fn encrypt(
            &self,
            key: TypedSymmetricKey,
            nonce: &[u8],
            plaintext: &[u8],
            aad: Option<&[u8]>,
        ) -> crate::Result<Vec<u8>> {
            self.symmetric_algorithm.encrypt(key, nonce, plaintext, aad)
        }

        fn encrypt_to_buffer(
            &self,
            key: TypedSymmetricKey,
            nonce: &[u8],
            plaintext: &[u8],
            output: &mut [u8],
            aad: Option<&[u8]>,
        ) -> crate::Result<usize> {
            self.symmetric_algorithm
                .encrypt_to_buffer(key, nonce, plaintext, output, aad)
        }

        fn decrypt(
            &self,
            key: TypedSymmetricKey,
            nonce: &[u8],
            aad: Option<&[u8]>,
            ciphertext: &[u8],
        ) -> crate::Result<Vec<u8>> {
            self.symmetric_algorithm
                .decrypt(key, nonce, aad, ciphertext)
        }

        fn decrypt_to_buffer(
            &self,
            key: TypedSymmetricKey,
            nonce: &[u8],
            ciphertext: &[u8],
            output: &mut [u8],
            aad: Option<&[u8]>,
        ) -> crate::Result<usize> {
            self.symmetric_algorithm
                .decrypt_to_buffer(key, nonce, ciphertext, output, aad)
        }

        fn generate_typed_key(&self) -> crate::Result<TypedSymmetricKey> {
            self.symmetric_algorithm.generate_typed_key()
        }

        fn generate_untyped_key(&self) -> crate::Result<UntypedSymmetricKey> {
            self.symmetric_algorithm.generate_untyped_key()
        }

        fn clone_box_symmetric(&self) -> Box<dyn SymmetricAlgorithm> {
            Box::new(self.clone())
        }

        fn key_size(&self) -> usize {
            self.symmetric_algorithm.key_size()
        }

        fn nonce_size(&self) -> usize {
            self.symmetric_algorithm.nonce_size()
        }

        fn tag_size(&self) -> usize {
            self.symmetric_algorithm.tag_size()
        }

        fn into_symmetric_boxed(self) -> Box<dyn SymmetricAlgorithm> {
            Box::new(self.symmetric_algorithm)
        }
    }
}

// --- Signature Algorithms ---
pub mod signature {
    use super::*;
    pub use seal_crypto::schemes::asymmetric::post_quantum::dilithium::{
        Dilithium2, Dilithium3, Dilithium5,
    };
    pub use seal_crypto::schemes::asymmetric::traditional::ecc::{EcdsaP256, Ed25519};

    impl SignatureAlgorithmDetails for Dilithium2 {
        const ALGORITHM: common::algorithms::SignatureAlgorithm =
            common::algorithms::SignatureAlgorithm::Dilithium2;
    }

    impl SignatureAlgorithmDetails for Dilithium3 {
        const ALGORITHM: common::algorithms::SignatureAlgorithm =
            common::algorithms::SignatureAlgorithm::Dilithium3;
    }

    impl SignatureAlgorithmDetails for Dilithium5 {
        const ALGORITHM: common::algorithms::SignatureAlgorithm =
            common::algorithms::SignatureAlgorithm::Dilithium5;
    }

    impl SignatureAlgorithmDetails for Ed25519 {
        const ALGORITHM: common::algorithms::SignatureAlgorithm =
            common::algorithms::SignatureAlgorithm::Ed25519;
    }

    impl SignatureAlgorithmDetails for EcdsaP256 {
        const ALGORITHM: common::algorithms::SignatureAlgorithm =
            common::algorithms::SignatureAlgorithm::EcdsaP256;
    }
}

pub mod kdf {
    use super::*;
    pub use seal_crypto::schemes::kdf::hkdf::{HkdfSha256, HkdfSha384, HkdfSha512};
    pub mod passwd {
        pub use seal_crypto::schemes::kdf::{
            argon2::Argon2,
            pbkdf2::{Pbkdf2Sha256, Pbkdf2Sha384, Pbkdf2Sha512},
        };
    }

    impl KdfAlgorithmDetails for HkdfSha256 {
        const ALGORITHM: common::algorithms::KdfAlgorithm =
            common::algorithms::KdfAlgorithm::HkdfSha256;
    }

    impl KdfAlgorithmDetails for HkdfSha384 {
        const ALGORITHM: common::algorithms::KdfAlgorithm =
            common::algorithms::KdfAlgorithm::HkdfSha384;
    }

    impl KdfAlgorithmDetails for HkdfSha512 {
        const ALGORITHM: common::algorithms::KdfAlgorithm =
            common::algorithms::KdfAlgorithm::HkdfSha512;
    }
}

pub mod xof {
    use super::*;
    pub use seal_crypto::schemes::xof::shake::{Shake128, Shake256};

    impl XofAlgorithmDetails for Shake128 {
        const ALGORITHM: common::algorithms::XofAlgorithm =
            common::algorithms::XofAlgorithm::Shake128;
    }

    impl XofAlgorithmDetails for Shake256 {
        const ALGORITHM: common::algorithms::XofAlgorithm =
            common::algorithms::XofAlgorithm::Shake256;
    }
}

pub mod hash {
    pub use seal_crypto::schemes::hash::{Sha256, Sha384, Sha512};
}
