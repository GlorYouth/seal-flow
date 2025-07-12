use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common;
use crate::error::{Error, FormatError, Result};
use crate::keys::{SymmetricKey as UntypedSymmetricKey, TypedSymmetricKey};
use seal_crypto::prelude::{SymmetricCipher, SymmetricDecryptor, SymmetricEncryptor};
use seal_crypto::schemes::symmetric::aes_gcm::{Aes128Gcm, Aes256Gcm};
use seal_crypto::schemes::symmetric::chacha20_poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use std::ops::Deref;

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
                key: &TypedSymmetricKey,
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
                key: &TypedSymmetricKey,
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
                key: &TypedSymmetricKey,
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
                key: &TypedSymmetricKey,
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
        key: &TypedSymmetricKey,
        nonce: &[u8],
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.algorithm.encrypt(key, nonce, plaintext, aad)
    }

    fn encrypt_to_buffer(
        &self,
        key: &TypedSymmetricKey,
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
        key: &TypedSymmetricKey,
        nonce: &[u8],
        aad: Option<&[u8]>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        self.algorithm.decrypt(key, nonce, aad, ciphertext)
    }

    fn decrypt_to_buffer(
        &self,
        key: &TypedSymmetricKey,
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
