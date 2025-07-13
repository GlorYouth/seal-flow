use crate::algorithms::traits::AsymmetricAlgorithm;
use crate::common;
use crate::error::{Error, FormatError, Result};
use crate::keys::{TypedAsymmetricKeyPair, TypedAsymmetricPrivateKey, TypedAsymmetricPublicKey};
use seal_crypto::prelude::{Kem, KeyGenerator};
use seal_crypto::schemes::asymmetric::post_quantum::kyber::{Kyber1024, Kyber512, Kyber768};
use seal_crypto::schemes::asymmetric::traditional::rsa::{Rsa2048, Rsa4096};
use seal_crypto::schemes::hash::Sha256;
use seal_crypto::zeroize::Zeroizing;
use std::ops::Deref;

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
