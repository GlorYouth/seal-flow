use crate::algorithms::traits::SignatureAlgorithm;
use crate::error::FormatError;
use crate::keys::{TypedSignatureKeyPair, TypedSignaturePrivateKey, TypedSignaturePublicKey};
use crate::prelude::SignatureAlgorithmEnum;
use seal_crypto::prelude::Signature;
use seal_crypto::prelude::{KeyGenerator, Signer, Verifier};
pub use seal_crypto::schemes::asymmetric::post_quantum::dilithium::{
    Dilithium2, Dilithium3, Dilithium5,
};
pub use seal_crypto::schemes::asymmetric::traditional::ecc::{EcdsaP256, Ed25519};

#[derive(Clone)]
pub struct SignatureAlgorithmWrapper {
    algorithm: Box<dyn SignatureAlgorithm>,
}

impl SignatureAlgorithmWrapper {
    pub fn new(algorithm: Box<dyn SignatureAlgorithm>) -> Self {
        Self { algorithm }
    }
}

impl SignatureAlgorithm for SignatureAlgorithmWrapper {
    fn sign(&self, message: &[u8], key: &TypedSignaturePrivateKey) -> crate::Result<Vec<u8>> {
        self.algorithm.sign(message, key)
    }

    fn verify(
        &self,
        message: &[u8],
        key: &TypedSignaturePublicKey,
        signature: Vec<u8>,
    ) -> crate::Result<bool> {
        self.algorithm.verify(message, key, signature)
    }

    fn generate_keypair(&self) -> crate::Result<TypedSignatureKeyPair> {
        self.algorithm.generate_keypair()
    }

    fn clone_box(&self) -> Box<dyn SignatureAlgorithm> {
        Box::new(self.clone())
    }

    fn algorithm(&self) -> SignatureAlgorithmEnum {
        self.algorithm.algorithm()
    }
}

#[derive(Clone, Default)]
pub struct Dilithium2Wrapper;

impl Dilithium2Wrapper {
    pub fn new() -> Self {
        Self
    }
}

impl SignatureAlgorithm for Dilithium2Wrapper {
    fn sign(&self, message: &[u8], key: &TypedSignaturePrivateKey) -> crate::Result<Vec<u8>> {
        match key {
            TypedSignaturePrivateKey::Dilithium2(sk) => {
                let sig = Dilithium2::sign(&sk, message)?;
                Ok(sig.0)
            }
            _ => Err(crate::Error::Format(FormatError::InvalidKeyType)),
        }
    }

    fn verify(
        &self,
        message: &[u8],
        key: &TypedSignaturePublicKey,
        signature: Vec<u8>,
    ) -> crate::Result<bool> {
        match key {
            TypedSignaturePublicKey::Dilithium2(pk) => {
                let _ = Dilithium2::verify(&pk, message, &Signature(signature))?;
                Ok(true)
            }
            _ => Err(crate::Error::Format(FormatError::InvalidKeyType)),
        }
    }

    fn generate_keypair(&self) -> crate::Result<TypedSignatureKeyPair> {
        let (pk, sk) = Dilithium2::generate_keypair()?;
        Ok(TypedSignatureKeyPair::Dilithium2((pk, sk)))
    }

    fn clone_box(&self) -> Box<dyn SignatureAlgorithm> {
        Box::new(self.clone())
    }

    fn algorithm(&self) -> SignatureAlgorithmEnum {
        SignatureAlgorithmEnum::Dilithium2
    }
}

#[derive(Clone, Default)]
pub struct Dilithium3Wrapper;

impl Dilithium3Wrapper {
    pub fn new() -> Self {
        Self
    }
}

impl SignatureAlgorithm for Dilithium3Wrapper {
    fn sign(&self, message: &[u8], key: &TypedSignaturePrivateKey) -> crate::Result<Vec<u8>> {
        match key {
            TypedSignaturePrivateKey::Dilithium2(sk) => {
                let sig = Dilithium2::sign(&sk, message)?;
                Ok(sig.0)
            }
            _ => Err(crate::Error::Format(FormatError::InvalidKeyType)),
        }
    }

    fn verify(
        &self,
        message: &[u8],
        key: &TypedSignaturePublicKey,
        signature: Vec<u8>,
    ) -> crate::Result<bool> {
        match key {
            TypedSignaturePublicKey::Dilithium2(pk) => {
                let _ = Dilithium2::verify(&pk, message, &Signature(signature))?;
                Ok(true)
            }
            _ => Err(crate::Error::Format(FormatError::InvalidKeyType)),
        }
    }

    fn generate_keypair(&self) -> crate::Result<TypedSignatureKeyPair> {
        let (pk, sk) = Dilithium2::generate_keypair()?;
        Ok(TypedSignatureKeyPair::Dilithium2((pk, sk)))
    }

    fn clone_box(&self) -> Box<dyn SignatureAlgorithm> {
        Box::new(self.clone())
    }

    fn algorithm(&self) -> SignatureAlgorithmEnum {
        SignatureAlgorithmEnum::Dilithium2
    }
}

#[derive(Clone, Default)]
pub struct Dilithium5Wrapper;

impl Dilithium5Wrapper {
    pub fn new() -> Self {
        Self
    }
}

impl SignatureAlgorithm for Dilithium5Wrapper {
    fn sign(&self, message: &[u8], key: &TypedSignaturePrivateKey) -> crate::Result<Vec<u8>> {
        match key {
            TypedSignaturePrivateKey::Dilithium5(sk) => {
                let sig = Dilithium5::sign(&sk, message)?;
                Ok(sig.0)
            }
            _ => Err(crate::Error::Format(FormatError::InvalidKeyType)),
        }
    }

    fn verify(
        &self,
        message: &[u8],
        key: &TypedSignaturePublicKey,
        signature: Vec<u8>,
    ) -> crate::Result<bool> {
        match key {
            TypedSignaturePublicKey::Dilithium5(pk) => {
                let _ = Dilithium5::verify(&pk, message, &Signature(signature))?;
                Ok(true)
            }
            _ => Err(crate::Error::Format(FormatError::InvalidKeyType)),
        }
    }

    fn generate_keypair(&self) -> crate::Result<TypedSignatureKeyPair> {
        let (pk, sk) = Dilithium5::generate_keypair()?;
        Ok(TypedSignatureKeyPair::Dilithium5((pk, sk)))
    }

    fn clone_box(&self) -> Box<dyn SignatureAlgorithm> {
        Box::new(self.clone())
    }

    fn algorithm(&self) -> SignatureAlgorithmEnum {
        SignatureAlgorithmEnum::Dilithium5
    }
}

#[derive(Clone, Default)]
pub struct Ed25519Wrapper;

impl Ed25519Wrapper {
    pub fn new() -> Self {
        Self
    }
}

impl SignatureAlgorithm for Ed25519Wrapper {
    fn sign(&self, message: &[u8], key: &TypedSignaturePrivateKey) -> crate::Result<Vec<u8>> {
        match key {
            TypedSignaturePrivateKey::Ed25519(sk) => {
                let sig = Ed25519::sign(&sk, message)?;
                Ok(sig.0)
            }
            _ => Err(crate::Error::Format(FormatError::InvalidKeyType)),
        }
    }

    fn verify(
        &self,
        message: &[u8],
        key: &TypedSignaturePublicKey,
        signature: Vec<u8>,
    ) -> crate::Result<bool> {
        match key {
            TypedSignaturePublicKey::Ed25519(pk) => {
                let _ = Ed25519::verify(&pk, message, &Signature(signature))?;
                Ok(true)
            }
            _ => Err(crate::Error::Format(FormatError::InvalidKeyType)),
        }
    }

    fn generate_keypair(&self) -> crate::Result<TypedSignatureKeyPair> {
        let (pk, sk) = Ed25519::generate_keypair()?;
        Ok(TypedSignatureKeyPair::Ed25519((pk, sk)))
    }

    fn clone_box(&self) -> Box<dyn SignatureAlgorithm> {
        Box::new(self.clone())
    }

    fn algorithm(&self) -> SignatureAlgorithmEnum {
        SignatureAlgorithmEnum::Ed25519
    }
}

#[derive(Clone, Default)]
pub struct EcdsaP256Wrapper;

impl EcdsaP256Wrapper {
    pub fn new() -> Self {
        Self
    }
}

impl SignatureAlgorithm for EcdsaP256Wrapper {
    fn sign(&self, message: &[u8], key: &TypedSignaturePrivateKey) -> crate::Result<Vec<u8>> {
        match key {
            TypedSignaturePrivateKey::EcdsaP256(sk) => {
                let sig = EcdsaP256::sign(&sk, message)?;
                Ok(sig.0)
            }
            _ => Err(crate::Error::Format(FormatError::InvalidKeyType)),
        }
    }

    fn verify(
        &self,
        message: &[u8],
        key: &TypedSignaturePublicKey,
        signature: Vec<u8>,
    ) -> crate::Result<bool> {
        match key {
            TypedSignaturePublicKey::EcdsaP256(pk) => {
                let _ = EcdsaP256::verify(&pk, message, &Signature(signature))?;
                Ok(true)
            }
            _ => Err(crate::Error::Format(FormatError::InvalidKeyType)),
        }
    }

    fn generate_keypair(&self) -> crate::Result<TypedSignatureKeyPair> {
        let (pk, sk) = EcdsaP256::generate_keypair()?;
        Ok(TypedSignatureKeyPair::EcdsaP256((pk, sk)))
    }

    fn clone_box(&self) -> Box<dyn SignatureAlgorithm> {
        Box::new(self.clone())
    }

    fn algorithm(&self) -> SignatureAlgorithmEnum {
        SignatureAlgorithmEnum::EcdsaP256
    }
}
