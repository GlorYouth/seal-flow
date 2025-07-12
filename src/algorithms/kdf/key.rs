use crate::algorithms::traits::KdfKeyAlgorithm;
use crate::error::Error;
use crate::keys::TypedSymmetricKey;
use crate::prelude::KdfKeyAlgorithmEnum;
use seal_crypto::prelude::KeyBasedDerivation;
use seal_crypto::schemes::kdf::hkdf::{HkdfSha256, HkdfSha384, HkdfSha512};

#[derive(Clone, Default)]
pub struct HkdfSha256Wrapper {
    algorithm: HkdfSha256,
}

impl KdfKeyAlgorithm for HkdfSha256Wrapper {
    fn derive(
        &self,
        ikm: &TypedSymmetricKey,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
    ) -> crate::Result<TypedSymmetricKey> {
        self.algorithm
            .derive(
                ikm.as_ref(),
                salt,
                info,
                ikm.algorithm().into_symmetric_wrapper().key_size(),
            )
            .map_err(Error::from)
            .and_then(|dk| TypedSymmetricKey::from_bytes(dk.as_bytes(), ikm.algorithm()))
    }

    fn algorithm(&self) -> KdfKeyAlgorithmEnum {
        KdfKeyAlgorithmEnum::HkdfSha256
    }

    fn clone_box(&self) -> Box<dyn KdfKeyAlgorithm> {
        Box::new(self.clone())
    }
}

#[derive(Clone, Default)]
pub struct HkdfSha384Wrapper {
    algorithm: HkdfSha384,
}

impl KdfKeyAlgorithm for HkdfSha384Wrapper {
    fn derive(
        &self,
        ikm: &TypedSymmetricKey,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
    ) -> crate::Result<TypedSymmetricKey> {
        self.algorithm
            .derive(
                ikm.as_ref(),
                salt,
                info,
                ikm.algorithm().into_symmetric_wrapper().key_size(),
            )
            .map_err(Error::from)
            .and_then(|dk| TypedSymmetricKey::from_bytes(dk.as_bytes(), ikm.algorithm()))
    }

    fn algorithm(&self) -> KdfKeyAlgorithmEnum {
        KdfKeyAlgorithmEnum::HkdfSha384
    }

    fn clone_box(&self) -> Box<dyn KdfKeyAlgorithm> {
        Box::new(self.clone())
    }
}

#[derive(Clone, Default)]
pub struct HkdfSha512Wrapper {
    algorithm: HkdfSha512,
}

impl KdfKeyAlgorithm for HkdfSha512Wrapper {
    fn derive(
        &self,
        ikm: &TypedSymmetricKey,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
    ) -> crate::Result<TypedSymmetricKey> {
        self.algorithm
            .derive(
                ikm.as_ref(),
                salt,
                info,
                ikm.algorithm().into_symmetric_wrapper().key_size(),
            )
            .map_err(Error::from)
            .and_then(|dk| TypedSymmetricKey::from_bytes(dk.as_bytes(), ikm.algorithm()))
    }

    fn algorithm(&self) -> KdfKeyAlgorithmEnum {
        KdfKeyAlgorithmEnum::HkdfSha512
    }

    fn clone_box(&self) -> Box<dyn KdfKeyAlgorithm> {
        Box::new(self.clone())
    }
}

#[derive(Clone)]
pub struct KdfKeyWrapper {
    algorithm: Box<dyn KdfKeyAlgorithm>,
}

impl KdfKeyAlgorithm for KdfKeyWrapper {
    fn derive(
        &self,
        ikm: &TypedSymmetricKey,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
    ) -> crate::Result<TypedSymmetricKey> {
        self.algorithm.derive(ikm, salt, info)
    }

    fn algorithm(&self) -> KdfKeyAlgorithmEnum {
        self.algorithm.algorithm()
    }

    fn clone_box(&self) -> Box<dyn KdfKeyAlgorithm> {
        Box::new(self.clone())
    }
}

impl KdfKeyWrapper {
    pub fn new(algorithm: Box<dyn KdfKeyAlgorithm>) -> Self {
        Self { algorithm }
    }
}
