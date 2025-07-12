use crate::algorithms::traits::XofAlgorithm;
use crate::error::{Error, Result};
use crate::keys::TypedSymmetricKey;
use crate::prelude::XofAlgorithmEnum;
use seal_crypto::prelude::KeyBasedDerivation;
use seal_crypto::schemes::xof::shake::{Shake128, Shake256};

#[derive(Clone, Default)]
pub struct Shake128Wrapper {
    shake: Shake128,
}

impl Shake128Wrapper {
    pub fn new() -> Self {
        Self {
            shake: Shake128::default(),
        }
    }
}

impl XofAlgorithm for Shake128Wrapper {
    fn derive(
        &self,
        ikm: &TypedSymmetricKey,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
    ) -> Result<TypedSymmetricKey> {
        self.shake
            .derive(
                ikm.as_ref(),
                salt,
                info,
                ikm.algorithm().into_symmetric_wrapper().key_size(),
            )
            .map_err(Error::from)
            .and_then(|dk| TypedSymmetricKey::from_bytes(dk.as_bytes(), ikm.algorithm()))
    }

    fn clone_box(&self) -> Box<dyn XofAlgorithm> {
        Box::new(self.clone())
    }

    fn algorithm(&self) -> XofAlgorithmEnum {
        XofAlgorithmEnum::Shake128
    }
}

#[derive(Clone, Default)]
pub struct Shake256Wrapper {
    shake: Shake256,
}

impl Shake256Wrapper {
    pub fn new() -> Self {
        Self {
            shake: Shake256::default(),
        }
    }
}

impl XofAlgorithm for Shake256Wrapper {
    fn derive(
        &self,
        ikm: &TypedSymmetricKey,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
    ) -> Result<TypedSymmetricKey> {
        self.shake
            .derive(
                ikm.as_ref(),
                salt,
                info,
                ikm.algorithm().into_symmetric_wrapper().key_size(),
            )
            .map_err(Error::from)
            .and_then(|dk| TypedSymmetricKey::from_bytes(dk.as_bytes(), ikm.algorithm()))
    }

    fn clone_box(&self) -> Box<dyn XofAlgorithm> {
        Box::new(self.clone())
    }

    fn algorithm(&self) -> XofAlgorithmEnum {
        XofAlgorithmEnum::Shake256
    }
}

pub struct XofWrapper {
    algorithm: Box<dyn XofAlgorithm>,
}

impl XofWrapper {
    pub fn new(algorithm: Box<dyn XofAlgorithm>) -> Self {
        Self { algorithm }
    }
}

impl XofAlgorithm for XofWrapper {
    fn derive(
        &self,
        ikm: &TypedSymmetricKey,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
    ) -> Result<TypedSymmetricKey> {
        self.algorithm.derive(ikm, salt, info)
    }

    fn clone_box(&self) -> Box<dyn XofAlgorithm> {
        self.algorithm.clone_box()
    }

    fn algorithm(&self) -> XofAlgorithmEnum {
        self.algorithm.algorithm()
    }
}
