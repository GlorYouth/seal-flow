use crate::algorithms::traits::XofAlgorithm;
use crate::error::{Error, Result};
use crate::prelude::XofAlgorithmEnum;
use seal_crypto::prelude::KeyBasedDerivation;
use seal_crypto::schemes::xof::shake::{Shake128, Shake256};
use seal_crypto::zeroize::Zeroizing;

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
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.shake.derive(ikm, salt, info, output_len).map(|dk| dk.0).map_err(Error::from)
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
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.shake
            .derive(ikm, salt, info, output_len)
            .map(|dk| dk.0)
            .map_err(Error::from)
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
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.algorithm.derive(ikm, salt, info, output_len)
    }

    fn clone_box(&self) -> Box<dyn XofAlgorithm> {
        self.algorithm.clone_box()
    }

    fn algorithm(&self) -> XofAlgorithmEnum {
        self.algorithm.algorithm()
    }
}
