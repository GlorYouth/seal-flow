use crate::algorithms::traits::KdfKeyAlgorithm;
use crate::error::Error;
use crate::prelude::KdfKeyAlgorithmEnum;
use seal_crypto::prelude::KeyBasedDerivation;
use seal_crypto::schemes::kdf::hkdf::{HkdfSha256, HkdfSha384, HkdfSha512};
use seal_crypto::zeroize::Zeroizing;

#[derive(Clone, Default)]
pub struct HkdfSha256Wrapper {
    algorithm: HkdfSha256,
}

impl KdfKeyAlgorithm for HkdfSha256Wrapper {
    fn derive(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> crate::Result<Zeroizing<Vec<u8>>> {
        self.algorithm
            .derive(
                ikm,
                salt,
                info,
                output_len,
            )
            .map(|dk| dk.0)
            .map_err(Error::from)
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
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> crate::Result<Zeroizing<Vec<u8>>> {
        self.algorithm
            .derive(
                ikm,
                salt,
                info,
                output_len,
            )
            .map(|dk| dk.0)
            .map_err(Error::from)
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
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> crate::Result<Zeroizing<Vec<u8>>> {
        self.algorithm
            .derive(ikm, salt, info, output_len)
            .map(|dk| dk.0)
            .map_err(Error::from)
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
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> crate::Result<Zeroizing<Vec<u8>>> {
        self.algorithm.derive(ikm, salt, info, output_len)
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
