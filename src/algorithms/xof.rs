use crate::algorithms::traits::XofAlgorithm;
use crate::error::{Error, Result};
use crate::prelude::XofAlgorithmEnum;
use seal_crypto::prelude::{XofDerivation, XofReader};
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
    fn reader<'a>(
        &self,
        ikm: &'a [u8],
        salt: Option<&'a [u8]>,
        info: Option<&'a [u8]>,
    ) -> Result<XofReaderWrapper<'a>> {
        self.shake.reader(ikm, salt, info)
            .map(|r| XofReaderWrapper::new(r))
            .map_err(Error::from)
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
    fn reader<'a>(
        &self,
        ikm: &'a [u8],
        salt: Option<&'a [u8]>,
        info: Option<&'a [u8]>,
    ) -> Result<XofReaderWrapper<'a>> {
        self.shake
            .reader(ikm, salt, info)
            .map(|r| XofReaderWrapper::new(r))
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
    fn reader<'a>(
        &self,
        ikm: &'a [u8],
        salt: Option<&'a [u8]>,
        info: Option<&'a [u8]>,
    ) -> Result<XofReaderWrapper<'a>> {
        self.algorithm.reader(ikm, salt, info)
    }

    fn clone_box(&self) -> Box<dyn XofAlgorithm> {
        self.algorithm.clone_box()
    }

    fn algorithm(&self) -> XofAlgorithmEnum {
        self.algorithm.algorithm()
    }
}

pub struct XofReaderWrapper<'a> {
    reader: XofReader<'a>,
}

impl<'a> XofReaderWrapper<'a> {
    pub fn new(reader: XofReader<'a>) -> Self {
        Self { reader }
    }

    pub fn read(&mut self, buffer: &mut [u8]) {
        use seal_crypto::prelude::DigestXofReader;
        self.reader.read(buffer);
    }

    pub fn read_boxed(&mut self, n: usize) -> Box<[u8]> {
        let mut buf = vec![0u8; n].into_boxed_slice();
        self.read(&mut buf);
        buf
    }
}