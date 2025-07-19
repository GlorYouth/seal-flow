use std::marker::PhantomData;

use crate::common::config::{ArcConfig, DecryptorConfig};
use rand::{rngs::OsRng, TryRngCore};
use seal_crypto_wrapper::wrappers::symmetric::SymmetricAlgorithmWrapper;
use crate::body::traits::ProcessingMode;
use crate::error::Result;

pub struct BodyEncryptConfig<'a> {
    pub(crate) nonce: Box<[u8]>,
    pub(crate) aad: Option<Vec<u8>>,
    pub(crate) config: ArcConfig,
    pub(crate) mode: ProcessingMode,
    _lifetime: PhantomData<&'a ()>
}

impl<'a> BodyEncryptConfig<'a> {
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub fn aad(&self) -> Option<&[u8]> {
        self.aad.as_deref()
    }

    pub fn chunk_size(&self) -> usize {
        self.config.chunk_size() as usize
    }

    pub fn channel_bound(&self) -> usize {
        self.config.channel_bound()
    }

    pub fn mode(&self) -> ProcessingMode {
        self.mode
    }
}

pub struct BodyEncryptConfigBuilder<'a> {
    algorithm: SymmetricAlgorithmWrapper,
    nonce: Option<Box<[u8]>>,
    aad: Option<Vec<u8>>,
    config: ArcConfig,
    mode: ProcessingMode,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> BodyEncryptConfigBuilder<'a> {
    pub fn new(algorithm: SymmetricAlgorithmWrapper, config: ArcConfig) -> Self {
        Self {
            algorithm,
            nonce: None,
            aad: None,
            config,
            mode: ProcessingMode::Ordinary,
            _lifetime: PhantomData,
        }
    }

    pub fn nonce(&mut self, mut f: impl FnMut(&mut [u8]) -> Result<()>) -> Result<()> {
        let mut nonce = Vec::with_capacity(self.algorithm.nonce_size());
        nonce.resize(self.algorithm.nonce_size(), 0);
        let mut nonce = nonce.into_boxed_slice();
        f(&mut nonce)?;
        self.nonce = Some(nonce);
        Ok(())
    }

    pub fn aad(&mut self, aad: Vec<u8>) -> &mut Self {
        self.aad = Some(aad);
        self
    }

    pub fn mode(&mut self, mode: ProcessingMode) -> &mut Self {
        self.mode = mode;
        self
    }

    pub fn build(mut self) -> Result<BodyEncryptConfig<'a>> {
        if self.nonce.is_none() {
            self.nonce(|nonce| {
                OsRng.try_fill_bytes(nonce)?;
                Ok(())
            })?;
        }

        Ok(BodyEncryptConfig {
            nonce: self.nonce.unwrap(),
            aad: self.aad,
            config: self.config,
            mode: self.mode,
            _lifetime: PhantomData,
        })
    }
}

pub struct BodyDecryptConfig<'a> {
    pub nonce: Box<[u8]>,
    pub aad: Option<Vec<u8>>,
    pub config: DecryptorConfig,
    pub mode: ProcessingMode,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> BodyDecryptConfig<'a> {
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub fn aad(&self) -> Option<&[u8]> {
        self.aad.as_deref()
    }

    pub fn chunk_size(&self) -> usize {
        self.config.chunk_size() as usize
    }

    pub fn channel_bound(&self) -> usize {
        self.config.channel_bound()
    }

    pub fn mode(&self) -> ProcessingMode {
        self.mode
    }
}
