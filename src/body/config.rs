use std::borrow::Cow;

use crate::common::config::{ArcConfig, DecryptorConfig};
use rand::{rngs::OsRng, TryRngCore};
use seal_crypto_wrapper::prelude::TypedSymmetricKey;
use crate::body::traits::ProcessingMode;
use crate::error::Result;

pub struct BodyEncryptConfig<'a> {
    pub(crate) key: Cow<'a, TypedSymmetricKey>,
    pub(crate) nonce: Box<[u8]>,
    pub(crate) aad: Option<Vec<u8>>,
    pub(crate) config: ArcConfig,
    pub(crate) mode: ProcessingMode,
}

impl<'a> BodyEncryptConfig<'a> {
    pub fn key(&self) -> &TypedSymmetricKey {
        self.key.as_ref()
    }

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
    key: Cow<'a, TypedSymmetricKey>,
    nonce: Option<Box<[u8]>>,
    aad: Option<Vec<u8>>,
    config: ArcConfig,
    mode: ProcessingMode,
}

impl<'a> BodyEncryptConfigBuilder<'a> {
    pub fn new(key: Cow<'a, TypedSymmetricKey>, config: ArcConfig) -> Self {
        Self {
            key,
            nonce: None,
            aad: None,
            config,
            mode: ProcessingMode::Ordinary,
        }
    }

    pub fn nonce(&mut self, mut f: impl FnMut(&mut [u8]) -> Result<()>) -> Result<&mut Self> {
        let algorithm = self.key.as_ref().algorithm().into_symmetric_wrapper();
        let mut nonce = Vec::with_capacity(algorithm.nonce_size());
        nonce.resize(algorithm.nonce_size(), 0);
        let mut nonce = nonce.into_boxed_slice();
        f(&mut nonce)?;
        self.nonce = Some(nonce);
        Ok(self)
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
            key: self.key,
            nonce: self.nonce.unwrap(),
            aad: self.aad,
            config: self.config,
            mode: self.mode,
        })
    }
}
    
    


pub struct BodyDecryptConfig<'a> {
    pub key: Cow<'a, TypedSymmetricKey>,
    pub nonce: Box<[u8]>,
    pub aad: Option<Vec<u8>>,
    pub config: DecryptorConfig,
    pub mode: ProcessingMode,
}

impl<'a> BodyDecryptConfig<'a> {
    pub fn key(&self) -> &TypedSymmetricKey {
        self.key.as_ref()
    }

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
