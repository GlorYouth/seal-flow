use std::marker::PhantomData;

use crate::common::config::{ArcConfig, DecryptorConfig};
use seal_crypto_wrapper::wrappers::symmetric::SymmetricAlgorithmWrapper;
use crate::common::mode::ProcessingMode;
use crate::common::header::SymmetricParams;
use crate::error::Result;
use sha2::{Sha256, Digest};

pub struct BodyEncryptConfig<'a> {
    pub(crate) symmetric_params: SymmetricParams,
    pub(crate) aad: Option<Vec<u8>>,
    pub(crate) config: ArcConfig,
    _lifetime: PhantomData<&'a ()>
}

impl<'a> BodyEncryptConfig<'a> {
    pub fn symmetric_params(&self) -> &SymmetricParams {
        &self.symmetric_params
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
        self.symmetric_params.mode
    }
}

pub struct BodyEncryptConfigBuilder<'a> {
    pub(crate) algorithm: SymmetricAlgorithmWrapper,
    pub(crate) base_nonce: Option<Box<[u8]>>, // 用于派生每个 chunk nonce 的基础 nonce
    pub(crate) aad: Option<Vec<u8>>,
    pub(crate) mode: ProcessingMode,
    pub(crate) config: ArcConfig,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> BodyEncryptConfigBuilder<'a> {

    pub fn new(algorithm: SymmetricAlgorithmWrapper, mode: ProcessingMode, config: ArcConfig) -> Self {
        Self {
            algorithm,
            base_nonce: None,
            aad: None,
            mode,
            config,
            _lifetime: PhantomData,
        }
    }

    pub fn set_base_nonce(&mut self, mut f: impl FnMut(&mut [u8]) -> Result<()>) -> Result<&mut Self> {
        let nonce_size = self.algorithm.nonce_size();
        let mut base_nonce = vec![0u8; nonce_size];
        f(&mut base_nonce)?;
        self.base_nonce = Some(base_nonce.into_boxed_slice());
        Ok(self)
    }

    pub fn set_aad(&mut self, aad: Vec<u8>) -> &mut Self {
        self.aad = Some(aad);
        self
    }

    pub fn build(mut self) -> Result<BodyEncryptConfig<'a>> {
        if self.base_nonce.is_none() {
            let nonce_size = self.algorithm.nonce_size();
            let mut base_nonce = vec![0u8; nonce_size];

            use crate::error::Error;
            base_nonce.copy_from_slice(&self.algorithm.generate_nonce().map(Vec::into_boxed_slice).map_err(Error::from)?);
            self.base_nonce = Some(base_nonce.into_boxed_slice());
        }

        let aad_hash = self.aad.as_ref().map(|aad| {
            let mut hasher = Sha256::new();
            hasher.update(aad);
            hasher.finalize().into()
        });

        Ok(BodyEncryptConfig {
            symmetric_params: SymmetricParams {
                algorithm: self.algorithm.algorithm(),
                chunk_size: self.config.chunk_size(),
                base_nonce: self.base_nonce.unwrap(),
                aad_hash,
                mode: self.mode,
            },
            aad: self.aad,
            config: self.config,
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
