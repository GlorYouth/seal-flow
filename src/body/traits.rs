//! Defines the traits for different body processing modes.
//!
//! 定义不同消息体处理模式的 trait。

use crate::body::asynchronous::{AsyncDecryptorSetup, AsyncEncryptorSetup};
use crate::body::config::{BodyDecryptConfig, BodyEncryptConfig};
use crate::body::ordinary::{OrdinaryDecryptor, OrdinaryEncryptor};
use crate::body::parallel::{ParallelDecryptor, ParallelEncryptor};
use crate::body::parallel_streaming::{
    ParallelStreamingDecryptor, ParallelStreamingEncryptor,
};
use crate::body::streaming::{StreamingDecryptorSetup, StreamingEncryptorSetup};
use crate::common::header::SymmetricParams;
use crate::error::Result;
use seal_crypto_wrapper::traits::SymmetricAlgorithmTrait;
use std::io::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessingMode {
    Ordinary,
    Streaming,
    Parallel,
    ParallelStreaming,
    #[cfg(feature = "async")]
    Asynchronous,
}

pub enum BodyEncryptor<'a> {
    Ordinary(OrdinaryEncryptor<'a>),
    Streaming(StreamingEncryptorSetup<'a>),
    Parallel(ParallelEncryptor<'a>),
    ParallelStreaming(ParallelStreamingEncryptor<'a>),
    #[cfg(feature = "async")]
    Asynchronous(AsyncEncryptorSetup<'a>),
}

pub struct SymmetricEncryptorSetup<'a> {
    pub symmetric_params: SymmetricParams,
    pub processor: BodyEncryptor<'a>,
}

pub enum BodyDecryptor<'a> {
    Ordinary(OrdinaryDecryptor<'a>),
    Streaming(StreamingDecryptorSetup<'a>),
    Parallel(ParallelDecryptor<'a>),
    ParallelStreaming(ParallelStreamingDecryptor<'a>),
    #[cfg(feature = "async")]
    Asynchronous(AsyncDecryptorSetup<'a>),
}

pub struct SymmetricDecryptorSetup<'a> {
    pub processor: BodyDecryptor<'a>,
}

pub trait FinishingWrite: Write {
    fn finish(self: Box<Self>) -> Result<()>;
}

pub trait BodyProcessor {
    fn setup_encryptor<'a>(
        &self,
        config: BodyEncryptConfig<'a>,
    ) -> Result<SymmetricEncryptorSetup<'a>>;

    fn setup_decryptor<'a>(
        &self,
        config: BodyDecryptConfig<'a>,
    ) -> Result<SymmetricDecryptorSetup<'a>>;
}

impl<S: SymmetricAlgorithmTrait + ?Sized> BodyProcessor for S {
    fn setup_encryptor<'a>(
        &self,
        config: BodyEncryptConfig<'a>,
    ) -> Result<SymmetricEncryptorSetup<'a>> {
        let mode = config.mode();
        let BodyEncryptConfig {
            key,
            nonce,
            aad,
            config,
            ..
        } = config;
        let symmetric_params = SymmetricParams::new(config.chunk_size(), nonce, aad.as_deref());

        let processor = match mode {
            ProcessingMode::Ordinary => {
                let encryptor = OrdinaryEncryptor {
                    symmetric_params: symmetric_params.clone(),
                    algorithm: self.algorithm().into_symmetric_wrapper(),
                    key,
                    aad,
                };
                BodyEncryptor::Ordinary(encryptor)
            }
            ProcessingMode::Streaming => {
                let setup = StreamingEncryptorSetup {
                    symmetric_params: symmetric_params.clone(),
                    algorithm: self.algorithm().into_symmetric_wrapper(),
                    key,
                    aad,
                };
                BodyEncryptor::Streaming(setup)
            }
            ProcessingMode::Parallel => {
                let encryptor = ParallelEncryptor {
                    symmetric_params: symmetric_params.clone(),
                    algorithm: self.algorithm().into_symmetric_wrapper(),
                    key,
                    aad,
                };
                BodyEncryptor::Parallel(encryptor)
            }
            ProcessingMode::ParallelStreaming => {
                let encryptor = ParallelStreamingEncryptor {
                    symmetric_params: symmetric_params.clone(),
                    algorithm: self.algorithm().into_symmetric_wrapper(),
                    key,
                    aad,
                    channel_bound: config.channel_bound(),
                };
                BodyEncryptor::ParallelStreaming(encryptor)
            }
            #[cfg(feature = "async")]
            ProcessingMode::Asynchronous => {
                let setup = AsyncEncryptorSetup {
                    symmetric_params: symmetric_params.clone(),
                    algorithm: self.algorithm().into_symmetric_wrapper(),
                    key,
                    aad,
                    channel_bound: config.channel_bound(),
                };
                BodyEncryptor::Asynchronous(setup)
            }
        };

        Ok(SymmetricEncryptorSetup {
            symmetric_params,
            processor,
        })
    }

    fn setup_decryptor<'a>(
        &self,
        config: BodyDecryptConfig<'a>,
    ) -> Result<SymmetricDecryptorSetup<'a>> {
        let mode = config.mode();
        let chunk_size = config.chunk_size();
        let channel_bound = config.channel_bound();

        let processor = match mode {
            ProcessingMode::Ordinary => {
                let decryptor = OrdinaryDecryptor {
                    algorithm: self.algorithm().into_symmetric_wrapper(),
                    key: config.key,
                    nonce: config.nonce,
                    chunk_size,
                    aad: config.aad,
                };
                BodyDecryptor::Ordinary(decryptor)
            }
            ProcessingMode::Streaming => {
                let setup = StreamingDecryptorSetup {
                    algorithm: self.algorithm().into_symmetric_wrapper(),
                    key: config.key,
                    nonce: config.nonce,
                    chunk_size,
                    aad: config.aad,
                };
                BodyDecryptor::Streaming(setup)
            }
            ProcessingMode::Parallel => {
                let decryptor = ParallelDecryptor {
                    algorithm: self.algorithm().into_symmetric_wrapper(),
                    key: config.key,
                    nonce: config.nonce,
                    chunk_size,
                    aad: config.aad,
                };
                BodyDecryptor::Parallel(decryptor)
            }
            ProcessingMode::ParallelStreaming => {
                let decryptor = ParallelStreamingDecryptor {
                    algorithm: self.algorithm().into_symmetric_wrapper(),
                    key: config.key,
                    nonce: config.nonce,
                    aad: config.aad,
                    chunk_size,
                    channel_bound,
                };
                BodyDecryptor::ParallelStreaming(decryptor)
            }
            #[cfg(feature = "async")]
            ProcessingMode::Asynchronous => {
                let setup = AsyncDecryptorSetup {
                    algorithm: self.algorithm().into_symmetric_wrapper(),
                    key: config.key,
                    nonce: config.nonce,
                    aad: config.aad,
                    chunk_size,
                    channel_bound,
                };
                BodyDecryptor::Asynchronous(setup)
            }
        };

        Ok(SymmetricDecryptorSetup { processor })
    }
}
