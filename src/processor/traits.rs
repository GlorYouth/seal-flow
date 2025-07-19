//! Defines the traits for different body processing modes.
//!
//! 定义不同消息体处理模式的 trait。

use crate::processor::asynchronous::{AsyncDecryptorSetup, AsyncEncryptorSetup};
use crate::processor::config::{BodyDecryptConfig, BodyEncryptConfig};
use crate::processor::ordinary::{OrdinaryDecryptor, OrdinaryEncryptor};
use crate::processor::parallel::{ParallelDecryptor, ParallelEncryptor};
use crate::processor::parallel_streaming::{
    ParallelStreamingDecryptor, ParallelStreamingEncryptor,
};
use crate::processor::streaming::{StreamingDecryptorSetup, StreamingEncryptorSetup};
use crate::common::header::SymmetricParams;
use crate::common::mode::ProcessingMode;
use crate::error::Result;
use seal_crypto_wrapper::traits::SymmetricAlgorithmTrait;
use std::io::Write;


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
            symmetric_params,
            aad,
            config: _,
            ..
        } = config;

        let processor = match mode {
            ProcessingMode::Ordinary => {
                let encryptor = OrdinaryEncryptor::new(
                    symmetric_params.clone(),
                    aad,
                );
                BodyEncryptor::Ordinary(encryptor)
            }
            ProcessingMode::Streaming => {
                let setup = StreamingEncryptorSetup::new(
                    symmetric_params.clone(),
                    aad,
                );
                BodyEncryptor::Streaming(setup)
            }
            ProcessingMode::Parallel => {
                let encryptor = ParallelEncryptor::new(
                    symmetric_params.clone(),
                    aad,
                );
                BodyEncryptor::Parallel(encryptor)
            }
            ProcessingMode::ParallelStreaming => {
                let encryptor = ParallelStreamingEncryptor::new(
                    symmetric_params.clone(),
                    aad,
                    config.config.channel_bound(),
                );
                BodyEncryptor::ParallelStreaming(encryptor)
            }
            #[cfg(feature = "async")]
            ProcessingMode::Asynchronous => {
                let setup = AsyncEncryptorSetup::new(
                    symmetric_params.clone(),
                    aad,
                    config.config.channel_bound(),
                );
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
                let decryptor = OrdinaryDecryptor::new(
                    self.algorithm().into_symmetric_wrapper(),
                    config.nonce,
                    chunk_size,
                    config.aad,
                );
                BodyDecryptor::Ordinary(decryptor)
            }
            ProcessingMode::Streaming => {
                let setup = StreamingDecryptorSetup::new(
                    self.algorithm().into_symmetric_wrapper(),
                    config.nonce,
                    chunk_size,
                    config.aad,
                );
                BodyDecryptor::Streaming(setup)
            }
            ProcessingMode::Parallel => {
                let decryptor = ParallelDecryptor::new(
                    self.algorithm().into_symmetric_wrapper(),
                    config.nonce,
                    chunk_size,
                    config.aad,
                );
                BodyDecryptor::Parallel(decryptor)
            }
            ProcessingMode::ParallelStreaming => {
                let decryptor = ParallelStreamingDecryptor::new(
                    self.algorithm().into_symmetric_wrapper(),
                    config.nonce,
                    config.aad,
                    chunk_size,
                    channel_bound,
                );
                BodyDecryptor::ParallelStreaming(decryptor)
            }
            #[cfg(feature = "async")]
            ProcessingMode::Asynchronous => {
                let setup = AsyncDecryptorSetup::new(
                    self.algorithm().into_symmetric_wrapper(),
                    config.nonce,
                    config.aad,
                    chunk_size,
                    channel_bound,
                );
                BodyDecryptor::Asynchronous(setup)
            }
        };

        Ok(SymmetricDecryptorSetup { processor })
    }
}
