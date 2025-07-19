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
use crate::error::Result;
use std::io::Write;

pub trait OrdinaryBodyProcessor {
    fn setup_encryptor<'a>(
        &self,
        config: BodyEncryptConfig<'a>,
    ) -> Result<OrdinaryEncryptor<'a>>;
    fn setup_decryptor<'a>(
        &self,
        config: BodyDecryptConfig<'a>,
    ) -> Result<OrdinaryDecryptor<'a>>;
}

pub trait StreamingBodyProcessor {
    fn setup_encryptor<'a>(
        &self,
        config: BodyEncryptConfig<'a>,
    ) -> Result<StreamingEncryptorSetup<'a>>;

    fn setup_decryptor<'a>(
        &self,
        config: BodyDecryptConfig<'a>,
    ) -> Result<StreamingDecryptorSetup<'a>>;
}

pub trait FinishingWrite: Write {
    fn finish(self: Box<Self>) -> Result<()>;
}

pub trait ParallelBodyProcessor {
    fn setup_encryptor<'a>(
        &self,
        config: BodyEncryptConfig<'a>,
    ) -> Result<ParallelEncryptor<'a>>;
    fn setup_decryptor<'a>(
        &self,
        config: BodyDecryptConfig<'a>,
    ) -> Result<ParallelDecryptor<'a>>;
}

pub trait ParallelStreamingBodyProcessor {
    fn setup_encryptor<'a>(
        &self,
        config: BodyEncryptConfig<'a>,
    ) -> Result<ParallelStreamingEncryptor<'a>>;
    fn setup_decryptor<'a>(
        &self,
        config: BodyDecryptConfig<'a>,
    ) -> Result<ParallelStreamingDecryptor<'a>>;
}

#[cfg(feature = "async")]
pub trait AsynchronousBodyProcessor {
    fn setup_encryptor<'a>(
        &self,
        config: BodyEncryptConfig<'a>,
    ) -> Result<AsyncEncryptorSetup<'a>>;

    fn setup_decryptor<'a>(
        &self,
        config: BodyDecryptConfig<'a>,
    ) -> Result<AsyncDecryptorSetup<'a>>;
}
