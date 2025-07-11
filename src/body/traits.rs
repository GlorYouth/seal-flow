//! Defines the traits for different body processing modes.
//!
//! 定义不同消息体处理模式的 trait。

use crate::body::config::{BodyDecryptConfig, BodyEncryptConfig};
use crate::error::Result;
use std::io::{Read, Write};

pub trait OrdinaryBodyProcessor {
    fn encrypt_body_in_memory<'a>(
        &self,
        plaintext: &[u8],
        config: BodyEncryptConfig<'a>,
    ) -> Result<Vec<u8>>;
    fn decrypt_body_in_memory<'a>(
        &self,
        ciphertext: &[u8],
        config: BodyDecryptConfig<'a>,
    ) -> Result<Vec<u8>>;
}

pub trait StreamingBodyProcessor {
    fn encrypt_body_to_stream<'a>(
        &self,
        writer: Box<dyn Write + 'a>,
        config: BodyEncryptConfig<'a>,
    ) -> Result<Box<dyn Write + 'a>>;

    fn decrypt_body_from_stream<'a>(
        &self,
        reader: Box<dyn Read + 'a>,
        config: BodyDecryptConfig<'a>,
    ) -> Result<Box<dyn Read + 'a>>;
}

pub trait ParallelBodyProcessor {
    fn encrypt_body_parallel<'a>(
        &self,
        plaintext: &[u8],
        config: BodyEncryptConfig<'a>,
    ) -> Result<Vec<u8>>;
    fn decrypt_body_parallel<'a>(
        &self,
        ciphertext: &[u8],
        config: BodyDecryptConfig<'a>,
    ) -> Result<Vec<u8>>;
}

pub trait ParallelStreamingBodyProcessor {
    fn encrypt_body_pipeline<'a>(
        &self,
        reader: Box<dyn Read + Send + 'a>,
        writer: Box<dyn Write + Send + 'a>,
        config: BodyEncryptConfig<'a>,
    ) -> Result<()>;
    fn decrypt_body_pipeline<'a>(
        &self,
        reader: Box<dyn Read + Send + 'a>,
        writer: Box<dyn Write + Send + 'a>,
        config: BodyDecryptConfig<'a>,
    ) -> Result<()>;
}

#[cfg(feature = "async")]
pub trait AsynchronousBodyProcessor {
    fn encrypt_body_async<'a>(
        &self,
        writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'a>,
        config: BodyEncryptConfig<'a>,
    ) -> Result<Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'a>>;

    fn decrypt_body_async<'a>(
        &self,
        reader: Box<dyn tokio::io::AsyncRead + Send + Unpin + 'a>,
        config: BodyDecryptConfig<'a>,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin + 'a>>;
}
