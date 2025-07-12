//! Defines the traits for symmetric encryption operations.
//!
//! 定义对称加密操作的 trait。

use crate::body::traits::FinishingWrite;
use crate::common::config::ArcConfig;
use crate::common::header::Header;
use crate::error::Result;
use crate::keys::TypedSymmetricKey;
use crate::symmetric::config::SymmetricConfig;
use std::io::{Read, Write};

pub trait SymmetricOrdinaryProcessor {
    fn encrypt_symmetric_in_memory<'a>(
        &self,
        plaintext: &[u8],
        config: SymmetricConfig<'a>,
    ) -> Result<Vec<u8>>;

    fn begin_decrypt_symmetric_in_memory<'a>(
        &self,
        ciphertext: &'a [u8],
        config: ArcConfig,
    ) -> Result<Box<dyn SymmetricOrdinaryPendingDecryptor<'a> + 'a>>;
}

pub trait SymmetricOrdinaryPendingDecryptor<'a> {
    fn into_plaintext(
        self: Box<Self>,
        key: &TypedSymmetricKey,
        aad: Option<Vec<u8>>,
    ) -> Result<Vec<u8>>;

    fn header(&self) -> &Header;
}

pub trait SymmetricStreamingProcessor {
    fn encrypt_symmetric_to_stream<'a>(
        &self,
        writer: Box<dyn Write + 'a>,
        config: SymmetricConfig<'a>,
    ) -> Result<Box<dyn FinishingWrite + 'a>>;

    fn begin_decrypt_symmetric_from_stream<'a>(
        &self,
        reader: Box<dyn Read + 'a>,
        config: ArcConfig,
    ) -> Result<Box<dyn SymmetricStreamingPendingDecryptor<'a> + 'a>>;
}

pub trait SymmetricStreamingPendingDecryptor<'a> {
    fn into_decryptor(
        self: Box<Self>,
        key: &TypedSymmetricKey,
        aad: Option<Vec<u8>>,
    ) -> Result<Box<dyn Read + 'a>>;

    fn header(&self) -> &Header;
}

pub trait SymmetricParallelProcessor {
    fn encrypt_symmetric_parallel<'a>(
        &self,
        plaintext: &[u8],
        config: SymmetricConfig<'a>,
    ) -> Result<Vec<u8>>;
    fn begin_decrypt_symmetric_parallel<'a>(
        &self,
        ciphertext: &'a [u8],
        config: ArcConfig,
    ) -> Result<Box<dyn SymmetricParallelPendingDecryptor<'a> + 'a>>;
}

pub trait SymmetricParallelPendingDecryptor<'a> {
    fn into_plaintext(
        self: Box<Self>,
        key: &TypedSymmetricKey,
        aad: Option<Vec<u8>>,
    ) -> Result<Vec<u8>>;

    fn header(&self) -> &Header;
}

pub trait SymmetricParallelStreamingProcessor {
    fn encrypt_symmetric_pipeline<'a>(
        &self,
        reader: Box<dyn Read + Send + 'a>,
        writer: Box<dyn Write + Send + 'a>,
        config: SymmetricConfig<'a>,
    ) -> Result<()>;

    fn begin_decrypt_symmetric_pipeline<'a>(
        &self,
        reader: Box<dyn Read + Send + 'a>,
        config: ArcConfig,
    ) -> Result<Box<dyn SymmetricParallelStreamingPendingDecryptor<'a> + 'a>>;
}

pub trait SymmetricParallelStreamingPendingDecryptor<'a> {
    fn decrypt_to_writer(
        self: Box<Self>,
        key: &TypedSymmetricKey,
        writer: Box<dyn Write + Send + 'a>,
        aad: Option<Vec<u8>>,
    ) -> Result<()>;

    fn header(&self) -> &Header;
}

#[cfg(feature = "async")]
use async_trait::async_trait;

#[cfg(feature = "async")]
#[async_trait]
pub trait SymmetricAsynchronousProcessor {
    async fn encrypt_symmetric_async<'a>(
        &self,
        writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'a>,
        config: SymmetricConfig<'a>,
    ) -> Result<Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'a>>;

    async fn begin_decrypt_symmetric_async<'a>(
        &self,
        reader: Box<dyn tokio::io::AsyncRead + Send + Unpin + 'a>,
        config: ArcConfig,
    ) -> Result<Box<dyn SymmetricAsynchronousPendingDecryptor<'a> + Send + 'a>>;
}

#[cfg(feature = "async")]
#[async_trait]
pub trait SymmetricAsynchronousPendingDecryptor<'decr_life>: Send {
    async fn into_decryptor<'a>(
        self: Box<Self>,
        key: &'a TypedSymmetricKey,
        aad: Option<Vec<u8>>,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin + 'decr_life>>;

    fn header(&self) -> &Header;
}
