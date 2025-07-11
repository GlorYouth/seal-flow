//! Defines the traits for different body processing modes.
//!
//! 定义不同消息体处理模式的 trait。

#[cfg(feature = "async")]
use crate::algorithms::symmetric::SymmetricAlgorithmWrapper;
use crate::common::header::Header;
use crate::error::Result;
use crate::keys::TypedSymmetricKey;
use std::io::{Read, Write};

pub trait SymmetricOrdinaryProcessor {
    fn encrypt_symmetric_in_memory(
        &self,
        algorithm: &SymmetricAlgorithmWrapper,
        key: TypedSymmetricKey,
        key_id: String,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    fn begin_decrypt_symmetric_in_memory<'a>(
        &self,
        ciphertext: &'a [u8],
    ) -> Result<Box<dyn SymmetricOrdinaryPendingDecryptor<'a> + 'a>>;
}

pub trait SymmetricOrdinaryPendingDecryptor<'a> {
    fn into_plaintext(
        self: Box<Self>,
        key: TypedSymmetricKey,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    fn header(&self) -> &Header;
}

pub trait SymmetricStreamingProcessor {
    fn encrypt_symmetric_to_stream<'a>(
        &self,
        algorithm: &SymmetricAlgorithmWrapper,
        key: TypedSymmetricKey,
        key_id: String,
        writer: Box<dyn Write + 'a>,
        aad: Option<&[u8]>,
    ) -> Result<Box<dyn Write + 'a>>;

    fn begin_decrypt_symmetric_from_stream<'a>(
        &self,
        reader: Box<dyn Read + 'a>,
    ) -> Result<Box<dyn SymmetricStreamingPendingDecryptor<'a> + 'a>>;
}

pub trait SymmetricStreamingPendingDecryptor<'a> {
    fn into_decryptor(
        self: Box<Self>,
        key: TypedSymmetricKey,
        aad: Option<&[u8]>,
    ) -> Result<Box<dyn Read + 'a>>;

    fn header(&self) -> &Header;
}

pub trait SymmetricParallelProcessor {
    fn encrypt_symmetric_parallel(
        &self,
        algorithm: &SymmetricAlgorithmWrapper,
        key: TypedSymmetricKey,
        key_id: String,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
    fn begin_decrypt_symmetric_parallel<'a>(
        &self,
        ciphertext: &'a [u8],
    ) -> Result<Box<dyn SymmetricParallelPendingDecryptor<'a> + 'a>>;
}

pub trait SymmetricParallelPendingDecryptor<'a> {
    fn into_plaintext(
        self: Box<Self>,
        key: TypedSymmetricKey,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    fn header(&self) -> &Header;
}

pub trait SymmetricParallelStreamingProcessor {
    fn encrypt_symmetric_pipeline<'a, 'b>(
        &self,
        algorithm: &SymmetricAlgorithmWrapper,
        key: TypedSymmetricKey,
        key_id: String,
        reader: Box<dyn Read + Send + 'a>,
        writer: Box<dyn Write + Send + 'a>,
        aad: Option<&'b [u8]>,
    ) -> Result<()>;

    fn begin_decrypt_symmetric_pipeline<'a>(
        &self,
        reader: Box<dyn Read + Send + 'a>,
    ) -> Result<Box<dyn SymmetricParallelStreamingPendingDecryptor<'a> + 'a>>;
}

pub trait SymmetricParallelStreamingPendingDecryptor<'a> {
    fn decrypt_to_writer(
        self: Box<Self>,
        key: TypedSymmetricKey,
        writer: Box<dyn Write + Send + 'a>,
        aad: Option<&[u8]>,
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
        algorithm: & SymmetricAlgorithmWrapper,
        key: TypedSymmetricKey,
        key_id: String,
        writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'a>,
        aad: Option<Vec<u8>>,
    ) -> Result<Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'a>>;

    async fn begin_decrypt_symmetric_async<'a>(
        &self,
        reader: Box<dyn tokio::io::AsyncRead + Send + Unpin + 'a>,
    ) -> Result<Box<dyn SymmetricAsynchronousPendingDecryptor<'a> + Send + 'a>>;
}

#[cfg(feature = "async")]
#[async_trait]
pub trait SymmetricAsynchronousPendingDecryptor<'decr_life>: Send {
    async fn into_decryptor(
        self: Box<Self>,
        key: TypedSymmetricKey,
        aad: Option<Vec<u8>>,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin + 'decr_life>>;

    fn header(&self) -> &Header;
}
