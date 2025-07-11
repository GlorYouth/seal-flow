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

    fn begin_decrypt_symmetric_in_memory(
        &self,
        ciphertext: &[u8],
    ) -> Result<Box<dyn SymmetricOrdinaryPendingDecryptor>>;
}

pub trait SymmetricOrdinaryPendingDecryptor {
    fn into_plaintext(
        self: Box<Self>,
        key: TypedSymmetricKey,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    fn header(&self) -> &Header;
}

pub trait SymmetricStreamingProcessor {
    fn encrypt_symmetric_to_stream(
        &self,
        algorithm: &SymmetricAlgorithmWrapper,
        key: TypedSymmetricKey,
        key_id: String,
        writer: Box<dyn Write>,
        aad: Option<&[u8]>,
    ) -> Result<Box<dyn Write>>;

    fn begin_decrypt_symmetric_from_stream(
        &self,
        reader: Box<dyn Read>,
    ) -> Result<Box<dyn SymmetricStreamingPendingDecryptor>>;
}

pub trait SymmetricStreamingPendingDecryptor {
    fn into_decryptor(
        self: Box<Self>,
        key: TypedSymmetricKey,
        aad: Option<&[u8]>,
    ) -> Result<Box<dyn Read>>;

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
    fn begin_decrypt_symmetric_parallel(
        &self,
        ciphertext: &[u8],
    ) -> Result<Box<dyn SymmetricParallelPendingDecryptor>>;
}

pub trait SymmetricParallelPendingDecryptor {
    fn into_plaintext(
        self: Box<Self>,
        key: TypedSymmetricKey,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    fn header(&self) -> &Header;
}

pub trait SymmetricParallelStreamingProcessor {
    fn encrypt_symmetric_pipeline(
        &self,
        algorithm: &SymmetricAlgorithmWrapper,
        key: TypedSymmetricKey,
        key_id: String,
        reader: Box<dyn Read + Send>,
        writer: Box<dyn Write + Send>,
        aad: Option<&[u8]>,
    ) -> Result<()>;

    fn begin_decrypt_symmetric_pipeline(
        &self,
        reader: Box<dyn Read + Send>,
    ) -> Result<Box<dyn SymmetricParallelStreamingPendingDecryptor>>;
}

pub trait SymmetricParallelStreamingPendingDecryptor {
    fn decrypt_to_writer(
        self: Box<Self>,
        key: TypedSymmetricKey,
        writer: Box<dyn Write + Send>,
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
        algorithm: &'a SymmetricAlgorithmWrapper,
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
    async fn into_decryptor<'a>(
        self: Box<Self>,
        key: TypedSymmetricKey,
        aad: Option<Vec<u8>>,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin + 'decr_life>>;

    fn header(&self) -> &Header;
}
