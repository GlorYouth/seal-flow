//! Defines the traits for different body processing modes.
//!
//! 定义不同消息体处理模式的 trait。

use crate::error::Result;
use crate::keys::TypedSymmetricKey;
use std::io::{Read, Write};

pub trait SymmetricOrdinaryProcessor {
    fn encrypt_in_memory(
        &self,
        key: TypedSymmetricKey,
        key_id: String,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
    fn decrypt_in_memory(
        &self,
        key: TypedSymmetricKey,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
}

pub trait SymmetricStreamingProcessor {
    fn encrypt_to_stream<'a>(
        &self,
        key: TypedSymmetricKey,
        key_id: String,
        writer: Box<dyn Write + 'a>,
        aad: Option<&[u8]>,
    ) -> Result<Box<dyn Write + 'a>>;

    fn decrypt_from_stream<'a>(
        &self,
        key: TypedSymmetricKey,
        reader: Box<dyn Read + 'a>,
        aad: Option<&[u8]>,
    ) -> Result<Box<dyn Read + 'a>>;
}

pub trait SymmetricParallelProcessor {
    fn encrypt_parallel(
        &self,
        key: TypedSymmetricKey,
        key_id: String,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
    fn decrypt_parallel(
        &self,
        key: TypedSymmetricKey,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
}

pub trait SymmetricParallelStreamingProcessor {
    fn encrypt_pipeline<'a>(
        &self,
        key: TypedSymmetricKey,
        key_id: String,
        reader: Box<dyn Read + Send + 'a>,
        writer: Box<dyn Write + Send + 'a>,
        aad: Option<&'a [u8]>,
    ) -> Result<()>;

    fn decrypt_pipeline<'a>(
        &self,
        key: TypedSymmetricKey,
        reader: Box<dyn Read + Send + 'a>,
        writer: Box<dyn Write + Send + 'a>,
        aad: Option<&'a [u8]>,
    ) -> Result<()>;
}

#[cfg(feature = "async")]
use async_trait::async_trait;

#[cfg(feature = "async")]
#[async_trait]
pub trait SymmetricAsynchronousProcessor {
    async fn encrypt_async<'a>(
        &self,
        key: TypedSymmetricKey,
        key_id: String,
        writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'a>,
        aad: Option<&'a [u8]>,
    ) -> Result<Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'a>>;

    async fn decrypt_async<'a>(
        &self,
        key: TypedSymmetricKey,
        reader: Box<dyn tokio::io::AsyncRead + Send + Unpin + 'a>,
        aad: Option<&'a [u8]>,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin + 'a>>;
}
