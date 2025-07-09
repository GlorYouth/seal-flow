//! Defines the traits for different body processing modes.
//!
//! 定义不同消息体处理模式的 trait。

use crate::error::Result;
use crate::keys::TypedSymmetricKey;
use std::io::{Read, Write};

pub trait OrdinaryBodyProcessor {
    fn encrypt_in_memory(
        &self,
        key: TypedSymmetricKey,
        nonce: &[u8; 12],
        header_bytes: Vec<u8>,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
    fn decrypt_in_memory(
        &self,
        key: TypedSymmetricKey,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
}

pub trait StreamingBodyProcessor {
    fn encrypt_to_stream<'a>(
        &self,
        key: TypedSymmetricKey,
        base_nonce: [u8; 12],
        writer: Box<dyn Write + 'a>,
        aad: Option<&[u8]>,
    ) -> Result<Box<dyn Write + 'a>>;

    fn decrypt_from_stream<'a>(
        &self,
        key: TypedSymmetricKey,
        base_nonce: [u8; 12],
        reader: Box<dyn Read + 'a>,
        aad: Option<&[u8]>,
    ) -> Result<Box<dyn Read + 'a>>;
}

pub trait ParallelBodyProcessor {
    fn encrypt_parallel(
        &self,
        key: TypedSymmetricKey,
        base_nonce: &[u8; 12],
        header_bytes: Vec<u8>,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
    fn decrypt_parallel(
        &self,
        key: TypedSymmetricKey,
        base_nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
}

pub trait ParallelStreamingBodyProcessor {
    fn encrypt_pipeline<'a>(
        &self,
        key: TypedSymmetricKey,
        base_nonce: [u8; 12],
        reader: Box<dyn Read + Send + 'a>,
        writer: Box<dyn Write + Send + 'a>,
        aad: Option<&'a [u8]>,
    ) -> Result<()>;
    fn decrypt_pipeline<'a>(
        &self,
        key: TypedSymmetricKey,
        base_nonce: [u8; 12],
        reader: Box<dyn Read + Send + 'a>,
        writer: Box<dyn Write + Send + 'a>,
        aad: Option<&'a [u8]>,
    ) -> Result<()>;
}

#[cfg(feature = "async")]
pub trait AsynchronousBodyProcessor {
    fn encrypt_async<'a>(
        &self,
        key: TypedSymmetricKey,
        base_nonce: [u8; 12],
        writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'a>,
        aad: Option<&'a [u8]>,
    ) -> Result<Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'a>>;

    fn decrypt_async<'a>(
        &self,
        key: TypedSymmetricKey,
        base_nonce: [u8; 12],
        reader: Box<dyn tokio::io::AsyncRead + Send + Unpin + 'a>,
        aad: Option<&'a [u8]>,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin + 'a>>;
}
