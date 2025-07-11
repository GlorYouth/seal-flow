//! Defines the high-level traits for hybrid encryption modes.
//!
//! 定义混合加密模式的高级 trait。

use crate::common::config::ArcConfig;
use crate::common::header::Header;
use crate::common::{DerivationSet, SignerSet};
use crate::error::Result;
use crate::hybrid::config::HybridConfig;
use crate::keys::{TypedAsymmetricPrivateKey, TypedAsymmetricPublicKey};
use std::io::{Read, Write};

/// Trait for ordinary (in-memory) hybrid encryption.
pub trait HybridOrdinaryProcessor {
    fn encrypt_hybrid_in_memory<'a>(
        &self,
        plaintext: &[u8],
        config: HybridConfig<'a>,
    ) -> Result<Vec<u8>>;

    fn begin_decrypt_hybrid_in_memory<'a>(
        &self,
        ciphertext: &'a [u8],
        config: ArcConfig,
    ) -> Result<Box<dyn HybridOrdinaryPendingDecryptor + 'a>>;
}

/// A pending decryptor for in-memory hybrid-encrypted data.
pub trait HybridOrdinaryPendingDecryptor {
    fn into_plaintext(
        self: Box<Self>,
        private_key: &TypedAsymmetricPrivateKey,
        aad: Option<Vec<u8>>,
    ) -> Result<Vec<u8>>;
    fn header(&self) -> &Header;
}

/// Trait for streaming hybrid encryption.
pub trait HybridStreamingProcessor {
    fn encrypt_hybrid_to_stream<'a>(
        &self,
        writer: Box<dyn Write + 'a>,
        config: HybridConfig<'a>,
    ) -> Result<Box<dyn Write + 'a>>;

    fn begin_decrypt_hybrid_from_stream<'a>(
        &self,
        reader: Box<dyn Read + 'a>,
        config: ArcConfig,
    ) -> Result<Box<dyn HybridStreamingPendingDecryptor<'a> + 'a>>;
}

/// A pending decryptor for streaming hybrid-encrypted data.
pub trait HybridStreamingPendingDecryptor<'a> {
    fn into_decryptor(
        self: Box<Self>,
        sk: &TypedAsymmetricPrivateKey,
        aad: Option<Vec<u8>>,
    ) -> Result<Box<dyn Read + 'a>>;

    fn header(&self) -> &Header;
}

/// Trait for parallel in-memory hybrid encryption.
pub trait HybridParallelProcessor {
    fn encrypt_parallel<'a>(&self, plaintext: &[u8], config: HybridConfig<'a>) -> Result<Vec<u8>>;

    fn begin_decrypt_hybrid_parallel<'a>(
        &self,
        ciphertext: &'a [u8],
        config: ArcConfig,
    ) -> Result<Box<dyn HybridParallelPendingDecryptor + 'a>>;
}

/// A pending decryptor for parallel in-memory hybrid-encrypted data.
pub trait HybridParallelPendingDecryptor {
    fn into_plaintext(
        self: Box<Self>,
        private_key: &TypedAsymmetricPrivateKey,
        aad: Option<Vec<u8>>,
    ) -> Result<Vec<u8>>;
    fn header(&self) -> &Header;
}

/// Trait for parallel streaming hybrid encryption.
pub trait HybridParallelStreamingProcessor {
    fn encrypt_hybrid_pipeline<'a>(
        &self,
        reader: Box<dyn Read + Send + 'a>,
        writer: Box<dyn Write + Send + 'a>,
        config: HybridConfig<'a>,
    ) -> Result<()>;

    fn begin_decrypt_hybrid_pipeline<'a>(
        &self,
        reader: Box<dyn Read + Send + 'a>,
        config: ArcConfig,
    ) -> Result<Box<dyn HybridParallelStreamingPendingDecryptor<'a> + 'a>>;
}

/// A pending decryptor for parallel streaming hybrid-encrypted data.
pub trait HybridParallelStreamingPendingDecryptor<'a> {
    fn decrypt_to_writer(
        self: Box<Self>,
        private_key: &TypedAsymmetricPrivateKey,
        writer: Box<dyn Write + Send + 'a>,
        aad: Option<Vec<u8>>,
    ) -> Result<()>;
    fn header(&self) -> &Header;
}

/// Trait for asynchronous hybrid encryption.
#[cfg(feature = "async")]
use async_trait::async_trait;

#[cfg(feature = "async")]
#[async_trait]
pub trait HybridAsynchronousProcessor {
    async fn encrypt_hybrid_async<'a>(
        &self,
        writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'a>,
        config: HybridConfig<'a>,
    ) -> Result<Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'a>>;

    async fn begin_decrypt_hybrid_async<'a>(
        &self,
        reader: Box<dyn tokio::io::AsyncRead + Send + Unpin + 'a>,
        config: ArcConfig,
    ) -> Result<Box<dyn HybridAsynchronousPendingDecryptor<'a> + Send + 'a>>;
}

/// A pending decryptor for asynchronous hybrid-encrypted data.
#[cfg(feature = "async")]
#[async_trait]
pub trait HybridAsynchronousPendingDecryptor<'decr_life>: Send {
    async fn into_decryptor<'a>(
        self: Box<Self>,
        private_key: &'a TypedAsymmetricPrivateKey,
        aad: Option<Vec<u8>>,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin + 'decr_life>>;
    fn header(&self) -> &Header;
}
