//! Defines the high-level traits for hybrid encryption modes.
//!
//! 定义混合加密模式的高级 trait。

use crate::common::header::Header;
use crate::common::{DerivationSet, SignerSet};
use crate::error::Result;
use crate::keys::{TypedAsymmetricPrivateKey, TypedAsymmetricPublicKey};
use crate::algorithms::hybrid::HybridAlgorithmWrapper;
use std::io::{Read, Write};

/// Trait for ordinary (in-memory) hybrid encryption.
pub trait HybridOrdinaryProcessor {
    fn encrypt_hybrid_in_memory(
        &self,
        algorithm: HybridAlgorithmWrapper,
        public_key: &TypedAsymmetricPublicKey,
        plaintext: &[u8],
        kek_id: String,
        signer: Option<SignerSet>,
        aad: Option<&[u8]>,
        derivation_config: Option<DerivationSet>,
    ) -> Result<Vec<u8>>;

    fn begin_decrypt_hybrid_in_memory(
        &self,
        ciphertext: &[u8],
    ) -> Result<Box<dyn HybridOrdinaryPendingDecryptor>>;
}

/// A pending decryptor for in-memory hybrid-encrypted data.
pub trait HybridOrdinaryPendingDecryptor {
    fn into_plaintext(
        self: Box<Self>,
        private_key: &TypedAsymmetricPrivateKey,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
    fn header(&self) -> &Header;
}

/// Trait for streaming hybrid encryption.
pub trait HybridStreamingProcessor {
    fn encrypt_hybrid_to_stream(
        &self,
        algorithm: &HybridAlgorithmWrapper,
        public_key: &TypedAsymmetricPublicKey,
        writer: Box<dyn Write>,
        kek_id: String,
        signer: Option<SignerSet>,
        aad: Option<&[u8]>,
        derivation_config: Option<DerivationSet>,
    ) -> Result<Box<dyn Write>>;

    fn begin_decrypt_hybrid_from_stream(
        &self,
        reader: Box<dyn Read>,
    ) -> Result<Box<dyn HybridStreamingPendingDecryptor>>;
}

/// A pending decryptor for streaming hybrid-encrypted data.
pub trait HybridStreamingPendingDecryptor {
    fn into_decryptor(
        self: Box<Self>,
        private_key: &TypedAsymmetricPrivateKey,
        aad: Option<&[u8]>,
    ) -> Result<Box<dyn Read>>;
    fn header(&self) -> &Header;
}

/// Trait for parallel in-memory hybrid encryption.
pub trait HybridParallelProcessor {
    fn encrypt_parallel(
        &self,
        algorithm: &HybridAlgorithmWrapper,
        public_key: &TypedAsymmetricPublicKey,
        plaintext: &[u8],
        kek_id: String,
        signer: Option<SignerSet>,
        aad: Option<&[u8]>,
        derivation_config: Option<DerivationSet>,
    ) -> Result<Vec<u8>>;

    fn begin_decrypt_hybrid_parallel(
        &self,
        ciphertext: &[u8],
    ) -> Result<Box<dyn HybridParallelPendingDecryptor>>;
}

/// A pending decryptor for parallel in-memory hybrid-encrypted data.
pub trait HybridParallelPendingDecryptor {
    fn into_plaintext(
        self: Box<Self>,
        private_key: &TypedAsymmetricPrivateKey,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
    fn header(&self) -> &Header;
}

/// Trait for parallel streaming hybrid encryption.
pub trait HybridParallelStreamingProcessor {
    fn encrypt_hybrid_pipeline(
        &self,
        algorithm: &HybridAlgorithmWrapper,
        public_key: &TypedAsymmetricPublicKey,
        reader: Box<dyn Read + Send>,
        writer: Box<dyn Write + Send>,
        kek_id: String,
        signer: Option<SignerSet>,
        aad: Option<&[u8]>,
        derivation_config: Option<DerivationSet>,
    ) -> Result<()>;

    fn begin_decrypt_hybrid_pipeline(
        &self,
        reader: Box<dyn Read + Send>,
    ) -> Result<Box<dyn HybridParallelStreamingPendingDecryptor>>;
}

/// A pending decryptor for parallel streaming hybrid-encrypted data.
pub trait HybridParallelStreamingPendingDecryptor {
    fn decrypt_to_writer(
        self: Box<Self>,
        private_key: &TypedAsymmetricPrivateKey,
        writer: Box<dyn Write + Send>,
        aad: Option<&[u8]>,
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
        algorithm: &HybridAlgorithmWrapper,
        public_key: &TypedAsymmetricPublicKey,
        writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'a>,
        kek_id: String,
        signer: Option<SignerSet>,
        aad: Option<Vec<u8>>,
        derivation_config: Option<DerivationSet>,
    ) -> Result<Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'a>>;

    async fn begin_decrypt_hybrid_async<'a>(
        &self,
        reader: Box<dyn tokio::io::AsyncRead + Send + Unpin + 'a>,
    ) -> Result<Box<dyn HybridAsynchronousPendingDecryptor<'a> + Send + 'a>>;
}

/// A pending decryptor for asynchronous hybrid-encrypted data.
#[cfg(feature = "async")]
#[async_trait]
pub trait HybridAsynchronousPendingDecryptor<'decr_life>: Send {
    async fn into_decryptor<'a>(
        self: Box<Self>,
        private_key: &'a TypedAsymmetricPrivateKey,
        aad: Option<&'a [u8]>,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin + 'decr_life>>;
    fn header(&self) -> &Header;
}
