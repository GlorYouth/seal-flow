//! Defines the high-level traits for hybrid encryption modes.
//!
//! 定义混合加密模式的高级 trait。

use crate::common::header::Header;
use crate::common::{DerivationSet, SignerSet};
use crate::error::Result;
use crate::keys::TypedAsymmetricPrivateKey;
use crate::keys::TypedAsymmetricPublicKey;
use std::future::Future;
use std::io::{Read, Write};

/// Trait for ordinary (in-memory) hybrid encryption.
pub trait HybridOrdinaryProcessor {
    fn encrypt_hybrid_in_memory(
        &self,
        public_key: &TypedAsymmetricPublicKey,
        plaintext: &[u8],
        kek_id: String,
        signer: Option<SignerSet>,
        aad: Option<&[u8]>,
        derivation_config: Option<DerivationSet>,
    ) -> Result<Vec<u8>>;

    fn begin_decrypt_hybrid_in_memory<'a, 'p>(
        &'p self,
        ciphertext: &'a [u8],
    ) -> Result<Box<dyn HybridOrdinaryPendingDecryptor<'a> + 'a>>
    where
        'p: 'a;
}

/// A pending decryptor for in-memory hybrid-encrypted data.
pub trait HybridOrdinaryPendingDecryptor<'a> {
    fn into_plaintext(
        self: Box<Self>,
        private_key: &TypedAsymmetricPrivateKey,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
    fn header(&self) -> &Header;
}

/// Trait for streaming hybrid encryption.
pub trait HybridStreamingProcessor {
    fn encrypt_hybrid_to_stream<'a>(
        &self,
        public_key: &TypedAsymmetricPublicKey,
        writer: Box<dyn Write + 'a>,
        kek_id: String,
        signer: Option<SignerSet>,
        aad: Option<&'a [u8]>,
        derivation_config: Option<DerivationSet>,
    ) -> Result<Box<dyn Write + 'a>>;

    fn begin_decrypt_hybrid_from_stream<'a, 'p, R>(
        &'p self,
        reader: R,
    ) -> Result<Box<dyn HybridStreamingPendingDecryptor<'a, R> + 'a>>
    where
        R: Read + 'a,
        'p: 'a;
}

/// A pending decryptor for streaming hybrid-encrypted data.
pub trait HybridStreamingPendingDecryptor<'a, R: Read> {
    fn into_decryptor(
        self: Box<Self>,
        private_key: &TypedAsymmetricPrivateKey,
        aad: Option<&'a [u8]>,
    ) -> Result<Box<dyn Read + 'a>>;
    fn header(&self) -> &Header;
}

/// Trait for parallel in-memory hybrid encryption.
pub trait HybridParallelProcessor {
    fn encrypt_parallel(
        &self,
        public_key: &TypedAsymmetricPublicKey,
        plaintext: &[u8],
        kek_id: String,
        signer: Option<SignerSet>,
        aad: Option<&[u8]>,
        derivation_config: Option<DerivationSet>,
    ) -> Result<Vec<u8>>;

    fn begin_decrypt_hybrid_parallel<'a, 'p>(
        &'p self,
        ciphertext: &'a [u8],
    ) -> Result<Box<dyn HybridParallelPendingDecryptor<'a> + 'a>>
    where
        'p: 'a;
}

/// A pending decryptor for parallel in-memory hybrid-encrypted data.
pub trait HybridParallelPendingDecryptor<'a> {
    fn into_plaintext(
        self: Box<Self>,
        private_key: &TypedAsymmetricPrivateKey,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
    fn header(&self) -> &Header;
}

/// Trait for parallel streaming hybrid encryption.
pub trait HybridParallelStreamingProcessor {
    fn encrypt_hybrid_pipeline<'a>(
        &self,
        public_key: &TypedAsymmetricPublicKey,
        reader: Box<dyn Read + Send + 'a>,
        writer: Box<dyn Write + Send + 'a>,
        kek_id: String,
        signer: Option<SignerSet>,
        aad: Option<&'a [u8]>,
        derivation_config: Option<DerivationSet>,
    ) -> Result<()>;

    fn begin_decrypt_hybrid_pipeline<'a, 'p, R>(
        &'p self,
        reader: R,
    ) -> Result<Box<dyn HybridParallelStreamingPendingDecryptor<'a, R> + 'a>>
    where
        R: Read + Send + 'a,
        'p: 'a;
}

/// A pending decryptor for parallel streaming hybrid-encrypted data.
pub trait HybridParallelStreamingPendingDecryptor<'a, R: Read + Send> {
    fn decrypt_to_writer(
        self: Box<Self>,
        private_key: &TypedAsymmetricPrivateKey,
        writer: Box<dyn Write + Send + 'a>,
        aad: Option<&'a [u8]>,
    ) -> Result<()>;
    fn header(&self) -> &Header;
}

/// Trait for asynchronous hybrid encryption.
#[cfg(feature = "async")]
pub trait HybridAsynchronousProcessor {
    fn encrypt_hybrid_async<'a>(
        &self,
        public_key: &TypedAsymmetricPublicKey,
        writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'a>,
        kek_id: String,
        signer: Option<SignerSet>,
        aad: Option<&'a [u8]>,
        derivation_config: Option<DerivationSet>,
    ) -> Result<Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'a>>;

    fn begin_decrypt_hybrid_async<'a, 'p, R>(
        &'p self,
        reader: R,
    ) -> impl Future<Output = Result<Box<dyn HybridAsynchronousPendingDecryptor<'a, R> + 'a>>> + Send
    where
        R: tokio::io::AsyncRead + Send + Unpin + 'a,
        'p: 'a;
}

/// A pending decryptor for asynchronous hybrid-encrypted data.
#[cfg(feature = "async")]
pub trait HybridAsynchronousPendingDecryptor<'a, R: tokio::io::AsyncRead + Send + Unpin> {
    fn into_decryptor(
        self: Box<Self>,
        private_key: &TypedAsymmetricPrivateKey,
        aad: Option<&[u8]>,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin + 'a>>;
    fn header(&self) -> &Header;
}
