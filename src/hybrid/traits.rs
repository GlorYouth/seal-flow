//! Defines the high-level traits for hybrid encryption modes.
//!
//! 定义混合加密模式的高级 trait。

use crate::common::{DerivationSet, SignerSet};
use crate::error::Result;
use crate::keys::TypedAsymmetricPrivateKey;
use crate::keys::TypedAsymmetricPublicKey;
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

    fn decrypt_hybrid_in_memory(
        &self,
        private_key: &TypedAsymmetricPrivateKey,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
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

    fn decrypt_hybrid_from_stream<'a>(
        &self,
        private_key: &TypedAsymmetricPrivateKey,
        reader: Box<dyn Read + 'a>,
        aad: Option<&'a [u8]>,
    ) -> Result<Box<dyn Read + 'a>>;
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

    fn decrypt_hybrid_parallel(
        &self,
        private_key: &TypedAsymmetricPrivateKey,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
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

    fn decrypt_hybrid_pipeline<'a>(
        &self,
        private_key: &TypedAsymmetricPrivateKey,
        reader: Box<dyn Read + Send + 'a>,
        writer: Box<dyn Write + Send + 'a>,
        aad: Option<&'a [u8]>,
    ) -> Result<()>;
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

    fn decrypt_hybrid_async<'a>(
        &self,
        private_key: &TypedAsymmetricPrivateKey,
        reader: Box<dyn tokio::io::AsyncRead + Send + Unpin + 'a>,
        aad: Option<&'a [u8]>,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin + 'a>>;
}
