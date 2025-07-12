//! This module provides pre-configured, easy-to-use algorithm suites for hybrid encryption.
//!
//! 该模块为混合加密提供了预先配置、易于使用的算法套件。
use std::io::{Read, Write};
use std::sync::Arc;
#[cfg(feature = "async")]
use tokio::io::AsyncWrite;

use crate::algorithms::traits::SignatureAlgorithm;
use crate::common::algorithms::{
    AsymmetricAlgorithm as AsymmetricAlgorithmEnum, SymmetricAlgorithm as SymmetricAlgorithmEnum,
};
use crate::common::config::ArcConfig;
use crate::keys::provider::EncryptionKeyProvider;
use crate::keys::{AsymmetricPrivateKey, AsymmetricPublicKey};
use crate::body::traits::FinishingWrite;
use crate::seal::traits::{
    AsyncStreamingEncryptor, InMemoryEncryptor, StreamingEncryptor, WithAad,
};
#[cfg(feature = "async")]
use async_trait::async_trait;

use super::encryptor::{HybridEncryptor, HybridEncryptorBuilder};

/// The recommended Key Encapsulation Mechanism for the Post-Quantum Cryptography (PQC) suite.
///
/// 后量子密码学 (PQC) 套件推荐的密钥封装机制。
pub const PQC_KEM_ALGORITHM: AsymmetricAlgorithmEnum = AsymmetricAlgorithmEnum::Kyber768;
/// The recommended Data Encapsulation Mechanism for the Post-Quantum Cryptography (PQC) suite.
///
/// 后量子密码学 (PQC) 套件推荐的数据封装机制。
pub const PQC_DEM_ALGORITHM: SymmetricAlgorithmEnum = SymmetricAlgorithmEnum::Aes256Gcm;

/// A builder for the PQC suite encryptor.
///
/// This builder provides a simplified API for creating a PQC-suite-based
/// encryptor, allowing for configuration via a key provider or direct keying.
///
/// PQC 套件加密器的构建器。
///
/// 此构建器提供了一个简化的 API，用于创建基于 PQC 套件的加密器，
/// 允许通过密钥提供程序或直接提供密钥进行配置。
pub struct PqcEncryptorBuilder {
    inner: HybridEncryptorBuilder,
}

impl PqcEncryptorBuilder {
    /// Creates a new PQC encryptor builder.
    ///
    /// 创建一个新的 PQC 加密器构建器。
    pub(crate) fn new(config: ArcConfig) -> Self {
        Self {
            inner: HybridEncryptorBuilder::new(config),
        }
    }

    /// Attaches an `EncryptionKeyProvider` to the builder.
    ///
    /// 将一个 `EncryptionKeyProvider` 附加到构建器上。
    pub fn with_key_provider(self, provider: Arc<dyn EncryptionKeyProvider>) -> Self {
        Self {
            inner: self.inner.with_key_provider(provider),
        }
    }

    /// Configures the encryptor with a recipient's public key provided directly.
    ///
    /// 使用直接提供的接收方公钥配置加密器。
    pub fn with_recipient(self, pk: AsymmetricPublicKey, kek_id: String) -> PqcEncryptor {
        PqcEncryptor {
            inner: self.inner.with_recipient(pk, kek_id),
        }
    }

    /// Configures the encryptor with a recipient's key ID.
    ///
    /// 使用接收方的密钥 ID 配置加密器。
    pub fn with_recipient_id(self, kek_id: &str) -> crate::Result<PqcEncryptor> {
        self.inner
            .with_recipient_id(kek_id)
            .map(|encryptor| PqcEncryptor { inner: encryptor })
    }
}

/// An encryptor specifically configured for the recommended Post-Quantum Cryptography (PQC) suite.
///
/// This struct simplifies the encryption process by pre-selecting `Kyber768` as the KEM
/// and `Aes256Gcm` as the DEK. It exposes a familiar builder-like API for setting
/// options like AAD and signers, without requiring the user to specify algorithm generics.
///
/// 一个专为推荐的后量子密码学 (PQC) 套件配置的加密器。
///
/// 该结构通过预先选择 `Kyber768` 作为 KEM 和 `Aes256Gcm` 作为 DEK 来简化加密过程。
/// 它提供了一个熟悉的、类似构建器的 API 来设置选项，如 AAD 和签名者，而无需用户指定算法泛型。
pub struct PqcEncryptor {
    inner: HybridEncryptor,
}

impl WithAad for PqcEncryptor {
    fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.inner = self.inner.with_aad(aad);
        self
    }
}

impl PqcEncryptor {
    /// Use a Key Derivation Function (KDF) to derive the Data Encryption Key (DEK).
    ///
    /// 使用密钥派生函数 (KDF) 派生数据加密密钥 (DEK)。
    pub fn with_kdf<Kdf>(
        mut self,
        deriver: Kdf,
        salt: Option<impl Into<Vec<u8>>>,
        info: Option<impl Into<Vec<u8>>>,
        output_len: u32,
    ) -> Self
    where
        Kdf: crate::algorithms::traits::KdfAlgorithm + 'static,
    {
        self.inner = self.inner.with_kdf(deriver, salt, info, output_len);
        self
    }

    /// Use an Extendable-Output Function (XOF) to derive the Data Encryption Key (DEK).
    ///
    /// 使用可扩展输出函数 (XOF) 派生数据加密密钥 (DEK)。
    pub fn with_xof<Xof>(
        mut self,
        deriver: Xof,
        salt: Option<impl Into<Vec<u8>>>,
        info: Option<impl Into<Vec<u8>>>,
        output_len: u32,
    ) -> Self
    where
        Xof: crate::algorithms::traits::XofAlgorithm,
    {
        self.inner = self.inner.with_xof(deriver, salt, info, output_len);
        self
    }

    /// Signs the encryption metadata (header) with the given private key.
    ///
    /// 使用给定的私钥对加密元数据（标头）进行签名。
    pub fn with_signer<SignerAlgo>(
        mut self,
        signing_key: AsymmetricPrivateKey,
        signer_key_id: String,
    ) -> Self
    where
        SignerAlgo: SignatureAlgorithm,
    {
        self.inner = self
            .inner
            .with_signer::<SignerAlgo>(signing_key, signer_key_id);
        self
    }

    /// Signs the encryption metadata (header) using a key resolved from the `EncryptionKeyProvider`.
    ///
    /// 使用从 `EncryptionKeyProvider` 解析的密钥对加密元数据（标头）进行签名。
    pub fn with_signer_id<SignerAlgo>(self, signer_key_id: &str) -> crate::Result<Self>
    where
        SignerAlgo: SignatureAlgorithm,
    {
        self.inner
            .with_signer_id::<SignerAlgo>(signer_key_id)
            .map(|encryptor| Self { inner: encryptor })
    }
}

impl InMemoryEncryptor for PqcEncryptor {
    /// Encrypts the given plaintext in-memory using the PQC suite.
    ///
    /// 使用 PQC 套件在内存中加密给定的明文。
    fn to_vec(self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        self.inner
            .execute_with(PQC_KEM_ALGORITHM, PQC_DEM_ALGORITHM)
            .to_vec(plaintext)
    }

    /// Encrypts the given plaintext in-memory using parallel processing with the PQC suite.
    ///
    /// 使用 PQC 套件通过并行处理在内存中加密给定的明文。
    fn to_vec_parallel(self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        self.inner
            .execute_with(PQC_KEM_ALGORITHM, PQC_DEM_ALGORITHM)
            .to_vec_parallel(plaintext)
    }
}

impl StreamingEncryptor for PqcEncryptor {
    /// Encrypts data from a reader and writes to a writer using parallel processing with the PQC suite.
    ///
    /// 使用 PQC 套件通过并行处理从 reader 加密数据并写入 writer。
    fn pipe_parallel<R, W>(self, reader: R, writer: W) -> crate::Result<()>
    where
        R: Read + Send,
        W: Write + Send,
    {
        self.inner
            .execute_with(PQC_KEM_ALGORITHM, PQC_DEM_ALGORITHM)
            .pipe_parallel(reader, writer)
    }

    fn into_writer<'a, W: Write + 'a>(
        self,
        writer: W,
    ) -> crate::Result<Box<dyn FinishingWrite + 'a>> {
        self.inner
            .execute_with(PQC_KEM_ALGORITHM, PQC_DEM_ALGORITHM)
            .into_writer(writer)
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl AsyncStreamingEncryptor for PqcEncryptor {
    /// Creates an asynchronous streaming encryptor that writes to the given `AsyncWrite` implementation using the PQC suite.
    ///
    /// 使用 PQC 套件创建一个异步流式加密器，该加密器写入给定的 `AsyncWrite` 实现。
    async fn into_async_writer<'a, W: AsyncWrite + Unpin + Send + 'a>(
        self,
        writer: W,
    ) -> crate::Result<Box<dyn AsyncWrite + Unpin + Send + 'a>> {
        self.inner
            .execute_with(PQC_KEM_ALGORITHM, PQC_DEM_ALGORITHM)
            .into_async_writer(writer)
            .await
    }
}
