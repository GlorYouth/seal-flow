//! High-level API for building and executing hybrid encryption operations.
//!
//! 用于构建和执行混合加密操作的高级 API。

use crate::algorithms::hybrid::HybridAlgorithmWrapper;
use crate::body::traits::FinishingWrite;
use crate::common::algorithms::SymmetricAlgorithm as SymmetricAlgorithmEnum;
use crate::common::config::ArcConfig;
use crate::common::header::{DerivationInfo, KdfInfo, XofInfo};
use crate::common::{DerivationSet, SignerSet};
use crate::error::KeyManagementError;
use crate::hybrid::config::HybridConfig;
use crate::hybrid::traits::{
    HybridAsynchronousProcessor, HybridOrdinaryProcessor, HybridParallelProcessor,
    HybridParallelStreamingProcessor, HybridStreamingProcessor,
};
use crate::keys::provider::EncryptionKeyProvider;
use crate::keys::{TypedAsymmetricPublicKey, TypedSignaturePrivateKey};
use crate::prelude::{KdfKeyAlgorithmEnum, XofAlgorithmEnum};
use crate::seal::traits::{
    AsyncStreamingEncryptor, InMemoryEncryptor, StreamingEncryptor as StreamingEncryptorTrait,
    WithAad, WithExtraData,
};
#[cfg(feature = "async")]
use async_trait::async_trait;
use std::borrow::Cow;
use std::io::{Read, Write};
use std::sync::Arc;
#[cfg(feature = "async")]
use tokio::io::AsyncWrite;

// --- Builder ---

/// A builder for hybrid encryption operations.
///
/// 混合加密操作的构建器。
pub struct HybridEncryptorBuilder {
    key_provider: Option<Arc<dyn EncryptionKeyProvider>>,
    config: ArcConfig,
}

impl HybridEncryptorBuilder {
    /// Creates a new `HybridEncryptorBuilder`.
    ///
    /// 创建一个新的 `HybridEncryptorBuilder`。
    pub fn new(config: ArcConfig) -> Self {
        Self {
            key_provider: None,
            config,
        }
    }

    /// Attaches an `EncryptionKeyProvider` to the builder.
    ///
    /// 将一个 `EncryptionKeyProvider` 附加到构建器上。
    pub fn with_key_provider(mut self, provider: Arc<dyn EncryptionKeyProvider>) -> Self {
        self.key_provider = Some(provider);
        self
    }

    /// Configures the encryptor with a recipient's public key provided directly.
    ///
    /// 使用直接提供的接收方公钥配置加密器。
    pub fn with_recipient(self, pk: TypedAsymmetricPublicKey, kek_id: String) -> HybridEncryptor {
        HybridEncryptor {
            pk,
            kek_id,
            aad: None,
            signer: None,
            derivation_config: None,
            extra_data: None,
            key_provider: self.key_provider,
            config: self.config,
        }
    }

    /// Configures the encryptor with a recipient's key ID.
    ///
    /// 使用接收方的密钥 ID 配置加密器。
    pub fn with_recipient_id(self, kek_id: &str) -> crate::Result<HybridEncryptor> {
        let provider = self
            .key_provider
            .as_ref()
            .ok_or(KeyManagementError::ProviderMissing)?;
        let pk = provider.get_asymmetric_public_key(kek_id)?;
        Ok(HybridEncryptor {
            pk,
            kek_id: kek_id.to_string(),
            aad: None,
            signer: None,
            derivation_config: None,
            extra_data: None,
            key_provider: self.key_provider,
            config: self.config,
        })
    }
}

// --- Encryptor Context ---

/// A context for hybrid encryption operations, allowing selection of execution mode.
///
/// 混合加密操作的上下文，允许选择执行模式。
pub struct HybridEncryptor {
    pub(crate) pk: TypedAsymmetricPublicKey,
    pub(crate) kek_id: String,
    pub(crate) aad: Option<Vec<u8>>,
    pub(crate) signer: Option<SignerSet>,
    pub(crate) derivation_config: Option<DerivationSet>,
    pub(crate) extra_data: Option<Vec<u8>>,
    key_provider: Option<Arc<dyn EncryptionKeyProvider>>,
    config: ArcConfig,
}

impl WithAad for HybridEncryptor {
    /// Sets the Associated Data (AAD) for this encryption operation.
    ///
    /// 为此加密操作设置关联数据 (AAD)。
    fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }
}

impl WithExtraData for HybridEncryptor {

    /// Sets the extra data for this encryption operation.
    ///
    /// 为此加密操作设置额外数据。
    fn with_extra_data(mut self, extra_data: impl Into<Vec<u8>>) -> Self {
        self.extra_data = Some(extra_data.into());
        self
    }
}

impl HybridEncryptor {
    /// Use a Key Derivation Function (KDF) to derive the Data Encryption Key (DEK).
    ///
    /// 使用密钥派生函数 (KDF) 派生数据加密密钥 (DEK)。
    pub fn with_kdf(
        mut self,
        algorithm: KdfKeyAlgorithmEnum,
        salt: Option<impl Into<Vec<u8>>>,
        info: Option<impl Into<Vec<u8>>>,
    ) -> Self {
        let salt = salt.map(|s| s.into());
        let info = info.map(|i| i.into());

        let kdf_info = KdfInfo {
            kdf_algorithm: algorithm.clone(),
            salt: salt.clone(),
            info: info.clone(),
        };
        use crate::common::DerivationWrapper;

        self.derivation_config = Some(DerivationSet {
            derivation_info: DerivationInfo::Kdf(kdf_info),
            wrapper: DerivationWrapper::Kdf(algorithm.into_kdf_key_wrapper()),
        });
        self
    }

    /// Use an Extendable-Output Function (XOF) to derive the Data Encryption Key (DEK).
    ///
    /// 使用可扩展输出函数 (XOF) 派生数据加密密钥 (DEK)。
    pub fn with_xof(
        mut self,
        algorithm: XofAlgorithmEnum,
        salt: Option<impl Into<Vec<u8>>>,
        info: Option<impl Into<Vec<u8>>>,
    ) -> Self {
        let salt = salt.map(|s| s.into());
        let info = info.map(|i| i.into());

        let xof_info = XofInfo {
            xof_algorithm: algorithm,
            salt: salt.clone(),
            info: info.clone(),
        };
        use crate::common::DerivationWrapper;

        self.derivation_config = Some(DerivationSet {
            derivation_info: DerivationInfo::Xof(xof_info),
            wrapper: DerivationWrapper::Xof(algorithm.into_xof_wrapper()),
        });
        self
    }

    /// Signs the encryption metadata (header) using a key resolved from the `EncryptionKeyProvider`.
    ///
    /// 使用从 `EncryptionKeyProvider` 解析的密钥对加密元数据（标头）进行签名。
    pub fn with_signer_id(mut self, signer_key_id: &str) -> crate::Result<Self> {
        let provider = self
            .key_provider
            .as_ref()
            .ok_or(KeyManagementError::ProviderMissing)?;
        let signing_key = provider.get_signing_private_key(signer_key_id)?;
        self.signer = Some(SignerSet {
            signer_key_id: signer_key_id.to_string(),
            signer: signing_key.algorithm().into_signature_wrapper(),
            signing_key: signing_key,
        });
        Ok(self)
    }

    /// Signs the encryption metadata (header) with the given private key.
    ///
    /// 使用给定的私钥对加密元数据（标头）进行签名。
    pub fn with_signer(
        mut self,
        signing_key: TypedSignaturePrivateKey,
        signer_key_id: String,
    ) -> crate::Result<Self> {
        self.signer = Some(SignerSet {
            signer_key_id,
            signer: signing_key.algorithm().into_signature_wrapper(),
            signing_key: signing_key,
        });
        Ok(self)
    }

    /// Configures the encryptor to use specific asymmetric and symmetric algorithms.
    ///
    /// 配置加密器以使用特定的对称算法。
    pub fn execute_with(self, symmetric: SymmetricAlgorithmEnum) -> HybridEncryptorWithAlgorithms {
        let asym_algo = self.pk.algorithm().into_asymmetric_wrapper();
        let sym_algo = symmetric.into_symmetric_wrapper();
        let algorithm = HybridAlgorithmWrapper::new(asym_algo, sym_algo);
        HybridEncryptorWithAlgorithms {
            algorithm,
            inner: self,
        }
    }
}

/// A hybrid encryptor that has been configured with specific algorithms.
///
/// 已配置特定算法的混合加密器。
pub struct HybridEncryptorWithAlgorithms {
    algorithm: HybridAlgorithmWrapper,
    inner: HybridEncryptor,
}

impl InMemoryEncryptor for HybridEncryptorWithAlgorithms {
    /// Encrypts the given plaintext in-memory.
    ///
    /// 在内存中加密给定的明文。
    fn to_vec(self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        let processor = crate::hybrid::ordinary::Ordinary::new();
        let pk = self.inner.pk;

        let config = HybridConfig {
            algorithm: Cow::Borrowed(&self.algorithm),
            public_key: Cow::Borrowed(&pk),
            kek_id: self.inner.kek_id,
            signer: self.inner.signer,
            aad: self.inner.aad,
            derivation_config: self.inner.derivation_config,
            extra_data: self.inner.extra_data,
            config: self.inner.config,
        };
        processor.encrypt_hybrid_in_memory(plaintext, config)
    }

    /// Encrypts the given plaintext in-memory using parallel processing.
    ///
    /// 使用并行处理在内存中加密给定的明文。
    fn to_vec_parallel(self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        let processor = crate::hybrid::parallel::Parallel::new();
        let pk = self.inner.pk;

        let config = HybridConfig {
            algorithm: Cow::Borrowed(&self.algorithm),
            public_key: Cow::Borrowed(&pk),
            kek_id: self.inner.kek_id,
            signer: self.inner.signer,
            aad: self.inner.aad,
            derivation_config: self.inner.derivation_config,
            extra_data: self.inner.extra_data,
            config: self.inner.config,
        };
        processor.encrypt_parallel(plaintext, config)
    }
}

impl StreamingEncryptorTrait for HybridEncryptorWithAlgorithms {
    /// Creates a streaming encryptor that wraps the given `Write` implementation.
    ///
    /// 创建一个包装了给定 `Write` 实现的流式加密器。
    fn into_writer<'a, W: Write + 'a>(
        self,
        writer: W,
    ) -> crate::Result<Box<dyn FinishingWrite + 'a>> {
        let processor = crate::hybrid::streaming::Streaming::new();
        let pk = self.inner.pk;

        let config = HybridConfig {
            algorithm: Cow::Owned(self.algorithm),
            public_key: Cow::Owned(pk),
            kek_id: self.inner.kek_id,
            signer: self.inner.signer,
            aad: self.inner.aad,
            derivation_config: self.inner.derivation_config,
            extra_data: self.inner.extra_data,
            config: self.inner.config,
        };
        processor.encrypt_hybrid_to_stream(Box::new(writer), config)
    }

    /// Encrypts data from a reader and writes to a writer using parallel processing.
    ///
    /// 使用并行处理从 reader 加密数据并写入 writer。
    fn pipe_parallel<R, W>(self, reader: R, writer: W) -> crate::Result<()>
    where
        R: Read + Send,
        W: Write + Send,
    {
        let processor = crate::hybrid::parallel_streaming::ParallelStreaming::new();
        let pk = self.inner.pk;
        let config = HybridConfig {
            algorithm: Cow::Borrowed(&self.algorithm),
            public_key: Cow::Borrowed(&pk),
            kek_id: self.inner.kek_id,
            signer: self.inner.signer,
            aad: self.inner.aad,
            derivation_config: self.inner.derivation_config,
            extra_data: self.inner.extra_data,
            config: self.inner.config,
        };
        processor.encrypt_hybrid_pipeline(Box::new(reader), Box::new(writer), config)
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl AsyncStreamingEncryptor for HybridEncryptorWithAlgorithms {
    /// Creates an asynchronous streaming encryptor that wraps the given `AsyncWrite` implementation.
    ///
    /// 创建一个包装了给定 `AsyncWrite` 实现的异步流式加密器。
    async fn into_async_writer<'a, W: AsyncWrite + Unpin + Send + 'a>(
        self,
        writer: W,
    ) -> crate::Result<Box<dyn AsyncWrite + Unpin + Send + 'a>> {
        let pk = self.inner.pk;
        let processor = crate::hybrid::asynchronous::Asynchronous::new();
        let config = HybridConfig {
            algorithm: Cow::Owned(self.algorithm),
            public_key: Cow::Owned(pk),
            kek_id: self.inner.kek_id,
            signer: self.inner.signer,
            aad: self.inner.aad,
            derivation_config: self.inner.derivation_config,
            extra_data: self.inner.extra_data,
            config: self.inner.config,
        };
        processor
            .encrypt_hybrid_async(Box::new(writer), config)
            .await
    }
}
