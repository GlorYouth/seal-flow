//! `seal-flow` is a stateless, high-level cryptographic workflow library
//! built on top of `seal-crypto`. It provides a unified, easy-to-use
//! interface for common cryptographic operations like hybrid encryption,
//! and supports multiple processing modes including one-shot (parallel),
//! streaming, and asynchronous.

// 模块声明
pub mod common;
pub mod hybrid;
pub mod error;
pub mod symmetric;

// 将核心类型提升到 Crate 根，方便使用
pub use error::{Error, Result};
pub use symmetric::{
    parallel::{symmetric_parallel_encrypt, symmetric_parallel_decrypt},
    streaming::{StreamingEncryptor, StreamingDecryptor},
    // 如果 async 特性开启，则导出异步类型
};
#[cfg(feature = "async")]
pub use symmetric::asynchronous::{AsyncStreamingEncryptor, AsyncStreamingDecryptor};
use crate::hybrid::ordinary::{hybrid_ordinary_decrypt, hybrid_ordinary_encrypt};
use seal_crypto::prelude::*;
use std::marker::PhantomData;
use seal_crypto::traits::kem::SharedSecret;
use crate::common::algorithms::{AsymmetricAlgorithm, SymmetricAlgorithm};

/// seal-flow 的主入口，使用建造者模式配置和执行加密/解密流程。
pub struct Flow;

impl Flow {
    /// 开始一个对称加密流程。
    pub fn new_symmetric<S: SymmetricEncryptor + 'static>(
        key: &S::Key,
        key_id: String,
        algorithm: SymmetricAlgorithm,
    ) -> SymmetricEncryptFlowBuilder<'_, S> {
        SymmetricEncryptFlowBuilder {
            key,
            key_id,
            algorithm,
        }
    }

    /// 开始一个混合加密流程的配置。
    pub fn new_hybrid<K, S>() -> HybridEncryptFlowBuilder<K, S>
    where
        K: Kem,
        S: SymmetricEncryptor<Key = SharedSecret>,
    {
        HybridEncryptFlowBuilder {
            _phantom: PhantomData,
        }
    }

    /// 开始一个解密流程。
    pub fn new_decryption() -> DecryptFlowBuilder {
        DecryptFlowBuilder
    }
}

// --- 各个 Builder 的定义 ---

/// 对称加密流程的建造者
pub struct SymmetricEncryptFlowBuilder<'a, S: SymmetricEncryptor> {
    key: &'a S::Key,
    key_id: String,
    algorithm: SymmetricAlgorithm,
}

impl<'a, S: SymmetricEncryptor> SymmetricEncryptFlowBuilder<'a, S> {
    /// 【一次性API】对内存中的数据进行并行加密。
    pub fn encrypt(self, plaintext: &[u8]) -> Result<Vec<u8>>
    where
        S: Sync,
        S::Key: Sync + Clone,
    {
        symmetric_parallel_encrypt::<S>(self.key, plaintext, self.key_id, self.algorithm)
    }

    /// 【流式API】返回一个配置好的 StreamingEncryptor。
    pub fn encrypt_to_writer<W: std::io::Write>(
        self,
        writer: W,
    ) -> Result<StreamingEncryptor<W, S>>
    where
        S::Key: Clone,
    {
        StreamingEncryptor::new(writer, self.key.clone(), self.key_id, self.algorithm)
    }

    /// 【异步流式API】返回一个配置好的 AsyncStreamingEncryptor。
    #[cfg(feature = "async")]
    pub async fn encrypt_to_async_writer<W: tokio::io::AsyncWrite + Unpin + Send>(
        self,
        writer: W,
    ) -> Result<AsyncStreamingEncryptor<W, S>>
    where
        S: Send + Sync,
        S::Key: Clone + Send + Sync,
    {
        AsyncStreamingEncryptor::new(writer, self.key.clone(), self.key_id, self.algorithm).await
    }
}

/// 混合加密流程的建造者
pub struct HybridEncryptFlowBuilder<K: Kem, S: SymmetricEncryptor> {
    _phantom: PhantomData<(K, S)>,
}

impl<K, S> HybridEncryptFlowBuilder<K, S>
where
    K: Kem<EncapsulatedKey = Vec<u8>>,
    S: SymmetricEncryptor<Key = SharedSecret> + SymmetricDecryptor,
{
    /// 【一次性API】执行混合加密。
    pub fn encrypt(
        self,
        pk: &K::PublicKey,
        plaintext: &[u8],
        kek_id: String,
        kek_algorithm: AsymmetricAlgorithm,
        dek_algorithm: SymmetricAlgorithm,
    ) -> Result<Vec<u8>> {
        hybrid_ordinary_encrypt::<K, S>(pk, plaintext, kek_id, kek_algorithm, dek_algorithm)
    }
}

/// 解密流程的建造者
pub struct DecryptFlowBuilder;

impl DecryptFlowBuilder {
    /// 提供对称解密所需的密钥。
    pub fn with_symmetric_key<S: SymmetricDecryptor + 'static>(
        self,
        key: &S::Key,
    ) -> DecryptExecutor<SymmetricDecryptionProvider<'_, S>> {
        DecryptExecutor {
            provider: SymmetricDecryptionProvider {
                key,
                _phantom: PhantomData,
            },
        }
    }

    /// 提供混合解密所需的私钥。
    pub fn with_asymmetric_key<K, S>(
        self,
        sk: &K::PrivateKey,
    ) -> DecryptExecutor<HybridDecryptionProvider<'_, K, S>>
    where
        K: Kem,
        S: SymmetricDecryptor<Key = SharedSecret>,
    {
        DecryptExecutor {
            provider: HybridDecryptionProvider {
                sk,
                _phantom: PhantomData,
            },
        }
    }
}

// --- Provider 结构体 ---
pub struct SymmetricDecryptionProvider<'a, S: SymmetricDecryptor> {
    key: &'a S::Key,
    _phantom: PhantomData<S>,
}
pub struct HybridDecryptionProvider<'a, K: Kem, S: SymmetricDecryptor> {
    sk: &'a K::PrivateKey,
    _phantom: PhantomData<(K, S)>,
}

/// 最终的解密执行器
pub struct DecryptExecutor<P> {
    provider: P,
}

// --- 为不同的 Provider 实现解密方法 ---
impl<'a, S: SymmetricDecryptor> DecryptExecutor<SymmetricDecryptionProvider<'a, S>> {
    /// 【一次性API】从内存中的密文解密。
    pub fn decrypt(self, ciphertext: &[u8]) -> Result<Vec<u8>>
    where
        S: Sync,
        S::Key: Sync + Clone,
    {
        symmetric_parallel_decrypt::<S>(self.provider.key, ciphertext)
    }

    /// 【流式API】从一个 reader 中解密数据。
    pub fn decrypt_from_reader<R: std::io::Read>(self, reader: R) -> Result<StreamingDecryptor<R, S>>
    where
        S::Key: Clone,
    {
        StreamingDecryptor::new(reader, self.provider.key.clone())
    }

    /// 【异步流式API】从一个 async reader 中解密数据。
    #[cfg(feature = "async")]
    pub async fn decrypt_from_async_reader<R: tokio::io::AsyncRead + Unpin>(
        self,
        reader: R,
    ) -> Result<AsyncStreamingDecryptor<R, S>>
    where
        S: Send + Sync,
        S::Key: Clone + Send + Sync,
    {
        AsyncStreamingDecryptor::new(reader, self.provider.key.clone()).await
    }
}

impl<'a, K, S> DecryptExecutor<HybridDecryptionProvider<'a, K, S>>
where
    K: Kem,
    S: SymmetricDecryptor<Key = SharedSecret> + SymmetricEncryptor,
{
    /// 【一次性API】从内存中的密文解密。
    pub fn decrypt(self, ciphertext: &[u8]) -> Result<Vec<u8>> 
    where <K as Kem>::EncapsulatedKey: From<Vec<u8>> {
        hybrid_ordinary_decrypt::<K, S>(self.provider.sk, ciphertext)
    }
}
