//! This module provides pre-configured, easy-to-use algorithm suites for hybrid encryption.
//!
//! 该模块为混合加密提供了预先配置、易于使用的算法套件。
use std::io::{Read, Write};

use seal_crypto::{
    schemes::{asymmetric::post_quantum::kyber::Kyber768, symmetric::aes_gcm::Aes256Gcm}
};

use crate::keys::AsymmetricPublicKey;
use super::encryptor::HybridEncryptor;
use super::HybridEncryptionOptions;

/// The recommended Key Encapsulation Mechanism for the Post-Quantum Cryptography (PQC) suite.
///
/// 后量子密码学 (PQC) 套件推荐的密钥封装机制。
pub type PqcKem = Kyber768;
/// The recommended Data Encapsulation Mechanism for the Post-Quantum Cryptography (PQC) suite.
///
/// 后量子密码学 (PQC) 套件推荐的数据封装机制。
pub type PqcDek = Aes256Gcm;

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
    inner: HybridEncryptor<PqcDek>,
}

impl PqcEncryptor {
    /// Creates a new PQC encryptor. This is typically called from `HybridSeal::encrypt_pqc_suite`.
    ///
    /// 创建一个新的 PQC 加密器。通常从 `HybridSeal::encrypt_pqc_suite` 调用。
    pub(crate) fn new(pk: AsymmetricPublicKey, kek_id: String) -> Self {
        Self {
            inner: HybridEncryptor {
                pk,
                kek_id,
                aad: None,
                signer: None,
                derivation_config: None,
                _phantom: std::marker::PhantomData,
            },
        }
    }

    /// Applies a set of pre-configured options to the encryptor.
    ///
    /// 将一组预先配置的选项应用于加密器。
    pub fn with_options(mut self, options: HybridEncryptionOptions) -> Self {
        self.inner = self.inner.with_options(options);
        self
    }

    /// Sets the Associated Data (AAD) for this encryption operation.
    ///
    /// 为此加密操作设置关联数据 (AAD)。
    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.inner = self.inner.with_aad(aad);
        self
    }

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
        Kdf: crate::algorithms::traits::KdfAlgorithm + Send + Sync + 'static,
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
        Xof: crate::algorithms::traits::XofAlgorithm + Send + Sync + 'static,
    {
        self.inner = self.inner.with_xof(deriver, salt, info, output_len);
        self
    }

    /// Encrypts the given plaintext in-memory using the PQC suite.
    ///
    /// 使用 PQC 套件在内存中加密给定的明文。
    pub fn to_vec(self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        self.inner.to_vec::<PqcKem>(plaintext)
    }

    /// Encrypts the given plaintext in-memory using parallel processing with the PQC suite.
    ///
    /// 使用 PQC 套件通过并行处理在内存中加密给定的明文。
    pub fn to_vec_parallel(self, plaintext: &[u8]) -> crate::Result<Vec<u8>>
    {
        self.inner.to_vec_parallel::<PqcKem>(plaintext)
    }

    /// Creates a streaming encryptor that writes to the given `Write` implementation using the PQC suite.
    ///
    /// 使用 PQC 套件创建一个流式加密器，该加密器写入给定的 `Write` 实现。
    pub fn into_writer<W: Write>(
        self,
        writer: W,
    ) -> crate::Result<crate::hybrid::streaming::Encryptor<W, PqcKem, PqcDek>> {
        self.inner.into_writer::<PqcKem, W>(writer)
    }

    /// Encrypts data from a reader and writes to a writer using parallel processing with the PQC suite.
    ///
    /// 使用 PQC 套件通过并行处理从 reader 加密数据并写入 writer。
    pub fn pipe_parallel<R, W>(self, reader: R, writer: W) -> crate::Result<()>
    where
        R: Read + Send,
        W: Write,
    {
        self.inner.pipe_parallel::<PqcKem, R, W>(reader, writer)
    }
} 