use crate::algorithms::traits::{
    AsymmetricAlgorithm, KdfAlgorithm, SignatureAlgorithm, SymmetricAlgorithm, XofAlgorithm,
};
use crate::common::algorithms::{
    KdfAlgorithm as KdfAlgorithmEnum, SignatureAlgorithm as SignatureAlgorithmEnum,
    XofAlgorithm as XofAlgorithmEnum,
};
use crate::common::header::{DerivationInfo, KdfInfo, XofInfo};
use crate::common::{DerivationSet, SignerSet};
use crate::error::KeyManagementError;
use crate::keys::provider::EncryptionKeyProvider;
use crate::keys::{AsymmetricPrivateKey, AsymmetricPublicKey};
use crate::seal::hybrid::{DerivationOptions, HybridEncryptionOptions};
use crate::seal::traits::{
    InMemoryEncryptor, IntoAsyncWriter, IntoWriter, StreamingEncryptor as StreamingEncryptorTrait,
};
use seal_crypto::prelude::*;
use seal_crypto::schemes::asymmetric::post_quantum::dilithium::{
    Dilithium2, Dilithium3, Dilithium5,
};
use seal_crypto::schemes::asymmetric::traditional::ecc::{EcdsaP256, Ed25519};
use seal_crypto::schemes::kdf::hkdf::{HkdfSha256, HkdfSha384, HkdfSha512};
use seal_crypto::schemes::xof::shake::{Shake128, Shake256};
use seal_crypto::zeroize::Zeroizing;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::io::AsyncWrite;

/// A builder for hybrid encryption operations.
///
/// This builder allows for flexible configuration of the encryption process,
/// including the use of a key provider.
///
/// 混合加密操作的构建器。
///
/// 该构建器允许灵活配置加密过程，包括使用密钥提供程序。
#[derive(Default)]
pub struct HybridEncryptorBuilder<S: SymmetricAlgorithm> {
    key_provider: Option<Arc<dyn EncryptionKeyProvider>>,
    _phantom: PhantomData<S>,
}

impl<S: SymmetricAlgorithm> HybridEncryptorBuilder<S> {
    /// Creates a new `HybridEncryptorBuilder`.
    ///
    /// 创建一个新的 `HybridEncryptorBuilder`。
    pub fn new() -> Self {
        Self {
            key_provider: None,
            _phantom: PhantomData,
        }
    }

    /// Attaches an `EncryptionKeyProvider` to the builder.
    ///
    /// This allows the encryptor to resolve recipient keys and signing keys
    /// using key IDs.
    ///
    /// 将一个 `EncryptionKeyProvider` 附加到构建器上。
    ///
    /// 这允许加密器使用密钥 ID 来解析接收方密钥和签名密钥。
    pub fn with_key_provider(mut self, provider: Arc<dyn EncryptionKeyProvider>) -> Self {
        self.key_provider = Some(provider);
        self
    }

    /// Configures the encryptor with a recipient's public key provided directly.
    ///
    /// 使用直接提供的接收方公钥配置加密器。
    pub fn with_recipient(self, pk: AsymmetricPublicKey, kek_id: String) -> HybridEncryptor<S> {
        HybridEncryptor {
            pk,
            kek_id,
            aad: None,
            signer: None,
            derivation_config: None,
            _phantom: PhantomData,
            key_provider: self.key_provider,
        }
    }

    /// Configures the encryptor with a recipient's key ID.
    ///
    /// The public key will be resolved using the attached `EncryptionKeyProvider`.
    ///
    /// 使用接收方的密钥 ID 配置加密器。
    ///
    /// 将使用附加的 `EncryptionKeyProvider` 解析公钥。
    pub fn with_recipient_id(self, kek_id: &str) -> crate::Result<HybridEncryptor<S>> {
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
            _phantom: PhantomData,
            key_provider: self.key_provider,
        })
    }
}

/// A context for hybrid encryption operations, allowing selection of execution mode.
///
/// 混合加密操作的上下文，允许选择执行模式。
pub struct HybridEncryptor<S>
where
    S: SymmetricAlgorithm,
{
    pub(crate) pk: AsymmetricPublicKey,
    pub(crate) kek_id: String,
    pub(crate) aad: Option<Vec<u8>>,
    pub(crate) signer: Option<SignerSet>,
    pub(crate) derivation_config: Option<DerivationSet>,
    pub(crate) _phantom: PhantomData<S>,
    key_provider: Option<Arc<dyn EncryptionKeyProvider>>,
}

impl<S> HybridEncryptor<S>
where
    S: SymmetricAlgorithm,
{
    /// Applies a set of pre-configured options to the encryptor.
    ///
    /// 将一组预先配置的选项应用于加密器。
    pub fn with_options(mut self, options: HybridEncryptionOptions) -> Self {
        if let Some(aad) = options.aad {
            self = self.with_aad(aad);
        }

        if let Some(signer_opts) = options.signer {
            match signer_opts.algorithm {
                SignatureAlgorithmEnum::Dilithium2 => {
                    self = self.with_signer::<Dilithium2>(signer_opts.key, signer_opts.key_id)
                }
                SignatureAlgorithmEnum::Dilithium3 => {
                    self = self.with_signer::<Dilithium3>(signer_opts.key, signer_opts.key_id)
                }
                SignatureAlgorithmEnum::Dilithium5 => {
                    self = self.with_signer::<Dilithium5>(signer_opts.key, signer_opts.key_id)
                }
                SignatureAlgorithmEnum::Ed25519 => {
                    self = self.with_signer::<Ed25519>(signer_opts.key, signer_opts.key_id)
                }
                SignatureAlgorithmEnum::EcdsaP256 => {
                    self = self.with_signer::<EcdsaP256>(signer_opts.key, signer_opts.key_id)
                }
            }
        }

        if let Some(derivation_opts) = options.derivation {
            self = match derivation_opts {
                DerivationOptions::Kdf(opts) => match opts.algorithm {
                    KdfAlgorithmEnum::HkdfSha256 => self.with_kdf::<HkdfSha256>(
                        HkdfSha256::default(),
                        opts.salt,
                        opts.info,
                        opts.output_len,
                    ),
                    KdfAlgorithmEnum::HkdfSha384 => self.with_kdf::<HkdfSha384>(
                        HkdfSha384::default(),
                        opts.salt,
                        opts.info,
                        opts.output_len,
                    ),
                    KdfAlgorithmEnum::HkdfSha512 => self.with_kdf::<HkdfSha512>(
                        HkdfSha512::default(),
                        opts.salt,
                        opts.info,
                        opts.output_len,
                    ),
                },
                DerivationOptions::Xof(opts) => match opts.algorithm {
                    XofAlgorithmEnum::Shake128 => self.with_xof::<Shake128>(
                        Shake128::default(),
                        opts.salt,
                        opts.info,
                        opts.output_len,
                    ),
                    XofAlgorithmEnum::Shake256 => self.with_xof::<Shake256>(
                        Shake256::default(),
                        opts.salt,
                        opts.info,
                        opts.output_len,
                    ),
                },
            };
        }

        self
    }

    /// Sets the Associated Data (AAD) for this encryption operation.
    ///
    /// 为此加密操作设置关联数据 (AAD)。
    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }

    /// Use a Key Derivation Function (KDF) to derive the Data Encryption Key (DEK)
    /// from the shared secret generated by the Key Encapsulation Mechanism (KEM).
    ///
    /// 使用密钥派生函数 (KDF) 从密钥封装机制 (KEM) 生成的共享秘密中派生数据加密密钥 (DEK)。
    pub fn with_kdf<Kdf>(
        mut self,
        deriver: Kdf,
        salt: Option<impl Into<Vec<u8>>>,
        info: Option<impl Into<Vec<u8>>>,
        output_len: u32,
    ) -> Self
    where
        Kdf: KdfAlgorithm,
    {
        let salt = salt.map(|s| s.into());
        let info = info.map(|i| i.into());

        let kdf_info = KdfInfo {
            kdf_algorithm: Kdf::ALGORITHM,
            salt: salt.clone(),
            info: info.clone(),
            output_len,
        };

        let deriver_fn = Box::new(move |ikm: &[u8]| {
            deriver
                .derive(ikm, salt.as_deref(), info.as_deref(), output_len as usize)
                .map(|dk| Zeroizing::new(dk.as_bytes().to_vec()))
                .map_err(|e| e.into())
        });

        self.derivation_config = Some(DerivationSet {
            derivation_info: DerivationInfo::Kdf(kdf_info),
            deriver_fn,
        });
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
        Xof: XofAlgorithm,
    {
        let salt = salt.map(|s| s.into());
        let info = info.map(|i| i.into());

        let xof_info = XofInfo {
            xof_algorithm: Xof::ALGORITHM,
            salt: salt.clone(),
            info: info.clone(),
            output_len,
        };

        let deriver_fn = Box::new(move |ikm: &[u8]| {
            let mut reader = deriver.reader(ikm, salt.as_deref(), info.as_deref())?;
            let mut dek_bytes = vec![0u8; output_len as usize];
            reader.read(&mut dek_bytes);
            Ok(Zeroizing::new(dek_bytes))
        });

        self.derivation_config = Some(DerivationSet {
            derivation_info: DerivationInfo::Xof(xof_info),
            deriver_fn,
        });
        self
    }

    /// Signs the encryption metadata (header) using a key resolved from the `EncryptionKeyProvider`.
    ///
    /// 使用从 `EncryptionKeyProvider` 解析的密钥对加密元数据（标头）进行签名。
    pub fn with_signer_id<SignerAlgo>(mut self, signer_key_id: &str) -> crate::Result<Self>
    where
        SignerAlgo: SignatureAlgorithm,
    {
        let provider = self
            .key_provider
            .as_ref()
            .ok_or(KeyManagementError::ProviderMissing)?;
        let signing_key = provider.get_signing_private_key(signer_key_id)?;
        self.signer = Some(SignerSet {
            signer_key_id: signer_key_id.to_string(),
            signer_algorithm: SignerAlgo::ALGORITHM,
            signer: Box::new(move |message, aad| {
                let sk = SignerAlgo::PrivateKey::from_bytes(signing_key.as_bytes())?;
                let mut data_to_sign = message.to_vec();
                if let Some(aad_data) = aad {
                    data_to_sign.extend_from_slice(aad_data);
                }
                SignerAlgo::sign(&sk, &data_to_sign)
                    .map(|s| s.0)
                    .map_err(|e| e.into())
            }),
        });
        Ok(self)
    }

    /// Signs the encryption metadata (header) with the given private key.
    /// The signature ensures the integrity and authenticity of the encryption parameters.
    ///
    /// 使用给定的私钥对加密元数据（标头）进行签名。
    /// 签名确保了加密参数的完整性和真实性。
    pub fn with_signer<SignerAlgo>(
        mut self,
        signing_key: AsymmetricPrivateKey,
        signer_key_id: String,
    ) -> Self
    where
        SignerAlgo: SignatureAlgorithm,
    {
        self.signer = Some(SignerSet {
            signer_key_id,
            signer_algorithm: SignerAlgo::ALGORITHM,
            signer: Box::new(move |message, aad| {
                let sk = SignerAlgo::PrivateKey::from_bytes(signing_key.as_bytes())?;
                let mut data_to_sign = message.to_vec();
                if let Some(aad_data) = aad {
                    data_to_sign.extend_from_slice(aad_data);
                }
                SignerAlgo::sign(&sk, &data_to_sign)
                    .map(|s| s.0)
                    .map_err(|e| e.into())
            }),
        });
        self
    }

    /// Configures the encryptor to use a specific asymmetric algorithm.
    ///
    /// This returns a new encryptor instance that is specialized for the given
    /// algorithm, which can then be used to perform the actual encryption.
    ///
    /// 配置加密器以使用特定的非对称算法。
    ///
    /// 这将返回一个为给定算法特化的新加密器实例，
    /// 然后可用于执行实际的加密操作。
    pub fn with_algorithm<A: AsymmetricAlgorithm>(self) -> HybridEncryptorWithAlgorithms<A, S> {
        HybridEncryptorWithAlgorithms {
            inner: self,
            _phantom_a: PhantomData,
        }
    }
}

/// A hybrid encryptor that has been configured with specific asymmetric and symmetric algorithms.
///
/// This struct provides the final encryption methods (`to_vec`, `into_writer`, etc.)
/// without requiring further generic algorithm specification.
///
/// 已配置特定非对称和对称算法的混合加密器。
///
/// 该结构提供了最终的加密方法（`to_vec`、`into_writer`等），
/// 无需进一步指定泛型算法。
pub struct HybridEncryptorWithAlgorithms<A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    inner: HybridEncryptor<S>,
    _phantom_a: PhantomData<A>,
}

impl<A, S> InMemoryEncryptor for HybridEncryptorWithAlgorithms<A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    /// Encrypts the given plaintext in-memory.
    ///
    /// 在内存中加密给定的明文。
    fn to_vec(self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        let pk = A::PublicKey::from_bytes(self.inner.pk.as_bytes())?;

        crate::hybrid::ordinary::encrypt::<A, S>(
            &pk,
            plaintext,
            self.inner.kek_id,
            self.inner.signer,
            self.inner.aad.as_deref(),
            self.inner.derivation_config,
        )
    }

    /// Encrypts the given plaintext in-memory using parallel processing.
    ///
    /// 使用并行处理在内存中加密给定的明文。
    fn to_vec_parallel(self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        let pk = A::PublicKey::from_bytes(self.inner.pk.as_bytes())?;
        crate::hybrid::parallel::encrypt::<A, S>(
            &pk,
            plaintext,
            self.inner.kek_id,
            self.inner.signer,
            self.inner.aad.as_deref(),
            self.inner.derivation_config,
        )
    }
}

impl<A, S> StreamingEncryptorTrait for HybridEncryptorWithAlgorithms<A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    /// Encrypts data from a reader and writes to a writer using parallel processing.
    ///
    /// 使用并行处理从 reader 加密数据并写入 writer。
    fn pipe_parallel<R, W>(self, reader: R, writer: W) -> crate::Result<()>
    where
        R: Read + Send,
        W: Write,
    {
        let pk = A::PublicKey::from_bytes(self.inner.pk.as_bytes())?;
        crate::hybrid::parallel_streaming::encrypt::<A, S, R, W>(
            &pk,
            reader,
            writer,
            self.inner.kek_id,
            self.inner.signer,
            self.inner.aad.as_deref(),
            self.inner.derivation_config,
        )
    }
}

impl<A, S> IntoWriter for HybridEncryptorWithAlgorithms<A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    type Encryptor<W: Write> = crate::hybrid::streaming::Encryptor<W, A, S>;

    fn into_writer<W: Write>(
        self,
        writer: W,
    ) -> crate::Result<crate::hybrid::streaming::Encryptor<W, A, S>> {
        let pk = A::PublicKey::from_bytes(self.inner.pk.as_bytes())?;

        crate::hybrid::streaming::Encryptor::new(
            writer,
            &pk,
            self.inner.kek_id,
            self.inner.signer,
            self.inner.aad.as_deref(),
            self.inner.derivation_config,
        )
    }
}

#[cfg(feature = "async")]
impl<A, S> IntoAsyncWriter for HybridEncryptorWithAlgorithms<A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    type AsyncEncryptor<W: AsyncWrite + Unpin + Send> =
        crate::hybrid::asynchronous::Encryptor<W, A, S>;

    fn into_async_writer<W: AsyncWrite + Unpin + Send>(
        self,
        writer: W,
    ) -> impl std::future::Future<Output = crate::Result<Self::AsyncEncryptor<W>>> + Send {
        let pk_bytes = self.inner.pk;
        let kek_id = self.inner.kek_id;
        let signer = self.inner.signer;
        let aad = self.inner.aad;
        let derivation_config = self.inner.derivation_config;

        async move {
            let pk = A::PublicKey::from_bytes(pk_bytes.as_bytes())?;
            crate::hybrid::asynchronous::Encryptor::new(
                writer,
                pk,
                kek_id,
                signer,
                aad.as_deref(),
                derivation_config,
            )
            .await
        }
    }
}
