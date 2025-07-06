use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::algorithms::{
    SymmetricAlgorithm as SymmetricAlgorithmEnum,
};
use crate::common::header::Header;
use crate::common::PendingImpl;
use crate::error::{FormatError, KeyManagementError};
use crate::keys::provider::KeyProvider;
use crate::keys::{AsymmetricPrivateKey, SignaturePublicKey, TypedAsymmetricPrivateKey};
use seal_crypto::schemes::asymmetric::{
    post_quantum::kyber::{Kyber1024, Kyber512, Kyber768},
    traditional::rsa::{Rsa2048, Rsa4096},
};
use seal_crypto::schemes::symmetric::{
    aes_gcm::{Aes128Gcm, Aes256Gcm},
    chacha20_poly1305::{ChaCha20Poly1305, XChaCha20Poly1305},
};
use std::io::{Read, Write};
use std::sync::Arc;
use tokio::io::AsyncRead;

/// A generic pending hybrid decryptor, waiting for configuration and private key.
/// This struct unifies the logic for various decryption modes (in-memory, streaming, etc.).
///
/// 一个通用的、等待配置和私钥的待处理混合解密器。
/// 该结构统一了各种解密模式（内存中、流式等）的逻辑。
pub struct PendingDecryptor<T> {
    inner: T,
    aad: Option<Vec<u8>>,
    verification_key: Option<SignaturePublicKey>,
    key_provider: Option<Arc<dyn KeyProvider>>,
}

impl<T: PendingImpl> PendingDecryptor<T> {
    /// Creates a new `PendingDecryptor` with the given inner implementation.
    ///
    /// 使用给定的内部实现创建一个新的 `PendingDecryptor`。
    fn new(inner: T, key_provider: Option<Arc<dyn KeyProvider>>) -> Self {
        Self {
            inner,
            aad: None,
            verification_key: None,
            key_provider,
        }
    }

    /// Returns a reference to the header.
    ///
    /// 返回对标头的引用。
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the Key-Encrypting-Key ID from the header.
    ///
    /// 从标头返回密钥加密密钥 (KEK) 的 ID。
    pub fn kek_id(&self) -> Option<&str> {
        self.header().payload.kek_id()
    }

    /// Returns the Signer-Key-ID from the header.
    ///
    /// 从标头返回签名者密钥的 ID。
    pub fn signer_key_id(&self) -> Option<&str> {
        self.header().payload.signer_key_id()
    }

    /// Sets the Associated Data (AAD) for this decryption operation.
    /// The AAD must match the value provided during encryption.
    ///
    /// 为此解密操作设置关联数据 (AAD)。
    /// AAD 必须与加密时提供的值匹配。
    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }

    /// Supplies a verification key from raw bytes
    ///
    /// 提供原始字节形式的验证密钥。
    pub fn with_verification_key(
        mut self,
        verification_key: SignaturePublicKey,
    ) -> crate::Result<Self> {
        self.verification_key = Some(verification_key);
        Ok(self)
    }
}

/// A type alias for a pending in-memory hybrid decryptor.
///
/// 待处理内存混合解密器的类型别名。
pub type PendingInMemoryDecryptor<'a> =
    PendingDecryptor<crate::hybrid::ordinary::PendingDecryptor<'a>>;
/// A type alias for a pending parallel in-memory hybrid decryptor.
///
/// 待处理并行内存混合解密器的类型别名。
pub type PendingInMemoryParallelDecryptor<'a> =
    PendingDecryptor<crate::hybrid::parallel::PendingDecryptor<'a>>;
/// A type alias for a pending synchronous streaming hybrid decryptor.
///
/// 待处理同步流混合解密器的类型别名。
pub type PendingStreamingDecryptor<R> =
    PendingDecryptor<crate::hybrid::streaming::PendingDecryptor<R>>;
/// A type alias for a pending parallel streaming hybrid decryptor.
///
/// 待处理并行流混合解密器的类型别名。
pub type PendingParallelStreamingDecryptor<R> =
    PendingDecryptor<crate::hybrid::parallel_streaming::PendingDecryptor<R>>;
/// A type alias for a pending asynchronous streaming hybrid decryptor.
///
/// 待处理异步流混合解密器的类型别名。
#[cfg(feature = "async")]
pub type PendingAsyncStreamingDecryptor<R> =
    PendingDecryptor<crate::hybrid::asynchronous::PendingDecryptor<R>>;

/// A builder for hybrid decryption operations.
///
/// 混合解密操作的构建器。
#[derive(Default)]
pub struct HybridDecryptorBuilder {
    key_provider: Option<Arc<dyn KeyProvider>>,
}

impl HybridDecryptorBuilder {
    /// Creates a new `HybridDecryptorBuilder`.
    ///
    /// 创建一个新的 `HybridDecryptorBuilder`。
    pub fn new() -> Self {
        Self { key_provider: None }
    }

    /// Attaches a `KeyProvider` to the builder.
    ///
    /// When a `KeyProvider` is set, you can use the `resolve_and_decrypt`
    /// method on the pending decryptor to automatically handle key lookup.
    ///
    /// 将一个 `KeyProvider` 附加到构建器上。
    ///
    /// 设置 `KeyProvider` 后，您可以在待处理解密器上使用 `resolve_and_decrypt`
    /// 方法来自动处理密钥查找。
    pub fn with_key_provider(mut self, provider: Arc<dyn KeyProvider>) -> Self {
        self.key_provider = Some(provider);
        self
    }

    /// Configures decryption from an in-memory byte slice.
    ///
    /// 从内存中的字节切片配置解密。
    pub fn slice<'a>(self, ciphertext: &'a [u8]) -> crate::Result<PendingInMemoryDecryptor<'a>> {
        let mid_level_pending =
            crate::hybrid::ordinary::PendingDecryptor::from_ciphertext(ciphertext)?;
        Ok(PendingDecryptor::new(
            mid_level_pending,
            self.key_provider,
        ))
    }

    /// Configures parallel decryption from an in-memory byte slice.
    ///
    /// 从内存中的字节切片配置并行解密。
    pub fn slice_parallel<'a>(
        self,
        ciphertext: &'a [u8],
    ) -> crate::Result<PendingInMemoryParallelDecryptor<'a>> {
        let mid_level_pending =
            crate::hybrid::parallel::PendingDecryptor::from_ciphertext(ciphertext)?;
        Ok(PendingDecryptor::new(
            mid_level_pending,
            self.key_provider,
        ))
    }

    /// Configures decryption from a synchronous `Read` stream.
    ///
    /// 从同步 `Read` 流配置解密。
    pub fn reader<R: Read>(
        self,
        reader: R,
    ) -> crate::Result<PendingStreamingDecryptor<R>> {
        let mid_level_pending = crate::hybrid::streaming::PendingDecryptor::from_reader(reader)?;
        Ok(PendingDecryptor::new(
            mid_level_pending,
            self.key_provider,
        ))
    }

    /// Configures parallel decryption from a synchronous `Read` stream.
    ///
    /// 从同步 `Read` 流配置并行解密。
    pub fn reader_parallel<R: Read + Send>(
        self,
        reader: R,
    ) -> crate::Result<PendingParallelStreamingDecryptor<R>> {
        let mid_level_pending =
            crate::hybrid::parallel_streaming::PendingDecryptor::from_reader(reader)?;
        Ok(PendingDecryptor::new(
            mid_level_pending,
            self.key_provider,
        ))
    }

    /// [Async] Configures decryption from an asynchronous `Read` stream.
    ///
    /// [异步] 从异步 `Read` 流配置解密。
    #[cfg(feature = "async")]
    pub async fn async_reader<R: AsyncRead + Unpin>(
        self,
        reader: R,
    ) -> crate::Result<PendingAsyncStreamingDecryptor<R>> {
        let mid_level_pending =
            crate::hybrid::asynchronous::PendingDecryptor::from_reader(reader).await?;
        Ok(PendingDecryptor::new(
            mid_level_pending,
            self.key_provider,
        ))
    }
}

impl<'a> PendingInMemoryDecryptor<'a> {
    /// Automatically resolves keys using the attached `KeyProvider` and completes decryption.
    ///
    /// 使用附加的 `KeyProvider` 自动解析密钥并完成解密。
    pub fn resolve_and_decrypt(mut self) -> crate::Result<Vec<u8>> {
        let provider = self
            .key_provider
            .as_ref()
            .ok_or(KeyManagementError::ProviderMissing)?;

        if let Some(signer_key_id) = self.signer_key_id() {
            let verification_key = provider.get_signature_public_key(signer_key_id)?;
            self.verification_key = Some(verification_key);
        }

        let kek_id = self.kek_id().ok_or(KeyManagementError::KekIdNotFound)?;
        let private_key = provider.get_asymmetric_private_key(kek_id)?;

        self.with_key(private_key)
    }

    /// Supplies a private key directly from its wrapper for decryption
    ///
    /// 提供包装好的私钥以进行解密。
    pub fn with_key(self, key: AsymmetricPrivateKey) -> crate::Result<Vec<u8>> {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;

        let asymmetric_algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(FormatError::InvalidHeader)?;

        let typed_key = key.into_typed(asymmetric_algorithm)?;
        let symmetric_algorithm = self.header().payload.symmetric_algorithm();

        match typed_key {
            TypedAsymmetricPrivateKey::Rsa2048(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key::<Rsa2048, Aes128Gcm>(&sk),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key::<Rsa2048, Aes256Gcm>(&sk),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key::<Rsa2048, XChaCha20Poly1305>(&sk),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key::<Rsa2048, ChaCha20Poly1305>(&sk),
            },
            TypedAsymmetricPrivateKey::Rsa4096(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key::<Rsa4096, Aes128Gcm>(&sk),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key::<Rsa4096, Aes256Gcm>(&sk),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key::<Rsa4096, XChaCha20Poly1305>(&sk),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key::<Rsa4096, ChaCha20Poly1305>(&sk),
            },
            TypedAsymmetricPrivateKey::Kyber512(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key::<Kyber512, Aes128Gcm>(&sk),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key::<Kyber512, Aes256Gcm>(&sk),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key::<Kyber512, XChaCha20Poly1305>(&sk),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key::<Kyber512, ChaCha20Poly1305>(&sk),
            },
            TypedAsymmetricPrivateKey::Kyber768(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key::<Kyber768, Aes128Gcm>(&sk),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key::<Kyber768, Aes256Gcm>(&sk),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key::<Kyber768, XChaCha20Poly1305>(&sk),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key::<Kyber768, ChaCha20Poly1305>(&sk),
            },
            TypedAsymmetricPrivateKey::Kyber1024(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key::<Kyber1024, Aes128Gcm>(&sk),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key::<Kyber1024, Aes256Gcm>(&sk),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key::<Kyber1024, XChaCha20Poly1305>(&sk),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key::<Kyber1024, ChaCha20Poly1305>(&sk),
            },
        }
    }

    /// Supplies the typed private key and returns the decrypted plaintext.
    ///
    /// 提供类型化的私钥并返回解密的明文。
    pub fn with_typed_key<A, S>(self, sk: &A::PrivateKey) -> crate::Result<Vec<u8>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
    {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
        self.inner.into_plaintext::<A, S>(sk, self.aad.as_deref())
    }
}

impl<'a> PendingInMemoryParallelDecryptor<'a> {
    /// Automatically resolves keys using the attached `KeyProvider` and completes decryption.
    ///
    /// 使用附加的 `KeyProvider` 自动解析密钥并完成解密。
    pub fn resolve_and_decrypt(mut self) -> crate::Result<Vec<u8>> {
        let provider = self
            .key_provider
            .as_ref()
            .ok_or(KeyManagementError::ProviderMissing)?;

        if let Some(signer_key_id) = self.signer_key_id() {
            let verification_key = provider.get_signature_public_key(signer_key_id)?;
            self.verification_key = Some(verification_key);
        }

        let kek_id = self.kek_id().ok_or(KeyManagementError::KekIdNotFound)?;
        let private_key = provider.get_asymmetric_private_key(kek_id)?;

        self.with_key(private_key)
    }

    /// Supplies a private key directly from its wrapper for decryption
    ///
    /// 提供包装好的私钥以进行解密。
    pub fn with_key(self, key: AsymmetricPrivateKey) -> crate::Result<Vec<u8>> {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;

        let asymmetric_algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(FormatError::InvalidHeader)?;

        let typed_key = key.into_typed(asymmetric_algorithm)?;
        let symmetric_algorithm = self.header().payload.symmetric_algorithm();

        match typed_key {
            TypedAsymmetricPrivateKey::Rsa2048(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key::<Rsa2048, Aes128Gcm>(&sk),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key::<Rsa2048, Aes256Gcm>(&sk),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key::<Rsa2048, XChaCha20Poly1305>(&sk),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key::<Rsa2048, ChaCha20Poly1305>(&sk),
            },
            TypedAsymmetricPrivateKey::Rsa4096(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key::<Rsa4096, Aes128Gcm>(&sk),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key::<Rsa4096, Aes256Gcm>(&sk),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key::<Rsa4096, XChaCha20Poly1305>(&sk),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key::<Rsa4096, ChaCha20Poly1305>(&sk),
            },
            TypedAsymmetricPrivateKey::Kyber512(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key::<Kyber512, Aes128Gcm>(&sk),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key::<Kyber512, Aes256Gcm>(&sk),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key::<Kyber512, XChaCha20Poly1305>(&sk),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key::<Kyber512, ChaCha20Poly1305>(&sk),
            },
            TypedAsymmetricPrivateKey::Kyber768(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key::<Kyber768, Aes128Gcm>(&sk),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key::<Kyber768, Aes256Gcm>(&sk),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key::<Kyber768, XChaCha20Poly1305>(&sk),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key::<Kyber768, ChaCha20Poly1305>(&sk),
            },
            TypedAsymmetricPrivateKey::Kyber1024(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key::<Kyber1024, Aes128Gcm>(&sk),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key::<Kyber1024, Aes256Gcm>(&sk),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key::<Kyber1024, XChaCha20Poly1305>(&sk),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key::<Kyber1024, ChaCha20Poly1305>(&sk),
            },
        }
    }

    /// Supplies the typed private key and returns the decrypted plaintext.
    ///
    /// 提供类型化的私钥并返回解密的明文。
    pub fn with_typed_key<A, S>(self, sk: &A::PrivateKey) -> crate::Result<Vec<u8>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
    {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
        self.inner.into_plaintext::<A, S>(sk, self.aad.as_deref())
    }
}

impl<R: Read> PendingStreamingDecryptor<R> {
    /// Automatically resolves keys using the attached `KeyProvider` and completes decryption.
    ///
    /// 使用附加的 `KeyProvider` 自动解析密钥并完成解密。
    pub fn resolve_and_decrypt<'s>(mut self) -> crate::Result<Box<dyn Read + 's>>
    where
        R: 's,
    {
        let provider = self
            .key_provider
            .as_ref()
            .ok_or(KeyManagementError::ProviderMissing)?;

        if let Some(signer_key_id) = self.signer_key_id() {
            let verification_key = provider.get_signature_public_key(signer_key_id)?;
            self.verification_key = Some(verification_key);
        }

        let kek_id = self.kek_id().ok_or(KeyManagementError::KekIdNotFound)?;
        let private_key = provider.get_asymmetric_private_key(kek_id)?;

        self.with_key(private_key)
    }

    /// Supplies a private key directly from its wrapper for decryption
    ///
    /// 提供包装好的私钥以进行解密。
    pub fn with_key<'s>(self, key: AsymmetricPrivateKey) -> crate::Result<Box<dyn Read + 's>>
    where
        R: 's,
    {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;

        let asymmetric_algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(FormatError::InvalidHeader)?;

        let typed_key = key.into_typed(asymmetric_algorithm)?;
        let symmetric_algorithm = self.header().payload.symmetric_algorithm();

        match typed_key {
            TypedAsymmetricPrivateKey::Rsa2048(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key::<Rsa2048, Aes128Gcm>(&sk).map(|d| Box::new(d) as Box<dyn Read>),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key::<Rsa2048, Aes256Gcm>(&sk).map(|d| Box::new(d) as Box<dyn Read>),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key::<Rsa2048, XChaCha20Poly1305>(&sk).map(|d| Box::new(d) as Box<dyn Read>),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key::<Rsa2048, ChaCha20Poly1305>(&sk).map(|d| Box::new(d) as Box<dyn Read>),
            },
            TypedAsymmetricPrivateKey::Rsa4096(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key::<Rsa4096, Aes128Gcm>(&sk).map(|d| Box::new(d) as Box<dyn Read>),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key::<Rsa4096, Aes256Gcm>(&sk).map(|d| Box::new(d) as Box<dyn Read>),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key::<Rsa4096, XChaCha20Poly1305>(&sk).map(|d| Box::new(d) as Box<dyn Read>),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key::<Rsa4096, ChaCha20Poly1305>(&sk).map(|d| Box::new(d) as Box<dyn Read>),
            },
            TypedAsymmetricPrivateKey::Kyber512(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key::<Kyber512, Aes128Gcm>(&sk).map(|d| Box::new(d) as Box<dyn Read>),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key::<Kyber512, Aes256Gcm>(&sk).map(|d| Box::new(d) as Box<dyn Read>),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key::<Kyber512, XChaCha20Poly1305>(&sk).map(|d| Box::new(d) as Box<dyn Read>),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key::<Kyber512, ChaCha20Poly1305>(&sk).map(|d| Box::new(d) as Box<dyn Read>),
            },
            TypedAsymmetricPrivateKey::Kyber768(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key::<Kyber768, Aes128Gcm>(&sk).map(|d| Box::new(d) as Box<dyn Read>),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key::<Kyber768, Aes256Gcm>(&sk).map(|d| Box::new(d) as Box<dyn Read>),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key::<Kyber768, XChaCha20Poly1305>(&sk).map(|d| Box::new(d) as Box<dyn Read>),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key::<Kyber768, ChaCha20Poly1305>(&sk).map(|d| Box::new(d) as Box<dyn Read>),
            },
            TypedAsymmetricPrivateKey::Kyber1024(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key::<Kyber1024, Aes128Gcm>(&sk).map(|d| Box::new(d) as Box<dyn Read>),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key::<Kyber1024, Aes256Gcm>(&sk).map(|d| Box::new(d) as Box<dyn Read>),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key::<Kyber1024, XChaCha20Poly1305>(&sk).map(|d| Box::new(d) as Box<dyn Read>),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key::<Kyber1024, ChaCha20Poly1305>(&sk).map(|d| Box::new(d) as Box<dyn Read>),
            },
        }
    }

    /// Supplies the typed private key and returns a fully initialized `Decryptor`.
    ///
    /// 提供类型化的私钥并返回一个完全初始化的 `Decryptor`。
    pub fn with_typed_key<A, S>(
        self,
        sk: &A::PrivateKey,
    ) -> crate::Result<crate::hybrid::streaming::Decryptor<R, A, S>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
    {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
        self.inner.into_decryptor::<A, S>(sk, self.aad.as_deref())
    }
}

impl<R> PendingParallelStreamingDecryptor<R>
where
    R: Read + Send,
{
    /// Automatically resolves keys and decrypts the stream to the provided writer.
    ///
    /// 自动解析密钥并将流解密到提供的写入器。
    pub fn resolve_and_decrypt_to_writer<W: Write>(mut self, writer: W) -> crate::Result<()> {
        let provider = self
            .key_provider
            .as_ref()
            .ok_or(KeyManagementError::ProviderMissing)?;

        if let Some(signer_key_id) = self.signer_key_id() {
            let verification_key = provider.get_signature_public_key(signer_key_id)?;
            self.verification_key = Some(verification_key);
        }

        let kek_id = self.kek_id().ok_or(KeyManagementError::KekIdNotFound)?;
        let private_key = provider.get_asymmetric_private_key(kek_id)?;

        self.with_key_to_writer(private_key, writer)
    }

    /// Supplies a private key directly from its wrapper for decryption
    ///
    /// 提供包装好的私钥以进行解密。
    pub fn with_key_to_writer<W: Write>(
        self,
        key: AsymmetricPrivateKey,
        writer: W,
    ) -> crate::Result<()> {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;

        let asymmetric_algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(FormatError::InvalidHeader)?;

        let typed_key = key.into_typed(asymmetric_algorithm)?;
        let symmetric_algorithm = self.header().payload.symmetric_algorithm();

        match typed_key {
            TypedAsymmetricPrivateKey::Rsa2048(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key_to_writer::<Rsa2048, Aes128Gcm, W>(&sk, writer),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key_to_writer::<Rsa2048, Aes256Gcm, W>(&sk, writer),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key_to_writer::<Rsa2048, XChaCha20Poly1305, W>(&sk, writer),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key_to_writer::<Rsa2048, ChaCha20Poly1305, W>(&sk, writer),
            },
            TypedAsymmetricPrivateKey::Rsa4096(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key_to_writer::<Rsa4096, Aes128Gcm, W>(&sk, writer),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key_to_writer::<Rsa4096, Aes256Gcm, W>(&sk, writer),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key_to_writer::<Rsa4096, XChaCha20Poly1305, W>(&sk, writer),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key_to_writer::<Rsa4096, ChaCha20Poly1305, W>(&sk, writer),
            },
            TypedAsymmetricPrivateKey::Kyber512(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key_to_writer::<Kyber512, Aes128Gcm, W>(&sk, writer),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key_to_writer::<Kyber512, Aes256Gcm, W>(&sk, writer),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key_to_writer::<Kyber512, XChaCha20Poly1305, W>(&sk, writer),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key_to_writer::<Kyber512, ChaCha20Poly1305, W>(&sk, writer),
            },
            TypedAsymmetricPrivateKey::Kyber768(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key_to_writer::<Kyber768, Aes128Gcm, W>(&sk, writer),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key_to_writer::<Kyber768, Aes256Gcm, W>(&sk, writer),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key_to_writer::<Kyber768, XChaCha20Poly1305, W>(&sk, writer),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key_to_writer::<Kyber768, ChaCha20Poly1305, W>(&sk, writer),
            },
            TypedAsymmetricPrivateKey::Kyber1024(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key_to_writer::<Kyber1024, Aes128Gcm, W>(&sk, writer),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key_to_writer::<Kyber1024, Aes256Gcm, W>(&sk, writer),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key_to_writer::<Kyber1024, XChaCha20Poly1305, W>(&sk, writer),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key_to_writer::<Kyber1024, ChaCha20Poly1305, W>(&sk, writer),
            },
        }
    }

    /// Supplies the typed private key and decrypts the stream, writing to the provided writer.
    ///
    /// 提供类型化的私钥并解密流，写入提供的写入器。
    pub fn with_typed_key_to_writer<A, S, W: Write>(
        self,
        sk: &A::PrivateKey,
        writer: W,
    ) -> crate::Result<()>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
    {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
        self.inner
            .decrypt_to_writer::<A, S, W>(sk, writer, self.aad.as_deref())
    }
}

#[cfg(feature = "async")]
impl<R: AsyncRead + Unpin> PendingAsyncStreamingDecryptor<R> {
    /// Automatically resolves keys and returns a decrypting async reader.
    ///
    /// 自动解析密钥并返回一个解密的异步读取器。
    pub async fn resolve_and_decrypt<'s>(
        mut self,
    ) -> crate::Result<Box<dyn AsyncRead + Unpin + Send + 's>>
    where
        R: Send + 's,
    {
        let provider = self
            .key_provider
            .as_ref()
            .ok_or(KeyManagementError::ProviderMissing)?;

        if let Some(signer_key_id) = self.signer_key_id() {
            let verification_key = provider.get_signature_public_key(signer_key_id)?;
            self.verification_key = Some(verification_key);
        }

        let kek_id = self.kek_id().ok_or(KeyManagementError::KekIdNotFound)?;
        let private_key = provider.get_asymmetric_private_key(kek_id)?;

        self.with_key(private_key).await
    }

    /// Supplies a private key directly from its wrapper for decryption
    ///
    /// 提供包装好的私钥以进行解密。
    pub async fn with_key<'s>(
        self,
        key: AsymmetricPrivateKey,
    ) -> crate::Result<Box<dyn AsyncRead + Unpin + Send + 's>>
    where
        R: Send + 's,
    {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;

        let asymmetric_algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(FormatError::InvalidHeader)?;

        let typed_key = key.into_typed(asymmetric_algorithm)?;
        let symmetric_algorithm = self.header().payload.symmetric_algorithm();

        match typed_key {
            TypedAsymmetricPrivateKey::Rsa2048(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key::<Rsa2048, Aes128Gcm>(sk).await.map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key::<Rsa2048, Aes256Gcm>(sk).await.map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key::<Rsa2048, XChaCha20Poly1305>(sk).await.map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key::<Rsa2048, ChaCha20Poly1305>(sk).await.map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
            },
            TypedAsymmetricPrivateKey::Rsa4096(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key::<Rsa4096, Aes128Gcm>(sk).await.map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key::<Rsa4096, Aes256Gcm>(sk).await.map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key::<Rsa4096, XChaCha20Poly1305>(sk).await.map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key::<Rsa4096, ChaCha20Poly1305>(sk).await.map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
            },
            TypedAsymmetricPrivateKey::Kyber512(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key::<Kyber512, Aes128Gcm>(sk).await.map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key::<Kyber512, Aes256Gcm>(sk).await.map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key::<Kyber512, XChaCha20Poly1305>(sk).await.map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key::<Kyber512, ChaCha20Poly1305>(sk).await.map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
            },
            TypedAsymmetricPrivateKey::Kyber768(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key::<Kyber768, Aes128Gcm>(sk).await.map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key::<Kyber768, Aes256Gcm>(sk).await.map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key::<Kyber768, XChaCha20Poly1305>(sk).await.map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key::<Kyber768, ChaCha20Poly1305>(sk).await.map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
            },
            TypedAsymmetricPrivateKey::Kyber1024(sk) => match symmetric_algorithm {
                SymmetricAlgorithmEnum::Aes128Gcm => self.with_typed_key::<Kyber1024, Aes128Gcm>(sk).await.map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
                SymmetricAlgorithmEnum::Aes256Gcm => self.with_typed_key::<Kyber1024, Aes256Gcm>(sk).await.map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
                SymmetricAlgorithmEnum::XChaCha20Poly1305 => self.with_typed_key::<Kyber1024, XChaCha20Poly1305>(sk).await.map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
                SymmetricAlgorithmEnum::ChaCha20Poly1305 => self.with_typed_key::<Kyber1024, ChaCha20Poly1305>(sk).await.map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
            },
        }
    }

    /// Supplies the typed private key and returns a fully initialized `Decryptor`.
    ///
    /// 提供类型化的私钥并返回一个完全初始化的 `Decryptor`。
    pub async fn with_typed_key<A, S>(
        self,
        sk: A::PrivateKey,
    ) -> crate::Result<crate::hybrid::asynchronous::Decryptor<R, A, S>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
    {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
        self.inner
            .into_decryptor::<A, S>(sk, self.aad.as_deref())
            .await
    }
}
