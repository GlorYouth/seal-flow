use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::algorithms::{
    AsymmetricAlgorithm as AsymmetricAlgorithmEnum, SymmetricAlgorithm as SymmetricAlgorithmEnum,
};
use crate::common::header::Header;
use crate::common::PendingImpl;
use crate::error::{FormatError, KeyManagementError};
use crate::keys::provider::KeyProvider;
use crate::keys::{AsymmetricPrivateKey, SignaturePublicKey};
use seal_crypto::prelude::*;
use seal_crypto::schemes::asymmetric::{
    post_quantum::kyber::{Kyber1024, Kyber512, Kyber768},
    traditional::rsa::{Rsa2048, Rsa4096},
};
use seal_crypto::schemes::symmetric::{
    aes_gcm::{Aes128Gcm, Aes256Gcm},
    chacha20_poly1305::{ChaCha20Poly1305, XChaCha20Poly1305},
};
use seal_crypto::zeroize::Zeroizing;
use std::io::{Read, Write};
use tokio::io::AsyncRead;

macro_rules! dispatch_symmetric_algorithm {
    ($algorithm:expr, $callback:ident, $($extra_args:tt)*) => {
        match $algorithm {
            SymmetricAlgorithmEnum::Aes128Gcm => $callback!(Aes128Gcm, $($extra_args)*),
            SymmetricAlgorithmEnum::Aes256Gcm => $callback!(Aes256Gcm, $($extra_args)*),
            SymmetricAlgorithmEnum::XChaCha20Poly1305 => $callback!(XChaCha20Poly1305, $($extra_args)*),
            SymmetricAlgorithmEnum::ChaCha20Poly1305 => $callback!(ChaCha20Poly1305, $($extra_args)*),
        }
    };
}

/// 创建一个宏来处理从原始字节转换为特定非对称算法密钥的过程
/// 这个宏替代了旧的枚举类型调度方式，直接从字节转换到密钥
macro_rules! dispatch_asymmetric_key_bytes {
    // 内部规则，处理算法列表
    (@internal $algorithm:expr, $key_bytes:expr, $callback:ident, $extra_args:tt,
     $(($algo_enum:path, $algo_type:ty)),*
    ) => {
        {
            match $algorithm {
                $(
                    $algo_enum => {
                        let sk = <$algo_type as AsymmetricKeySet>::PrivateKey::from_bytes($key_bytes)?;
                        $callback!(sk, $algo_type, $extra_args)
                    },
                )*
            }
        }
    };

    // 宏的公共入口点
    ($algorithm:expr, $key_bytes:expr, $callback:ident, $($extra_args:tt)*) => {
        dispatch_asymmetric_key_bytes!(@internal $algorithm, $key_bytes, $callback, ($($extra_args)*),
            (AsymmetricAlgorithmEnum::Rsa2048, Rsa2048),
            (AsymmetricAlgorithmEnum::Rsa4096, Rsa4096),
            (AsymmetricAlgorithmEnum::Kyber512, Kyber512),
            (AsymmetricAlgorithmEnum::Kyber768, Kyber768),
            (AsymmetricAlgorithmEnum::Kyber1024, Kyber1024)
        )
    };
}

/// A generic pending hybrid decryptor, waiting for configuration and private key.
/// This struct unifies the logic for various decryption modes (in-memory, streaming, etc.).
pub struct PendingDecryptor<'a, T> {
    inner: T,
    aad: Option<Vec<u8>>,
    verification_key: Option<SignaturePublicKey>,
    key_provider: Option<&'a dyn KeyProvider>,
}

impl<'a, T: PendingImpl> PendingDecryptor<'a, T> {
    /// Creates a new `PendingDecryptor` with the given inner implementation.
    fn new(inner: T, key_provider: Option<&'a dyn KeyProvider>) -> Self {
        Self {
            inner,
            aad: None,
            verification_key: None,
            key_provider,
        }
    }

    /// Returns a reference to the header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the Key-Encrypting-Key ID from the header.
    pub fn kek_id(&self) -> Option<&str> {
        self.header().payload.kek_id()
    }

    /// Returns the Signer-Key-ID from the header.
    pub fn signer_key_id(&self) -> Option<&str> {
        self.header().payload.signer_key_id()
    }

    /// Sets the Associated Data (AAD) for this decryption operation.
    /// The AAD must match the value provided during encryption.
    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }

    /// Supplies a verification key from raw bytes
    pub fn with_verification_key(
        mut self,
        verification_key: SignaturePublicKey,
    ) -> crate::Result<Self> {
        self.verification_key = Some(verification_key);
        Ok(self)
    }
}

/// A type alias for a pending in-memory hybrid decryptor.
pub type PendingInMemoryDecryptor<'a> =
    PendingDecryptor<'a, crate::hybrid::ordinary::PendingDecryptor<'a>>;
/// A type alias for a pending parallel in-memory hybrid decryptor.
pub type PendingInMemoryParallelDecryptor<'a> =
    PendingDecryptor<'a, crate::hybrid::parallel::PendingDecryptor<'a>>;
/// A type alias for a pending synchronous streaming hybrid decryptor.
pub type PendingStreamingDecryptor<'a, R> =
    PendingDecryptor<'a, crate::hybrid::streaming::PendingDecryptor<R>>;
/// A type alias for a pending parallel streaming hybrid decryptor.
pub type PendingParallelStreamingDecryptor<'a, R> =
    PendingDecryptor<'a, crate::hybrid::parallel_streaming::PendingDecryptor<R>>;
/// A type alias for a pending asynchronous streaming hybrid decryptor.
#[cfg(feature = "async")]
pub type PendingAsyncStreamingDecryptor<'a, R> =
    PendingDecryptor<'a, crate::hybrid::asynchronous::PendingDecryptor<R>>;

/// A builder for hybrid decryption operations.
#[derive(Default)]
pub struct HybridDecryptorBuilder<'a> {
    key_provider: Option<&'a dyn KeyProvider>,
}

impl<'a> HybridDecryptorBuilder<'a> {
    /// Creates a new `HybridDecryptorBuilder`.
    pub fn new() -> Self {
        Self { key_provider: None }
    }

    /// Attaches a `KeyProvider` to the builder.
    ///
    /// When a `KeyProvider` is set, you can use the `resolve_and_decrypt`
    /// method on the pending decryptor to automatically handle key lookup.
    pub fn with_key_provider(mut self, provider: &'a dyn KeyProvider) -> Self {
        self.key_provider = Some(provider);
        self
    }

    /// Configures decryption from an in-memory byte slice.
    pub fn slice(self, ciphertext: &'a [u8]) -> crate::Result<PendingInMemoryDecryptor<'a>> {
        let mid_level_pending =
            crate::hybrid::ordinary::PendingDecryptor::from_ciphertext(ciphertext)?;
        Ok(PendingDecryptor::new(
            mid_level_pending,
            self.key_provider,
        ))
    }

    /// Configures parallel decryption from an in-memory byte slice.
    pub fn slice_parallel(
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
    pub fn reader<R: Read + 'static>(
        self,
        reader: R,
    ) -> crate::Result<PendingStreamingDecryptor<'a, R>> {
        let mid_level_pending = crate::hybrid::streaming::PendingDecryptor::from_reader(reader)?;
        Ok(PendingDecryptor::new(
            mid_level_pending,
            self.key_provider,
        ))
    }

    /// Configures parallel decryption from a synchronous `Read` stream.
    pub fn reader_parallel<R: Read + Send>(
        self,
        reader: R,
    ) -> crate::Result<PendingParallelStreamingDecryptor<'a, R>> {
        let mid_level_pending =
            crate::hybrid::parallel_streaming::PendingDecryptor::from_reader(reader)?;
        Ok(PendingDecryptor::new(
            mid_level_pending,
            self.key_provider,
        ))
    }

    /// [Async] Configures decryption from an asynchronous `Read` stream.
    #[cfg(feature = "async")]
    pub async fn async_reader<R: AsyncRead + Unpin>(
        self,
        reader: R,
    ) -> crate::Result<PendingAsyncStreamingDecryptor<'a, R>> {
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
    pub fn resolve_and_decrypt(mut self) -> crate::Result<Vec<u8>> {
        let provider = self
            .key_provider
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
        pub fn with_key(self, key: AsymmetricPrivateKey) -> crate::Result<Vec<u8>> {
            self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;

        let asymmetric_algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(FormatError::InvalidHeader)?;

        let symmetric_algorithm = self.header().payload.symmetric_algorithm();

        macro_rules! do_decrypt {
            ($S:ty, $sk:ident, $A:ty) => {
                self.with_typed_key::<$A, $S>(&$sk)
            };
        }

        macro_rules! do_dispatch_symmetric {
            ($sk:ident, $A:ty, ()) => {
                dispatch_symmetric_algorithm!(symmetric_algorithm, do_decrypt, $sk, $A)
            };
        }

        dispatch_asymmetric_key_bytes!(asymmetric_algorithm, key.as_bytes(), do_dispatch_symmetric,)
    }

    /// Supplies the typed private key and returns the decrypted plaintext.
    pub fn with_typed_key<A, S>(self, sk: &A::PrivateKey) -> crate::Result<Vec<u8>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
        A::EncapsulatedKey: From<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
        self.inner.into_plaintext::<A, S>(sk, self.aad.as_deref())
    }
}

impl<'a> PendingInMemoryParallelDecryptor<'a> {
    /// Automatically resolves keys using the attached `KeyProvider` and completes decryption.
    pub fn resolve_and_decrypt(mut self) -> crate::Result<Vec<u8>> {
        let provider = self
            .key_provider
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
    pub fn with_key(self, key: AsymmetricPrivateKey) -> crate::Result<Vec<u8>> {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;

        let asymmetric_algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(FormatError::InvalidHeader)?;

        let symmetric_algorithm = self.header().payload.symmetric_algorithm();

        macro_rules! do_decrypt {
            ($S:ty, $sk:ident, $A:ty) => {
                self.with_typed_key::<$A, $S>(&$sk)
            };
        }

        macro_rules! do_dispatch_symmetric {
            ($sk:ident, $A:ty, ()) => {
                dispatch_symmetric_algorithm!(symmetric_algorithm, do_decrypt, $sk, $A)
            };
        }

        dispatch_asymmetric_key_bytes!(asymmetric_algorithm, key.as_bytes(), do_dispatch_symmetric,)
    }

    /// Supplies the typed private key and returns the decrypted plaintext.
    pub fn with_typed_key<A, S>(self, sk: &A::PrivateKey) -> crate::Result<Vec<u8>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
        S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync,
        A::PrivateKey: Clone,
        A::EncapsulatedKey: From<Vec<u8>>,
    {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
        self.inner.into_plaintext::<A, S>(sk, self.aad.as_deref())
    }
}

impl<'a, R: Read + 'static> PendingStreamingDecryptor<'a, R> {
    /// Automatically resolves keys using the attached `KeyProvider` and completes decryption.
    pub fn resolve_and_decrypt(mut self) -> crate::Result<Box<dyn Read + 'static>> {
        let provider = self
            .key_provider
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
    pub fn with_key(self, key: AsymmetricPrivateKey) -> crate::Result<Box<dyn Read + 'static>> {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;

        let asymmetric_algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(FormatError::InvalidHeader)?;

        let symmetric_algorithm = self.header().payload.symmetric_algorithm();

        macro_rules! do_decrypt {
            ($S:ty, $sk:ident, $A:ty) => {
                self.with_typed_key::<$A, $S>(&$sk)
                    .map(|d| Box::new(d) as Box<dyn Read>)
            };
        }

        macro_rules! do_dispatch_symmetric {
            ($sk:ident, $A:ty, ()) => {
                dispatch_symmetric_algorithm!(symmetric_algorithm, do_decrypt, $sk, $A)
            };
        }

        dispatch_asymmetric_key_bytes!(asymmetric_algorithm, key.as_bytes(), do_dispatch_symmetric,)
    }

    /// Supplies the typed private key and returns a fully initialized `Decryptor`.
    pub fn with_typed_key<A, S>(
        self,
        sk: &A::PrivateKey,
    ) -> crate::Result<crate::hybrid::streaming::Decryptor<R, A, S>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
        A::PrivateKey: Clone,
        A::EncapsulatedKey: From<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
        self.inner.into_decryptor::<A, S>(sk, self.aad.as_deref())
    }
}

impl<'a, R> PendingParallelStreamingDecryptor<'a, R>
where
    R: Read + Send,
{
    /// Automatically resolves keys and decrypts the stream to the provided writer.
    pub fn resolve_and_decrypt_to_writer<W: Write>(mut self, writer: W) -> crate::Result<()> {
        let provider = self
            .key_provider
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

        let symmetric_algorithm = self.header().payload.symmetric_algorithm();

        macro_rules! do_decrypt {
            ($S:ty, $sk:ident, $A:ty, $writer:ident) => {
                self.with_typed_key_to_writer::<$A, $S, W>(&$sk, $writer)
            };
        }

        macro_rules! do_dispatch_symmetric {
            ($sk:ident, $A:ty, ($writer:ident)) => {
                dispatch_symmetric_algorithm!(symmetric_algorithm, do_decrypt, $sk, $A, $writer)
            };
        }

        dispatch_asymmetric_key_bytes!(
            asymmetric_algorithm,
            key.as_bytes(),
            do_dispatch_symmetric,
            writer
        )
    }

    /// Supplies the typed private key and decrypts the stream, writing to the provided writer.
    pub fn with_typed_key_to_writer<A, S, W: Write>(
        self,
        sk: &A::PrivateKey,
        writer: W,
    ) -> crate::Result<()>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
        S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync,
        A::PrivateKey: Clone,
        A::EncapsulatedKey: From<Vec<u8>> + Send,
    {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
        self.inner
            .decrypt_to_writer::<A, S, W>(sk, writer, self.aad.as_deref())
    }
}

#[cfg(feature = "async")]
impl<'a, R: AsyncRead + Unpin> PendingAsyncStreamingDecryptor<'a, R> {
    /// Automatically resolves keys and returns a decrypting async reader.
    pub async fn resolve_and_decrypt<'s>(
        mut self,
    ) -> crate::Result<Box<dyn AsyncRead + Unpin + Send + 's>>
    where
        R: Send + 's,
    {
        let provider = self
            .key_provider
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

        let symmetric_algorithm = self.header().payload.symmetric_algorithm();

        macro_rules! do_decrypt {
            ($S:ty, $sk:ident, $A:ty) => {
                self.with_typed_key::<$A, $S>($sk)
                    .await
                    .map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>)
            };
        }

        macro_rules! do_dispatch_symmetric {
            ($sk:ident, $A:ty, ()) => {
                dispatch_symmetric_algorithm!(symmetric_algorithm, do_decrypt, $sk, $A)
            };
        }

        dispatch_asymmetric_key_bytes!(asymmetric_algorithm, key.as_bytes(), do_dispatch_symmetric,)
    }

    /// Supplies the typed private key and returns a fully initialized `Decryptor`.
    pub async fn with_typed_key<A, S>(
        self,
        sk: A::PrivateKey,
    ) -> crate::Result<crate::hybrid::asynchronous::Decryptor<R, A, S>>
    where
        A: AsymmetricAlgorithm + 'static,
        S: SymmetricAlgorithm + 'static,
        A::PrivateKey: Send,
        A::EncapsulatedKey: From<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync + 'static,
    {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
        self.inner
            .into_decryptor::<A, S>(sk, self.aad.as_deref())
            .await
    }
}
