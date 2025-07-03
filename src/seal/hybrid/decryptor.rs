use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::algorithms::{
    AsymmetricAlgorithm as AsymmetricAlgorithmEnum, SymmetricAlgorithm as SymmetricAlgorithmEnum,
};
use crate::common::header::Header;
use crate::keys::{AsymmetricPrivateKey, SignaturePublicKey};
use crate::Error;
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

/// A builder for hybrid decryption operations.
#[derive(Default)]
pub struct HybridDecryptorBuilder;

impl HybridDecryptorBuilder {
    /// Creates a new `HybridDecryptorBuilder`.
    pub fn new() -> Self {
        Self
    }

    /// Configures decryption from an in-memory byte slice.
    pub fn slice(self, ciphertext: &[u8]) -> crate::Result<PendingInMemoryDecryptor> {
        let mid_level_pending =
            crate::hybrid::ordinary::PendingDecryptor::from_ciphertext(ciphertext)?;
        Ok(PendingInMemoryDecryptor {
            inner: mid_level_pending,
            aad: None,
            verification_key: None,
        })
    }

    /// Configures parallel decryption from an in-memory byte slice.
    pub fn slice_parallel(
        self,
        ciphertext: &[u8],
    ) -> crate::Result<PendingInMemoryParallelDecryptor> {
        let mid_level_pending =
            crate::hybrid::parallel::PendingDecryptor::from_ciphertext(ciphertext)?;
        Ok(PendingInMemoryParallelDecryptor {
            inner: mid_level_pending,
            aad: None,
            verification_key: None,
        })
    }

    /// Configures decryption from a synchronous `Read` stream.
    pub fn reader<R: Read>(self, reader: R) -> crate::Result<PendingStreamingDecryptor<R>> {
        let mid_level_pending = crate::hybrid::streaming::PendingDecryptor::from_reader(reader)?;
        Ok(PendingStreamingDecryptor {
            inner: mid_level_pending,
            aad: None,
            verification_key: None,
        })
    }

    /// Configures parallel decryption from a synchronous `Read` stream.
    pub fn reader_parallel<R: Read + Send>(
        self,
        reader: R,
    ) -> crate::Result<PendingParallelStreamingDecryptor<R>> {
        let mid_level_pending =
            crate::hybrid::parallel_streaming::PendingDecryptor::from_reader(reader)?;
        Ok(PendingParallelStreamingDecryptor {
            inner: mid_level_pending,
            aad: None,
            verification_key: None,
        })
    }

    /// [Async] Configures decryption from an asynchronous `Read` stream.
    #[cfg(feature = "async")]
    pub async fn async_reader<R: AsyncRead + Unpin>(
        self,
        reader: R,
    ) -> crate::Result<PendingAsyncStreamingDecryptor<R>> {
        let mid_level_pending =
            crate::hybrid::asynchronous::PendingDecryptor::from_reader(reader).await?;
        Ok(PendingAsyncStreamingDecryptor {
            inner: mid_level_pending,
            aad: None,
            verification_key: None,
        })
    }
}

/// A pending in-memory hybrid decryptor, waiting for the private key.
pub struct PendingInMemoryDecryptor<'a> {
    inner: crate::hybrid::ordinary::PendingDecryptor<'a>,
    aad: Option<Vec<u8>>,
    verification_key: Option<SignaturePublicKey>,
}

impl<'a> PendingInMemoryDecryptor<'a> {
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

    /// Supplies a private key directly from its wrapper for decryption
    pub fn with_key(self, key: AsymmetricPrivateKey) -> crate::Result<Vec<u8>> {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;

        let asymmetric_algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(Error::InvalidHeader)?;

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

        dispatch_asymmetric_key_bytes!(
            asymmetric_algorithm,
            key.as_bytes(),
            do_dispatch_symmetric,
        )
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

/// A pending parallel in-memory hybrid decryptor, waiting for the private key.
pub struct PendingInMemoryParallelDecryptor<'a> {
    inner: crate::hybrid::parallel::PendingDecryptor<'a>,
    aad: Option<Vec<u8>>,
    verification_key: Option<SignaturePublicKey>,
}

impl<'a> PendingInMemoryParallelDecryptor<'a> {
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

    /// Supplies a private key directly from its wrapper for decryption
    pub fn with_key(self, key: AsymmetricPrivateKey) -> crate::Result<Vec<u8>> {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;

        let asymmetric_algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(Error::InvalidHeader)?;

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

        dispatch_asymmetric_key_bytes!(
            asymmetric_algorithm,
            key.as_bytes(),
            do_dispatch_symmetric,
        )
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

/// A pending synchronous streaming hybrid decryptor.
pub struct PendingStreamingDecryptor<R: Read + 'static> {
    inner: crate::hybrid::streaming::PendingDecryptor<R>,
    aad: Option<Vec<u8>>,
    verification_key: Option<SignaturePublicKey>,
}

impl<R: Read + 'static> PendingStreamingDecryptor<R> {
    /// Returns a reference to the stream's header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the Key-Encrypting-Key ID from the stream's header.
    pub fn kek_id(&self) -> Option<&str> {
        self.header().payload.kek_id()
    }

    /// Returns the Signer-Key-ID from the stream's header.
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

    /// Supplies a private key directly from its wrapper for decryption
    pub fn with_key(self, key: AsymmetricPrivateKey) -> crate::Result<Box<dyn Read + 'static>> {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;

        let asymmetric_algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(Error::InvalidHeader)?;

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

        dispatch_asymmetric_key_bytes!(
            asymmetric_algorithm,
            key.as_bytes(),
            do_dispatch_symmetric,
        )
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

/// A pending parallel streaming hybrid decryptor.
pub struct PendingParallelStreamingDecryptor<R>
where
    R: Read + Send,
{
    inner: crate::hybrid::parallel_streaming::PendingDecryptor<R>,
    aad: Option<Vec<u8>>,
    verification_key: Option<SignaturePublicKey>,
}

impl<R> PendingParallelStreamingDecryptor<R>
where
    R: Read + Send,
{
    /// Returns a reference to the stream's header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the Key-Encrypting-Key ID from the stream's header.
    pub fn kek_id(&self) -> Option<&str> {
        self.header().payload.kek_id()
    }

    /// Returns the Signer-Key-ID from the stream's header.
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

    /// Supplies a private key from its wrapper and decrypts to the provided writer
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
            .ok_or(Error::InvalidHeader)?;

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

/// A pending asynchronous streaming hybrid decryptor.
#[cfg(feature = "async")]
pub struct PendingAsyncStreamingDecryptor<R: AsyncRead + Unpin> {
    inner: crate::hybrid::asynchronous::PendingDecryptor<R>,
    aad: Option<Vec<u8>>,
    verification_key: Option<SignaturePublicKey>,
}

#[cfg(feature = "async")]
impl<R: AsyncRead + Unpin> PendingAsyncStreamingDecryptor<R> {
    /// Returns a reference to the stream's header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the Key-Encrypting-Key ID from the stream's header.
    pub fn kek_id(&self) -> Option<&str> {
        self.header().payload.kek_id()
    }

    /// Returns the Signer-Key-ID from the stream's header.
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
    pub async fn with_verification_key(
        mut self,
        verification_key: SignaturePublicKey,
    ) -> crate::Result<Self> {
        self.verification_key = Some(verification_key);
        Ok(self)
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
            .ok_or(Error::InvalidHeader)?;

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

        dispatch_asymmetric_key_bytes!(
            asymmetric_algorithm,
            key.as_bytes(),
            do_dispatch_symmetric,
        )
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


