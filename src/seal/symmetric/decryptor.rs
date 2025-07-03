use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::algorithms::SymmetricAlgorithm as SymmetricAlgorithmEnum;
use crate::common::header::Header;
use crate::common::PendingImpl;
use crate::keys::SymmetricKey;
use std::io::{Read, Write};
use tokio::io::AsyncRead;

use seal_crypto::prelude::*;
use seal_crypto::schemes::symmetric::aes_gcm::{Aes128Gcm, Aes256Gcm};
use seal_crypto::schemes::symmetric::chacha20_poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};

/// 创建一个宏来处理从原始字节转换为特定算法密钥的过程
/// 这个宏替代了旧的枚举类型调度方式，直接从字节转换到密钥
macro_rules! dispatch_symmetric_key_bytes {
    // 内部规则，处理算法列表
    (@internal $algorithm:expr, $key_bytes:expr, $callback:ident, $extra_args:tt,
     $(($algo_enum:path, $algo_type:ty)),*
    ) => {
        {
            match $algorithm {
                $(
                    $algo_enum => {
                        let key = <$algo_type as SymmetricKeySet>::Key::from_bytes($key_bytes)?;
                        $callback!(key, $algo_type, $extra_args)
                    },
                )*
            }
        }
    };

    // 宏的公共入口点
    ($algorithm:expr, $key_bytes:expr, $callback:ident, $($extra_args:tt)*) => {
        dispatch_symmetric_key_bytes!(@internal $algorithm, $key_bytes, $callback, ($($extra_args)*),
            (SymmetricAlgorithmEnum::Aes128Gcm, Aes128Gcm),
            (SymmetricAlgorithmEnum::Aes256Gcm, Aes256Gcm),
            (SymmetricAlgorithmEnum::ChaCha20Poly1305, ChaCha20Poly1305),
            (SymmetricAlgorithmEnum::XChaCha20Poly1305, XChaCha20Poly1305)
        )
    };
}

/// A generic pending symmetric decryptor, waiting for configuration and key.
/// This struct unifies the logic for various decryption modes (in-memory, streaming, etc.).
pub struct PendingDecryptor<T> {
    inner: T,
    aad: Option<Vec<u8>>,
}

impl<T: PendingImpl> PendingDecryptor<T> {
    /// Creates a new `PendingDecryptor` with the given inner implementation.
    fn new(inner: T) -> Self {
        Self { inner, aad: None }
    }

    /// Returns a reference to the header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the key ID from the header.
    pub fn key_id(&self) -> Option<&str> {
        self.header().payload.key_id()
    }

    /// Sets the Associated Data (AAD) for this decryption operation.
    /// The AAD must match the value provided during encryption.
    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }
}

/// A type alias for a pending in-memory symmetric decryptor.
pub type PendingInMemoryDecryptor<'a> =
    PendingDecryptor<crate::symmetric::ordinary::PendingDecryptor<'a>>;
/// A type alias for a pending parallel in-memory symmetric decryptor.
pub type PendingInMemoryParallelDecryptor<'a> =
    PendingDecryptor<crate::symmetric::parallel::PendingDecryptor<'a>>;
/// A type alias for a pending synchronous streaming symmetric decryptor.
pub type PendingStreamingDecryptor<R> =
    PendingDecryptor<crate::symmetric::streaming::PendingDecryptor<R>>;
/// A type alias for a pending parallel streaming symmetric decryptor.
pub type PendingParallelStreamingDecryptor<R> =
    PendingDecryptor<crate::symmetric::parallel_streaming::PendingDecryptor<R>>;
/// A type alias for a pending asynchronous streaming symmetric decryptor.
#[cfg(feature = "async")]
pub type PendingAsyncStreamingDecryptor<R> =
    PendingDecryptor<crate::symmetric::asynchronous::PendingDecryptor<R>>;

/// A builder for symmetric decryption operations.
#[derive(Default)]
pub struct SymmetricDecryptorBuilder;

impl SymmetricDecryptorBuilder {
    /// Creates a new `SymmetricDecryptorBuilder`.
    pub fn new() -> Self {
        Self
    }

    /// Configures decryption from an in-memory byte slice.
    ///
    /// Returns a `PendingInMemoryDecryptor` that allows inspecting the header
    /// before providing the key.
    pub fn slice(self, ciphertext: &[u8]) -> crate::Result<PendingInMemoryDecryptor> {
        let mid_level_pending =
            crate::symmetric::ordinary::PendingDecryptor::from_ciphertext(ciphertext)?;
        Ok(PendingDecryptor::new(mid_level_pending))
    }

    /// Configures parallel decryption from an in-memory byte slice.
    pub fn slice_parallel(
        self,
        ciphertext: &[u8],
    ) -> crate::Result<PendingInMemoryParallelDecryptor> {
        let mid_level_pending =
            crate::symmetric::parallel::PendingDecryptor::from_ciphertext(ciphertext)?;
        Ok(PendingDecryptor::new(mid_level_pending))
    }

    /// Configures decryption from a synchronous `Read` stream.
    pub fn reader<R: Read>(self, reader: R) -> crate::Result<PendingStreamingDecryptor<R>> {
        let mid_level_pending = crate::symmetric::streaming::PendingDecryptor::from_reader(reader)?;
        Ok(PendingDecryptor::new(mid_level_pending))
    }

    /// Configures parallel decryption from a synchronous `Read` stream.
    pub fn reader_parallel<R: Read + Send>(
        self,
        reader: R,
    ) -> crate::Result<PendingParallelStreamingDecryptor<R>> {
        let mid_level_pending =
            crate::symmetric::parallel_streaming::PendingDecryptor::from_reader(reader)?;
        Ok(PendingDecryptor::new(mid_level_pending))
    }

    /// Begins an asynchronous streaming decryption operation.
    #[cfg(feature = "async")]
    pub async fn async_reader<R: AsyncRead + Unpin>(
        self,
        reader: R,
    ) -> crate::Result<PendingAsyncStreamingDecryptor<R>> {
        let mid_level_pending =
            crate::symmetric::asynchronous::PendingDecryptor::from_reader(reader).await?;
        Ok(PendingDecryptor::new(mid_level_pending))
    }
}

impl<'a> PendingInMemoryDecryptor<'a> {
    /// Supplies a key from its raw bytes for decryption.
    pub fn with_key(self, key: SymmetricKey) -> crate::Result<Vec<u8>> {
        let algorithm = self.inner.header().payload.symmetric_algorithm();

        // 使用新的宏来替换重复的match语句
        macro_rules! do_decrypt {
            ($k:ident, $S:ty, ()) => {
                self.inner.into_plaintext::<$S>($k, self.aad.as_deref())
            };
        }

        dispatch_symmetric_key_bytes!(algorithm, key.as_bytes(), do_decrypt,)
    }

    /// Supplies the typed key and returns the decrypted plaintext.
    pub fn with_typed_key<S: SymmetricAlgorithm>(self, key: S::Key) -> crate::Result<Vec<u8>>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner
            .into_plaintext::<S>(key.clone(), self.aad.as_deref())
    }
}

impl<'a> PendingInMemoryParallelDecryptor<'a> {
    /// Supplies a key from its raw bytes for decryption.
    pub fn with_key(self, key: SymmetricKey) -> crate::Result<Vec<u8>> {
        let algorithm = self.inner.header().payload.symmetric_algorithm();

        // 使用新的宏来替换重复的match语句
        macro_rules! do_decrypt {
            ($k:ident, $S:ty, ()) => {
                self.inner.into_plaintext::<$S>($k, self.aad.as_deref())
            };
        }

        dispatch_symmetric_key_bytes!(algorithm, key.as_bytes(), do_decrypt,)
    }

    /// Supplies the typed key and returns the decrypted plaintext.
    pub fn with_typed_key<S: SymmetricAlgorithm>(self, key: S::Key) -> crate::Result<Vec<u8>>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner
            .into_plaintext::<S>(key.clone(), self.aad.as_deref())
    }
}

impl<R: Read> PendingStreamingDecryptor<R> {
    /// Supplies a key from its raw bytes for decryption.
    pub fn with_key<'s>(self, key: SymmetricKey) -> crate::Result<Box<dyn Read + 's>>
    where
        R: 's,
    {
        let algorithm = self.inner.header().payload.symmetric_algorithm();

        // 使用新的宏来替换重复的match语句
        macro_rules! do_decrypt {
            ($k:ident, $S:ty, ()) => {
                self.inner
                    .into_decryptor::<$S>($k, self.aad.as_deref())
                    .map(|d| Box::new(d) as Box<dyn Read>)
            };
        }

        dispatch_symmetric_key_bytes!(algorithm, key.as_bytes(), do_decrypt,)
    }

    /// Supplies the typed key and returns a fully initialized `Decryptor`.
    pub fn with_typed_key<S: SymmetricAlgorithm>(
        self,
        key: S::Key,
    ) -> crate::Result<crate::symmetric::streaming::Decryptor<R, S>>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner.into_decryptor(key.clone(), self.aad.as_deref())
    }
}

impl<R> PendingParallelStreamingDecryptor<R>
where
    R: Read + Send,
{
    /// Supplies a key from its raw bytes and decrypts to the provided writer.
    pub fn with_key_to_writer<W: Write>(self, key: SymmetricKey, writer: W) -> crate::Result<()> {
        let algorithm = self.inner.header().payload.symmetric_algorithm();

        // 使用新的宏来替换重复的match语句
        macro_rules! do_decrypt {
            ($k:ident, $S:ty, ($writer:ident)) => {
                self.inner
                    .decrypt_to_writer::<$S, W>($k, $writer, self.aad.as_deref())
            };
        }

        dispatch_symmetric_key_bytes!(algorithm, key.as_bytes(), do_decrypt, writer)
    }

    /// Supplies the typed key and decrypts the stream, writing to the provided writer.
    pub fn with_typed_key_to_writer<S: SymmetricAlgorithm, W: Write>(
        self,
        key: S::Key,
        writer: W,
    ) -> crate::Result<()>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner
            .decrypt_to_writer::<S, W>(key.clone(), writer, self.aad.as_deref())
    }
}

#[cfg(feature = "async")]
impl<R: AsyncRead + Unpin> PendingAsyncStreamingDecryptor<R> {
    /// Supplies a key from its raw bytes for decryption.
    pub fn with_key<'s>(self, key: SymmetricKey) -> crate::Result<Box<dyn AsyncRead + Unpin + 's>>
    where
        R: 's,
    {
        let algorithm = self.inner.header().payload.symmetric_algorithm();

        // 使用新的宏来替换重复的match语句
        macro_rules! do_decrypt {
            ($k:ident, $S:ty, ()) => {
                self.inner
                    .into_decryptor::<$S>($k, self.aad.as_deref())
                    .map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin>)
            };
        }

        dispatch_symmetric_key_bytes!(algorithm, key.as_bytes(), do_decrypt,)
    }

    /// Supplies the typed key and returns a fully initialized `Decryptor`.
    pub fn with_typed_key<S: SymmetricAlgorithm>(
        self,
        key: S::Key,
    ) -> crate::Result<crate::symmetric::asynchronous::Decryptor<R, S>>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner.into_decryptor(key.clone(), self.aad.as_deref())
    }
}
