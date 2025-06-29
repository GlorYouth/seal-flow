use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::Header;
use crate::prelude::SymmetricKeyProvider;
use crate::Error;
use std::io::{Read, Write};
use tokio::io::AsyncRead;

macro_rules! dispatch_symmetric_algorithm {
    // Internal rule for processing the algorithm list.
    (@internal $algorithm:expr, $key:expr, $callback:ident, $extra_args:tt,
     $(($algo_enum:path, $algo_type:ty, $key_enum:path)),*
    ) => {
        {
            use crate::common::algorithms::SymmetricAlgorithm as SymmetricAlgorithmEnum;
            use crate::keys::SymmetricKey;
            use seal_crypto::schemes::symmetric::aes_gcm::{Aes128Gcm, Aes256Gcm};
            use seal_crypto::schemes::symmetric::chacha20_poly1305::{
                ChaCha20Poly1305, XChaCha20Poly1305,
            };

            match $algorithm {
                $(
                    $algo_enum => match $key {
                        $key_enum(k) => $callback!(k, $algo_type, $extra_args),
                        _ => Err(Error::MismatchedKeyType),
                    },
                )*
            }
        }
    };

    // Public entry point for the macro.
    ($algorithm:expr, $key:expr, $callback:ident, $($extra_args:tt)*) => {
        dispatch_symmetric_algorithm!(@internal $algorithm, $key, $callback, ($($extra_args)*),
            (SymmetricAlgorithmEnum::Aes128Gcm, Aes128Gcm, SymmetricKey::Aes128Gcm),
            (SymmetricAlgorithmEnum::Aes256Gcm, Aes256Gcm, SymmetricKey::Aes256Gcm),
            (SymmetricAlgorithmEnum::ChaCha20Poly1305, ChaCha20Poly1305, SymmetricKey::Chacha20Poly1305),
            (SymmetricAlgorithmEnum::XChaCha20Poly1305, XChaCha20Poly1305, SymmetricKey::XChaCha20Poly1305)
        )
    };
}

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
        Ok(PendingInMemoryDecryptor {
            inner: mid_level_pending,
            aad: None,
        })
    }

    /// Configures parallel decryption from an in-memory byte slice.
    pub fn slice_parallel(
        self,
        ciphertext: &[u8],
    ) -> crate::Result<PendingInMemoryParallelDecryptor> {
        let mid_level_pending =
            crate::symmetric::parallel::PendingDecryptor::from_ciphertext(ciphertext)?;
        Ok(PendingInMemoryParallelDecryptor {
            inner: mid_level_pending,
            aad: None,
        })
    }

    /// Configures decryption from a synchronous `Read` stream.
    pub fn reader<R: Read>(self, reader: R) -> crate::Result<PendingStreamingDecryptor<R>> {
        let mid_level_pending = crate::symmetric::streaming::PendingDecryptor::from_reader(reader)?;
        Ok(PendingStreamingDecryptor {
            inner: mid_level_pending,
            aad: None,
        })
    }

    /// Configures parallel decryption from a synchronous `Read` stream.
    pub fn reader_parallel<R: Read + Send>(
        self,
        reader: R,
    ) -> crate::Result<PendingParallelStreamingDecryptor<R>> {
        let mid_level_pending =
            crate::symmetric::parallel_streaming::PendingDecryptor::from_reader(reader)?;
        Ok(PendingParallelStreamingDecryptor {
            inner: mid_level_pending,
            aad: None,
        })
    }

    /// Begins an asynchronous streaming decryption operation.
    #[cfg(feature = "async")]
    pub async fn async_reader<R: AsyncRead + Unpin>(
        self,
        reader: R,
    ) -> crate::Result<PendingAsyncStreamingDecryptor<R>> {
        let mid_level_pending =
            crate::symmetric::asynchronous::PendingDecryptor::from_reader(reader).await?;
        Ok(PendingAsyncStreamingDecryptor {
            inner: mid_level_pending,
            aad: None,
        })
    }
}

/// A pending in-memory decryptor, waiting for a key.
pub struct PendingInMemoryDecryptor<'a> {
    inner: crate::symmetric::ordinary::PendingDecryptor<'a>,
    aad: Option<Vec<u8>>,
}

impl<'a> PendingInMemoryDecryptor<'a> {
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

    /// Supplies a `SymmetricKeyProvider` to automatically look up the key and decrypt.
    pub fn with_provider<P: SymmetricKeyProvider>(self, provider: &P) -> crate::Result<Vec<u8>> {
        let key_id = self.key_id().ok_or(Error::InvalidHeader)?;
        let key = provider
            .get_symmetric_key(key_id)
            .ok_or(Error::KeyNotFound)?;
        let algorithm = self.inner.header().payload.symmetric_algorithm();

        macro_rules! do_decrypt {
            ($k:ident, $S:ty, ()) => {
                self.inner
                    .into_plaintext::<$S>($k.clone(), self.aad.as_deref())
            };
        }

        dispatch_symmetric_algorithm!(algorithm, key, do_decrypt,)
    }

    /// Supplies the key and returns the decrypted plaintext.
    pub fn with_key<S: SymmetricAlgorithm>(self, key: S::Key) -> crate::Result<Vec<u8>>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner
            .into_plaintext::<S>(key.clone(), self.aad.as_deref())
    }
}

/// A pending parallel in-memory decryptor, waiting for a key.
pub struct PendingInMemoryParallelDecryptor<'a> {
    inner: crate::symmetric::parallel::PendingDecryptor<'a>,
    aad: Option<Vec<u8>>,
}

impl<'a> PendingInMemoryParallelDecryptor<'a> {
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

    /// Supplies a `SymmetricKeyProvider` to automatically look up the key and decrypt.
    pub fn with_provider<P: SymmetricKeyProvider>(self, provider: &P) -> crate::Result<Vec<u8>> {
        let key_id = self.key_id().ok_or(Error::InvalidHeader)?;
        let key = provider
            .get_symmetric_key(key_id)
            .ok_or(Error::KeyNotFound)?;
        let algorithm = self.inner.header().payload.symmetric_algorithm();

        macro_rules! do_decrypt {
            ($k:ident, $S:ty, ()) => {
                self.inner
                    .into_plaintext::<$S>($k.clone(), self.aad.as_deref())
            };
        }

        dispatch_symmetric_algorithm!(algorithm, key, do_decrypt,)
    }

    /// Supplies the key and returns the decrypted plaintext.
    pub fn with_key<S: SymmetricAlgorithm>(self, key: S::Key) -> crate::Result<Vec<u8>>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner
            .into_plaintext::<S>(key.clone(), self.aad.as_deref())
    }
}

/// A pending synchronous streaming decryptor, waiting for a key.
pub struct PendingStreamingDecryptor<R: Read> {
    inner: crate::symmetric::streaming::PendingDecryptor<R>,
    aad: Option<Vec<u8>>,
}

impl<R: Read> PendingStreamingDecryptor<R> {
    /// Returns a reference to the stream's header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the key ID from the stream's header.
    pub fn key_id(&self) -> Option<&str> {
        self.header().payload.key_id()
    }

    /// Sets the Associated Data (AAD) for this decryption operation.
    /// The AAD must match the value provided during encryption.
    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }

    /// Supplies a `SymmetricKeyProvider` to automatically look up the key and create a decryptor.
    pub fn with_provider<'s, P>(self, provider: &'s P) -> crate::Result<Box<dyn Read + 's>>
    where
        P: SymmetricKeyProvider,
        R: 's,
    {
        let key_id = self.key_id().ok_or(Error::InvalidHeader)?;
        let key = provider
            .get_symmetric_key(key_id)
            .ok_or(Error::KeyNotFound)?;
        let algorithm = self.inner.header().payload.symmetric_algorithm();

        macro_rules! do_decrypt {
            ($k:ident, $S:ty, ()) => {
                self.inner
                    .into_decryptor::<$S>($k.clone(), self.aad.as_deref())
                    .map(|d| Box::new(d) as Box<dyn Read>)
            };
        }

        dispatch_symmetric_algorithm!(algorithm, key, do_decrypt,)
    }
    /// Supplies the key and returns a fully initialized `Decryptor`.
    pub fn with_key<S: SymmetricAlgorithm>(
        self,
        key: S::Key,
    ) -> crate::Result<crate::symmetric::streaming::Decryptor<R, S>>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner.into_decryptor(key.clone(), self.aad.as_deref())
    }
}

/// A pending parallel streaming decryptor, waiting for a key.
pub struct PendingParallelStreamingDecryptor<R>
where
    R: Read + Send,
{
    inner: crate::symmetric::parallel_streaming::PendingDecryptor<R>,
    aad: Option<Vec<u8>>,
}

impl<R> PendingParallelStreamingDecryptor<R>
where
    R: Read + Send,
{
    /// Returns a reference to the stream's header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the key ID from the stream's header.
    pub fn key_id(&self) -> Option<&str> {
        self.header().payload.key_id()
    }

    /// Sets the Associated Data (AAD) for this decryption operation.
    /// The AAD must match the value provided during encryption.
    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }

    /// Supplies a `SymmetricKeyProvider` to automatically look up the key and decrypt the stream.
    pub fn with_provider<W, P>(self, provider: &P, writer: W) -> crate::Result<()>
    where
        W: Write + Send,
        P: SymmetricKeyProvider,
    {
        let key_id = self.key_id().ok_or(Error::InvalidHeader)?;
        let key = provider
            .get_symmetric_key(key_id)
            .ok_or(Error::KeyNotFound)?;
        let algorithm = self.inner.header().payload.symmetric_algorithm();

        macro_rules! do_decrypt {
            ($k:ident, $S:ty, ($writer:ident)) => {
                self.inner
                    .decrypt_to_writer::<$S, W>($k.clone(), $writer, self.aad.as_deref())
            };
        }

        dispatch_symmetric_algorithm!(algorithm, key, do_decrypt, writer)
    }
    /// Supplies the key and decrypts the stream, writing to the provided writer.
    pub fn with_key_to_writer<S: SymmetricAlgorithm, W: Write>(
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

/// A pending asynchronous streaming decryptor, waiting for a key.
#[cfg(feature = "async")]
pub struct PendingAsyncStreamingDecryptor<R: AsyncRead + Unpin> {
    inner: crate::symmetric::asynchronous::PendingDecryptor<R>,
    aad: Option<Vec<u8>>,
}

#[cfg(feature = "async")]
impl<R: AsyncRead + Unpin> PendingAsyncStreamingDecryptor<R> {
    /// Returns a reference to the stream's header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the key ID from the stream's header.
    pub fn key_id(&self) -> Option<&str> {
        self.header().payload.key_id()
    }

    /// Sets the Associated Data (AAD) for this decryption operation.
    /// The AAD must match the value provided during encryption.
    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }

    /// Supplies a `SymmetricKeyProvider` to automatically look up the key and create a decryptor.
    pub fn with_provider<'s, P>(
        self,
        provider: &'s P,
    ) -> crate::Result<Box<dyn AsyncRead + Unpin + 's>>
    where
        P: SymmetricKeyProvider,
        R: 's,
    {
        let key_id = self.key_id().ok_or(Error::InvalidHeader)?;
        let key = provider
            .get_symmetric_key(key_id)
            .ok_or(Error::KeyNotFound)?;
        let algorithm = self.inner.header().payload.symmetric_algorithm();

        macro_rules! do_decrypt {
            ($k:ident, $S:ty, ()) => {
                self.inner
                    .into_decryptor::<$S>($k.clone(), self.aad.as_deref())
                    .map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin>)
            };
        }

        dispatch_symmetric_algorithm!(algorithm, key, do_decrypt,)
    }

    /// Supplies the key and returns a fully initialized `Decryptor`.
    pub fn with_key<S: SymmetricAlgorithm>(
        self,
        key: S::Key,
    ) -> crate::Result<crate::symmetric::asynchronous::Decryptor<R, S>>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner.into_decryptor(key.clone(), self.aad.as_deref())
    }
}
