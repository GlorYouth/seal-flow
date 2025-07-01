use crate::algorithms::traits::SymmetricAlgorithm;
use crate::keys::SymmetricKey;
use seal_crypto::zeroize::Zeroizing;
use std::io::{Read, Write};
use tokio::io::AsyncWrite;

/// A context for symmetric encryption operations, allowing selection of execution mode.
pub struct SymmetricEncryptor {
    pub(crate) key: SymmetricKey,
    pub(crate) key_id: String,
    pub(crate) aad: Option<Vec<u8>>,
}

impl SymmetricEncryptor {
    /// Sets the Associated Data (AAD) for this encryption operation.
    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }

    /// Encrypts the given plaintext in-memory.
    pub fn to_vec<S: SymmetricAlgorithm>(self, plaintext: &[u8]) -> crate::Result<Vec<u8>>
    where
        S::Key: From<Zeroizing<Vec<u8>>> + Clone + Send + Sync,
    {
        crate::symmetric::ordinary::encrypt::<S>(
            S::Key::from(self.key.into_bytes()),
            plaintext,
            self.key_id,
            self.aad.as_deref(),
        )
    }

    /// Encrypts the given plaintext in-memory using parallel processing.
    pub fn to_vec_parallel<S: SymmetricAlgorithm>(self, plaintext: &[u8]) -> crate::Result<Vec<u8>>
    where
        S::Key: From<Zeroizing<Vec<u8>>> + Clone + Send + Sync,
    {
        crate::symmetric::parallel::encrypt::<S>(
            S::Key::from(self.key.into_bytes()),
            plaintext,
            self.key_id,
            self.aad.as_deref(),
        )
    }

    /// Creates a streaming encryptor that writes to the given `Write` implementation.
    pub fn into_writer<S: SymmetricAlgorithm, W: Write>(
        self,
        writer: W,
    ) -> crate::Result<crate::symmetric::streaming::Encryptor<W, S>>
    where
        S::Key: From<Zeroizing<Vec<u8>>> + Clone + Send + Sync,
    {
        crate::symmetric::streaming::Encryptor::new(
            writer,
            S::Key::from(self.key.into_bytes()),
            self.key_id,
            self.aad.as_deref(),
        )
    }

    /// [Async] Creates an asynchronous streaming encryptor.
    #[cfg(feature = "async")]
    pub async fn into_async_writer<S: SymmetricAlgorithm, W: AsyncWrite + Unpin>(
        self,
        writer: W,
    ) -> crate::Result<crate::symmetric::asynchronous::Encryptor<W, S>>
    where
        S::Key: From<Zeroizing<Vec<u8>>> + Clone + Send + Sync,
    {
        crate::symmetric::asynchronous::Encryptor::new(
            writer,
            S::Key::from(self.key.into_bytes()),
            self.key_id,
            self.aad.as_deref(),
        )
        .await
    }

    /// Encrypts data from a reader and writes to a writer using parallel processing.
    pub fn pipe_parallel<S: SymmetricAlgorithm, R, W>(
        self,
        reader: R,
        writer: W,
    ) -> crate::Result<()>
    where
        R: Read + Send,
        W: Write,
        S::Key: From<Zeroizing<Vec<u8>>> + Clone + Send + Sync,
    {
        crate::symmetric::parallel_streaming::encrypt::<S, R, W>(
            S::Key::from(self.key.into_bytes()),
            reader,
            writer,
            self.key_id,
            self.aad.as_deref(),
        )
    }
}
