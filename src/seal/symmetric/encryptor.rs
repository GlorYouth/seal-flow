use crate::algorithms::traits::SymmetricAlgorithm;
use std::io::{Read, Write};
use std::marker::PhantomData;
use tokio::io::AsyncWrite;

/// A context for symmetric encryption operations, allowing selection of execution mode.
pub struct SymmetricEncryptor<'a, S: SymmetricAlgorithm> {
    pub(crate) key: &'a S::Key,
    pub(crate) key_id: String,
    pub(crate) aad: Option<Vec<u8>>,
    pub(crate) _phantom: PhantomData<S>,
}

impl<'a, S: SymmetricAlgorithm> SymmetricEncryptor<'a, S>
where
    S::Key: Clone + Send + Sync,
{
    /// Sets the Associated Data (AAD) for this encryption operation.
    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }

    /// Encrypts the given plaintext in-memory.
    pub fn to_vec(self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        crate::symmetric::ordinary::encrypt::<S>(
            self.key.clone(),
            plaintext,
            self.key_id,
            self.aad.as_deref(),
        )
    }

    /// Encrypts the given plaintext in-memory using parallel processing.
    pub fn to_vec_parallel(self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        crate::symmetric::parallel::encrypt::<S>(
            self.key.clone(),
            plaintext,
            self.key_id,
            self.aad.as_deref(),
        )
    }

    /// Creates a streaming encryptor that writes to the given `Write` implementation.
    pub fn into_writer<W: Write>(
        self,
        writer: W,
    ) -> crate::Result<crate::symmetric::streaming::Encryptor<W, S>> {
        crate::symmetric::streaming::Encryptor::new(
            writer,
            self.key.clone(),
            self.key_id,
            self.aad.as_deref(),
        )
    }

    /// [Async] Creates an asynchronous streaming encryptor.
    #[cfg(feature = "async")]
    pub async fn into_async_writer<W: AsyncWrite + Unpin>(
        self,
        writer: W,
    ) -> crate::Result<crate::symmetric::asynchronous::Encryptor<W, S>> {
        crate::symmetric::asynchronous::Encryptor::new(
            writer,
            self.key.clone(),
            self.key_id,
            self.aad.as_deref(),
        )
        .await
    }

    /// Encrypts data from a reader and writes to a writer using parallel processing.
    pub fn pipe_parallel<R, W>(self, reader: R, writer: W) -> crate::Result<()>
    where
        R: Read + Send,
        W: Write,
    {
        crate::symmetric::parallel_streaming::encrypt::<S, R, W>(
            self.key.clone(),
            reader,
            writer,
            self.key_id,
            self.aad.as_deref(),
        )
    }
}
