use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::Header;
use std::io::{Read, Write};
use std::marker::PhantomData;
use tokio::io::{AsyncRead, AsyncWrite};

/// A factory for creating symmetric encryption and decryption executors.
/// This struct is the main entry point for the high-level symmetric API.
#[derive(Default)]
pub struct SymmetricSeal;

impl SymmetricSeal {
    /// Creates a new `SymmetricSeal` factory.
    pub fn new() -> Self {
        Self
    }

    /// Begins a symmetric encryption operation.
    ///
    /// This captures the essential encryption parameters (algorithm, key, key ID)
    /// and returns a context object. You can then call methods on this context
    /// to select the desired execution mode (e.g., in-memory, streaming).
    pub fn encrypt<'a, S>(
        &self,
        key: &'a S::Key,
        key_id: String,
    ) -> SymmetricEncryptor<'a, S>
    where
        S: SymmetricAlgorithm,
        S::Key: Clone + Send + Sync,
    {
        SymmetricEncryptor {
            key,
            key_id,
            _phantom: PhantomData,
        }
    }

    /// Begins a decryption operation.
    ///
    /// This returns a builder that you can use to configure the decryptor
    /// based on the source of the ciphertext (e.g., from a slice or a stream).
    pub fn decrypt(&self) -> SymmetricDecryptorBuilder {
        SymmetricDecryptorBuilder::new()
    }
}

/// A context for symmetric encryption operations, allowing selection of execution mode.
pub struct SymmetricEncryptor<'a, S: SymmetricAlgorithm> {
    key: &'a S::Key,
    key_id: String,
    _phantom: PhantomData<S>,
}

impl<'a, S: SymmetricAlgorithm> SymmetricEncryptor<'a, S>
where
    S::Key: Clone + Send + Sync,
{
    /// Encrypts the given plaintext in-memory.
    pub fn to_vec(self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        crate::symmetric::ordinary::encrypt::<S>(self.key, plaintext, self.key_id)
    }

    /// Encrypts the given plaintext in-memory using parallel processing.
    pub fn to_vec_parallel(self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        crate::symmetric::parallel::encrypt::<S>(self.key, plaintext, self.key_id)
    }

    /// Creates a streaming encryptor that writes to the given `Write` implementation.
    pub fn into_writer<W: Write>(
        self,
        writer: W,
    ) -> crate::Result<crate::symmetric::streaming::Encryptor<W, S>> {
        crate::symmetric::streaming::Encryptor::new(writer, self.key.clone(), self.key_id)
    }

    /// [Async] Creates an asynchronous streaming encryptor.
    #[cfg(feature = "async")]
    pub async fn into_async_writer<W: AsyncWrite + Unpin>(
        self,
        writer: W,
    ) -> crate::Result<crate::symmetric::asynchronous::Encryptor<W, S>> {
        crate::symmetric::asynchronous::Encryptor::new(writer, self.key.clone(), self.key_id).await
    }

    /// Encrypts data from a reader and writes to a writer using parallel processing.
    pub fn pipe_parallel<R, W>(self, reader: R, writer: W) -> crate::Result<()>
    where
        R: Read + Send,
        W: Write + Send,
    {
        crate::symmetric::parallel_streaming::encrypt::<S, R, W>(
            self.key,
            reader,
            writer,
            self.key_id,
        )
    }
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
    pub fn from_slice<'a>(
        &self,
        ciphertext: &'a [u8],
    ) -> crate::Result<PendingInMemoryDecryptor<'a>> {
        let mid_level_pending =
            crate::symmetric::ordinary::PendingDecryptor::from_ciphertext(ciphertext)?;
        Ok(PendingInMemoryDecryptor {
            inner: mid_level_pending,
        })
    }

    /// Configures parallel decryption from an in-memory byte slice.
    pub fn from_slice_parallel<'a>(
        &self,
        ciphertext: &'a [u8],
    ) -> crate::Result<PendingInMemoryParallelDecryptor<'a>> {
        let mid_level_pending =
            crate::symmetric::parallel::PendingDecryptor::from_ciphertext(ciphertext)?;
        Ok(PendingInMemoryParallelDecryptor {
            inner: mid_level_pending,
        })
    }

    /// Configures decryption from a synchronous `Read` stream.
    pub fn from_reader<R: Read>(
        &self,
        reader: R,
    ) -> crate::Result<PendingStreamingDecryptor<R>> {
        let mid_level_pending =
            crate::symmetric::streaming::PendingDecryptor::from_reader(reader)?;
        Ok(PendingStreamingDecryptor {
            inner: mid_level_pending,
        })
    }

    /// Configures parallel decryption from a synchronous `Read` stream.
    pub fn from_reader_parallel<R: Read + Send>(
        &self,
        reader: R,
    ) -> crate::Result<PendingParallelStreamingDecryptor<R>> {
        let mid_level_pending =
            crate::symmetric::parallel_streaming::PendingDecryptor::from_reader(reader)?;
        Ok(PendingParallelStreamingDecryptor {
            inner: mid_level_pending,
        })
    }

    /// Begins an asynchronous streaming decryption operation.
    #[cfg(feature = "async")]
    pub async fn from_async_reader<R: AsyncRead + Unpin>(
        &self,
        reader: R,
    ) -> crate::Result<PendingAsyncStreamingDecryptor<R>> {
        let mid_level_pending =
            crate::symmetric::asynchronous::PendingDecryptor::from_reader(reader).await?;
        Ok(PendingAsyncStreamingDecryptor {
            inner: mid_level_pending,
        })
    }
}

/// A pending in-memory decryptor, waiting for a key.
pub struct PendingInMemoryDecryptor<'a> {
    inner: crate::symmetric::ordinary::PendingDecryptor<'a>,
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

    /// Supplies the key and returns the decrypted plaintext.
    pub fn with_key<S: SymmetricAlgorithm>(self, key: &S::Key) -> crate::Result<Vec<u8>>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner.into_plaintext::<S>(key)
    }
}

/// A pending parallel in-memory decryptor, waiting for a key.
pub struct PendingInMemoryParallelDecryptor<'a> {
    inner: crate::symmetric::parallel::PendingDecryptor<'a>,
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

    /// Supplies the key and returns the decrypted plaintext.
    pub fn with_key<S: SymmetricAlgorithm>(self, key: &S::Key) -> crate::Result<Vec<u8>>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner.into_plaintext::<S>(key)
    }
}

/// A pending synchronous streaming decryptor, waiting for a key.
pub struct PendingStreamingDecryptor<R: Read> {
    inner: crate::symmetric::streaming::PendingDecryptor<R>,
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

    /// Supplies the key and returns a fully initialized `Decryptor`.
    pub fn with_key<S: SymmetricAlgorithm>(
        self,
        key: &S::Key,
    ) -> crate::Result<crate::symmetric::streaming::Decryptor<R, S>>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner.into_decryptor(key)
    }
}

/// A pending parallel streaming decryptor, waiting for a key.
pub struct PendingParallelStreamingDecryptor<R>
where
    R: Read + Send,
{
    inner: crate::symmetric::parallel_streaming::PendingDecryptor<R>,
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

    /// Supplies the key and decrypts the stream, writing to the provided writer.
    pub fn with_key_to_writer<S: SymmetricAlgorithm, W: Write>(
        self,
        key: &S::Key,
        writer: W,
    ) -> crate::Result<()>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner.decrypt_to_writer::<S, W>(key, writer)
    }
}

/// A pending asynchronous streaming decryptor, waiting for a key.
#[cfg(feature = "async")]
pub struct PendingAsyncStreamingDecryptor<R: AsyncRead + Unpin> {
    inner: crate::symmetric::asynchronous::PendingDecryptor<R>,
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

    /// Supplies the key and returns a fully initialized `Decryptor`.
    pub fn with_key<S: SymmetricAlgorithm>(
        self,
        key: &S::Key,
    ) -> crate::Result<crate::symmetric::asynchronous::Decryptor<R, S>>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner.into_decryptor(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::prelude::*;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
    use std::collections::HashMap;
    use std::io::{Cursor, Read, Write};
    #[cfg(feature = "async")]
    use tokio::io::AsyncReadExt;

    const TEST_KEY_ID: &str = "test-key";

    fn get_test_data() -> &'static [u8] {
        b"This is a reasonably long test message to ensure that we cross chunk boundaries."
    }

    #[test]
    fn test_in_memory_roundtrip() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = get_test_data();

        let seal = SymmetricSeal::new();
        let encrypted = seal
            .encrypt::<Aes256Gcm>(&key, TEST_KEY_ID.to_string())
            .to_vec(plaintext)
            .unwrap();
        let pending = seal.decrypt().from_slice(&encrypted).unwrap();
        assert_eq!(pending.key_id(), Some(TEST_KEY_ID));
        let decrypted = pending.with_key::<Aes256Gcm>(&key).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_in_memory_parallel_roundtrip() -> crate::Result<()> {
        let key = Aes256Gcm::generate_key()?;
        let plaintext = get_test_data();
        let key_id = "test-key-id-2".to_string();
        let seal = SymmetricSeal::new();

        let encrypted = seal
            .encrypt::<Aes256Gcm>(&key, key_id.clone())
            .to_vec_parallel(plaintext)?;

        let pending = seal.decrypt().from_slice_parallel(&encrypted)?;
        assert_eq!(pending.key_id(), Some(key_id.as_str()));
        let decrypted = pending.with_key::<Aes256Gcm>(&key)?;

        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_streaming_roundtrip() {
        let mut key_store = HashMap::new();
        let key = Aes256Gcm::generate_key().unwrap();
        key_store.insert(TEST_KEY_ID.to_string(), key.clone());

        let plaintext = get_test_data();
        let seal = SymmetricSeal::new();

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor = seal
            .encrypt::<Aes256Gcm>(&key, TEST_KEY_ID.to_string())
            .into_writer(&mut encrypted_data)
            .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt
        let pending = seal
            .decrypt()
            .from_reader(Cursor::new(&encrypted_data))
            .unwrap();
        let key_id = pending.key_id().unwrap();
        let decryption_key = key_store.get(key_id).unwrap();
        let mut decryptor = pending.with_key::<Aes256Gcm>(decryption_key).unwrap();

        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).unwrap();
        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[test]
    fn test_parallel_streaming_roundtrip() -> crate::Result<()> {
        let key = Aes256Gcm::generate_key()?;
        let plaintext = get_test_data();
        let key_id = "test-key-id-p-streaming".to_string();
        let seal = SymmetricSeal::new();

        let mut encrypted = Vec::new();
        seal.encrypt::<Aes256Gcm>(&key, key_id.clone())
            .pipe_parallel(Cursor::new(plaintext), &mut encrypted)?;

        let pending = seal
            .decrypt()
            .from_reader_parallel(Cursor::new(&encrypted))?;
        assert_eq!(pending.key_id(), Some(key_id.as_str()));

        let mut decrypted = Vec::new();
        pending.with_key_to_writer::<Aes256Gcm, _>(&key, &mut decrypted)?;

        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[cfg(feature = "async")]
    mod async_tests {
        use super::*;
        use std::collections::HashMap;
        use tokio::io::AsyncWriteExt;

        #[tokio::test]
        async fn test_asynchronous_streaming_roundtrip() {
            let mut key_store = HashMap::new();
            let key = Aes256Gcm::generate_key().unwrap();
            key_store.insert(TEST_KEY_ID.to_string(), key.clone());
            let plaintext = get_test_data();

            let seal = SymmetricSeal::new();

            // Encrypt
            let mut encrypted_data = Vec::new();
            let mut encryptor = seal
                .encrypt::<Aes256Gcm>(&key, TEST_KEY_ID.to_string())
                .into_async_writer(&mut encrypted_data)
                .await
                .unwrap();
            encryptor.write_all(plaintext).await.unwrap();
            encryptor.shutdown().await.unwrap();

            // Decrypt
            let pending = seal
                .decrypt()
                .from_async_reader(Cursor::new(&encrypted_data))
                .await
                .unwrap();
            let key_id = pending.key_id().unwrap();
            let decryption_key = key_store.get(key_id).unwrap();
            let mut decryptor = pending.with_key::<Aes256Gcm>(decryption_key).unwrap();

            let mut decrypted_data = Vec::new();
            decryptor.read_to_end(&mut decrypted_data).await.unwrap();
            assert_eq!(plaintext, decrypted_data.as_slice());
        }
    }
}
