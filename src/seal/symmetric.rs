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

    /// Configures the operation to run in-memory.
    pub fn in_memory<S>(&self) -> SymmetricInMemoryExecutor<S>
    where
        S: SymmetricAlgorithm,
    {
        SymmetricInMemoryExecutor {
            _phantom: PhantomData,
        }
    }

    /// Configures the operation to run in-memory using parallel processing.
    pub fn in_memory_parallel<S>(&self) -> SymmetricInMemoryParallelExecutor<S>
    where
        S: SymmetricAlgorithm,
    {
        SymmetricInMemoryParallelExecutor {
            _phantom: PhantomData,
        }
    }

    /// Configures a synchronous streaming encryption operation.
    pub fn streaming_encryptor<S, W>(
        &self,
        writer: W,
        key: &S::Key,
        key_id: String,
    ) -> crate::Result<crate::symmetric::streaming::Encryptor<W, S>>
    where
        S: SymmetricAlgorithm,
        S::Key: Clone + Send + Sync,
        W: Write,
    {
        crate::symmetric::streaming::Encryptor::new(writer, key.clone(), key_id)
    }

    /// Begins a synchronous streaming decryption operation.
    ///
    /// This returns a `PendingDecryptor` which allows inspecting the stream's
    /// header before providing the key required for decryption.
    pub fn streaming_decryptor_from_reader<S, R>(
        &self,
        reader: R,
    ) -> crate::Result<PendingStreamingDecryptor<R, S>>
    where
        S: SymmetricAlgorithm,
        R: Read,
    {
        let mid_level_pending = crate::symmetric::streaming::PendingDecryptor::from_reader(reader)?;
        Ok(PendingStreamingDecryptor {
            inner: mid_level_pending,
            _phantom: PhantomData,
        })
    }

    /// Configures a parallel streaming operation.
    pub fn parallel_streaming<S>(&self) -> SymmetricParallelStreamingExecutor<S>
    where
        S: SymmetricAlgorithm,
    {
        SymmetricParallelStreamingExecutor {
            _phantom: PhantomData,
        }
    }

    /// Configures an asynchronous streaming encryption operation.
    #[cfg(feature = "async")]
    pub async fn asynchronous_encryptor<S, W>(
        &self,
        writer: W,
        key: &S::Key,
        key_id: String,
    ) -> crate::Result<crate::symmetric::asynchronous::Encryptor<W, S>>
    where
        S: SymmetricAlgorithm,
        S::Key: Clone + Send + Sync,
        W: AsyncWrite + Unpin,
    {
        crate::symmetric::asynchronous::Encryptor::new(writer, key.clone(), key_id).await
    }

    /// Begins an asynchronous streaming decryption operation.
    #[cfg(feature = "async")]
    pub async fn asynchronous_decryptor_from_reader<S, R>(
        &self,
        reader: R,
    ) -> crate::Result<PendingAsyncStreamingDecryptor<R, S>>
    where
        S: SymmetricAlgorithm,
        R: AsyncRead + Unpin,
    {
        let mid_level_pending =
            crate::symmetric::asynchronous::PendingDecryptor::from_reader(reader).await?;
        Ok(PendingAsyncStreamingDecryptor {
            inner: mid_level_pending,
            _phantom: PhantomData,
        })
    }
}

/// An executor for in-memory symmetric operations.
pub struct SymmetricInMemoryExecutor<S: SymmetricAlgorithm> {
    _phantom: PhantomData<S>,
}

impl<S: SymmetricAlgorithm> SymmetricInMemoryExecutor<S> {
    /// Encrypts the given plaintext.
    pub fn encrypt(
        &self,
        key: &S::Key,
        plaintext: &[u8],
        key_id: String,
    ) -> crate::Result<Vec<u8>>
    where
        S::Key: Clone + Send + Sync,
    {
        crate::symmetric::ordinary::encrypt::<S>(key, plaintext, key_id)
    }

    /// Begins the decryption process for the given ciphertext.
    pub fn decrypt<'a>(
        &self,
        ciphertext: &'a [u8],
    ) -> crate::Result<PendingInMemoryDecryptor<'a, S>> {
        let mid_level_pending =
            crate::symmetric::ordinary::PendingDecryptor::from_ciphertext(ciphertext)?;
        Ok(PendingInMemoryDecryptor {
            inner: mid_level_pending,
        })
    }
}

/// A pending in-memory decryptor, waiting for a key.
pub struct PendingInMemoryDecryptor<'a, S: SymmetricAlgorithm> {
    inner: crate::symmetric::ordinary::PendingDecryptor<'a, S>,
}

impl<'a, S: SymmetricAlgorithm> PendingInMemoryDecryptor<'a, S> {
    /// Returns a reference to the header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the key ID from the header.
    pub fn key_id(&self) -> Option<&str> {
        self.header().payload.key_id()
    }

    /// Supplies the key and returns the decrypted plaintext.
    pub fn with_key(self, key: &S::Key) -> crate::Result<Vec<u8>>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner.into_plaintext(key)
    }
}

/// An executor for parallel in-memory symmetric operations.
pub struct SymmetricInMemoryParallelExecutor<S: SymmetricAlgorithm> {
    _phantom: PhantomData<S>,
}

impl<S: SymmetricAlgorithm> SymmetricInMemoryParallelExecutor<S> {
    /// Encrypts the given plaintext in parallel.
    pub fn encrypt(
        &self,
        key: &S::Key,
        plaintext: &[u8],
        key_id: String,
    ) -> crate::Result<Vec<u8>>
    where
        S::Key: Clone + Send + Sync,
    {
        crate::symmetric::parallel::encrypt::<S>(key, plaintext, key_id)
    }

    /// Begins the decryption process for the given ciphertext, to be run in parallel.
    pub fn decrypt<'a>(
        &self,
        ciphertext: &'a [u8],
    ) -> crate::Result<PendingInMemoryParallelDecryptor<'a, S>> {
        let mid_level_pending =
            crate::symmetric::parallel::PendingDecryptor::from_ciphertext(ciphertext)?;
        Ok(PendingInMemoryParallelDecryptor {
            inner: mid_level_pending,
        })
    }
}

/// A pending parallel in-memory decryptor, waiting for a key.
pub struct PendingInMemoryParallelDecryptor<'a, S: SymmetricAlgorithm> {
    inner: crate::symmetric::parallel::PendingDecryptor<'a, S>,
}

impl<'a, S: SymmetricAlgorithm> PendingInMemoryParallelDecryptor<'a, S> {
    /// Returns a reference to the header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the key ID from the header.
    pub fn key_id(&self) -> Option<&str> {
        self.header().payload.key_id()
    }

    /// Supplies the key and returns the decrypted plaintext.
    pub fn with_key(self, key: &S::Key) -> crate::Result<Vec<u8>>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner.into_plaintext(key)
    }
}

/// A pending synchronous streaming decryptor, waiting for a key.
pub struct PendingStreamingDecryptor<R: Read, S: SymmetricAlgorithm> {
    inner: crate::symmetric::streaming::PendingDecryptor<R>,
    _phantom: PhantomData<S>,
}

impl<R: Read, S: SymmetricAlgorithm> PendingStreamingDecryptor<R, S> {
    /// Returns a reference to the stream's header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the key ID from the stream's header.
    pub fn key_id(&self) -> Option<&str> {
        self.header().payload.key_id()
    }

    /// Supplies the key and returns a fully initialized `Decryptor`.
    pub fn with_key(
        self,
        key: &S::Key,
    ) -> crate::Result<crate::symmetric::streaming::Decryptor<R, S>>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner.into_decryptor(key)
    }
}

/// An executor for parallel streaming symmetric operations.
pub struct SymmetricParallelStreamingExecutor<S: SymmetricAlgorithm> {
    _phantom: PhantomData<S>,
}

impl<S: SymmetricAlgorithm> SymmetricParallelStreamingExecutor<S> {
    /// Encrypts data from a reader and writes to a writer using parallel processing.
    pub fn encrypt<R, W>(
        &self,
        key: &S::Key,
        reader: R,
        writer: W,
        key_id: String,
    ) -> crate::Result<()>
    where
        S::Key: Clone + Send + Sync,
        R: Read + Send,
        W: Write + Send,
    {
        crate::symmetric::parallel_streaming::encrypt::<S, R, W>(key, reader, writer, key_id)
    }

    /// Begins the decryption process for a stream.
    pub fn decrypt<R>(&self, reader: R) -> crate::Result<PendingParallelStreamingDecryptor<R, S>>
    where
        R: Read + Send,
    {
        let mid_level_pending =
            crate::symmetric::parallel_streaming::PendingDecryptor::from_reader(reader)?;
        Ok(PendingParallelStreamingDecryptor {
            inner: mid_level_pending,
            _phantom: PhantomData,
        })
    }
}

/// A pending parallel streaming decryptor, waiting for a key.
pub struct PendingParallelStreamingDecryptor<R, S>
where
    R: Read + Send,
    S: SymmetricAlgorithm,
{
    inner: crate::symmetric::parallel_streaming::PendingDecryptor<R, S>,
    _phantom: PhantomData<()>,
}

impl<R, S> PendingParallelStreamingDecryptor<R, S>
where
    R: Read + Send,
    S: SymmetricAlgorithm,
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
    pub fn with_key_to_writer<W: Write>(self, key: &S::Key, writer: W) -> crate::Result<()>
    where
        S::Key: Clone + Send + Sync,
    {
        self.inner.decrypt_to_writer(key, writer)
    }
}

/// A pending asynchronous streaming decryptor, waiting for a key.
#[cfg(feature = "async")]
pub struct PendingAsyncStreamingDecryptor<R: AsyncRead + Unpin, S: SymmetricAlgorithm> {
    inner: crate::symmetric::asynchronous::PendingDecryptor<R>,
    _phantom: PhantomData<S>,
}

#[cfg(feature = "async")]
impl<R: AsyncRead + Unpin, S: SymmetricAlgorithm> PendingAsyncStreamingDecryptor<R, S> {
    /// Returns a reference to the stream's header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the key ID from the stream's header.
    pub fn key_id(&self) -> Option<&str> {
        self.header().payload.key_id()
    }

    /// Supplies the key and returns a fully initialized `Decryptor`.
    pub fn with_key(
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
            .in_memory::<Aes256Gcm>()
            .encrypt(&key, plaintext, TEST_KEY_ID.to_string())
            .unwrap();
        let pending = seal.in_memory::<Aes256Gcm>().decrypt(&encrypted).unwrap();
        assert_eq!(pending.key_id(), Some(TEST_KEY_ID));
        let decrypted = pending.with_key(&key).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_in_memory_parallel_roundtrip() -> crate::Result<()> {
        let key = Aes256Gcm::generate_key()?;
        let plaintext = get_test_data();
        let key_id = "test-key-id-2".to_string();
        let seal = SymmetricSeal::new();

        let encrypted = seal
            .in_memory_parallel::<Aes256Gcm>()
            .encrypt(&key, plaintext, key_id.clone())?;

        let pending = seal
            .in_memory_parallel::<Aes256Gcm>()
            .decrypt(&encrypted)?;
        assert_eq!(pending.key_id(), Some(key_id.as_str()));
        let decrypted = pending.with_key(&key)?;

        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_streaming_roundtrip() {
        let mut key_store = HashMap::new();
        let key = Aes256Gcm::generate_key().unwrap();
        key_store.insert(TEST_KEY_ID.to_string(), key);

        let plaintext = get_test_data();
        let seal = SymmetricSeal::new();

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor = seal
            .streaming_encryptor::<Aes256Gcm, _>(
                &mut encrypted_data,
                key_store.get(TEST_KEY_ID).unwrap(),
                TEST_KEY_ID.to_string(),
            )
            .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt
        let pending = seal
            .streaming_decryptor_from_reader::<Aes256Gcm, _>(Cursor::new(&encrypted_data))
            .unwrap();
        let key_id = pending.key_id().unwrap();
        let decryption_key = key_store.get(key_id).unwrap();
        let mut decryptor = pending.with_key(decryption_key).unwrap();

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
        seal.parallel_streaming::<Aes256Gcm>()
            .encrypt(&key, Cursor::new(plaintext), &mut encrypted, key_id.clone())?;

        let pending = seal
            .parallel_streaming::<Aes256Gcm>()
            .decrypt(Cursor::new(&encrypted))?;
        assert_eq!(pending.key_id(), Some(key_id.as_str()));

        let mut decrypted = Vec::new();
        pending.with_key_to_writer(&key, &mut decrypted)?;

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
            key_store.insert(TEST_KEY_ID.to_string(), key);
            let plaintext = get_test_data();

            let seal = SymmetricSeal::new();

            // Encrypt
            let mut encrypted_data = Vec::new();
            let mut encryptor = seal
                .asynchronous_encryptor::<Aes256Gcm, _>(
                    &mut encrypted_data,
                    key_store.get(TEST_KEY_ID).unwrap(),
                    TEST_KEY_ID.to_string(),
                )
                .await
                .unwrap();
            encryptor.write_all(plaintext).await.unwrap();
            encryptor.shutdown().await.unwrap();

            // Decrypt
            let pending = seal
                .asynchronous_decryptor_from_reader::<Aes256Gcm, _>(Cursor::new(&encrypted_data))
                .await
                .unwrap();
            let key_id = pending.key_id().unwrap();
            let decryption_key = key_store.get(key_id).unwrap();
            let mut decryptor = pending.with_key(decryption_key).unwrap();

            let mut decrypted_data = Vec::new();
            decryptor.read_to_end(&mut decrypted_data).await.unwrap();
            assert_eq!(plaintext, decrypted_data.as_slice());
        }
    }
}
