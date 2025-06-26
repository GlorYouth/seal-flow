use crate::algorithms::traits::SymmetricAlgorithm;
use std::io::{Read, Write};
use std::marker::PhantomData;
use tokio::io::{AsyncRead, AsyncWrite};

/// A factory for creating symmetric encryption and decryption executors.
///
/// This struct holds the symmetric key and provides a fluent interface to select
/// the execution mode (e.g., in-memory, streaming).
pub struct SymmetricSeal<'k, K: 'k> {
    key: &'k K,
}

impl<'k, K: 'k> SymmetricSeal<'k, K> {
    /// Creates a new `SymmetricSeal` factory.
    ///
    /// # Arguments
    ///
    /// * `key`: The symmetric key to use for all operations created from this factory.
    pub fn new(key: &'k K) -> Self {
        Self { key }
    }

    /// Configures the operation to run in-memory.
    ///
    /// This is suitable for data that can be comfortably held in memory.
    /// It uses a single-threaded approach.
    pub fn in_memory<S>(&self) -> SymmetricInMemoryExecutor<'k, K, S>
    where
        S: SymmetricAlgorithm<Key = K>,
        K: Clone + Send + Sync,
    {
        SymmetricInMemoryExecutor {
            key: self.key,
            _phantom: PhantomData,
        }
    }

    /// Configures the operation to run in-memory using parallel processing.
    ///
    /// This is suitable for large data that can be held in memory, where
    /// encryption/decryption can be sped up by processing chunks in parallel.
    pub fn in_memory_parallel<S>(&self) -> SymmetricInMemoryParallelExecutor<'k, K, S>
    where
        S: SymmetricAlgorithm<Key = K>,
        K: Clone + Send + Sync,
    {
        SymmetricInMemoryParallelExecutor {
            key: self.key,
            _phantom: PhantomData,
        }
    }

    /// Configures a synchronous streaming operation.
    ///
    /// Returns a builder that can create `Encryptor` and `Decryptor` instances.
    pub fn streaming<S>(&self) -> SymmetricStreamingBuilder<'k, K, S>
    where
        S: SymmetricAlgorithm<Key = K>,
    {
        SymmetricStreamingBuilder {
            key: self.key,
            _phantom: PhantomData,
        }
    }

    /// Configures a parallel streaming operation.
    ///
    /// This returns an executor that can encrypt or decrypt data by piping from a `Reader`
    /// to a `Writer`, using multiple threads to process chunks in parallel.
    pub fn parallel_streaming<S>(&self) -> SymmetricParallelStreamingExecutor<'k, K, S>
    where
        S: SymmetricAlgorithm<Key = K>,
    {
        SymmetricParallelStreamingExecutor {
            key: self.key,
            _phantom: PhantomData,
        }
    }

    /// Configures an asynchronous streaming operation.
    ///
    /// Returns a builder that can create `Encryptor` and `Decryptor` instances for use with `tokio`.
    #[cfg(feature = "async")]
    pub fn asynchronous<S>(&self) -> SymmetricAsyncStreamingBuilder<'k, K, S>
    where
        S: SymmetricAlgorithm<Key = K>,
    {
        SymmetricAsyncStreamingBuilder {
            key: self.key,
            _phantom: PhantomData,
        }
    }
}

/// An executor for in-memory symmetric operations.
pub struct SymmetricInMemoryExecutor<'k, K, S: SymmetricAlgorithm<Key = K>> {
    key: &'k K,
    _phantom: PhantomData<S>,
}

impl<'k, K, S: SymmetricAlgorithm<Key = K>> SymmetricInMemoryExecutor<'k, K, S>
where
    K: Clone + Send + Sync,
{
    /// Encrypts the given plaintext.
    pub fn encrypt(&self, plaintext: &[u8], key_id: String) -> crate::Result<Vec<u8>> {
        crate::symmetric::ordinary::encrypt::<S>(self.key, plaintext, key_id)
    }

    /// Decrypts the given ciphertext.
    pub fn decrypt(&self, ciphertext: &[u8]) -> crate::Result<Vec<u8>> {
        crate::symmetric::ordinary::decrypt::<S>(self.key, ciphertext)
    }
}

/// An executor for parallel in-memory symmetric operations.
pub struct SymmetricInMemoryParallelExecutor<'k, K, S: SymmetricAlgorithm<Key = K>> {
    key: &'k K,
    _phantom: PhantomData<S>,
}

impl<'k, K, S: SymmetricAlgorithm<Key = K>> SymmetricInMemoryParallelExecutor<'k, K, S>
where
    K: Clone + Send + Sync,
{
    /// Encrypts the given plaintext in parallel.
    pub fn encrypt(&self, plaintext: &[u8], key_id: String) -> crate::Result<Vec<u8>> {
        crate::symmetric::parallel::encrypt::<S>(self.key, plaintext, key_id)
    }

    /// Decrypts the given ciphertext in parallel.
    pub fn decrypt(&self, ciphertext: &[u8]) -> crate::Result<Vec<u8>> {
        crate::symmetric::parallel::decrypt::<S>(self.key, ciphertext)
    }
}

/// A builder for synchronous streaming encryptors and decryptors.
pub struct SymmetricStreamingBuilder<'k, K, S>
where
    S: SymmetricAlgorithm<Key = K>,
{
    key: &'k K,
    _phantom: PhantomData<S>,
}

impl<'k, K, S> SymmetricStreamingBuilder<'k, K, S>
where
    S: SymmetricAlgorithm<Key = K>,
    K: Clone + Send + Sync,
{
    /// Builds an `Encryptor` that wraps the given writer.
    pub fn encryptor<W: Write>(
        &self,
        writer: W,
        key_id: String,
    ) -> crate::Result<crate::symmetric::streaming::Encryptor<W, S>> {
        crate::symmetric::streaming::Encryptor::new(writer, self.key.clone(), key_id)
    }

    /// Builds a `Decryptor` that wraps the given reader.
    pub fn decryptor<R: Read>(
        &self,
        reader: R,
    ) -> crate::Result<crate::symmetric::streaming::Decryptor<R, S>> {
        crate::symmetric::streaming::Decryptor::new(reader, self.key)
    }
}

/// An executor for parallel streaming symmetric operations.
pub struct SymmetricParallelStreamingExecutor<'k, K, S: SymmetricAlgorithm<Key = K>> {
    key: &'k K,
    _phantom: PhantomData<S>,
}

impl<'k, K, S: SymmetricAlgorithm<Key = K>> SymmetricParallelStreamingExecutor<'k, K, S>
where
    K: Sync + Clone + Send,
{
    /// Encrypts data from a reader and writes to a writer using parallel processing.
    pub fn encrypt<R: Read + Send, W: Write>(
        &self,
        reader: R,
        writer: W,
        key_id: String,
    ) -> crate::Result<()> {
        crate::symmetric::parallel_streaming::encrypt::<S, R, W>(self.key, reader, writer, key_id)
    }

    /// Decrypts data from a reader and writes to a writer using parallel processing.
    pub fn decrypt<R: Read + Send, W: Write>(&self, reader: R, writer: W) -> crate::Result<()> {
        crate::symmetric::parallel_streaming::decrypt::<S, R, W>(self.key, reader, writer)
    }
}

/// A builder for asynchronous streaming encryptors and decryptors.
#[cfg(feature = "async")]
pub struct SymmetricAsyncStreamingBuilder<'k, K, S>
where
    S: SymmetricAlgorithm<Key = K>,
{
    key: &'k K,
    _phantom: PhantomData<S>,
}

#[cfg(feature = "async")]
impl<'k, K, S> SymmetricAsyncStreamingBuilder<'k, K, S>
where
    S: SymmetricAlgorithm<Key = K>,
    K: Clone + Send + Sync,
{
    /// Builds an `Encryptor` that wraps the given asynchronous writer.
    pub async fn encryptor<W: AsyncWrite + Unpin>(
        &self,
        writer: W,
        key_id: String,
    ) -> crate::Result<crate::symmetric::asynchronous::Encryptor<W, S>> {
        crate::symmetric::asynchronous::Encryptor::new(writer, self.key.clone(), key_id).await
    }

    /// Builds a `Decryptor` that wraps the given asynchronous reader.
    pub async fn decryptor<R: AsyncRead + Unpin>(
        &self,
        reader: R,
    ) -> crate::Result<crate::symmetric::asynchronous::Decryptor<R, S>> {
        crate::symmetric::asynchronous::Decryptor::new(reader, self.key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::prelude::*;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
    use std::io::Cursor;

    const TEST_KEY_ID: &str = "test-key";

    fn get_test_data() -> &'static [u8] {
        b"This is a reasonably long test message to ensure that we cross chunk boundaries."
    }

    #[test]
    fn test_in_memory_roundtrip() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = get_test_data();

        let seal = SymmetricSeal::new(&key);
        let encrypted = seal
            .in_memory::<Aes256Gcm>()
            .encrypt(plaintext, TEST_KEY_ID.to_string())
            .unwrap();

        let decrypted = seal.in_memory::<Aes256Gcm>().decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_in_memory_parallel_roundtrip() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = get_test_data();

        let seal = SymmetricSeal::new(&key);
        let encrypted = seal
            .in_memory_parallel::<Aes256Gcm>()
            .encrypt(plaintext, TEST_KEY_ID.to_string())
            .unwrap();

        let decrypted = seal
            .in_memory_parallel::<Aes256Gcm>()
            .decrypt(&encrypted)
            .unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_streaming_roundtrip() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = get_test_data();
        let seal = SymmetricSeal::new(&key);

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor = seal
            .streaming::<Aes256Gcm>()
            .encryptor(&mut encrypted_data, TEST_KEY_ID.to_string())
            .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt
        let encrypted_cursor = Cursor::new(encrypted_data);
        let mut decryptor = seal
            .streaming::<Aes256Gcm>()
            .decryptor(encrypted_cursor)
            .unwrap();
        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[test]
    fn test_parallel_streaming_roundtrip() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = get_test_data();
        let seal = SymmetricSeal::new(&key);

        // Encrypt
        let source = Cursor::new(plaintext);
        let mut encrypted_data = Vec::new();
        seal.parallel_streaming::<Aes256Gcm>()
            .encrypt(source, &mut encrypted_data, TEST_KEY_ID.to_string())
            .unwrap();

        // Decrypt
        let encrypted_source = Cursor::new(encrypted_data);
        let mut decrypted_data = Vec::new();
        seal.parallel_streaming::<Aes256Gcm>()
            .decrypt(encrypted_source, &mut decrypted_data)
            .unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[cfg(feature = "async")]
    mod async_tests {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        #[tokio::test]
        async fn test_asynchronous_streaming_roundtrip() {
            let key = Aes256Gcm::generate_key().unwrap();
            let plaintext = get_test_data();
            let seal = SymmetricSeal::new(&key);

            // Encrypt
            let mut encrypted_data = Vec::new();
            let mut encryptor = seal
                .asynchronous::<Aes256Gcm>()
                .encryptor(&mut encrypted_data, TEST_KEY_ID.to_string())
                .await
                .unwrap();
            encryptor.write_all(plaintext).await.unwrap();
            encryptor.shutdown().await.unwrap();

            // Decrypt
            let encrypted_cursor = Cursor::new(encrypted_data);
            let mut decryptor = seal
                .asynchronous::<Aes256Gcm>()
                .decryptor(encrypted_cursor)
                .await
                .unwrap();
            let mut decrypted_data = Vec::new();
            decryptor.read_to_end(&mut decrypted_data).await.unwrap();

            assert_eq!(plaintext, decrypted_data.as_slice());
        }
    }
}
