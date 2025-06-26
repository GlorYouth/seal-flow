use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::crypto::zeroize::Zeroizing;
use seal_crypto::prelude::AsymmetricKeySet;
use std::io::{Read, Write};
use std::marker::PhantomData;
use tokio::io::{AsyncRead, AsyncWrite};

/// A factory for creating hybrid encryption and decryption executors.
///
/// This struct holds the asymmetric key (public for encryption, private for decryption)
/// and provides a fluent interface to select the execution mode.
pub struct HybridSeal<'k, A: AsymmetricAlgorithm + 'k> {
    key: KeyVariant<'k, A>,
}

/// Holds either a public key for encryption or a private key for decryption.
pub(crate) enum KeyVariant<'k, K: AsymmetricKeySet + 'k> {
    Public(&'k K::PublicKey),
    Private(&'k K::PrivateKey),
}

impl<'k, A: AsymmetricAlgorithm> HybridSeal<'k, A> {
    /// Creates a new `HybridSeal` factory for encryption using a public key.
    pub fn new_encrypt(pk: &'k A::PublicKey) -> Self {
        Self {
            key: KeyVariant::Public(pk),
        }
    }

    /// Creates a new `HybridSeal` factory for decryption using a private key.
    pub fn new_decrypt(sk: &'k A::PrivateKey) -> Self {
        Self {
            key: KeyVariant::Private(sk),
        }
    }

    /// Configures the operation to run in-memory.
    pub fn in_memory<S>(&self) -> HybridInMemoryExecutor<'k, A, S>
    where
        S: SymmetricAlgorithm,
        S::Key: From<Zeroizing<Vec<u8>>>,
        A::PrivateKey: Clone,
        A::EncapsulatedKey: From<Vec<u8>> + Into<Vec<u8>> + Send,
    {
        HybridInMemoryExecutor {
            key: self.key.clone_key(),
            _phantom: PhantomData,
        }
    }

    /// Configures the operation to run in-memory using parallel processing.
    pub fn in_memory_parallel<S>(&self) -> HybridInMemoryParallelExecutor<'k, A, S>
    where
        S: SymmetricAlgorithm,
        S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync + Clone,
        A::PrivateKey: Clone,
        A::PublicKey: Clone,
        A::EncapsulatedKey: From<Vec<u8>> + Into<Vec<u8>> + Send,
        Vec<u8>: From<<A as seal_crypto::prelude::Kem>::EncapsulatedKey>,
    {
        HybridInMemoryParallelExecutor {
            key: self.key.clone_key(),
            _phantom: PhantomData,
        }
    }

    /// Configures a synchronous streaming operation.
    pub fn streaming<S>(&self) -> HybridStreamingBuilder<'k, A, S>
    where
        S: SymmetricAlgorithm,
        S::Key: From<Zeroizing<Vec<u8>>>,
        A::PrivateKey: Clone,
        A::EncapsulatedKey: From<Vec<u8>> + Into<Vec<u8>>,
    {
        HybridStreamingBuilder {
            key: self.key.clone_key(),
            _phantom: PhantomData,
        }
    }

    /// Configures a parallel streaming operation.
    pub fn parallel_streaming<S>(&self) -> HybridParallelStreamingExecutor<'k, A, S>
    where
        S: SymmetricAlgorithm,
        S::Key: From<Zeroizing<Vec<u8>>>,
        A::PrivateKey: Clone + Send + Sync,
        A::PublicKey: Clone + Send + Sync,
        A::EncapsulatedKey: From<Vec<u8>> + Into<Vec<u8>> + Send,
    {
        HybridParallelStreamingExecutor {
            key: self.key.clone_key(),
            _phantom: PhantomData,
        }
    }

    /// Configures an asynchronous streaming operation.
    #[cfg(feature = "async")]
    pub fn asynchronous<S>(&self) -> HybridAsyncStreamingBuilder<'k, A, S>
    where
        S: SymmetricAlgorithm,
        S::Key: From<Zeroizing<Vec<u8>>> + Clone + Send + Sync,
        A::PrivateKey: Clone + Send + Sync,
        A::PublicKey: Clone + Send + Sync,
        A::EncapsulatedKey: From<Vec<u8>> + Into<Vec<u8>> + Send,
    {
        HybridAsyncStreamingBuilder {
            key: self.key.clone_key(),
            _phantom: PhantomData,
        }
    }
}

/// An executor for in-memory hybrid operations.
pub struct HybridInMemoryExecutor<'k, A, S>
where
    A: AsymmetricKeySet,
    S: SymmetricAlgorithm,
{
    key: KeyVariant<'k, A>,
    _phantom: PhantomData<(A, S)>,
}

impl<'k, A, S> HybridInMemoryExecutor<'k, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>>,
    A::EncapsulatedKey: From<Vec<u8>> + Into<Vec<u8>> + Send,
{
    /// Encrypts the given plaintext.
    pub fn encrypt(&self, plaintext: &[u8], kek_id: String) -> crate::Result<Vec<u8>> {
        match self.key {
            KeyVariant::Public(pk) => {
                crate::hybrid::ordinary::encrypt::<A, S>(pk, plaintext, kek_id)
            }
            KeyVariant::Private(_) => Err(crate::error::Error::WrongKeyType),
        }
    }

    /// Decrypts the given ciphertext.
    pub fn decrypt(&self, ciphertext: &[u8]) -> crate::Result<Vec<u8>> {
        match self.key {
            KeyVariant::Private(sk) => crate::hybrid::ordinary::decrypt::<A, S>(sk, ciphertext),
            KeyVariant::Public(_) => Err(crate::error::Error::WrongKeyType),
        }
    }
}

/// An executor for parallel in-memory hybrid operations.
pub struct HybridInMemoryParallelExecutor<'k, A, S>
where
    A: AsymmetricKeySet,
    S: SymmetricAlgorithm,
{
    key: KeyVariant<'k, A>,
    _phantom: PhantomData<(A, S)>,
}

impl<'k, A, S> HybridInMemoryParallelExecutor<'k, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync + Clone,
    A::PrivateKey: Clone,
    A::PublicKey: Clone,
    A::EncapsulatedKey: From<Vec<u8>> + Into<Vec<u8>> + Send,
    Vec<u8>: From<<A as seal_crypto::prelude::Kem>::EncapsulatedKey>,
{
    /// Encrypts the given plaintext in parallel.
    pub fn encrypt(&self, plaintext: &[u8], kek_id: String) -> crate::Result<Vec<u8>> {
        match self.key {
            KeyVariant::Public(pk) => {
                crate::hybrid::parallel::encrypt::<A, S>(pk, plaintext, kek_id)
            }
            KeyVariant::Private(_) => Err(crate::error::Error::WrongKeyType),
        }
    }

    /// Decrypts the given ciphertext in parallel.
    pub fn decrypt(&self, ciphertext: &[u8]) -> crate::Result<Vec<u8>> {
        match self.key {
            KeyVariant::Private(sk) => crate::hybrid::parallel::decrypt::<A, S>(sk, ciphertext),
            KeyVariant::Public(_) => Err(crate::error::Error::WrongKeyType),
        }
    }
}

/// A builder for synchronous streaming hybrid operations.
pub struct HybridStreamingBuilder<'k, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    key: KeyVariant<'k, A>,
    _phantom: PhantomData<(A, S)>,
}

impl<'k, A, S> HybridStreamingBuilder<'k, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>> + Clone,
    A::PrivateKey: Clone,
    A::EncapsulatedKey: From<Vec<u8>> + Into<Vec<u8>>,
    Vec<u8>: From<<A as seal_crypto::prelude::Kem>::EncapsulatedKey>,
{
    /// Builds a streaming encryptor.
    pub fn encryptor<W: Write>(
        &self,
        writer: W,
        kek_id: String,
    ) -> crate::Result<crate::hybrid::streaming::Encryptor<W, A, S>> {
        match self.key {
            KeyVariant::Public(pk) => crate::hybrid::streaming::Encryptor::new(writer, pk, kek_id),
            KeyVariant::Private(_) => Err(crate::error::Error::WrongKeyType),
        }
    }

    /// Builds a streaming decryptor.
    pub fn decryptor<R: Read>(
        &self,
        reader: R,
    ) -> crate::Result<crate::hybrid::streaming::Decryptor<R, A, S>> {
        match self.key {
            KeyVariant::Private(sk) => crate::hybrid::streaming::Decryptor::new(reader, sk),
            KeyVariant::Public(_) => Err(crate::error::Error::WrongKeyType),
        }
    }
}

/// An executor for parallel streaming hybrid operations.
pub struct HybridParallelStreamingExecutor<'k, A, S>
where
    A: AsymmetricKeySet,
    S: SymmetricAlgorithm,
{
    key: KeyVariant<'k, A>,
    _phantom: PhantomData<(A, S)>,
}

impl<'k, A, S> HybridParallelStreamingExecutor<'k, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>>,
    A::PrivateKey: Clone + Send + Sync,
    A::PublicKey: Clone + Send + Sync,
    A::EncapsulatedKey: From<Vec<u8>> + Into<Vec<u8>> + Send,
{
    /// Encrypts data from a reader and writes to a writer using parallel processing.
    pub fn encrypt<R: Read + Send + Sync, W: Write + Send + Sync>(
        &self,
        reader: R,
        writer: W,
        kek_id: String,
    ) -> crate::Result<()> {
        match self.key {
            KeyVariant::Public(pk) => {
                crate::hybrid::parallel_streaming::encrypt::<A, S, R, W>(pk, reader, writer, kek_id)
            }
            KeyVariant::Private(_) => Err(crate::error::Error::WrongKeyType),
        }
    }

    /// Decrypts data from a reader and writes to a writer using parallel processing.
    pub fn decrypt<R: Read + Send + Sync, W: Write + Send + Sync>(
        &self,
        reader: R,
        writer: W,
    ) -> crate::Result<()> {
        match self.key {
            KeyVariant::Private(sk) => {
                crate::hybrid::parallel_streaming::decrypt::<A, S, R, W>(sk, reader, writer)
            }
            KeyVariant::Public(_) => Err(crate::error::Error::WrongKeyType),
        }
    }
}

/// A builder for asynchronous streaming hybrid operations.
#[cfg(feature = "async")]
pub struct HybridAsyncStreamingBuilder<'k, A, S>
where
    A: AsymmetricKeySet,
    S: SymmetricAlgorithm,
{
    key: KeyVariant<'k, A>,
    _phantom: PhantomData<(A, S)>,
}

#[cfg(feature = "async")]
impl<'k, A, S> HybridAsyncStreamingBuilder<'k, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>> + Clone + Send + Sync,
    A::PrivateKey: Clone + Send + Sync,
    A::PublicKey: Clone + Send + Sync,
    A::EncapsulatedKey: From<Vec<u8>> + Into<Vec<u8>> + Send,
{
    /// Builds an asynchronous streaming encryptor.
    pub async fn encryptor<W>(
        &self,
        writer: W,
        kek_id: String,
    ) -> crate::Result<crate::hybrid::asynchronous::Encryptor<W, A, S>>
    where
        W: AsyncWrite + Unpin,
    {
        match self.key {
            KeyVariant::Public(pk) => {
                crate::hybrid::asynchronous::Encryptor::new(writer, pk.clone(), kek_id).await
            }
            KeyVariant::Private(_) => Err(crate::error::Error::WrongKeyType),
        }
    }

    /// Builds an asynchronous streaming decryptor.
    pub async fn decryptor<R>(
        &self,
        reader: R,
    ) -> crate::Result<crate::hybrid::asynchronous::Decryptor<R, A, S>>
    where
        R: AsyncRead + Unpin,
    {
        match self.key {
            KeyVariant::Private(sk) => {
                crate::hybrid::asynchronous::Decryptor::new(reader, sk.clone()).await
            }
            KeyVariant::Public(_) => Err(crate::error::Error::WrongKeyType),
        }
    }
}

impl<'k, K: AsymmetricKeySet> Clone for KeyVariant<'k, K> {
    fn clone(&self) -> Self {
        match *self {
            KeyVariant::Public(pk) => KeyVariant::Public(pk),
            KeyVariant::Private(sk) => KeyVariant::Private(sk),
        }
    }
}

impl<'k, K: AsymmetricKeySet> KeyVariant<'k, K> {
    fn clone_key(&self) -> Self {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use seal_crypto::prelude::KeyGenerator;
    use seal_crypto::schemes::asymmetric::traditional::rsa::Rsa2048;
    use seal_crypto::schemes::hash::Sha256;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
    use std::io::Cursor;

    const TEST_KEK_ID: &str = "test-kek";

    fn get_test_data() -> &'static [u8] {
        b"This is a hybrid encryption test message, also long enough to cross chunk boundaries."
    }

    type TestKem = Rsa2048<Sha256>;
    type TestDek = Aes256Gcm;

    #[test]
    fn test_in_memory_roundtrip() {
        let (pk, sk) = TestKem::generate_keypair().unwrap();
        let plaintext = get_test_data();

        let encrypt_seal = HybridSeal::<TestKem>::new_encrypt(&pk);
        let encrypted = encrypt_seal
            .in_memory::<TestDek>()
            .encrypt(plaintext, TEST_KEK_ID.to_string())
            .unwrap();

        let decrypt_seal = HybridSeal::<TestKem>::new_decrypt(&sk);
        let decrypted = decrypt_seal
            .in_memory::<TestDek>()
            .decrypt(&encrypted)
            .unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_in_memory_parallel_roundtrip() {
        let (pk, sk) = TestKem::generate_keypair().unwrap();
        let plaintext = get_test_data();

        let encrypt_seal = HybridSeal::<TestKem>::new_encrypt(&pk);
        let encrypted = encrypt_seal
            .in_memory_parallel::<TestDek>()
            .encrypt(plaintext, TEST_KEK_ID.to_string())
            .unwrap();

        let decrypt_seal = HybridSeal::<TestKem>::new_decrypt(&sk);
        let decrypted = decrypt_seal
            .in_memory_parallel::<TestDek>()
            .decrypt(&encrypted)
            .unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_streaming_roundtrip() {
        let (pk, sk) = TestKem::generate_keypair().unwrap();
        let plaintext = get_test_data();

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor = HybridSeal::<TestKem>::new_encrypt(&pk)
            .streaming::<TestDek>()
            .encryptor(&mut encrypted_data, TEST_KEK_ID.to_string())
            .unwrap();
        let mut source = Cursor::new(plaintext);
        std::io::copy(&mut source, &mut encryptor).unwrap();
        // Explicitly finish the stream to finalize encryption.
        encryptor.finish().unwrap();

        // Decrypt
        let encrypted_cursor = Cursor::new(&encrypted_data);
        let mut decryptor = HybridSeal::<TestKem>::new_decrypt(&sk)
            .streaming::<TestDek>()
            .decryptor(encrypted_cursor)
            .unwrap();
        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[test]
    fn test_parallel_streaming_roundtrip() {
        let (pk, sk) = TestKem::generate_keypair().unwrap();
        let plaintext = get_test_data();

        // Encrypt
        let source = Cursor::new(plaintext);
        let mut encrypted_data = Vec::new();
        HybridSeal::<TestKem>::new_encrypt(&pk)
            .parallel_streaming::<TestDek>()
            .encrypt(source, &mut encrypted_data, TEST_KEK_ID.to_string())
            .unwrap();

        // Decrypt
        let encrypted_source = Cursor::new(encrypted_data);
        let mut decrypted_data = Vec::new();
        HybridSeal::<TestKem>::new_decrypt(&sk)
            .parallel_streaming::<TestDek>()
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
            let (pk, sk) = TestKem::generate_keypair().unwrap();
            let plaintext = get_test_data();

            // Encrypt
            let mut encrypted_data = Vec::new();
            let mut encryptor = HybridSeal::<TestKem>::new_encrypt(&pk)
                .asynchronous::<TestDek>()
                .encryptor(&mut encrypted_data, TEST_KEK_ID.to_string())
                .await
                .unwrap();
            encryptor.write_all(plaintext).await.unwrap();
            encryptor.shutdown().await.unwrap();

            // Decrypt
            let encrypted_cursor = Cursor::new(encrypted_data);
            let mut decryptor = HybridSeal::<TestKem>::new_decrypt(&sk)
                .asynchronous::<TestDek>()
                .decryptor(encrypted_cursor)
                .await
                .unwrap();
            let mut decrypted_data = Vec::new();
            decryptor.read_to_end(&mut decrypted_data).await.unwrap();

            assert_eq!(plaintext, decrypted_data.as_slice());
        }
    }

    #[test]
    fn test_wrong_key_type_errors() {
        let (pk, sk) = TestKem::generate_keypair().unwrap();
        let plaintext = get_test_data();
        let encrypted = HybridSeal::<TestKem>::new_encrypt(&pk)
            .in_memory::<TestDek>()
            .encrypt(plaintext, TEST_KEK_ID.to_string())
            .unwrap();

        // Try decrypting with public key
        let result = HybridSeal::<TestKem>::new_encrypt(&pk)
            .in_memory::<TestDek>()
            .decrypt(&encrypted);
        assert!(matches!(result, Err(Error::WrongKeyType)));

        // Try encrypting with private key
        let result = HybridSeal::<TestKem>::new_decrypt(&sk)
            .in_memory::<TestDek>()
            .encrypt(plaintext, TEST_KEK_ID.to_string());
        assert!(matches!(result, Err(Error::WrongKeyType)));
    }
}
