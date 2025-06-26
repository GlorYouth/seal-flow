use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::header::Header;
use crate::crypto::zeroize::Zeroizing;
use std::io::{Read, Write};
use std::marker::PhantomData;
use tokio::io::{AsyncRead, AsyncWrite};

/// A factory for creating hybrid encryption and decryption executors.
#[derive(Default)]
pub struct HybridSeal;

impl HybridSeal {
    /// Creates a new `HybridSeal` factory.
    pub fn new() -> Self {
        Self
    }

    /// Configures the operation to run in-memory.
    pub fn in_memory<A, S>(&self) -> HybridInMemoryExecutor<A, S>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
    {
        HybridInMemoryExecutor {
            _phantom: PhantomData,
        }
    }

    /// Configures the operation to run in-memory using parallel processing.
    pub fn in_memory_parallel<A, S>(&self) -> HybridInMemoryParallelExecutor<A, S>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
    {
        HybridInMemoryParallelExecutor {
            _phantom: PhantomData,
        }
    }

    /// Configures a synchronous streaming encryption operation.
    pub fn streaming_encryptor<A, S, W>(
        &self,
        writer: W,
        pk: &A::PublicKey,
        kek_id: String,
    ) -> crate::Result<crate::hybrid::streaming::Encryptor<W, A, S>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
        W: Write,
        Vec<u8>: From<<A as seal_crypto::prelude::Kem>::EncapsulatedKey>,
        S::Key: From<Zeroizing<Vec<u8>>> + Clone,
    {
        crate::hybrid::streaming::Encryptor::new(writer, pk, kek_id)
    }

    /// Begins a synchronous streaming decryption operation.
    pub fn streaming_decryptor_from_reader<A, S, R>(
        &self,
        reader: R,
    ) -> crate::Result<PendingStreamingDecryptor<R, A, S>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
        R: Read,
    {
        let mid_level_pending =
            crate::hybrid::streaming::PendingDecryptor::<R, A, S>::from_reader(reader)?;
        Ok(PendingStreamingDecryptor {
            inner: mid_level_pending,
            _phantom: PhantomData,
        })
    }

    /// Configures a parallel streaming operation.
    pub fn parallel_streaming<A, S>(&self) -> HybridParallelStreamingExecutor<A, S>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
    {
        HybridParallelStreamingExecutor {
            _phantom: PhantomData,
        }
    }

    /// Configures an asynchronous streaming encryption operation.
    #[cfg(feature = "async")]
    pub async fn asynchronous_encryptor<A, S, W>(
        &self,
        writer: W,
        pk: A::PublicKey,
        kek_id: String,
    ) -> crate::Result<crate::hybrid::asynchronous::Encryptor<W, A, S>>
    where
        A: AsymmetricAlgorithm,
        A::EncapsulatedKey: Into<Vec<u8>> + Send,
        S: SymmetricAlgorithm,
        W: AsyncWrite + Unpin,
    {
        crate::hybrid::asynchronous::Encryptor::new(writer, pk, kek_id).await
    }

    /// Begins an asynchronous streaming decryption operation.
    #[cfg(feature = "async")]
    pub async fn asynchronous_decryptor_from_reader<A, S, R>(
        &self,
        reader: R,
    ) -> crate::Result<PendingAsyncStreamingDecryptor<R, A, S>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
        R: AsyncRead + Unpin,
    {
        let mid_level_pending =
            crate::hybrid::asynchronous::PendingDecryptor::<R, A, S>::from_reader(reader).await?;
        Ok(PendingAsyncStreamingDecryptor {
            inner: mid_level_pending,
            _phantom: PhantomData,
        })
    }
}

/// An executor for in-memory hybrid operations.
pub struct HybridInMemoryExecutor<A, S> {
    _phantom: PhantomData<(A, S)>,
}

impl<A, S> HybridInMemoryExecutor<A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    /// Encrypts the given plaintext.
    pub fn encrypt(
        &self,
        pk: &A::PublicKey,
        plaintext: &[u8],
        kek_id: String,
    ) -> crate::Result<Vec<u8>>
    where
        A::EncapsulatedKey: Into<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        crate::hybrid::ordinary::encrypt::<A, S>(pk, plaintext, kek_id)
    }

    /// Begins the decryption process for the given ciphertext.
    pub fn decrypt<'a>(
        &self,
        ciphertext: &'a [u8],
    ) -> crate::Result<PendingInMemoryDecryptor<'a, A, S>> {
        let mid_level_pending =
            crate::hybrid::ordinary::PendingDecryptor::from_ciphertext(ciphertext)?;
        Ok(PendingInMemoryDecryptor {
            inner: mid_level_pending,
        })
    }
}

/// A pending in-memory hybrid decryptor, waiting for the private key.
pub struct PendingInMemoryDecryptor<'a, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    inner: crate::hybrid::ordinary::PendingDecryptor<'a, A, S>,
}

impl<'a, A, S> PendingInMemoryDecryptor<'a, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    /// Returns a reference to the header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the Key-Encrypting-Key ID from the header.
    pub fn kek_id(&self) -> Option<&str> {
        self.header().payload.kek_id()
    }

    /// Supplies the private key and returns the decrypted plaintext.
    pub fn with_private_key(self, sk: &A::PrivateKey) -> crate::Result<Vec<u8>>
    where
        A::EncapsulatedKey: From<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        self.inner.into_plaintext(sk)
    }
}

/// An executor for parallel in-memory hybrid operations.
pub struct HybridInMemoryParallelExecutor<A, S> {
    _phantom: PhantomData<(A, S)>,
}

impl<A, S> HybridInMemoryParallelExecutor<A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    /// Encrypts the given plaintext in parallel.
    pub fn encrypt(
        &self,
        pk: &A::PublicKey,
        plaintext: &[u8],
        kek_id: String,
    ) -> crate::Result<Vec<u8>>
    where
        S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync + Clone,
        Vec<u8>: From<<A as seal_crypto::prelude::Kem>::EncapsulatedKey>,
    {
        crate::hybrid::parallel::encrypt::<A, S>(pk, plaintext, kek_id)
    }

    /// Begins the decryption process for the given ciphertext, to be run in parallel.
    pub fn decrypt<'a>(
        &self,
        ciphertext: &'a [u8],
    ) -> crate::Result<PendingInMemoryParallelDecryptor<'a, A, S>> {
        let mid_level_pending =
            crate::hybrid::parallel::PendingDecryptor::from_ciphertext(ciphertext)?;
        Ok(PendingInMemoryParallelDecryptor {
            inner: mid_level_pending,
        })
    }
}

/// A pending parallel in-memory hybrid decryptor, waiting for the private key.
pub struct PendingInMemoryParallelDecryptor<'a, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    inner: crate::hybrid::parallel::PendingDecryptor<'a, A, S>,
}

impl<'a, A, S> PendingInMemoryParallelDecryptor<'a, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    /// Returns a reference to the header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the Key-Encrypting-Key ID from the header.
    pub fn kek_id(&self) -> Option<&str> {
        self.header().payload.kek_id()
    }

    /// Supplies the private key and returns the decrypted plaintext.
    pub fn with_private_key(self, sk: &A::PrivateKey) -> crate::Result<Vec<u8>>
    where
        S::Key: From<Zeroizing<Vec<u8>>>,
        A::PrivateKey: Clone,
        A::EncapsulatedKey: From<Vec<u8>>,
    {
        self.inner.into_plaintext(sk)
    }
}

/// A pending synchronous streaming hybrid decryptor.
pub struct PendingStreamingDecryptor<R: Read, A: AsymmetricAlgorithm, S: SymmetricAlgorithm> {
    inner: crate::hybrid::streaming::PendingDecryptor<R, A, S>,
    _phantom: PhantomData<()>,
}

impl<R: Read, A, S> PendingStreamingDecryptor<R, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    /// Returns a reference to the stream's header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the Key-Encrypting-Key ID from the stream's header.
    pub fn kek_id(&self) -> Option<&str> {
        self.header().payload.kek_id()
    }

    /// Supplies the private key and returns a fully initialized `Decryptor`.
    pub fn with_private_key(
        self,
        sk: &A::PrivateKey,
    ) -> crate::Result<crate::hybrid::streaming::Decryptor<R, A, S>>
    where
        A::PrivateKey: Clone,
        A::EncapsulatedKey: From<Vec<u8>>,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        self.inner.into_decryptor(sk)
    }
}

/// An executor for parallel streaming hybrid operations.
pub struct HybridParallelStreamingExecutor<A, S> {
    _phantom: PhantomData<(A, S)>,
}

impl<A, S> HybridParallelStreamingExecutor<A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    /// Encrypts data from a reader and writes to a writer using parallel processing.
    pub fn encrypt<R, W>(
        &self,
        pk: &A::PublicKey,
        reader: R,
        writer: W,
        kek_id: String,
    ) -> crate::Result<()>
    where
        R: Read + Send + Sync,
        W: Write + Send + Sync,
        A::EncapsulatedKey: Into<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        crate::hybrid::parallel_streaming::encrypt::<A, S, R, W>(pk, reader, writer, kek_id)
    }

    /// Begins the decryption process for a stream.
    pub fn decrypt<R>(&self, reader: R) -> crate::Result<PendingParallelStreamingDecryptor<R, A, S>>
    where
        R: Read + Send,
    {
        let mid_level_pending =
            crate::hybrid::parallel_streaming::PendingDecryptor::from_reader(reader)?;
        Ok(PendingParallelStreamingDecryptor {
            inner: mid_level_pending,
            _phantom: PhantomData,
        })
    }
}

/// A pending parallel streaming hybrid decryptor.
pub struct PendingParallelStreamingDecryptor<R, A, S>
where
    R: Read + Send,
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    inner: crate::hybrid::parallel_streaming::PendingDecryptor<R, A, S>,
    _phantom: PhantomData<()>,
}

impl<R, A, S> PendingParallelStreamingDecryptor<R, A, S>
where
    R: Read + Send,
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    /// Returns a reference to the stream's header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the Key-Encrypting-Key ID from the stream's header.
    pub fn kek_id(&self) -> Option<&str> {
        self.header().payload.kek_id()
    }

    /// Supplies the private key and decrypts the stream, writing to the provided writer.
    pub fn with_private_key_to_writer<W: Write>(
        self,
        sk: &A::PrivateKey,
        writer: W,
    ) -> crate::Result<()>
    where
        S::Key: From<Zeroizing<Vec<u8>>>,
        A::PrivateKey: Clone,
        A::EncapsulatedKey: From<Vec<u8>>,
    {
        self.inner.decrypt_to_writer(sk, writer)
    }
}

/// A pending asynchronous streaming hybrid decryptor.
#[cfg(feature = "async")]
pub struct PendingAsyncStreamingDecryptor<R: AsyncRead + Unpin, A, S> {
    inner: crate::hybrid::asynchronous::PendingDecryptor<R, A, S>,
    _phantom: PhantomData<()>,
}

#[cfg(feature = "async")]
impl<R: AsyncRead + Unpin, A, S> PendingAsyncStreamingDecryptor<R, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    /// Returns a reference to the stream's header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the Key-Encrypting-Key ID from the stream's header.
    pub fn kek_id(&self) -> Option<&str> {
        self.header().payload.kek_id()
    }

    /// Supplies the private key and returns a fully initialized `Decryptor`.
    pub async fn with_private_key(
        self,
        sk: A::PrivateKey,
    ) -> crate::Result<crate::hybrid::asynchronous::Decryptor<R, A, S>>
    where
        A::EncapsulatedKey: From<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        self.inner.into_decryptor(sk).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::prelude::*;
    use seal_crypto::schemes::{
        asymmetric::traditional::rsa::Rsa2048, hash::Sha256, symmetric::aes_gcm::Aes256Gcm,
    };
    use std::collections::HashMap;
    use std::io::{Cursor, Read, Write};
    #[cfg(feature = "async")]

    const TEST_KEK_ID: &str = "test-kek";

    fn get_test_data() -> &'static [u8] {
        b"This is a reasonably long test message to ensure that we cross chunk boundaries."
    }

    type TestKem = Rsa2048<Sha256>;
    type TestDek = Aes256Gcm;

    #[test]
    fn test_in_memory_roundtrip() -> crate::Result<()> {
        let (pk, sk) = TestKem::generate_keypair()?;
        let plaintext = get_test_data();
        let kek_id = "test-kek-id".to_string();
        let seal = HybridSeal::new();

        let encrypted = seal
            .in_memory::<TestKem, TestDek>()
            .encrypt(&pk, plaintext, kek_id.clone())?;

        let pending = seal.in_memory::<TestKem, TestDek>().decrypt(&encrypted)?;
        assert_eq!(pending.kek_id(), Some(kek_id.as_str()));
        let decrypted = pending.with_private_key(&sk)?;

        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_in_memory_parallel_roundtrip() -> crate::Result<()> {
        let (pk, sk) = TestKem::generate_keypair()?;
        let plaintext = get_test_data();
        let kek_id = "test-kek-id-parallel".to_string();
        let seal = HybridSeal::new();

        let encrypted = seal
            .in_memory_parallel::<TestKem, TestDek>()
            .encrypt(&pk, plaintext, kek_id.clone())?;

        let pending = seal
            .in_memory_parallel::<TestKem, TestDek>()
            .decrypt(&encrypted)?;
        assert_eq!(pending.kek_id(), Some(kek_id.as_str()));
        let decrypted = pending.with_private_key(&sk)?;

        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_streaming_roundtrip() {
        let mut key_store = HashMap::new();
        let (pk, sk) = TestKem::generate_keypair().unwrap();
        key_store.insert(TEST_KEK_ID.to_string(), sk);

        let plaintext = get_test_data();
        let seal = HybridSeal::new();

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor = seal
            .streaming_encryptor::<TestKem, TestDek, _>(
                &mut encrypted_data,
                &pk,
                TEST_KEK_ID.to_string(),
            )
            .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt
        let pending = seal
            .streaming_decryptor_from_reader::<TestKem, TestDek, _>(Cursor::new(&encrypted_data))
            .unwrap();
        let kek_id = pending.kek_id().unwrap();
        let decryption_key = key_store.get(kek_id).unwrap();
        let mut decryptor = pending.with_private_key(decryption_key).unwrap();

        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted_data);
    }

    #[test]
    fn test_parallel_streaming_roundtrip() -> crate::Result<()> {
        let (pk, sk) = TestKem::generate_keypair()?;
        let plaintext = get_test_data();
        let kek_id = "test-kek-id-p-streaming".to_string();
        let seal = HybridSeal::new();

        let mut encrypted = Vec::new();
        seal.parallel_streaming::<TestKem, TestDek>()
            .encrypt(&pk, Cursor::new(plaintext), &mut encrypted, kek_id.clone())?;

        let pending = seal
            .parallel_streaming::<TestKem, TestDek>()
            .decrypt(Cursor::new(&encrypted))?;
        assert_eq!(pending.kek_id(), Some(kek_id.as_str()));

        let mut decrypted = Vec::new();
        pending.with_private_key_to_writer(&sk, &mut decrypted)?;

        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[cfg(feature = "async")]
    mod async_tests {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        #[tokio::test]
        async fn test_asynchronous_streaming_roundtrip() {
            let mut key_store = HashMap::new();
            let (pk, sk) = TestKem::generate_keypair().unwrap();
            key_store.insert(TEST_KEK_ID.to_string(), sk.clone());

            let plaintext = get_test_data();
            let seal = HybridSeal::new();

            // Encrypt
            let mut encrypted_data = Vec::new();
            let mut encryptor = seal
                .asynchronous_encryptor::<TestKem, TestDek, _>(
                    &mut encrypted_data,
                    pk,
                    TEST_KEK_ID.to_string(),
                )
                .await
                .unwrap();
            encryptor.write_all(plaintext).await.unwrap();
            encryptor.shutdown().await.unwrap();

            // Decrypt
            let pending = seal
                .asynchronous_decryptor_from_reader::<TestKem, TestDek, _>(std::io::Cursor::new(
                    &encrypted_data,
                ))
                .await
                .unwrap();
            let kek_id = pending.kek_id().unwrap();
            let decryption_key = key_store.get(kek_id).unwrap();
            let mut decryptor = pending
                .with_private_key(decryption_key.clone())
                .await
                .unwrap();

            let mut decrypted_data = Vec::new();
            decryptor.read_to_end(&mut decrypted_data).await.unwrap();
            assert_eq!(plaintext.to_vec(), decrypted_data);
        }
    }
}
