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

    /// Begins a hybrid encryption operation.
    ///
    /// This captures the essential encryption parameters (algorithms, public key, KEK ID)
    /// and returns a context object. You can then call methods on this context
    /// to select the desired execution mode (e.g., in-memory, streaming).
    pub fn encrypt<'a, A, S>(
        &self,
        pk: &'a A::PublicKey,
        kek_id: String,
    ) -> HybridEncryptor<'a, A, S>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
    {
        HybridEncryptor {
            pk,
            kek_id,
            _phantom: PhantomData,
        }
    }

    /// Begins a hybrid decryption operation.
    ///
    /// This returns a builder that you can use to configure the decryptor
    /// based on the source of the ciphertext (e.g., from a slice or a stream).
    pub fn decrypt(&self) -> HybridDecryptorBuilder {
        HybridDecryptorBuilder::new()
    }
}

/// A context for hybrid encryption operations, allowing selection of execution mode.
pub struct HybridEncryptor<'a, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    pk: &'a A::PublicKey,
    kek_id: String,
    _phantom: PhantomData<(A, S)>,
}

impl<'a, A, S> HybridEncryptor<'a, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    /// Encrypts the given plaintext in-memory.
    pub fn to_vec(self, plaintext: &[u8]) -> crate::Result<Vec<u8>>
    where
        A::EncapsulatedKey: Into<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        crate::hybrid::ordinary::encrypt::<A, S>(self.pk, plaintext, self.kek_id)
    }

    /// Encrypts the given plaintext in-memory using parallel processing.
    pub fn to_vec_parallel(self, plaintext: &[u8]) -> crate::Result<Vec<u8>>
    where
        S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync + Clone,
        Vec<u8>: From<<A as seal_crypto::prelude::Kem>::EncapsulatedKey>,
    {
        crate::hybrid::parallel::encrypt::<A, S>(self.pk, plaintext, self.kek_id)
    }

    /// Creates a streaming encryptor that writes to the given `Write` implementation.
    pub fn into_writer<W: Write>(
        self,
        writer: W,
    ) -> crate::Result<crate::hybrid::streaming::Encryptor<W, A, S>>
    where
        Vec<u8>: From<<A as seal_crypto::prelude::Kem>::EncapsulatedKey>,
        S::Key: From<Zeroizing<Vec<u8>>> + Clone,
    {
        crate::hybrid::streaming::Encryptor::new(writer, self.pk, self.kek_id)
    }

    /// Encrypts data from a reader and writes to a writer using parallel processing.
    pub fn pipe_parallel<R, W>(self, reader: R, writer: W) -> crate::Result<()>
    where
        R: Read + Send + Sync,
        W: Write + Send + Sync,
        A::EncapsulatedKey: Into<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        crate::hybrid::parallel_streaming::encrypt::<A, S, R, W>(
            self.pk, reader, writer, self.kek_id,
        )
    }

    /// [Async] Creates an asynchronous streaming encryptor.
    #[cfg(feature = "async")]
    pub async fn into_async_writer<W: AsyncWrite + Unpin>(
        self,
        writer: W,
    ) -> crate::Result<crate::hybrid::asynchronous::Encryptor<W, A, S>>
    where
        A::PublicKey: Clone,
        A::EncapsulatedKey: Into<Vec<u8>> + Send,
    {
        crate::hybrid::asynchronous::Encryptor::new(writer, self.pk.clone(), self.kek_id).await
    }
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
    pub fn from_slice<'a>(
        &self,
        ciphertext: &'a [u8],
    ) -> crate::Result<PendingInMemoryDecryptor<'a>> {
        let mid_level_pending =
            crate::hybrid::ordinary::PendingDecryptor::from_ciphertext(ciphertext)?;
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
            crate::hybrid::parallel::PendingDecryptor::from_ciphertext(ciphertext)?;
        Ok(PendingInMemoryParallelDecryptor {
            inner: mid_level_pending,
        })
    }

    /// Configures decryption from a synchronous `Read` stream.
    pub fn from_reader<R: Read>(
        &self,
        reader: R,
    ) -> crate::Result<PendingStreamingDecryptor<R>> {
        let mid_level_pending = crate::hybrid::streaming::PendingDecryptor::from_reader(reader)?;
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
            crate::hybrid::parallel_streaming::PendingDecryptor::from_reader(reader)?;
        Ok(PendingParallelStreamingDecryptor {
            inner: mid_level_pending,
        })
    }

    /// [Async] Configures decryption from an asynchronous `Read` stream.
    #[cfg(feature = "async")]
    pub async fn from_async_reader<R: AsyncRead + Unpin>(
        &self,
        reader: R,
    ) -> crate::Result<PendingAsyncStreamingDecryptor<R>> {
        let mid_level_pending =
            crate::hybrid::asynchronous::PendingDecryptor::from_reader(reader).await?;
        Ok(PendingAsyncStreamingDecryptor {
            inner: mid_level_pending,
        })
    }
}

/// A pending in-memory hybrid decryptor, waiting for the private key.
pub struct PendingInMemoryDecryptor<'a> {
    inner: crate::hybrid::ordinary::PendingDecryptor<'a>,
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

    /// Supplies the private key and returns the decrypted plaintext.
    pub fn with_private_key<A, S>(self, sk: &A::PrivateKey) -> crate::Result<Vec<u8>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
        A::EncapsulatedKey: From<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        self.inner.into_plaintext::<A, S>(sk)
    }
}

/// A pending parallel in-memory hybrid decryptor, waiting for the private key.
pub struct PendingInMemoryParallelDecryptor<'a> {
    inner: crate::hybrid::parallel::PendingDecryptor<'a>,
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

    /// Supplies the private key and returns the decrypted plaintext.
    pub fn with_private_key<A, S>(self, sk: &A::PrivateKey) -> crate::Result<Vec<u8>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
        S::Key: From<Zeroizing<Vec<u8>>>,
        A::PrivateKey: Clone,
        A::EncapsulatedKey: From<Vec<u8>>,
    {
        self.inner.into_plaintext::<A, S>(sk)
    }
}

/// A pending synchronous streaming hybrid decryptor.
pub struct PendingStreamingDecryptor<R: Read> {
    inner: crate::hybrid::streaming::PendingDecryptor<R>,
}

impl<R: Read> PendingStreamingDecryptor<R> {
    /// Returns a reference to the stream's header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the Key-Encrypting-Key ID from the stream's header.
    pub fn kek_id(&self) -> Option<&str> {
        self.header().payload.kek_id()
    }

    /// Supplies the private key and returns a fully initialized `Decryptor`.
    pub fn with_private_key<A, S>(
        self,
        sk: &A::PrivateKey,
    ) -> crate::Result<crate::hybrid::streaming::Decryptor<R, A, S>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
        A::PrivateKey: Clone,
        A::EncapsulatedKey: From<Vec<u8>>,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        self.inner.into_decryptor::<A, S>(sk)
    }
}

/// A pending parallel streaming hybrid decryptor.
pub struct PendingParallelStreamingDecryptor<R>
where
    R: Read + Send,
{
    inner: crate::hybrid::parallel_streaming::PendingDecryptor<R>,
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

    /// Supplies the private key and decrypts the stream, writing to the provided writer.
    pub fn with_private_key_to_writer<A, S, W: Write>(
        self,
        sk: &A::PrivateKey,
        writer: W,
    ) -> crate::Result<()>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
        S::Key: From<Zeroizing<Vec<u8>>>,
        A::PrivateKey: Clone,
        A::EncapsulatedKey: From<Vec<u8>>,
    {
        self.inner.decrypt_to_writer::<A, S, W>(sk, writer)
    }
}

/// A pending asynchronous streaming hybrid decryptor.
#[cfg(feature = "async")]
pub struct PendingAsyncStreamingDecryptor<R: AsyncRead + Unpin> {
    inner: crate::hybrid::asynchronous::PendingDecryptor<R>,
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

    /// Supplies the private key and returns a fully initialized `Decryptor`.
    pub async fn with_private_key<A, S>(
        self,
        sk: A::PrivateKey,
    ) -> crate::Result<crate::hybrid::asynchronous::Decryptor<R, A, S>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
        A::EncapsulatedKey: From<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        self.inner.into_decryptor::<A, S>(sk).await
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
            .encrypt::<TestKem, TestDek>(&pk, kek_id.clone())
            .to_vec(plaintext)?;

        let pending = seal.decrypt().from_slice(&encrypted)?;
        assert_eq!(pending.kek_id(), Some(kek_id.as_str()));
        let decrypted = pending.with_private_key::<TestKem, TestDek>(&sk)?;

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
            .encrypt::<TestKem, TestDek>(&pk, kek_id.clone())
            .to_vec_parallel(plaintext)?;

        let pending = seal.decrypt().from_slice_parallel(&encrypted)?;
        assert_eq!(pending.kek_id(), Some(kek_id.as_str()));
        let decrypted = pending.with_private_key::<TestKem, TestDek>(&sk)?;

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
            .encrypt::<TestKem, TestDek>(&pk, TEST_KEK_ID.to_string())
            .into_writer(&mut encrypted_data)
            .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt
        let pending = seal
            .decrypt()
            .from_reader(Cursor::new(&encrypted_data))
            .unwrap();
        let kek_id = pending.kek_id().unwrap();
        let decryption_key = key_store.get(kek_id).unwrap();
        let mut decryptor = pending
            .with_private_key::<TestKem, TestDek>(decryption_key)
            .unwrap();

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
        seal.encrypt::<TestKem, TestDek>(&pk, kek_id.clone())
            .pipe_parallel(Cursor::new(plaintext), &mut encrypted)?;

        let pending = seal.decrypt().from_reader_parallel(Cursor::new(&encrypted))?;
        assert_eq!(pending.kek_id(), Some(kek_id.as_str()));

        let mut decrypted = Vec::new();
        pending.with_private_key_to_writer::<TestKem, TestDek, _>(&sk, &mut decrypted)?;

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
                .encrypt::<TestKem, TestDek>(&pk, TEST_KEK_ID.to_string())
                .into_async_writer(&mut encrypted_data)
                .await
                .unwrap();
            encryptor.write_all(plaintext).await.unwrap();
            encryptor.shutdown().await.unwrap();

            // Decrypt
            let pending = seal
                .decrypt()
                .from_async_reader(std::io::Cursor::new(&encrypted_data))
                .await
                .unwrap();
            let kek_id = pending.kek_id().unwrap();
            let decryption_key = key_store.get(kek_id).unwrap();
            let mut decryptor = pending
                .with_private_key::<TestKem, TestDek>(decryption_key.clone())
                .await
                .unwrap();

            let mut decrypted_data = Vec::new();
            decryptor.read_to_end(&mut decrypted_data).await.unwrap();
            assert_eq!(plaintext.to_vec(), decrypted_data);
        }
    }
}
