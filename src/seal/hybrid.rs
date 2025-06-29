use crate::algorithms::traits::{AsymmetricAlgorithm, SignatureAlgorithm, SymmetricAlgorithm};
use crate::common::algorithms::AsymmetricAlgorithm as AsymmetricAlgorithmEnum;
use crate::common::header::Header;
use crate::common::SignerSet;
use crate::crypto::zeroize::Zeroizing;
use crate::error::Error;
use crate::keys::{AsymmetricPrivateKey, SignaturePublicKey};
use crate::provider::{AsymmetricKeyProvider, SignatureKeyProvider};
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
            aad: None,
            signer: None,
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

/// Verifies the header signature if a verification key is provided.
fn verify_header(
    header: &Header,
    verification_key: Option<SignaturePublicKey>,
    aad: Option<&[u8]>,
) -> crate::Result<()> {
    // 如果没有提供验证密钥，跳过验证
    let verification_key = match verification_key {
        Some(key) => key,
        None => return Ok(()),
    };

    // 如果头部有签名，则进行验证
    if let Some(algo) = header.payload.signer_algorithm() {
        // 获取签名载荷和签名本身
        let (mut payload_bytes, signature) = header.payload.get_signed_payload_and_sig()?;

        // 将 AAD（如果存在）附加到要验证的负载中
        if let Some(aad_data) = aad {
            payload_bytes.extend_from_slice(aad_data);
        }

        use seal_crypto::prelude::*;
        use seal_crypto::schemes::asymmetric::post_quantum::dilithium::{
            Dilithium2, Dilithium3, Dilithium5,
        };
        // 根据签名算法选择正确的验证方法
        match algo {
            crate::common::algorithms::SignatureAlgorithm::Dilithium2 => match verification_key {
                crate::keys::SignaturePublicKey::Dilithium2(key) => {
                    Dilithium2::verify(&key, &payload_bytes, &Signature(signature))?;
                }
                _ => return Err(Error::UnsupportedOperation),
            },
            crate::common::algorithms::SignatureAlgorithm::Dilithium3 => match verification_key {
                crate::keys::SignaturePublicKey::Dilithium3(key) => {
                    Dilithium3::verify(&key, &payload_bytes, &Signature(signature))?;
                }
                _ => return Err(Error::UnsupportedOperation),
            },
            crate::common::algorithms::SignatureAlgorithm::Dilithium5 => match verification_key {
                crate::keys::SignaturePublicKey::Dilithium5(key) => {
                    Dilithium5::verify(&key, &payload_bytes, &Signature(signature))?;
                }
                _ => return Err(Error::UnsupportedOperation),
            },
        }
        Ok(())
    } else {
        // 没有签名，但提供了验证密钥
        Err(Error::SignatureMissing)
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
    aad: Option<Vec<u8>>,
    signer: Option<SignerSet>,
    _phantom: PhantomData<(A, S)>,
}

impl<'a, A, S> HybridEncryptor<'a, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    /// Sets the Associated Data (AAD) for this encryption operation.
    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }

    /// Signs the encryption metadata (header) with the given private key.
    /// The signature ensures the integrity and authenticity of the encryption parameters.
    pub fn with_signer<SignerAlgo>(
        mut self,
        signing_key: SignerAlgo::PrivateKey,
        signer_key_id: String,
    ) -> Self
    where
        SignerAlgo: SignatureAlgorithm + 'static,
        SignerAlgo::PrivateKey: Sync + Send,
    {
        self.signer = Some(SignerSet {
            signer_key_id,
            signer_algorithm: SignerAlgo::ALGORITHM,
            signer: Box::new(move |message, aad| {
                let mut data_to_sign = message.to_vec();
                if let Some(aad_data) = aad {
                    data_to_sign.extend_from_slice(aad_data);
                }
                SignerAlgo::sign(&signing_key, &data_to_sign)
                    .map(|s| s.0)
                    .map_err(|e| e.into())
            }),
        });
        self
    }

    /// Encrypts the given plaintext in-memory.
    pub fn to_vec(self, plaintext: &[u8]) -> crate::Result<Vec<u8>>
    where
        A::EncapsulatedKey: Into<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        crate::hybrid::ordinary::encrypt::<A, S>(
            self.pk,
            plaintext,
            self.kek_id,
            self.signer,
            self.aad.as_deref(),
        )
    }

    /// Encrypts the given plaintext in-memory using parallel processing.
    pub fn to_vec_parallel(self, plaintext: &[u8]) -> crate::Result<Vec<u8>>
    where
        S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync + Clone,
        Vec<u8>: From<<A as seal_crypto::prelude::Kem>::EncapsulatedKey>,
    {
        crate::hybrid::parallel::encrypt::<A, S>(
            self.pk,
            plaintext,
            self.kek_id,
            self.signer,
            self.aad.as_deref(),
        )
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
        crate::hybrid::streaming::Encryptor::new(
            writer,
            self.pk,
            self.kek_id,
            self.signer,
            self.aad.as_deref(),
        )
    }

    /// Encrypts data from a reader and writes to a writer using parallel processing.
    pub fn pipe_parallel<R, W>(self, reader: R, writer: W) -> crate::Result<()>
    where
        R: Read + Send,
        W: Write,
        A::EncapsulatedKey: Into<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync,
    {
        crate::hybrid::parallel_streaming::encrypt::<A, S, R, W>(
            self.pk,
            reader,
            writer,
            self.kek_id,
            self.signer,
            self.aad.as_deref(),
        )
    }

    /// [Async] Creates an asynchronous streaming encryptor.
    #[cfg(feature = "async")]
    pub async fn into_async_writer<W: AsyncWrite + Unpin>(
        self,
        writer: W,
    ) -> crate::Result<crate::hybrid::asynchronous::Encryptor<W, A, S>>
    where
        A: AsymmetricAlgorithm + 'static,
        A::PublicKey: Send,
        A::EncapsulatedKey: Into<Vec<u8>> + Send,
        S: SymmetricAlgorithm + 'static,
        S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync + 'static,
    {
        crate::hybrid::asynchronous::Encryptor::new(
            writer,
            self.pk.clone().into(),
            self.kek_id,
            self.signer,
            self.aad.as_deref(),
        )
        .await
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
    pub fn slice(self, ciphertext: &[u8]) -> crate::Result<PendingInMemoryDecryptor> {
        let mid_level_pending =
            crate::hybrid::ordinary::PendingDecryptor::from_ciphertext(ciphertext)?;
        Ok(PendingInMemoryDecryptor {
            inner: mid_level_pending,
            aad: None,
            verification_key: None,
        })
    }

    /// Configures parallel decryption from an in-memory byte slice.
    pub fn slice_parallel(
        self,
        ciphertext: &[u8],
    ) -> crate::Result<PendingInMemoryParallelDecryptor> {
        let mid_level_pending =
            crate::hybrid::parallel::PendingDecryptor::from_ciphertext(ciphertext)?;
        Ok(PendingInMemoryParallelDecryptor {
            inner: mid_level_pending,
            aad: None,
            verification_key: None,
        })
    }

    /// Configures decryption from a synchronous `Read` stream.
    pub fn reader<R: Read>(self, reader: R) -> crate::Result<PendingStreamingDecryptor<R>> {
        let mid_level_pending = crate::hybrid::streaming::PendingDecryptor::from_reader(reader)?;
        Ok(PendingStreamingDecryptor {
            inner: mid_level_pending,
            aad: None,
            verification_key: None,
        })
    }

    /// Configures parallel decryption from a synchronous `Read` stream.
    pub fn reader_parallel<R: Read + Send>(
        self,
        reader: R,
    ) -> crate::Result<PendingParallelStreamingDecryptor<R>> {
        let mid_level_pending =
            crate::hybrid::parallel_streaming::PendingDecryptor::from_reader(reader)?;
        Ok(PendingParallelStreamingDecryptor {
            inner: mid_level_pending,
            aad: None,
            verification_key: None,
        })
    }

    /// [Async] Configures decryption from an asynchronous `Read` stream.
    #[cfg(feature = "async")]
    pub async fn async_reader<R: AsyncRead + Unpin>(
        self,
        reader: R,
    ) -> crate::Result<PendingAsyncStreamingDecryptor<R>> {
        let mid_level_pending =
            crate::hybrid::asynchronous::PendingDecryptor::from_reader(reader).await?;
        Ok(PendingAsyncStreamingDecryptor {
            inner: mid_level_pending,
            aad: None,
            verification_key: None,
        })
    }
}

/// A pending in-memory hybrid decryptor, waiting for the private key.
pub struct PendingInMemoryDecryptor<'a> {
    inner: crate::hybrid::ordinary::PendingDecryptor<'a>,
    aad: Option<Vec<u8>>,
    verification_key: Option<SignaturePublicKey>,
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

    /// Returns the Signer-Key-ID from the header.
    pub fn signer_key_id(&self) -> Option<&str> {
        self.header().payload.signer_key_id()
    }

    /// Sets the Associated Data (AAD) for this decryption operation.
    /// The AAD must match the value provided during encryption.
    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }

    /// Supplies a key provider to automatically look up the verification key.
    pub fn with_verifier<P>(mut self, provider: &'a P) -> crate::Result<Self>
    where
        P: SignatureKeyProvider,
    {
        let signer_id = self.signer_key_id().ok_or(Error::SignerKeyIdMissing)?;
        let verification_key = provider
            .get_signature_key(signer_id)
            .ok_or(Error::KeyNotFound)?;
        self.verification_key = Some(verification_key);
        Ok(self)
    }

    /// Supplies a `AsymmetricKeyProvider` to automatically look up the key and decrypt.
    pub fn with_provider<P, S>(self, provider: &P) -> crate::Result<Vec<u8>>
    where
        P: AsymmetricKeyProvider,
        S: SymmetricAlgorithm,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        verify_header(
            self.header(),
            self.verification_key.clone(),
            self.aad.as_deref(),
        )?;

        let kek_id = self.kek_id().ok_or(Error::KekIdNotFound)?;
        let key = provider
            .get_asymmetric_key(kek_id)
            .ok_or(Error::KeyNotFound)?;

        let algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(Error::InvalidHeader)?;

        use seal_crypto::schemes::asymmetric::{
            post_quantum::kyber::{Kyber1024, Kyber512, Kyber768},
            traditional::rsa::{Rsa2048, Rsa4096},
        };

        match algorithm {
            AsymmetricAlgorithmEnum::Rsa2048 => match key {
                AsymmetricPrivateKey::Rsa2048(k) => self.with_private_key::<Rsa2048, S>(&k),
                _ => Err(Error::MismatchedKeyType),
            },
            AsymmetricAlgorithmEnum::Rsa4096 => match key {
                AsymmetricPrivateKey::Rsa4096(k) => self.with_private_key::<Rsa4096, S>(&k),
                _ => Err(Error::MismatchedKeyType),
            },
            AsymmetricAlgorithmEnum::Kyber512 => match key {
                AsymmetricPrivateKey::Kyber512(k) => self.with_private_key::<Kyber512, S>(&k),
                _ => Err(Error::MismatchedKeyType),
            },
            AsymmetricAlgorithmEnum::Kyber768 => match key {
                AsymmetricPrivateKey::Kyber768(k) => self.with_private_key::<Kyber768, S>(&k),
                _ => Err(Error::MismatchedKeyType),
            },
            AsymmetricAlgorithmEnum::Kyber1024 => match key {
                AsymmetricPrivateKey::Kyber1024(k) => self.with_private_key::<Kyber1024, S>(&k),
                _ => Err(Error::MismatchedKeyType),
            },
        }
    }

    /// Supplies the private key and returns the decrypted plaintext.
    pub fn with_private_key<A, S>(self, sk: &A::PrivateKey) -> crate::Result<Vec<u8>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
        A::EncapsulatedKey: From<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        verify_header(
            self.header(),
            self.verification_key.clone(),
            self.aad.as_deref(),
        )?;
        self.inner.into_plaintext::<A, S>(sk, self.aad.as_deref())
    }
}

/// A pending parallel in-memory hybrid decryptor, waiting for the private key.
pub struct PendingInMemoryParallelDecryptor<'a> {
    inner: crate::hybrid::parallel::PendingDecryptor<'a>,
    aad: Option<Vec<u8>>,
    verification_key: Option<SignaturePublicKey>,
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

    /// Returns the Signer-Key-ID from the header.
    pub fn signer_key_id(&self) -> Option<&str> {
        self.header().payload.signer_key_id()
    }

    /// Sets the Associated Data (AAD) for this decryption operation.
    /// The AAD must match the value provided during encryption.
    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }

    /// Supplies a key provider to automatically look up the verification key.
    pub fn with_verifier<P>(mut self, provider: &'a P) -> crate::Result<Self>
    where
        P: SignatureKeyProvider,
    {
        let signer_id = self.signer_key_id().ok_or(Error::SignerKeyIdMissing)?;
        let verification_key = provider
            .get_signature_key(signer_id)
            .ok_or(Error::KeyNotFound)?;
        self.verification_key = Some(verification_key);
        Ok(self)
    }

    /// Supplies a `AsymmetricKeyProvider` to automatically look up the key and decrypt.
    pub fn with_provider<P, S>(self, provider: &P) -> crate::Result<Vec<u8>>
    where
        P: AsymmetricKeyProvider,
        S: SymmetricAlgorithm,
        S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync,
    {
        verify_header(
            self.header(),
            self.verification_key.clone(),
            self.aad.as_deref(),
        )?;
        let kek_id = self.kek_id().ok_or(Error::KekIdNotFound)?;
        let key = provider
            .get_asymmetric_key(kek_id)
            .ok_or(Error::KeyNotFound)?;

        let algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(Error::InvalidHeader)?;

        use seal_crypto::schemes::asymmetric::{
            post_quantum::kyber::{Kyber1024, Kyber512, Kyber768},
            traditional::rsa::{Rsa2048, Rsa4096},
        };

        match algorithm {
            AsymmetricAlgorithmEnum::Rsa2048 => match key {
                AsymmetricPrivateKey::Rsa2048(k) => self.with_private_key::<Rsa2048, S>(&k),
                _ => Err(Error::MismatchedKeyType),
            },
            AsymmetricAlgorithmEnum::Rsa4096 => match key {
                AsymmetricPrivateKey::Rsa4096(k) => self.with_private_key::<Rsa4096, S>(&k),
                _ => Err(Error::MismatchedKeyType),
            },
            AsymmetricAlgorithmEnum::Kyber512 => match key {
                AsymmetricPrivateKey::Kyber512(k) => self.with_private_key::<Kyber512, S>(&k),
                _ => Err(Error::MismatchedKeyType),
            },
            AsymmetricAlgorithmEnum::Kyber768 => match key {
                AsymmetricPrivateKey::Kyber768(k) => self.with_private_key::<Kyber768, S>(&k),
                _ => Err(Error::MismatchedKeyType),
            },
            AsymmetricAlgorithmEnum::Kyber1024 => match key {
                AsymmetricPrivateKey::Kyber1024(k) => self.with_private_key::<Kyber1024, S>(&k),
                _ => Err(Error::MismatchedKeyType),
            },
        }
    }

    /// Supplies the private key and returns the decrypted plaintext.
    pub fn with_private_key<A, S>(self, sk: &A::PrivateKey) -> crate::Result<Vec<u8>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
        S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync,
        A::PrivateKey: Clone,
        A::EncapsulatedKey: From<Vec<u8>>,
    {
        verify_header(
            self.header(),
            self.verification_key.clone(),
            self.aad.as_deref(),
        )?;
        self.inner.into_plaintext::<A, S>(sk, self.aad.as_deref())
    }
}

/// A pending synchronous streaming hybrid decryptor.
pub struct PendingStreamingDecryptor<R: Read + 'static> {
    inner: crate::hybrid::streaming::PendingDecryptor<R>,
    aad: Option<Vec<u8>>,
    verification_key: Option<SignaturePublicKey>,
}

impl<R: Read + 'static> PendingStreamingDecryptor<R> {
    /// Returns a reference to the stream's header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// Returns the Key-Encrypting-Key ID from the stream's header.
    pub fn kek_id(&self) -> Option<&str> {
        self.header().payload.kek_id()
    }

    /// Returns the Signer-Key-ID from the stream's header.
    pub fn signer_key_id(&self) -> Option<&str> {
        self.header().payload.signer_key_id()
    }

    /// Sets the Associated Data (AAD) for this decryption operation.
    /// The AAD must match the value provided during encryption.
    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }

    /// Supplies a key provider to automatically look up the verification key.
    pub fn with_verifier<P>(mut self, provider: &P) -> crate::Result<Self>
    where
        P: SignatureKeyProvider,
    {
        let signer_id = self.signer_key_id().ok_or(Error::SignerKeyIdMissing)?;
        let verification_key = provider
            .get_signature_key(signer_id)
            .ok_or(Error::KeyNotFound)?;
        self.verification_key = Some(verification_key);
        Ok(self)
    }

    /// Supplies a `AsymmetricKeyProvider` to automatically look up the key and create a decryptor.
    pub fn with_provider<P, S>(self, provider: &P) -> crate::Result<Box<dyn Read + 'static>>
    where
        P: AsymmetricKeyProvider,
        S: SymmetricAlgorithm,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        verify_header(
            self.header(),
            self.verification_key.clone(),
            self.aad.as_deref(),
        )?;

        let kek_id = self.kek_id().ok_or(Error::KekIdNotFound)?;
        let key = provider
            .get_asymmetric_key(kek_id)
            .ok_or(Error::KeyNotFound)?;

        let algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(Error::InvalidHeader)?;

        use seal_crypto::schemes::asymmetric::{
            post_quantum::kyber::{Kyber1024, Kyber512, Kyber768},
            traditional::rsa::{Rsa2048, Rsa4096},
        };

        match algorithm {
            AsymmetricAlgorithmEnum::Rsa2048 => match key {
                AsymmetricPrivateKey::Rsa2048(k) => self
                    .with_private_key::<Rsa2048, S>(&k)
                    .map(|d| Box::new(d) as Box<dyn Read>),
                _ => Err(Error::MismatchedKeyType),
            },
            AsymmetricAlgorithmEnum::Rsa4096 => match key {
                AsymmetricPrivateKey::Rsa4096(k) => self
                    .with_private_key::<Rsa4096, S>(&k)
                    .map(|d| Box::new(d) as Box<dyn Read>),
                _ => Err(Error::MismatchedKeyType),
            },
            AsymmetricAlgorithmEnum::Kyber512 => match key {
                AsymmetricPrivateKey::Kyber512(k) => self
                    .with_private_key::<Kyber512, S>(&k)
                    .map(|d| Box::new(d) as Box<dyn Read>),
                _ => Err(Error::MismatchedKeyType),
            },
            AsymmetricAlgorithmEnum::Kyber768 => match key {
                AsymmetricPrivateKey::Kyber768(k) => self
                    .with_private_key::<Kyber768, S>(&k)
                    .map(|d| Box::new(d) as Box<dyn Read>),
                _ => Err(Error::MismatchedKeyType),
            },
            AsymmetricAlgorithmEnum::Kyber1024 => match key {
                AsymmetricPrivateKey::Kyber1024(k) => self
                    .with_private_key::<Kyber1024, S>(&k)
                    .map(|d| Box::new(d) as Box<dyn Read>),
                _ => Err(Error::MismatchedKeyType),
            },
        }
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
        A::EncapsulatedKey: From<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        verify_header(
            self.header(),
            self.verification_key.clone(),
            self.aad.as_deref(),
        )?;
        self.inner.into_decryptor::<A, S>(sk, self.aad.as_deref())
    }
}

/// A pending parallel streaming hybrid decryptor.
pub struct PendingParallelStreamingDecryptor<R>
where
    R: Read + Send,
{
    inner: crate::hybrid::parallel_streaming::PendingDecryptor<R>,
    aad: Option<Vec<u8>>,
    verification_key: Option<SignaturePublicKey>,
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

    /// Returns the Signer-Key-ID from the stream's header.
    pub fn signer_key_id(&self) -> Option<&str> {
        self.header().payload.signer_key_id()
    }

    /// Sets the Associated Data (AAD) for this decryption operation.
    /// The AAD must match the value provided during encryption.
    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }

    /// Supplies a key provider to automatically look up the verification key.
    pub fn with_verifier<P>(mut self, provider: &P) -> crate::Result<Self>
    where
        P: SignatureKeyProvider,
    {
        let signer_id = self.signer_key_id().ok_or(Error::SignerKeyIdMissing)?;
        let verification_key = provider
            .get_signature_key(signer_id)
            .ok_or(Error::KeyNotFound)?;
        // This is a limitation for now, we need to make the provider own the key
        // or use other mechanisms to manage lifetime.
        // For simplicity, we assume static lifetime for keys from provider in streaming mode.
        self.verification_key = Some(verification_key.clone());
        Ok(self)
    }

    /// Supplies a `AsymmetricKeyProvider` to automatically look up the key and decrypt the stream.
    pub fn with_provider<P, S, W>(self, provider: &P, writer: W) -> crate::Result<()>
    where
        P: AsymmetricKeyProvider,
        S: SymmetricAlgorithm,
        W: Write,
        S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync,
    {
        verify_header(
            self.header(),
            self.verification_key.clone(),
            self.aad.as_deref(),
        )?;

        let kek_id = self.kek_id().ok_or(Error::KekIdNotFound)?;
        let key = provider
            .get_asymmetric_key(kek_id)
            .ok_or(Error::KeyNotFound)?;

        let algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(Error::InvalidHeader)?;

        use seal_crypto::schemes::asymmetric::{
            post_quantum::kyber::{Kyber1024, Kyber512, Kyber768},
            traditional::rsa::{Rsa2048, Rsa4096},
        };

        match algorithm {
            AsymmetricAlgorithmEnum::Rsa2048 => match key {
                AsymmetricPrivateKey::Rsa2048(k) => {
                    self.with_private_key_to_writer::<Rsa2048, S, W>(&k, writer)
                }
                _ => Err(Error::MismatchedKeyType),
            },
            AsymmetricAlgorithmEnum::Rsa4096 => match key {
                AsymmetricPrivateKey::Rsa4096(k) => {
                    self.with_private_key_to_writer::<Rsa4096, S, W>(&k, writer)
                }
                _ => Err(Error::MismatchedKeyType),
            },
            AsymmetricAlgorithmEnum::Kyber512 => match key {
                AsymmetricPrivateKey::Kyber512(k) => {
                    self.with_private_key_to_writer::<Kyber512, S, W>(&k, writer)
                }
                _ => Err(Error::MismatchedKeyType),
            },
            AsymmetricAlgorithmEnum::Kyber768 => match key {
                AsymmetricPrivateKey::Kyber768(k) => {
                    self.with_private_key_to_writer::<Kyber768, S, W>(&k, writer)
                }
                _ => Err(Error::MismatchedKeyType),
            },
            AsymmetricAlgorithmEnum::Kyber1024 => match key {
                AsymmetricPrivateKey::Kyber1024(k) => {
                    self.with_private_key_to_writer::<Kyber1024, S, W>(&k, writer)
                }
                _ => Err(Error::MismatchedKeyType),
            },
        }
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
        S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync,
        A::PrivateKey: Clone,
        A::EncapsulatedKey: From<Vec<u8>> + Send,
    {
        verify_header(
            self.header(),
            self.verification_key.clone(),
            self.aad.as_deref(),
        )?;
        self.inner
            .decrypt_to_writer::<A, S, W>(sk, writer, self.aad.as_deref())
    }
}

/// A pending asynchronous streaming hybrid decryptor.
#[cfg(feature = "async")]
pub struct PendingAsyncStreamingDecryptor<R: AsyncRead + Unpin> {
    inner: crate::hybrid::asynchronous::PendingDecryptor<R>,
    aad: Option<Vec<u8>>,
    verification_key: Option<SignaturePublicKey>,
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

    /// Returns the Signer-Key-ID from the stream's header.
    pub fn signer_key_id(&self) -> Option<&str> {
        self.header().payload.signer_key_id()
    }

    /// Sets the Associated Data (AAD) for this decryption operation.
    /// The AAD must match the value provided during encryption.
    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.aad = Some(aad.into());
        self
    }

    /// Supplies a key provider to automatically look up the verification key.
    pub async fn with_verifier<P>(mut self, provider: &P) -> crate::Result<Self>
    where
        P: SignatureKeyProvider,
    {
        let signer_id = self.signer_key_id().ok_or(Error::SignerKeyIdMissing)?;
        let verification_key = provider
            .get_signature_key(signer_id)
            .ok_or(Error::KeyNotFound)?;
        self.verification_key = Some(verification_key.clone());
        Ok(self)
    }

    /// Supplies a `AsymmetricKeyProvider` to automatically look up the key and create a decryptor.
    pub async fn with_provider<'s, P, S>(
        self,
        provider: &'s P,
    ) -> crate::Result<Box<dyn AsyncRead + Unpin + Send + 's>>
    where
        P: AsymmetricKeyProvider,
        S: SymmetricAlgorithm,
        S::Key: From<Zeroizing<Vec<u8>>> + Clone + Send + Sync,
        R: Send + 's,
    {
        verify_header(
            self.header(),
            self.verification_key.clone(),
            self.aad.as_deref(),
        )?;

        let kek_id = self.kek_id().ok_or(Error::KekIdNotFound)?;
        let key = provider
            .get_asymmetric_key(kek_id)
            .ok_or(Error::KeyNotFound)?;

        let algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(Error::InvalidHeader)?;

        use seal_crypto::schemes::asymmetric::{
            post_quantum::kyber::{Kyber1024, Kyber512, Kyber768},
            traditional::rsa::{Rsa2048, Rsa4096},
        };

        match algorithm {
            AsymmetricAlgorithmEnum::Rsa2048 => match key {
                AsymmetricPrivateKey::Rsa2048(k) => self
                    .with_private_key::<Rsa2048, S>(k.clone())
                    .await
                    .map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
                _ => Err(Error::MismatchedKeyType),
            },
            AsymmetricAlgorithmEnum::Rsa4096 => match key {
                AsymmetricPrivateKey::Rsa4096(k) => self
                    .with_private_key::<Rsa4096, S>(k.clone())
                    .await
                    .map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
                _ => Err(Error::MismatchedKeyType),
            },
            AsymmetricAlgorithmEnum::Kyber512 => match key {
                AsymmetricPrivateKey::Kyber512(k) => self
                    .with_private_key::<Kyber512, S>(k.clone())
                    .await
                    .map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
                _ => Err(Error::MismatchedKeyType),
            },
            AsymmetricAlgorithmEnum::Kyber768 => match key {
                AsymmetricPrivateKey::Kyber768(k) => self
                    .with_private_key::<Kyber768, S>(k.clone())
                    .await
                    .map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
                _ => Err(Error::MismatchedKeyType),
            },
            AsymmetricAlgorithmEnum::Kyber1024 => match key {
                AsymmetricPrivateKey::Kyber1024(k) => self
                    .with_private_key::<Kyber1024, S>(k.clone())
                    .await
                    .map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>),
                _ => Err(Error::MismatchedKeyType),
            },
        }
    }

    /// Supplies the private key and returns a fully initialized `Decryptor`.
    pub async fn with_private_key<A, S>(
        self,
        sk: A::PrivateKey,
    ) -> crate::Result<crate::hybrid::asynchronous::Decryptor<R, A, S>>
    where
        A: AsymmetricAlgorithm + 'static,
        S: SymmetricAlgorithm + 'static,
        A::PrivateKey: Send,
        A::EncapsulatedKey: From<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync + 'static,
    {
        verify_header(
            self.header(),
            self.verification_key.clone(),
            self.aad.as_deref(),
        )?;
        self.inner
            .into_decryptor::<A, S>(sk, self.aad.as_deref())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{AsymmetricPrivateKey, SignaturePublicKey};
    use crate::provider::{AsymmetricKeyProvider, SignatureKeyProvider};
    use once_cell::sync::Lazy;
    use seal_crypto::prelude::*;
    use seal_crypto::schemes::asymmetric::post_quantum::dilithium::Dilithium2;
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
    type TestSigner = Dilithium2;

    static TEST_KEY_PAIR_RSA2048: Lazy<(
        <TestKem as AsymmetricKeySet>::PublicKey,
        <TestKem as AsymmetricKeySet>::PrivateKey,
    )> = Lazy::new(|| TestKem::generate_keypair().unwrap());

    struct TestKeyProvider {
        keys: HashMap<String, AsymmetricPrivateKey>,
    }

    impl TestKeyProvider {
        fn new() -> Self {
            let mut keys = HashMap::new();
            keys.insert(
                "test-provider-key".to_string(),
                AsymmetricPrivateKey::Rsa2048(TEST_KEY_PAIR_RSA2048.1.clone()),
            );
            Self { keys }
        }
    }

    impl AsymmetricKeyProvider for TestKeyProvider {
        fn get_asymmetric_key<'a>(&'a self, kek_id: &str) -> Option<AsymmetricPrivateKey> {
            self.keys.get(kek_id).cloned()
        }
    }

    struct TestSignatureProvider {
        keys: HashMap<String, SignaturePublicKey>,
    }

    impl TestSignatureProvider {
        fn new() -> Self {
            Self {
                keys: HashMap::new(),
            }
        }
        fn add_key(&mut self, id: String, key: SignaturePublicKey) {
            self.keys.insert(id, key);
        }
    }

    impl SignatureKeyProvider for TestSignatureProvider {
        fn get_signature_key<'a>(&'a self, signer_key_id: &str) -> Option<SignaturePublicKey> {
            self.keys.get(signer_key_id).cloned()
        }
    }

    #[test]
    fn test_in_memory_roundtrip() -> crate::Result<()> {
        let (pk, sk) = TestKem::generate_keypair()?;
        let plaintext = get_test_data();
        let kek_id = "test-kek-id".to_string();
        let seal = HybridSeal::new();

        let encrypted = seal
            .encrypt::<TestKem, TestDek>(&pk, kek_id.clone())
            .to_vec(plaintext)?;

        let pending = seal.decrypt().slice(&encrypted)?;
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

        let pending = seal.decrypt().slice_parallel(&encrypted)?;
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
        let pending = seal.decrypt().reader(Cursor::new(encrypted_data)).unwrap();
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

        let pending = seal.decrypt().reader_parallel(Cursor::new(&encrypted))?;
        assert_eq!(pending.kek_id(), Some(kek_id.as_str()));

        let mut decrypted = Vec::new();
        pending.with_private_key_to_writer::<TestKem, TestDek, _>(&sk, &mut decrypted)?;

        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_with_provider_roundtrip() -> crate::Result<()> {
        let provider = TestKeyProvider::new();
        let kek_id = "test-provider-key".to_string();

        let pk = &TEST_KEY_PAIR_RSA2048.0;

        let plaintext = get_test_data();
        let seal = HybridSeal::new();

        let encrypted = seal
            .encrypt::<TestKem, TestDek>(pk, kek_id.clone())
            .to_vec(plaintext)?;

        let pending = seal.decrypt().slice(&encrypted)?;
        assert_eq!(pending.kek_id(), Some(kek_id.as_str()));
        let decrypted = pending.with_provider::<_, TestDek>(&provider)?;

        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_aad_roundtrip() -> crate::Result<()> {
        let (pk, sk) = TestKem::generate_keypair()?;
        let plaintext = get_test_data();
        let aad = b"test-associated-data-for-hybrid";
        let kek_id = "aad-kek".to_string();
        let seal = HybridSeal::new();

        // Encrypt with AAD
        let encrypted = seal
            .encrypt::<TestKem, TestDek>(&pk, kek_id.clone())
            .with_aad(aad)
            .to_vec(plaintext)?;

        // Decrypt with correct AAD
        let pending = seal.decrypt().slice(&encrypted)?;
        assert_eq!(pending.kek_id(), Some(kek_id.as_str()));
        let decrypted = pending
            .with_aad(aad)
            .with_private_key::<TestKem, TestDek>(&sk)?;
        assert_eq!(plaintext, decrypted.as_slice());

        // Decrypt with wrong AAD fails
        let pending_fail = seal.decrypt().slice(&encrypted)?;
        let result = pending_fail
            .with_aad(b"wrong-aad")
            .with_private_key::<TestKem, TestDek>(&sk);
        assert!(result.is_err());

        // Decrypt with no AAD fails
        let pending_fail2 = seal.decrypt().slice(&encrypted)?;
        let result2 = pending_fail2.with_private_key::<TestKem, TestDek>(&sk);
        assert!(result2.is_err());

        Ok(())
    }

    #[test]
    fn test_signed_aad_tampering_fails() -> crate::Result<()> {
        // 1. Setup keys
        let (enc_pk, enc_sk) = TestKem::generate_keypair()?;
        let (sig_pk, sig_sk) = TestSigner::generate_keypair()?;

        // 2. Setup provider for verifier
        let signer_key_id = "test-signer-key-mem".to_string();
        let mut sig_provider = TestSignatureProvider::new();
        sig_provider.add_key(
            signer_key_id.clone(),
            SignaturePublicKey::Dilithium2(sig_pk),
        );

        let plaintext = get_test_data();
        let aad = b"test-signed-aad-memory";
        let kek_id = "test-signed-aad-kek-mem".to_string();
        let seal = HybridSeal::new();

        // 3. Encrypt with signer and AAD
        let encrypted = seal
            .encrypt::<TestKem, TestDek>(&enc_pk, kek_id)
            .with_aad(aad)
            .with_signer::<TestSigner>(sig_sk, signer_key_id.clone())
            .to_vec(plaintext)?;

        // 4. Successful roundtrip with correct verifier and AAD
        let decrypted = seal
            .decrypt()
            .slice(&encrypted)?
            .with_aad(aad)
            .with_verifier(&sig_provider)?
            .with_private_key::<TestKem, TestDek>(&enc_sk)?;
        assert_eq!(decrypted.as_slice(), plaintext);

        // 5. Fails with wrong AAD
        let res = seal
            .decrypt()
            .slice(&encrypted)?
            .with_aad(b"wrong aad")
            .with_verifier(&sig_provider)?
            .with_private_key::<TestKem, TestDek>(&enc_sk);
        assert!(res.is_err(), "Decryption should fail with wrong AAD");
        assert!(matches!(res.err(), Some(Error::Crypto(_))));

        // 6. Fails with no AAD
        let res2 = seal
            .decrypt()
            .slice(&encrypted)?
            .with_verifier(&sig_provider)?
            .with_private_key::<TestKem, TestDek>(&enc_sk);
        assert!(res2.is_err(), "Decryption should fail with no AAD");

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
                .async_reader(std::io::Cursor::new(&encrypted_data))
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

        #[tokio::test]
        async fn test_async_signed_aad_tampering_fails() -> crate::Result<()> {
            let (enc_pk, enc_sk) = TestKem::generate_keypair()?;
            let (sig_pk, sig_sk) = TestSigner::generate_keypair()?;

            let signer_key_id = "test-signer-key-async".to_string();
            let mut sig_provider = TestSignatureProvider::new();
            sig_provider.add_key(
                signer_key_id.clone(),
                SignaturePublicKey::Dilithium2(sig_pk),
            );

            let plaintext = get_test_data();
            let aad = b"test-signed-aad-async";
            let kek_id = "test-signed-aad-kek-async".to_string();
            let seal = HybridSeal::new();

            // Encrypt
            let mut encrypted = Vec::new();
            let mut encryptor = seal
                .encrypt::<TestKem, TestDek>(&enc_pk, kek_id)
                .with_aad(aad)
                .with_signer::<TestSigner>(sig_sk, signer_key_id)
                .into_async_writer(&mut encrypted)
                .await?;
            encryptor.write_all(plaintext).await?;
            encryptor.shutdown().await?;

            // Successful roundtrip
            let mut decryptor = seal
                .decrypt()
                .async_reader(Cursor::new(&encrypted))
                .await?
                .with_aad(aad)
                .with_verifier(&sig_provider)
                .await?
                .with_private_key::<TestKem, TestDek>(enc_sk.clone())
                .await?;
            let mut decrypted_ok = Vec::new();
            decryptor.read_to_end(&mut decrypted_ok).await?;
            assert_eq!(decrypted_ok, plaintext);

            // Fails with wrong AAD
            let res = seal
                .decrypt()
                .async_reader(Cursor::new(&encrypted))
                .await?
                .with_aad(b"wrong-aad")
                .with_verifier(&sig_provider)
                .await?
                .with_private_key::<TestKem, TestDek>(enc_sk.clone())
                .await;
            assert!(res.is_err());

            Ok(())
        }
    }
}
