use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::header::Header;
use crate::keys::SignaturePublicKey;
use crate::prelude::AsymmetricKeyProvider;
use crate::provider::SignatureKeyProvider;
use crate::Error;
use seal_crypto::zeroize::Zeroizing;
use std::io::{Read, Write};
use tokio::io::AsyncRead;

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

        use crate::common::algorithms::AsymmetricAlgorithm as AsymmetricAlgorithmEnum;
        use crate::keys::AsymmetricPrivateKey;
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

        use crate::common::algorithms::AsymmetricAlgorithm as AsymmetricAlgorithmEnum;
        use crate::keys::AsymmetricPrivateKey;
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

        use crate::common::algorithms::AsymmetricAlgorithm as AsymmetricAlgorithmEnum;
        use crate::keys::AsymmetricPrivateKey;
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

        use crate::common::algorithms::AsymmetricAlgorithm as AsymmetricAlgorithmEnum;
        use crate::keys::AsymmetricPrivateKey;
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

        use crate::common::algorithms::AsymmetricAlgorithm as AsymmetricAlgorithmEnum;
        use crate::keys::AsymmetricPrivateKey;
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
