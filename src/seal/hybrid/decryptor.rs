use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::header::Header;
use crate::keys::SignaturePublicKey;
use crate::prelude::AsymmetricKeyProvider;
use crate::provider::SignatureKeyProvider;
use crate::Error;
use seal_crypto::zeroize::Zeroizing;
use std::io::{Read, Write};
use tokio::io::AsyncRead;

/// Dispatches a call to a handler macro based on the asymmetric algorithm.
///
/// This macro abstracts the repetitive `match` block for handling different
/// asymmetric algorithms and their corresponding private key types.
///
/// # Arguments
///
/// * `$algorithm`: An expression that evaluates to `common::algorithms::AsymmetricAlgorithm`.
/// * `$key`: An expression that evaluates to `keys::AsymmetricPrivateKey`.
/// * `$callback`: The identifier of a macro to call upon a successful match.
/// * `$($extra_args:tt)*`: Optional extra arguments to pass to the callback macro.
///
/// # Callback Macro Signature
///
/// The callback macro will receive:
/// 1. The unwrapped private key variable (`k`).
/// 2. The corresponding algorithm type (e.g., `Rsa2048`).
/// 3. Any extra arguments passed to this macro.
macro_rules! dispatch_asymmetric_algorithm {
    // Internal rule for processing the algorithm list.
    (@internal $algorithm:expr, $key:expr, $callback:ident, $extra_args:tt,
     $(($algo_enum:path, $algo_type:ty, $key_enum:path)),*
    ) => {
        {
            // Note: The `use` statements are now inside the final expansion,
            // so they are only included when the macro is used.
            use crate::common::algorithms::AsymmetricAlgorithm as AsymmetricAlgorithmEnum;
            use crate::keys::AsymmetricPrivateKey;
            use seal_crypto::schemes::asymmetric::{
                post_quantum::kyber::{Kyber1024, Kyber512, Kyber768},
                traditional::rsa::{Rsa2048, Rsa4096},
            };

            match $algorithm {
                $(
                    $algo_enum => match $key {
                        $key_enum(k) => $callback!(k, $algo_type, $extra_args),
                        _ => Err(Error::MismatchedKeyType),
                    },
                )*
            }
        }
    };

    // Public entry point for the macro.
    // It "transcribes" the list of algorithms and "pushes down" to the internal rule.
    ($algorithm:expr, $key:expr, $callback:ident, $($extra_args:tt)*) => {
        dispatch_asymmetric_algorithm!(@internal $algorithm, $key, $callback, ($($extra_args)*),
            (AsymmetricAlgorithmEnum::Rsa2048, Rsa2048, AsymmetricPrivateKey::Rsa2048),
            (AsymmetricAlgorithmEnum::Rsa4096, Rsa4096, AsymmetricPrivateKey::Rsa4096),
            (AsymmetricAlgorithmEnum::Kyber512, Kyber512, AsymmetricPrivateKey::Kyber512),
            (AsymmetricAlgorithmEnum::Kyber768, Kyber768, AsymmetricPrivateKey::Kyber768),
            (AsymmetricAlgorithmEnum::Kyber1024, Kyber1024, AsymmetricPrivateKey::Kyber1024)
        )
    };
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
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;

        let kek_id = self.kek_id().ok_or(Error::KekIdNotFound)?;
        let key = provider
            .get_asymmetric_key(kek_id)
            .ok_or(Error::KeyNotFound)?;

        let algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(Error::InvalidHeader)?;

        macro_rules! do_decrypt {
            ($k:ident, $A:ty, ()) => {
                self.with_private_key::<$A, S>(&$k)
            };
        }

        dispatch_asymmetric_algorithm!(algorithm, key, do_decrypt,)
    }

    /// Supplies the private key and returns the decrypted plaintext.
    pub fn with_private_key<A, S>(self, sk: &A::PrivateKey) -> crate::Result<Vec<u8>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
        A::EncapsulatedKey: From<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
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
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
        let kek_id = self.kek_id().ok_or(Error::KekIdNotFound)?;
        let key = provider
            .get_asymmetric_key(kek_id)
            .ok_or(Error::KeyNotFound)?;

        let algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(Error::InvalidHeader)?;

        macro_rules! do_decrypt {
            ($k:ident, $A:ty, ()) => {
                self.with_private_key::<$A, S>(&$k)
            };
        }

        dispatch_asymmetric_algorithm!(algorithm, key, do_decrypt,)
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
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
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
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;

        let kek_id = self.kek_id().ok_or(Error::KekIdNotFound)?;
        let key = provider
            .get_asymmetric_key(kek_id)
            .ok_or(Error::KeyNotFound)?;

        let algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(Error::InvalidHeader)?;

        macro_rules! do_decrypt {
            ($k:ident, $A:ty, ()) => {
                self.with_private_key::<$A, S>(&$k)
                    .map(|d| Box::new(d) as Box<dyn Read>)
            };
        }

        dispatch_asymmetric_algorithm!(algorithm, key, do_decrypt,)
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
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
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
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;

        let kek_id = self.kek_id().ok_or(Error::KekIdNotFound)?;
        let key = provider
            .get_asymmetric_key(kek_id)
            .ok_or(Error::KeyNotFound)?;

        let algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(Error::InvalidHeader)?;

        macro_rules! do_decrypt {
            ($k:ident, $A:ty, ($writer:ident)) => {
                self.with_private_key_to_writer::<$A, S, W>(&$k, $writer)
            };
        }

        dispatch_asymmetric_algorithm!(algorithm, key, do_decrypt, writer)
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
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
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
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;

        let kek_id = self.kek_id().ok_or(Error::KekIdNotFound)?;
        let key = provider
            .get_asymmetric_key(kek_id)
            .ok_or(Error::KeyNotFound)?;

        let algorithm = self
            .header()
            .payload
            .asymmetric_algorithm()
            .ok_or(Error::InvalidHeader)?;

        macro_rules! do_decrypt {
            ($k:ident, $A:ty, ()) => {
                self.with_private_key::<$A, S>($k.clone())
                    .await
                    .map(|d| Box::new(d) as Box<dyn AsyncRead + Unpin + Send>)
            };
        }

        dispatch_asymmetric_algorithm!(algorithm, key, do_decrypt,)
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
        self.header()
            .verify(self.verification_key.clone(), self.aad.as_deref())?;
        self.inner
            .into_decryptor::<A, S>(sk, self.aad.as_deref())
            .await
    }
}
