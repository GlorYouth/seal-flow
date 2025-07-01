use crate::algorithms::traits::{AsymmetricAlgorithm, SignatureAlgorithm, SymmetricAlgorithm};
use crate::common::SignerSet;
use crate::keys::{AsymmetricPrivateKey, AsymmetricPublicKey};
use seal_crypto::prelude::*;
use seal_crypto::zeroize::Zeroizing;
use std::io::{Read, Write};
use std::marker::PhantomData;
use tokio::io::AsyncWrite;

/// A context for hybrid encryption operations, allowing selection of execution mode.
pub struct HybridEncryptor<S>
where
    S: SymmetricAlgorithm,
{
    pub(crate) pk: AsymmetricPublicKey,
    pub(crate) kek_id: String,
    pub(crate) aad: Option<Vec<u8>>,
    pub(crate) signer: Option<SignerSet>,
    pub(crate) _phantom: PhantomData<S>,
}

impl<S> HybridEncryptor<S>
where
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
        signing_key: AsymmetricPrivateKey,
        signer_key_id: String,
    ) -> Self
    where
        SignerAlgo: SignatureAlgorithm + 'static,
    {
        self.signer = Some(SignerSet {
            signer_key_id,
            signer_algorithm: SignerAlgo::ALGORITHM,
            signer: Box::new(move |message, aad| {
                let sk = SignerAlgo::PrivateKey::from_bytes(signing_key.as_bytes())?;
                let mut data_to_sign = message.to_vec();
                if let Some(aad_data) = aad {
                    data_to_sign.extend_from_slice(aad_data);
                }
                SignerAlgo::sign(&sk, &data_to_sign)
                    .map(|s| s.0)
                    .map_err(|e| e.into())
            }),
        });
        self
    }

    /// Encrypts the given plaintext in-memory.
    pub fn to_vec<A: AsymmetricAlgorithm>(self, plaintext: &[u8]) -> crate::Result<Vec<u8>>
    where
        A::EncapsulatedKey: Into<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        let pk = A::PublicKey::from_bytes(self.pk.as_bytes())?;
        crate::hybrid::ordinary::encrypt::<A, S>(
            &pk,
            plaintext,
            self.kek_id,
            self.signer,
            self.aad.as_deref(),
        )
    }

    /// Encrypts the given plaintext in-memory using parallel processing.
    pub fn to_vec_parallel<A: AsymmetricAlgorithm>(self, plaintext: &[u8]) -> crate::Result<Vec<u8>>
    where
        S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync + Clone,
        A: AsymmetricAlgorithm,
        Vec<u8>: From<<A as seal_crypto::prelude::Kem>::EncapsulatedKey>,
    {
        let pk = A::PublicKey::from_bytes(self.pk.as_bytes())?;
        crate::hybrid::parallel::encrypt::<A, S>(
            &pk,
            plaintext,
            self.kek_id,
            self.signer,
            self.aad.as_deref(),
        )
    }

    /// Creates a streaming encryptor that writes to the given `Write` implementation.
    pub fn into_writer<A: AsymmetricAlgorithm, W: Write>(
        self,
        writer: W,
    ) -> crate::Result<crate::hybrid::streaming::Encryptor<W, A, S>>
    where
        Vec<u8>: From<<A as seal_crypto::prelude::Kem>::EncapsulatedKey>,
        S::Key: From<Zeroizing<Vec<u8>>> + Clone,
    {
        let pk = A::PublicKey::from_bytes(self.pk.as_bytes())?;
        crate::hybrid::streaming::Encryptor::new(
            writer,
            &pk,
            self.kek_id,
            self.signer,
            self.aad.as_deref(),
        )
    }

    /// Encrypts data from a reader and writes to a writer using parallel processing.
    pub fn pipe_parallel<A: AsymmetricAlgorithm, R, W>(
        self,
        reader: R,
        writer: W,
    ) -> crate::Result<()>
    where
        R: Read + Send,
        W: Write,
        A::EncapsulatedKey: Into<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync,
    {
        let pk = A::PublicKey::from_bytes(self.pk.as_bytes())?;
        crate::hybrid::parallel_streaming::encrypt::<A, S, R, W>(
            &pk,
            reader,
            writer,
            self.kek_id,
            self.signer,
            self.aad.as_deref(),
        )
    }

    /// [Async] Creates an asynchronous streaming encryptor.
    #[cfg(feature = "async")]
    pub async fn into_async_writer<A: AsymmetricAlgorithm, W: AsyncWrite + Unpin>(
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
        let pk = A::PublicKey::from_bytes(self.pk.as_bytes())?;
        crate::hybrid::asynchronous::Encryptor::new(
            writer,
            pk,
            self.kek_id,
            self.signer,
            self.aad.as_deref(),
        )
        .await
    }
}
