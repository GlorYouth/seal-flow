//! This module provides pre-configured, easy-to-use algorithm suites for hybrid encryption.
use std::io::{Read, Write};

use seal_crypto::{
    prelude::SymmetricKeySet, schemes::{asymmetric::post_quantum::kyber::Kyber768, symmetric::aes_gcm::Aes256Gcm}, zeroize::Zeroizing
};

use crate::keys::AsymmetricPublicKey;
use super::encryptor::HybridEncryptor;
use super::HybridEncryptionOptions;

/// The recommended Key Encapsulation Mechanism for the Post-Quantum Cryptography (PQC) suite.
pub type PqcKem = Kyber768;
/// The recommended Data Encapsulation Mechanism for the Post-Quantum Cryptography (PQC) suite.
pub type PqcDek = Aes256Gcm;

/// An encryptor specifically configured for the recommended Post-Quantum Cryptography (PQC) suite.
///
/// This struct simplifies the encryption process by pre-selecting `Kyber768` as the KEM
/// and `Aes256Gcm` as the DEK. It exposes a familiar builder-like API for setting
/// options like AAD and signers, without requiring the user to specify algorithm generics.
pub struct PqcEncryptor {
    inner: HybridEncryptor<PqcDek>,
}

impl PqcEncryptor {
    /// Creates a new PQC encryptor. This is typically called from `HybridSeal::encrypt_pqc_suite`.
    pub(crate) fn new(pk: AsymmetricPublicKey, kek_id: String) -> Self {
        Self {
            inner: HybridEncryptor {
                pk,
                kek_id,
                aad: None,
                signer: None,
                derivation_config: None,
                _phantom: std::marker::PhantomData,
            },
        }
    }

    /// Applies a set of pre-configured options to the encryptor.
    pub fn with_options(mut self, options: HybridEncryptionOptions) -> Self {
        self.inner = self.inner.with_options(options);
        self
    }

    /// Sets the Associated Data (AAD) for this encryption operation.
    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.inner = self.inner.with_aad(aad);
        self
    }

    /// Use a Key Derivation Function (KDF) to derive the Data Encryption Key (DEK).
    pub fn with_kdf<Kdf>(
        mut self,
        deriver: Kdf,
        salt: Option<impl Into<Vec<u8>>>,
        info: Option<impl Into<Vec<u8>>>,
        output_len: u32,
    ) -> Self
    where
        Kdf: crate::algorithms::traits::KdfAlgorithm + Send + Sync + 'static,
    {
        self.inner = self.inner.with_kdf(deriver, salt, info, output_len);
        self
    }

    /// Use an Extendable-Output Function (XOF) to derive the Data Encryption Key (DEK).
    pub fn with_xof<Xof>(
        mut self,
        deriver: Xof,
        salt: Option<impl Into<Vec<u8>>>,
        info: Option<impl Into<Vec<u8>>>,
        output_len: u32,
    ) -> Self
    where
        Xof: crate::algorithms::traits::XofAlgorithm + Send + Sync + 'static,
    {
        self.inner = self.inner.with_xof(deriver, salt, info, output_len);
        self
    }

    /// Encrypts the given plaintext in-memory using the PQC suite.
    pub fn to_vec(self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        self.inner.to_vec::<PqcKem>(plaintext)
    }

    /// Encrypts the given plaintext in-memory using parallel processing with the PQC suite.
    pub fn to_vec_parallel(self, plaintext: &[u8]) -> crate::Result<Vec<u8>>
    where
        <PqcDek as SymmetricKeySet>::Key:
            From<Zeroizing<Vec<u8>>> + Send + Sync + Clone,
        Vec<u8>: From<<PqcKem as seal_crypto::prelude::Kem>::EncapsulatedKey>,
    {
        self.inner.to_vec_parallel::<PqcKem>(plaintext)
    }

    /// Creates a streaming encryptor that writes to the given `Write` implementation using the PQC suite.
    pub fn into_writer<W: Write>(
        self,
        writer: W,
    ) -> crate::Result<crate::hybrid::streaming::Encryptor<W, PqcKem, PqcDek>> {
        self.inner.into_writer::<PqcKem, W>(writer)
    }

    /// Encrypts data from a reader and writes to a writer using parallel processing with the PQC suite.
    pub fn pipe_parallel<R, W>(self, reader: R, writer: W) -> crate::Result<()>
    where
        R: Read + Send,
        W: Write,
    {
        self.inner.pipe_parallel::<PqcKem, R, W>(reader, writer)
    }
} 