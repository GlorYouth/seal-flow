//! This module defines type-erased wrappers for cryptographic keys.
use seal_crypto::prelude::AsymmetricKeySet;
use seal_crypto::prelude::SymmetricKeySet;
use seal_crypto::schemes::asymmetric::post_quantum::kyber::{Kyber1024, Kyber512, Kyber768};
use seal_crypto::schemes::asymmetric::traditional::rsa::{Rsa2048, Rsa4096};
use seal_crypto::schemes::symmetric::aes_gcm::{Aes128Gcm, Aes256Gcm};
use seal_crypto::schemes::symmetric::chacha20_poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};

/// A type-erased wrapper for a symmetric encryption key.
///
/// This enum allows high-level APIs to accept a key without needing to know the
/// specific algorithm at compile time. The API can then dynamically dispatch to
/// the correct cryptographic implementation based on the algorithm specified in the
/// ciphertext header.
#[derive(Clone, Copy)]
pub enum SymmetricKey<'a> {
    Aes128Gcm(&'a <Aes128Gcm as SymmetricKeySet>::Key),
    Aes256Gcm(&'a <Aes256Gcm as SymmetricKeySet>::Key),
    Chacha20Poly1305(&'a <ChaCha20Poly1305 as SymmetricKeySet>::Key),
    XChaCha20Poly1305(&'a <XChaCha20Poly1305 as SymmetricKeySet>::Key),
}

/// A type-erased wrapper for an asymmetric private key.
///
/// This enum allows high-level APIs to accept a key without needing to know the
/// specific algorithm at compile time.
#[derive(Clone, Copy)]
pub enum AsymmetricPrivateKey<'a> {
    Rsa2048(&'a <Rsa2048 as AsymmetricKeySet>::PrivateKey),
    Rsa4096(&'a <Rsa4096 as AsymmetricKeySet>::PrivateKey),
    Kyber512(&'a <Kyber512 as AsymmetricKeySet>::PrivateKey),
    Kyber768(&'a <Kyber768 as AsymmetricKeySet>::PrivateKey),
    Kyber1024(&'a <Kyber1024 as AsymmetricKeySet>::PrivateKey),
}
