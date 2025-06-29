//! This module defines type-erased wrappers for cryptographic keys.
use seal_crypto::{
    prelude::*,
    schemes::{
        asymmetric::{
            post_quantum::{
                dilithium::{Dilithium2, Dilithium3, Dilithium5},
                kyber::{Kyber1024, Kyber512, Kyber768},
            },
            traditional::rsa::{Rsa2048, Rsa4096},
        },
        symmetric::{
            aes_gcm::{Aes128Gcm, Aes256Gcm},
            chacha20_poly1305::{ChaCha20Poly1305, XChaCha20Poly1305},
        },
    },
};

/// A type-erased wrapper for a symmetric encryption key.
///
/// This enum allows high-level APIs to accept a key without needing to know the
/// specific algorithm at compile time. This is particularly useful for key providers
/// or other key management systems that need to handle multiple key types and choose
/// the correct cryptographic implementation based on the algorithm specified in the
/// ciphertext header.
#[derive(Debug, Clone)]
pub enum SymmetricKey {
    Aes128Gcm(<Aes128Gcm as SymmetricKeySet>::Key),
    Aes256Gcm(<Aes256Gcm as SymmetricKeySet>::Key),
    Chacha20Poly1305(<ChaCha20Poly1305 as SymmetricKeySet>::Key),
    XChaCha20Poly1305(<XChaCha20Poly1305 as SymmetricKeySet>::Key),
}

/// A type-erased wrapper for an asymmetric private key.
///
/// This enum allows high-level APIs to accept a key without needing to know the
/// specific algorithm at compile time.
#[derive(Debug, Clone)]
pub enum AsymmetricPrivateKey {
    Rsa2048(<Rsa2048 as AsymmetricKeySet>::PrivateKey),
    Rsa4096(<Rsa4096 as AsymmetricKeySet>::PrivateKey),
    Kyber512(<Kyber512 as AsymmetricKeySet>::PrivateKey),
    Kyber768(<Kyber768 as AsymmetricKeySet>::PrivateKey),
    Kyber1024(<Kyber1024 as AsymmetricKeySet>::PrivateKey),
}

#[derive(Debug, Clone)]
pub enum SignaturePublicKey {
    Dilithium2(<Dilithium2 as AsymmetricKeySet>::PublicKey),
    Dilithium3(<Dilithium3 as AsymmetricKeySet>::PublicKey),
    Dilithium5(<Dilithium5 as AsymmetricKeySet>::PublicKey),
}