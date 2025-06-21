//! Defines the concrete algorithm types and implements the corresponding traits.

use super::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common;
use seal_crypto::{
    systems::{
        asymmetric::rsa::{Rsa2048 as Rsa2048Params, Rsa4096 as Rsa4096Params, RsaScheme},
        asymmetric::kyber::{Kyber512 as Kyber512Params, Kyber768 as Kyber768Params, Kyber1024 as Kyber1024Params, KyberScheme},
        symmetric::aes_gcm::{Aes128 as Aes128Params, Aes256 as Aes256Params, AesGcmScheme},
    },
};
// --- Symmetric Algorithms ---

/// Marker type for AES-128-GCM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Aes128Gcm;
impl SymmetricAlgorithm for Aes128Gcm {
    type Key = seal_crypto::zeroize::Zeroizing<Vec<u8>>;
    type Scheme = AesGcmScheme<Aes128Params>;
    const ALGORITHM: common::algorithms::SymmetricAlgorithm =
        common::algorithms::SymmetricAlgorithm::Aes128Gcm;
}

/// Marker type for AES-256-GCM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Aes256Gcm;
impl SymmetricAlgorithm for Aes256Gcm {
    type Key = seal_crypto::zeroize::Zeroizing<Vec<u8>>;
    type Scheme = AesGcmScheme<Aes256Params>;
    const ALGORITHM: common::algorithms::SymmetricAlgorithm =
        common::algorithms::SymmetricAlgorithm::Aes256Gcm;
}

// --- Asymmetric Algorithms ---


/// Marker type for RSA-2048 with SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rsa2048;
impl AsymmetricAlgorithm for Rsa2048 {
    type PublicKey = Vec<u8>;
    type PrivateKey = seal_crypto::zeroize::Zeroizing<Vec<u8>>;
    type Scheme = RsaScheme<Rsa2048Params>;
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Rsa2048;
}

/// Marker type for RSA-4096 with SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rsa4096;
impl AsymmetricAlgorithm for Rsa4096 {
    type PublicKey = Vec<u8>;
    type PrivateKey = seal_crypto::zeroize::Zeroizing<Vec<u8>>;
    type Scheme = RsaScheme<Rsa4096Params>;
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Rsa4096;
}


/// Marker type for Kyber-512 with SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Kyber512;
impl AsymmetricAlgorithm for Kyber512 {
    type PublicKey = Vec<u8>;
    type PrivateKey = seal_crypto::zeroize::Zeroizing<Vec<u8>>;
    type Scheme = KyberScheme<Kyber512Params>;
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Kyber512;
}


/// Marker type for Kyber-768 with SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Kyber768;
impl AsymmetricAlgorithm for Kyber768 {
    type PublicKey = Vec<u8>;
    type PrivateKey = seal_crypto::zeroize::Zeroizing<Vec<u8>>;
    type Scheme = KyberScheme<Kyber768Params>;
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Kyber768;
}


/// Marker type for Kyber-1024 with SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Kyber1024;
impl AsymmetricAlgorithm for Kyber1024 {
    type PublicKey = Vec<u8>;
    type PrivateKey = seal_crypto::zeroize::Zeroizing<Vec<u8>>;
    type Scheme = KyberScheme<Kyber1024Params>;
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Kyber1024;
}