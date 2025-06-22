//! Defines the concrete algorithm types and implements the corresponding traits.

use super::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common;
use std::marker::PhantomData;

use seal_crypto::{
    prelude::*,
    schemes::{
        symmetric::aes_gcm::{Aes128Gcm as Aes128, Aes256Gcm as Aes256},
        asymmetric::{
            kyber::{
                Kyber1024 as Kyber1024Params, Kyber512 as Kyber512Params,
                Kyber768 as Kyber768Params, KyberScheme
            },
            rsa::{Rsa2048 as Rsa2048Params, Rsa4096 as Rsa4096Params, RsaScheme},
        },
        hash::Sha256,
    },
};
// --- Symmetric Algorithms ---

/// Marker type for AES-128-GCM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Aes128Gcm;
impl SymmetricAlgorithm for Aes128Gcm {
    type Scheme = Aes128;
    const ALGORITHM: common::algorithms::SymmetricAlgorithm =
        common::algorithms::SymmetricAlgorithm::Aes128Gcm;
}

/// Marker type for AES-256-GCM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Aes256Gcm;
impl SymmetricAlgorithm for Aes256Gcm {
    type Scheme = Aes256;
    const ALGORITHM: common::algorithms::SymmetricAlgorithm =
        common::algorithms::SymmetricAlgorithm::Aes256Gcm;
}


// --- Asymmetric Algorithms ---

/// Marker type for RSA-2048 with SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rsa2048<Hash = Sha256> {
    _sha: PhantomData<Hash>,
}
impl<Hash: 'static + Hasher> AsymmetricAlgorithm for Rsa2048<Hash> {
    type Scheme = RsaScheme<Rsa2048Params, Hash>;
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Rsa2048;
}

/// Marker type for RSA-4096 with SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rsa4096<Hash = Sha256> {
    _sha: PhantomData<Hash>,
}
impl<Hash: 'static + Hasher> AsymmetricAlgorithm for Rsa4096<Hash> {
    type Scheme = RsaScheme<Rsa4096Params, Hash>;
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Rsa4096;
}

/// Marker type for Kyber-512 with SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Kyber512;
impl AsymmetricAlgorithm for Kyber512 {
    type Scheme = KyberScheme<Kyber512Params>;
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Kyber512;
}

/// Marker type for Kyber-768 with SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Kyber768;
impl AsymmetricAlgorithm for Kyber768 {
    type Scheme = KyberScheme<Kyber768Params>;
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Kyber768;
}

/// Marker type for Kyber-1024 with SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Kyber1024;
impl AsymmetricAlgorithm for Kyber1024 {
    type Scheme = KyberScheme<Kyber1024Params>;
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Kyber1024;
}
