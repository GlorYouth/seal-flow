//! Defines the concrete algorithm types and implements the corresponding traits.

use super::traits::{AsymmetricAlgorithmDetails, SymmetricAlgorithmDetails};
use crate::common;

pub(crate) use seal_crypto::{
    prelude::*,
    schemes::{
        asymmetric::{
            kyber::{Kyber1024, Kyber512, Kyber768, KyberScheme},
            rsa::{Rsa2048 as Rsa2048Crypto, Rsa4096 as Rsa4096Crypto, RsaScheme},
        },
        hash::Sha256,
        symmetric::aes_gcm::{Aes128Gcm, Aes256Gcm},
    },
};

// --- Symmetric Algorithms ---

pub type Aes128GcmScheme = Aes128Gcm;
pub type Aes256GcmScheme = Aes256Gcm;

impl SymmetricAlgorithmDetails for Aes128Gcm {
    const ALGORITHM: common::algorithms::SymmetricAlgorithm =
        common::algorithms::SymmetricAlgorithm::Aes128Gcm;
}

impl SymmetricAlgorithmDetails for Aes256Gcm {
    const ALGORITHM: common::algorithms::SymmetricAlgorithm =
        common::algorithms::SymmetricAlgorithm::Aes256Gcm;
}

// --- Asymmetric Algorithms ---

// --- Type aliases for convenience ---
pub type Rsa2048<Sha = Sha256> = RsaScheme<Rsa2048Crypto, Sha>;
pub type Rsa4096Sha256<Sha = Sha256> = RsaScheme<Rsa4096Crypto, Sha>;

pub type Kyber512Scheme = KyberScheme<Kyber512>;
pub type Kyber768Scheme = KyberScheme<Kyber768>;
pub type Kyber1024Scheme = KyberScheme<Kyber1024>;

impl<H: 'static + Hasher> AsymmetricAlgorithmDetails for RsaScheme<Rsa2048Crypto, H> {
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Rsa2048;
}

impl<H: 'static + Hasher> AsymmetricAlgorithmDetails for RsaScheme<Rsa4096Crypto, H> {
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Rsa4096;
}

impl AsymmetricAlgorithmDetails for KyberScheme<Kyber512> {
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Kyber512;
}

impl AsymmetricAlgorithmDetails for KyberScheme<Kyber768> {
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Kyber768;
}

impl AsymmetricAlgorithmDetails for KyberScheme<Kyber1024> {
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Kyber1024;
}
