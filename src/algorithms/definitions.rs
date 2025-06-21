//! Defines the concrete algorithm types and implements the corresponding traits.

use super::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common;
use seal_crypto::{
    systems::{
        asymmetric::rsa::{Rsa2048 as Rsa2048Params, RsaScheme},
        symmetric::aes_gcm::{Aes256 as Aes256Params, AesGcmScheme},
    },
};
// --- Symmetric Algorithms ---

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
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Rsa2048;
    type Scheme = RsaScheme<Rsa2048Params>;
    type PublicKey = Vec<u8>;
    type PrivateKey = seal_crypto::zeroize::Zeroizing<Vec<u8>>;
}
