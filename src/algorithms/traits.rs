//! Defines the core traits for type-safe algorithm specification.

use crate::common;
use seal_crypto::{
    traits::{
        kem::Kem,
        symmetric::{
            SymmetricCipher, SymmetricDecryptor, SymmetricEncryptor, SymmetricKeyGenerator,
        },
    },
};

/// A marker trait representing a specific symmetric encryption algorithm.
///
/// This trait connects a high-level algorithm type in `seal-flow` to its
/// underlying cryptographic implementation (`Scheme`) in `seal-crypto`.
pub trait SymmetricAlgorithm: 'static + Send + Sync {
    /// The key type used by this algorithm.
    type Key;

    /// The associated `Scheme` from `seal-crypto` that implements the core cryptographic operations.
    type Scheme: SymmetricEncryptor<Key = Self::Key>
        + SymmetricDecryptor<Key = Self::Key>
        + SymmetricKeyGenerator
        + SymmetricCipher
        + Send
        + Sync;
    
    /// The corresponding enum variant for this algorithm, used for serialization
    /// and header creation.
    const ALGORITHM: common::algorithms::SymmetricAlgorithm;
}

/// A marker trait representing a specific asymmetric key encapsulation mechanism (KEM).
///
/// This trait connects a high-level algorithm type in `seal-flow` to its
/// underlying KEM implementation (`Scheme`) in `seal-crypto`.
pub trait AsymmetricAlgorithm: 'static + Send + Sync {
    /// The public key type for this algorithm.
    type PublicKey;
    /// The private key type for this algorithm.
    type PrivateKey;

    /// The associated `Scheme` from `seal-crypto` that implements KEM and key-pair generation.
    type Scheme: Kem<PublicKey = Self::PublicKey, PrivateKey = Self::PrivateKey>
        + Send
        + Sync;
    
    /// The corresponding enum variant for this algorithm, used for serialization
    /// and header creation.
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm;
} 