//! Defines the core traits for type-safe algorithm specification.

use crate::common;
use seal_crypto::prelude::*;

/// Trait to provide the details for a specific symmetric algorithm.
/// The implementor of this trait is the scheme itself.
pub trait SymmetricAlgorithmDetails: AeadScheme + 'static {
    /// The corresponding algorithm enum.
    const ALGORITHM: common::algorithms::SymmetricAlgorithm;
}

/// Represents a concrete symmetric encryption algorithm.
/// This is a marker trait that bundles `SymmetricAlgorithmDetails` with key bounds.
pub trait SymmetricAlgorithm: SymmetricAlgorithmDetails {}

impl<T: SymmetricAlgorithmDetails> SymmetricAlgorithm for T {}

/// Trait to provide the details for a specific asymmetric algorithm.
/// The implementor of this trait is the scheme itself.
pub trait AsymmetricAlgorithmDetails: Kem + KeyGenerator + 'static {
    /// The corresponding algorithm enum.
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm;
}

/// Represents a concrete asymmetric key encapsulation mechanism (KEM).
/// This is a marker trait that bundles `AsymmetricAlgorithmDetails` with key bounds.
pub trait AsymmetricAlgorithm: AsymmetricAlgorithmDetails {}

impl<T: AsymmetricAlgorithmDetails> AsymmetricAlgorithm for T {}
