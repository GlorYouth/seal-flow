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

/// Trait to provide the details for a specific key-based key derivation function (KDF).
/// The implementor of this trait is the scheme itself.
pub trait KdfAlgorithmDetails: KeyBasedDerivation + 'static {
    /// The corresponding algorithm enum.
    const ALGORITHM: common::algorithms::KdfAlgorithm;
}

/// Represents a concrete key-based key derivation function (KDF).
/// This is a marker trait that bundles `KdfAlgorithmDetails`.
pub trait KdfAlgorithm: KdfAlgorithmDetails {}

impl<T: KdfAlgorithmDetails> KdfAlgorithm for T {}

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

/// Trait to provide the details for a specific digital signature algorithm.
/// The implementor of this trait is the scheme itself.
pub trait SignatureAlgorithmDetails: SignatureScheme + 'static {
    /// The corresponding algorithm enum.
    const ALGORITHM: common::algorithms::SignatureAlgorithm;
}

/// Represents a concrete digital signature scheme.
/// This is a marker trait that bundles `SignatureAlgorithmDetails`.
pub trait SignatureAlgorithm: SignatureAlgorithmDetails {}

impl<T: SignatureAlgorithmDetails> SignatureAlgorithm for T {}

/// Trait to provide the details for a specific extendable-output function (XOF).
/// The implementor of this trait is the scheme itself.
pub trait XofAlgorithmDetails: XofDerivation + 'static {
    /// The corresponding algorithm enum.
    const ALGORITHM: common::algorithms::XofAlgorithm;
}

/// Represents a concrete extendable-output function (XOF).
/// This is a marker trait that bundles `XofAlgorithmDetails`.
pub trait XofAlgorithm: XofAlgorithmDetails {}

impl<T: XofAlgorithmDetails> XofAlgorithm for T {}
