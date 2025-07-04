//! `seal-flow` is a stateless, high-level cryptographic workflow library
//! built on top of `seal-crypto`. It provides a unified, easy-to-use
//! interface for common cryptographic operations like hybrid encryption,
//! and supports multiple processing modes including one-shot (parallel),
//! streaming, and asynchronous.

// Re-export the entire `seal-crypto` crate for direct access to its APIs.
pub use seal_crypto as crypto;

pub mod prelude {
    //! A "prelude" for users of the `seal-flow` crate.
    pub use crate::common::PendingImpl;
    pub use crate::error::{Error, Result};
    pub use crate::keys::{
        AsymmetricPrivateKey, AsymmetricPublicKey, SignaturePublicKey, SymmetricKey,
    };
    pub use crate::seal::{HybridSeal, SymmetricSeal};
    pub use crate::keys::provider::KeyProvider;
}

pub mod error;
pub mod seal;

/// Provides direct access to the mid-level execution flows.
///
/// This API layer is for users who need more fine-grained control over the
/// execution process than what the high-level [`seal`] API provides.
/// For example, you might use this to directly create a streaming encryptor
/// without using the `HybridSeal` or `SymmetricSeal` builders.
pub mod flows {
    /// Mid-level flows for symmetric encryption.
    pub mod symmetric {
        pub use crate::symmetric::{
            asynchronous, ordinary, parallel, parallel_streaming, streaming,
        };
    }

    /// Mid-level flows for hybrid encryption.
    pub mod hybrid {
        pub use crate::hybrid::{asynchronous, ordinary, parallel, parallel_streaming, streaming};
    }
}

mod algorithms;
pub mod common;
mod hybrid;
pub(crate) mod impls;
mod keys;
mod symmetric;

pub use error::{Error, Result};
