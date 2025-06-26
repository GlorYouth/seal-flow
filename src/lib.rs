//! `seal-flow` is a stateless, high-level cryptographic workflow library
//! built on top of `seal-crypto`. It provides a unified, easy-to-use
//! interface for common cryptographic operations like hybrid encryption,
//! and supports multiple processing modes including one-shot (parallel),
//! streaming, and asynchronous.

// Re-export the entire `seal-crypto` crate for direct access to its APIs.
pub use seal_crypto as crypto;

pub mod prelude {
    //! A "prelude" for users of the `seal-flow` crate.
    pub use crate::error::{Error, Result};
    pub use crate::seal::{HybridSeal, SymmetricSeal};
}

pub mod error;
pub mod seal;

mod algorithms;
mod common;
mod hybrid;
mod symmetric;

pub use error::{Error, Result};
