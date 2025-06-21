//! `seal-flow` is a stateless, high-level cryptographic workflow library
//! built on top of `seal-crypto`. It provides a unified, easy-to-use
//! interface for common cryptographic operations like hybrid encryption,
//! and supports multiple processing modes including one-shot (parallel),
//! streaming, and asynchronous.

pub mod algorithms;
pub mod common;
pub mod error;
pub mod hybrid;
pub mod symmetric;

pub use error::{Error, Result};
