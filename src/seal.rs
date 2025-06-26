//! Provides a unified, high-level API for SealFlow operations.
//!
//! This module introduces a builder pattern to configure and execute encryption
//! and decryption tasks, abstracting away the underlying implementation details
//! (like ordinary, parallel, or streaming modes).
//!
//! The main entry points are:
//! - [`symmetric::SymmetricSeal`]: For symmetric encryption operations.
//! - [`hybrid::HybridSeal`]: For hybrid (asymmetric + symmetric) encryption operations.
//!
//! # Example: Decryption Workflow with Peeking
//!
//! ```ignore
//! use seal_flow::seal::{peek_symmetric_key_id, symmetric::SymmetricSeal};
//! use std::io::Cursor;
//!
//! // Assume `get_key_from_store` and `encrypted_data` exist.
//! let key_id = peek_symmetric_key_id(Cursor::new(&encrypted_data)).unwrap();
//! let key = get_key_from_store(&key_id).unwrap();
//!
//! let decrypted = SymmetricSeal::new(&key)
//!     .in_memory::<Aes256Gcm>()
//!     .decrypt(&encrypted_data)
//!     .unwrap();
//! ```
pub mod hybrid;
pub mod symmetric;

pub use hybrid::HybridSeal;
pub use symmetric::SymmetricSeal;

