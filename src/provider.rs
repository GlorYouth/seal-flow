//! This module defines traits for abstracting key retrieval.
use crate::keys::{AsymmetricPrivateKey, SymmetricKey};

/// A trait for objects that can provide symmetric keys based on a key identifier.
///
/// This allows high-level decryption APIs to automatically select the correct key
/// and algorithm without requiring the user to manually manage key instances.
pub trait SymmetricKeyProvider {
    /// Retrieves a symmetric key by its ID.
    ///
    /// The implementation should look up the key corresponding to the `key_id`
    /// and return it wrapped in the appropriate `SymmetricKey` enum variant.
    ///
    /// # Arguments
    ///
    /// * `key_id` - The unique identifier for the key.
    ///
    /// # Returns
    ///
    /// An `Option` containing the `SymmetricKey` if found, otherwise `None`.
    fn get_symmetric_key<'a>(&'a self, key_id: &str) -> Option<SymmetricKey<'a>>;
}

/// A trait for objects that can provide asymmetric private keys based on a KEK ID.
pub trait AsymmetricKeyProvider {
    /// Retrieves an asymmetric private key by its KEK ID.
    ///
    /// # Arguments
    ///
    /// * `kek_id` - The unique identifier for the key-encrypting key.
    ///
    /// # Returns
    ///
    /// An `Option` containing the `AsymmetricPrivateKey` if found, otherwise `None`.
    fn get_asymmetric_key<'a>(&'a self, kek_id: &str) -> Option<AsymmetricPrivateKey<'a>>;
}
