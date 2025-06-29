//! Defines traits for key management.
use crate::keys::{AsymmetricPrivateKey, SignaturePublicKey, SymmetricKey};

/// A trait for objects that can provide symmetric keys based on a key ID.
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
    fn get_symmetric_key(&self, key_id: &str) -> Option<SymmetricKey>;
}

/// A trait for objects that can provide asymmetric private keys based on a key ID.
///
/// This allows high-level encryption APIs to automatically select the correct key
/// and algorithm without requiring the user to manually manage key instances.
pub trait AsymmetricKeyProvider {
    /// Retrieves an asymmetric private key by its ID.
    ///
    /// # Arguments
    ///
    /// * `kek_id` - The unique identifier for the key-encrypting key.
    ///
    /// # Returns
    ///
    /// An `Option` containing the `AsymmetricPrivateKey` if found, otherwise `None`.
    fn get_asymmetric_key(&self, kek_id: &str) -> Option<AsymmetricPrivateKey>;
}

/// A trait for objects that can provide signature verification keys (public keys) by a key ID.
pub trait SignatureKeyProvider {
    /// Retrieves a signature public key by its ID.
    fn get_signature_key(&self, signer_key_id: &str) -> Option<SignaturePublicKey>;
}
