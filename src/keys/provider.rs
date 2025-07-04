use crate::error::Result;
use crate::keys::{AsymmetricPrivateKey, SignaturePublicKey, SymmetricKey};

/// A trait for dynamically looking up cryptographic keys by their ID.
///
/// Users can implement this for their own key management systems to integrate
/// seamlessly with the Decryptor.
pub trait KeyProvider {
    /// Looks up a symmetric key by its ID.
    /// Used for symmetric decryption.
    fn get_symmetric_key(&self, key_id: &str) -> Result<SymmetricKey>;

    /// Looks up an asymmetric private key by its ID.
    /// Used for key unwrapping in hybrid decryption.
    fn get_asymmetric_private_key(&self, key_id: &str) -> Result<AsymmetricPrivateKey>;

    /// Looks up a signature verification public key by its ID.
    /// Used for verifying metadata signatures during hybrid decryption.
    fn get_signature_public_key(&self, key_id: &str) -> Result<SignaturePublicKey>;
} 