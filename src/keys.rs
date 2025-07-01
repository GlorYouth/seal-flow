//! This module defines byte wrappers for cryptographic keys.
use bytes::Bytes;

/// A byte wrapper for a symmetric encryption key.
///
/// This struct stores raw key bytes that can be converted to specific algorithm keys
/// when needed. This simplifies key management while maintaining flexibility.
#[derive(Debug, Clone)]
pub struct SymmetricKey(pub Bytes);

impl SymmetricKey {
    /// Create a new symmetric key from bytes
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        Self(bytes.into())
    }

    /// Get a reference to the raw bytes of the key
    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    /// Consume the key and return the inner bytes
    pub fn into_bytes(self) -> Bytes {
        self.0
    }
}

/// A byte wrapper for an asymmetric private key.
#[derive(Debug, Clone)]
pub struct AsymmetricPrivateKey(pub Bytes);

impl AsymmetricPrivateKey {
    /// Create a new asymmetric private key from bytes
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        Self(bytes.into())
    }

    /// Get a reference to the raw bytes of the key
    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    /// Consume the key and return the inner bytes
    pub fn into_bytes(self) -> Bytes {
        self.0
    }
}

/// A byte wrapper for a signature public key.
#[derive(Debug, Clone)]
pub struct SignaturePublicKey(pub Bytes);

impl SignaturePublicKey {
    /// Create a new signature public key from bytes
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        Self(bytes.into())
    }

    /// Get a reference to the raw bytes of the key
    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    /// Consume the key and return the inner bytes
    pub fn into_bytes(self) -> Bytes {
        self.0
    }
}
