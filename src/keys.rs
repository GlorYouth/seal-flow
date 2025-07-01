//! This module defines byte wrappers for cryptographic keys.
use seal_crypto::zeroize;

/// A byte wrapper for a symmetric encryption key.
///
/// This struct stores raw key bytes that can be converted to specific algorithm keys
/// when needed. This simplifies key management while maintaining flexibility.
#[derive(Debug, Clone)]
pub struct SymmetricKey(pub zeroize::Zeroizing<Vec<u8>>);

impl SymmetricKey {
    /// Create a new symmetric key from bytes
    pub fn new(bytes: impl Into<zeroize::Zeroizing<Vec<u8>>>) -> Self {
        Self(bytes.into())
    }

    /// Get a reference to the raw bytes of the key
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the key and return the inner bytes
    pub fn into_bytes(self) -> zeroize::Zeroizing<Vec<u8>> {
        self.0
    }
}

/// A byte wrapper for an asymmetric private key.
#[derive(Debug, Clone)]
pub struct AsymmetricPrivateKey(pub zeroize::Zeroizing<Vec<u8>>);

impl AsymmetricPrivateKey {
    /// Create a new asymmetric private key from bytes
    pub fn new(bytes: impl Into<zeroize::Zeroizing<Vec<u8>>>) -> Self {
        Self(bytes.into())
    }

    /// Get a reference to the raw bytes of the key
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the key and return the inner bytes
    pub fn into_bytes(self) -> zeroize::Zeroizing<Vec<u8>> {
        self.0
    }
}

/// A byte wrapper for an asymmetric public key.
#[derive(Debug, Clone)]
pub struct AsymmetricPublicKey(pub zeroize::Zeroizing<Vec<u8>>);

impl AsymmetricPublicKey {
    /// Create a new asymmetric public key from bytes
    pub fn new(bytes: impl Into<zeroize::Zeroizing<Vec<u8>>>) -> Self {
        Self(bytes.into())
    }

    /// Get a reference to the raw bytes of the key
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the key and return the inner bytes
    pub fn into_bytes(self) -> zeroize::Zeroizing<Vec<u8>> {
        self.0
    }
}

/// A byte wrapper for a signature public key.
#[derive(Debug, Clone)]
pub struct SignaturePublicKey(pub zeroize::Zeroizing<Vec<u8>>);

impl SignaturePublicKey {
    /// Create a new signature public key from bytes
    pub fn new(bytes: impl Into<zeroize::Zeroizing<Vec<u8>>>) -> Self {
        Self(bytes.into())
    }

    /// Get a reference to the raw bytes of the key
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the key and return the inner bytes
    pub fn into_bytes(self) -> zeroize::Zeroizing<Vec<u8>> {
        self.0
    }
}
