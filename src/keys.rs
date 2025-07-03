//! This module defines byte wrappers for cryptographic keys.
use crate::crypto::errors::Error;
use seal_crypto::{prelude::*, zeroize};

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

    /// Derives a new symmetric key from the current key using a specified key-based KDF.
    ///
    /// This is suitable for key rotation, where a master key is used to generate
    /// sub-keys for specific purposes.
    ///
    /// # Type Parameters
    ///
    /// * `K` - The type of the key-based derivation algorithm, which must implement `KeyBasedDerivation`.
    ///
    /// # Arguments
    ///
    /// * `deriver` - An instance of the key-based KDF scheme (e.g., `HkdfSha256`).
    /// * `salt` - An optional salt. While optional in HKDF, providing a salt is highly recommended.
    /// * `info` - Optional context-specific information.
    /// * `output_len` - The desired length of the derived key in bytes.
    pub fn derive_key<K>(
        &self,
        deriver: &K,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Self, Error>
    where
        K: KeyBasedDerivation,
    {
        let derived_key_bytes = deriver.derive(self.as_bytes(), salt, info, output_len)?;
        Ok(SymmetricKey::new(derived_key_bytes.as_bytes().to_vec()))
    }

    /// Derives a symmetric key from a password using a specified password-based KDF.
    ///
    /// This is ideal for generating a cryptographic key from a low-entropy user password.
    /// The concrete algorithm instance (e.g., `Pbkdf2Sha256`) should be configured
    /// with the desired number of iterations before being passed to this function.
    ///
    /// # Type Parameters
    ///
    /// * `P` - The type of the password-based derivation algorithm, which must implement `PasswordBasedDerivation`.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to derive the key from.
    /// * `deriver` - An instance of the password-based KDF scheme (e.g., `Pbkdf2Sha256::new(100_000)`).
    /// * `salt` - A salt. This is **required** for password-based derivation to be secure.
    /// * `output_len` - The desired length of the derived key in bytes.
    pub fn derive_from_password<P>(
        password: &[u8],
        deriver: &P,
        salt: &[u8],
        output_len: usize,
    ) -> Result<Self, Error>
    where
        P: PasswordBasedDerivation,
    {
        let derived_key_bytes = deriver.derive(password, salt, output_len)?;
        Ok(SymmetricKey::new(derived_key_bytes.as_bytes().to_vec()))
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
#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::schemes::kdf::{hkdf::HkdfSha256, pbkdf2::Pbkdf2Sha256};

    #[test]
    fn test_symmetric_key_from_bytes() {
        let key_bytes = vec![0u8; 32];
        let key = SymmetricKey::new(key_bytes.clone());

        assert_eq!(key.as_bytes(), key_bytes.as_slice());
    }

    #[test]
    fn test_symmetric_key_derive_key() {
        // 使用HKDF-SHA256进行密钥派生
        let master_key = SymmetricKey::new(vec![0u8; 32]);
        let deriver = HkdfSha256::default();

        // 使用不同的上下文信息派生出不同的子密钥
        let salt = b"salt_value";
        let info1 = b"encryption_key";
        let info2 = b"signing_key";

        let derived_key1 = master_key
            .derive_key(&deriver, Some(salt), Some(info1), 32)
            .unwrap();
        let derived_key2 = master_key
            .derive_key(&deriver, Some(salt), Some(info2), 32)
            .unwrap();

        // 相同的主密钥和参数应该产生相同的派生密钥
        let derived_key1_again = master_key
            .derive_key(&deriver, Some(salt), Some(info1), 32)
            .unwrap();

        // 不同的上下文信息应该产生不同的派生密钥
        assert_ne!(derived_key1.as_bytes(), derived_key2.as_bytes());

        // 相同的参数应该产生相同的派生密钥
        assert_eq!(derived_key1.as_bytes(), derived_key1_again.as_bytes());
    }

    #[test]
    fn test_symmetric_key_derive_from_password() {
        // 使用PBKDF2-SHA256从密码派生密钥
        let password = b"my_secure_password";
        let salt = b"random_salt_value";

        // 设置较少的迭代次数以加速测试（实际应用中应使用更多迭代）
        let deriver = Pbkdf2Sha256::new(1000);

        let derived_key1 =
            SymmetricKey::derive_from_password(password, &deriver, salt, 32).unwrap();

        // 相同的密码、盐和迭代次数应该产生相同的密钥
        let derived_key2 =
            SymmetricKey::derive_from_password(password, &deriver, salt, 32).unwrap();

        assert_eq!(derived_key1.as_bytes(), derived_key2.as_bytes());

        // 不同的密码应该产生不同的密钥
        let different_password = b"different_password";
        let derived_key3 =
            SymmetricKey::derive_from_password(different_password, &deriver, salt, 32).unwrap();

        assert_ne!(derived_key1.as_bytes(), derived_key3.as_bytes());

        // 不同的盐应该产生不同的密钥
        let different_salt = b"different_salt_value";
        let derived_key4 =
            SymmetricKey::derive_from_password(password, &deriver, different_salt, 32).unwrap();

        assert_ne!(derived_key1.as_bytes(), derived_key4.as_bytes());
    }

    #[test]
    fn test_key_derivation_output_length() {
        let master_key = SymmetricKey::new(vec![0u8; 32]);
        let deriver = HkdfSha256::default();
        let salt = b"salt";
        let info = b"info";

        // 测试不同长度的输出
        let key_16 = master_key
            .derive_key(&deriver, Some(salt), Some(info), 16)
            .unwrap();
        let key_32 = master_key
            .derive_key(&deriver, Some(salt), Some(info), 32)
            .unwrap();
        let key_64 = master_key
            .derive_key(&deriver, Some(salt), Some(info), 64)
            .unwrap();

        assert_eq!(key_16.as_bytes().len(), 16);
        assert_eq!(key_32.as_bytes().len(), 32);
        assert_eq!(key_64.as_bytes().len(), 64);
    }
}
