use crate::keys::{
    SignaturePublicKey, TypedAsymmetricPrivateKey, TypedAsymmetricPublicKey,
    TypedSignaturePrivateKey, TypedSymmetricKey,
};

#[derive(Debug, thiserror::Error)]
pub enum KeyProviderError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Key management error: {0}")]
    KeyManagementError(crate::error::KeyManagementError),
    #[error("Format error: {0}")]
    FormatError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Other error: {0}")]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

/// A trait for dynamically looking up cryptographic keys by their ID.
///
/// Users can implement this for their own key management systems to integrate
/// seamlessly with the Decryptor.
///
/// 一个通过 ID 动态查找加密密钥的 trait。
///
/// 用户可以为自己的密钥管理系统实现此 trait，以便与解密器无缝集成。
pub trait KeyProvider: Send + Sync {
    /// Looks up a symmetric key by its ID.
    /// Used for symmetric decryption.
    ///
    /// 通过 ID 查找对称密钥。
    /// 用于对称解密。
    fn get_symmetric_key(&self, key_id: &str) -> Result<TypedSymmetricKey, KeyProviderError>;

    /// Looks up an asymmetric private key by its ID.
    /// Used for key unwrapping in hybrid decryption.
    ///
    /// 通过 ID 查找非对称私钥。
    /// 用于混合解密中的密钥解包。
    fn get_asymmetric_private_key(
        &self,
        key_id: &str,
    ) -> Result<TypedAsymmetricPrivateKey, KeyProviderError>;

    /// Looks up a signature verification public key by its ID.
    /// Used for verifying metadata signatures during hybrid decryption.
    ///
    /// 通过 ID 查找签名验证公钥。
    /// 用于在混合解密期间验证元数据签名。
    fn get_signature_public_key(
        &self,
        key_id: &str,
    ) -> Result<SignaturePublicKey, KeyProviderError>;
}

/// A trait for dynamically looking up cryptographic keys by their ID for encryption.
///
/// Users can implement this for their own key management systems to integrate
/// seamlessly with the Encryptor.
///
/// 一个通过 ID 动态查找加密密钥以进行加密的 trait。
///
/// 用户可以为自己的密钥管理系统实现此 trait，以便与加密器无缝集成。
pub trait EncryptionKeyProvider: Send + Sync {
    /// Looks up an asymmetric public key by its ID.
    /// Used for hybrid encryption (recipient's KEM key).
    ///
    /// 通过 ID 查找非对称公钥。
    /// 用于混合加密（接收方的 KEM 密钥）。
    fn get_asymmetric_public_key(
        &self,
        key_id: &str,
    ) -> Result<TypedAsymmetricPublicKey, KeyProviderError>;

    /// Looks up an asymmetric private key by its ID.
    /// Used for signing in hybrid encryption (sender's signing key).
    ///
    /// 通过 ID 查找非对称私钥。
    /// 用于混合加密中的签名（发送方的签名密钥）。
    fn get_signing_private_key(
        &self,
        key_id: &str,
    ) -> Result<TypedSignaturePrivateKey, KeyProviderError>;
}
