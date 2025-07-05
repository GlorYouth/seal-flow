use crate::error::Result;
use crate::keys::{AsymmetricPrivateKey, SignaturePublicKey, SymmetricKey};

/// A trait for dynamically looking up cryptographic keys by their ID.
///
/// Users can implement this for their own key management systems to integrate
/// seamlessly with the Decryptor.
///
/// 一个通过 ID 动态查找加密密钥的 trait。
///
/// 用户可以为自己的密钥管理系统实现此 trait，以便与解密器无缝集成。
pub trait KeyProvider {
    /// Looks up a symmetric key by its ID.
    /// Used for symmetric decryption.
    ///
    /// 通过 ID 查找对称密钥。
    /// 用于对称解密。
    fn get_symmetric_key(&self, key_id: &str) -> Result<SymmetricKey>;

    /// Looks up an asymmetric private key by its ID.
    /// Used for key unwrapping in hybrid decryption.
    ///
    /// 通过 ID 查找非对称私钥。
    /// 用于混合解密中的密钥解包。
    fn get_asymmetric_private_key(&self, key_id: &str) -> Result<AsymmetricPrivateKey>;

    /// Looks up a signature verification public key by its ID.
    /// Used for verifying metadata signatures during hybrid decryption.
    ///
    /// 通过 ID 查找签名验证公钥。
    /// 用于在混合解密期间验证元数据签名。
    fn get_signature_public_key(&self, key_id: &str) -> Result<SignaturePublicKey>;
} 