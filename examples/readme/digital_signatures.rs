//! This example demonstrates a hybrid encryption workflow with digital signatures,
//! using a `KeyProvider` to manage decryption and verification keys.
//！本示例演示了带有数字签名的混合加密工作流，
//！使用 `KeyProvider` 来管理解密和验证密钥。

use seal_flow::base::keys::{
    TypedAsymmetricPrivateKey, TypedSignaturePublicKey, TypedSymmetricKey,
};
use seal_flow::error::KeyManagementError;
use seal_flow::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;

// --- Algorithm Configuration ---
// --- 算法配置 ---
const KEM_ALGO: AsymmetricAlgorithmEnum = AsymmetricAlgorithmEnum::Rsa2048Sha256;
const DEK_ALGO: SymmetricAlgorithmEnum = SymmetricAlgorithmEnum::Aes256Gcm;
const SIG_ALGO: SignatureAlgorithmEnum = SignatureAlgorithmEnum::Ed25519;

// --- Key IDs ---
// --- 密钥ID ---
const KEM_KEY_ID: &str = "recipient-kem-key-01";
const SIG_KEY_ID: &str = "sender-sig-key-01";

/// A simple in-memory key provider for demonstration purposes.
/// In a real-world scenario, this might connect to a secure key management service.
///
/// 一个用于演示的简单内存密钥提供程序。
/// 在实际场景中，这可能会连接到安全的密钥管理服务。
#[derive(Default)]
struct InMemoryKeyProvider {
    asymmetric_private_keys: HashMap<String, TypedAsymmetricPrivateKey>,
    signature_public_keys: HashMap<String, TypedSignaturePublicKey>,
}

impl InMemoryKeyProvider {
    /// Helper to add an asymmetric private key for decryption.
    /// 添加用于解密的非对称私钥的辅助函数。
    fn add_asymmetric_private_key(
        &mut self,
        key_id: String,
        key: impl Into<TypedAsymmetricPrivateKey>,
    ) {
        self.asymmetric_private_keys.insert(key_id, key.into());
    }

    /// Helper to add a signature public key for verification.
    /// 添加用于验证的签名公钥的辅助函数。
    fn add_signature_public_key(&mut self, key_id: String, key: impl Into<TypedSignaturePublicKey>) {
        self.signature_public_keys.insert(key_id, key.into());
    }
}

impl KeyProvider for InMemoryKeyProvider {
    /// This provider does not handle symmetric keys.
    /// 此提供程序不处理对称密钥。
    fn get_symmetric_key(&self, key_id: &str) -> Result<TypedSymmetricKey, KeyProviderError> {
        Err(KeyProviderError::KeyManagementError(
            KeyManagementError::KeyNotFound(key_id.to_string()),
        ))
    }

    /// Looks up an asymmetric private key needed for decryption.
    /// 查找解密所需的非对称私钥。
    fn get_asymmetric_private_key(
        &self,
        key_id: &str,
    ) -> Result<TypedAsymmetricPrivateKey, KeyProviderError> {
        self.asymmetric_private_keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| {
                KeyProviderError::KeyManagementError(KeyManagementError::KeyNotFound(
                    key_id.to_string(),
                ))
            })
    }

    /// Looks up a signature public key needed for verification.
    /// 查找验证所需的签名公钥。
    fn get_signature_public_key(
        &self,
        key_id: &str,
    ) -> Result<TypedSignaturePublicKey, KeyProviderError> {
        self.signature_public_keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| {
                KeyProviderError::KeyManagementError(KeyManagementError::KeyNotFound(
                    key_id.to_string(),
                ))
            })
    }
}

fn main() -> seal_flow::error::Result<()> {
    println!("--- Running Hybrid Encryption with Digital Signatures Example ---");

    // The high-level API factory is stateless and reusable.
    // 高级 API 工厂是无状态且可重用的。
    let seal = HybridSeal::default();
    let mut provider = InMemoryKeyProvider::default();

    // 1. Key Generation (simulating sender and recipient)
    // 1. 密钥生成（模拟发送方和接收方）

    // Recipient generates a KEM key pair.
    // 接收方生成一个 KEM 密钥对。
    let (pk_kem, sk_kem) = KEM_ALGO
        .into_asymmetric_wrapper()
        .generate_keypair()?
        .into_keypair();

    // Sender generates a signing key pair.
    // 发送方生成一个签名密钥对。
    let (pk_sig, sk_sig) = SIG_ALGO
        .into_signature_wrapper()
        .generate_keypair()?
        .into_keypair();

    // The recipient securely shares `pk_kem` with the sender.
    // The recipient stores `sk_kem` in their key management system (our provider).
    // 接收方安全地将 `pk_kem` 分享给发送方。
    // 接收方将 `sk_kem` 存储在他们的密钥管理系统（即此处的 provider）中。
    provider.add_asymmetric_private_key(KEM_KEY_ID.to_string(), sk_kem);

    // The sender shares `pk_sig` with the recipient for signature verification.
    // The recipient stores `pk_sig` in their key management system.
    // 发送方将 `pk_sig` 分享给接收方用于签名验证。
    // 接收方将 `pk_sig` 存储在他们的密钥管理系统中。
    provider.add_signature_public_key(SIG_KEY_ID.to_string(), pk_sig);

    let plaintext = b"This data is signed and encrypted, and will be verified by a KeyProvider.";
    println!("Plaintext: \"{}\"", String::from_utf8_lossy(plaintext));

    // 2. Encrypt and Sign (Sender's Side)
    // 2. 加密和签名（发送方）
    // The sender uses the recipient's public key (`pk_kem`) to encrypt
    // and their own private key (`sk_sig`) to sign.
    // 发送方使用接收方的公钥（`pk_kem`）进行加密，并使用自己的私钥（`sk_sig`）进行签名。
    let ciphertext = seal
        .encrypt(pk_kem, KEM_KEY_ID.to_string())
        .with_signer(sk_sig, SIG_KEY_ID.to_string())?
        .execute_with(DEK_ALGO)
        .to_vec(plaintext)?;

    println!("\nEncryption and signing successful. Ciphertext size: {} bytes.", ciphertext.len());

    // 3. Decrypt and Verify (Recipient's Side)
    // 3. 解密和验证（接收方）
    // The recipient uses the KeyProvider to automatically look up the correct keys.
    // `resolve_and_decrypt_to_vec` will read the key IDs from the ciphertext header
    // and ask the provider for the corresponding private KEM key and public signature key.
    // 接收方使用 KeyProvider 自动查找正确的密钥。
    // `resolve_and_decrypt_to_vec` 会从密文头中读取密钥 ID，
    // 然后向提供程序请求相应的私有 KEM 密钥和公共签名密钥。
    println!("Attempting to decrypt and verify using the KeyProvider...");
    let decrypted_text = seal
        .decrypt()
        .with_key_provider(Arc::new(provider))
        .slice(&ciphertext)?
        .resolve_and_decrypt_to_vec()?;

    assert_eq!(plaintext, &decrypted_text[..]);
    println!("\nSuccessfully decrypted and verified the message!");
    println!("Decrypted Text: \"{}\"", String::from_utf8_lossy(&decrypted_text));
    println!("\nDigital signature workflow with KeyProvider is successful!");
    Ok(())
}
