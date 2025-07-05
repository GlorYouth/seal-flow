//! This example demonstrates the usage of the `KeyProvider` trait to simplify
//! the decryption workflow.
//！本示例演示了如何使用 `KeyProvider` trait 来简化解密工作流。

use seal_flow::algorithms::signature::Ed25519;
use seal_flow::algorithms::asymmetric::Rsa2048;
use seal_flow::algorithms::hash::Sha256;
use seal_flow::algorithms::symmetric::Aes256Gcm;
use seal_flow::error::KeyManagementError;
use seal_flow::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;

/// A simple implementation of `KeyProvider` that stores keys in memory.
/// In a real application, this might connect to a Hardware Security Module (HSM),
/// a database, or a cloud Key Management Service (KMS).
///
/// `KeyProvider` trait 的一个简单实现，它将密钥存储在内存中。
/// 在实际应用中，这里可能会连接到硬件安全模块（HSM）、数据库或云密钥管理服务（KMS）。
#[derive(Default)]
struct InMemoryKeyProvider {
    symmetric_keys: HashMap<String, SymmetricKey>,
    asymmetric_private_keys: HashMap<String, AsymmetricPrivateKey>,
    signature_public_keys: HashMap<String, SignaturePublicKey>,
}

impl InMemoryKeyProvider {
    /// Helper method to add a symmetric key.
    fn add_symmetric_key(&mut self, key_id: String, key: impl Into<SymmetricKey>) {
        self.symmetric_keys.insert(key_id, key.into());
    }

    /// Helper method to add an asymmetric private key.
    fn add_asymmetric_private_key(
        &mut self,
        key_id: String,
        key: impl Into<AsymmetricPrivateKey>,
    ) {
        self.asymmetric_private_keys
            .insert(key_id, key.into());
    }

    /// Helper method to add a signature public key.
    fn add_signature_public_key(
        &mut self,
        key_id: String,
        key: impl Into<SignaturePublicKey>,
    ) {
        self.signature_public_keys.insert(key_id, key.into());
    }
}

impl KeyProvider for InMemoryKeyProvider {
    /// Looks up a symmetric key by its ID.
    fn get_symmetric_key(&self, key_id: &str) -> Result<SymmetricKey, KeyProviderError> {
        self.symmetric_keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| KeyProviderError::KeyManagementError(KeyManagementError::KeyNotFound(key_id.to_string())))
    }

    /// Looks up an asymmetric private key by its ID.
    fn get_asymmetric_private_key(&self, key_id: &str) -> Result<AsymmetricPrivateKey, KeyProviderError> {
        self.asymmetric_private_keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| KeyProviderError::KeyManagementError(KeyManagementError::KeyNotFound(key_id.to_string())))
    }

    /// Looks up a signature verification public key by its ID.
    fn get_signature_public_key(&self, key_id: &str) -> Result<SignaturePublicKey, KeyProviderError> {
        self.signature_public_keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| KeyProviderError::KeyManagementError(KeyManagementError::KeyNotFound(key_id.to_string())))
    }
}

fn main() -> seal_flow::error::Result<()> {
    run_symmetric_example()?;
    run_hybrid_example()?;
    Ok(())
}

/// Demonstrates using the KeyProvider for symmetric decryption.
fn run_symmetric_example() -> seal_flow::error::Result<()> {
    println!("--- Running Symmetric Encryption Example with KeyProvider ---");
    // 1. Setup
    // 1. 准备工作
    let seal = SymmetricSeal::new();
    let mut provider = InMemoryKeyProvider::default();

    let key = Aes256Gcm::generate_key()?;
    let key_id = "symmetric-key-01".to_string();
    provider.add_symmetric_key(key_id.clone(), SymmetricKey::new(key.to_bytes()));

    let plaintext = b"This message is protected by a key from a KeyProvider.";

    // 2. Encrypt
    // 2. 加密
    let ciphertext = seal
        .encrypt(SymmetricKey::new(key.to_bytes()), key_id)
        .to_vec::<Aes256Gcm>(plaintext)?;
    println!("Encryption successful.");

    // 3. Decrypt using the KeyProvider
    // 3. 使用 KeyProvider 进行解密
    //
    // Instead of manually looking up the key, we attach the provider
    // and call `resolve_and_decrypt()`. The library handles the key lookup internally.
    // 我们不再需要手动查找密钥，而是附加 provider 并调用 `resolve_and_decrypt()`。
    // 库会在内部处理密钥的查找。
    println!("Decrypting with resolve_and_decrypt()...");
    let decrypted = seal
        .decrypt()
        .with_key_provider(Arc::new(provider))
        .slice(&ciphertext)?
        .resolve_and_decrypt()?;

    assert_eq!(plaintext, &decrypted[..]);
    println!("Decryption successful! The KeyProvider workflow works for symmetric encryption.\n");

    Ok(())
}

/// Demonstrates using the KeyProvider for hybrid decryption with signatures.
fn run_hybrid_example() -> seal_flow::error::Result<()> {
    println!("--- Running Hybrid Encryption Example with KeyProvider ---");

    type Kem = Rsa2048<Sha256>;
    type Dek = Aes256Gcm;
    type Sig = Ed25519;

    // 1. Setup
    // 1. 准备工作
    let seal = HybridSeal::new();
    let mut provider = InMemoryKeyProvider::default();

    // Generate and store KEM keys for the recipient.
    // 为接收方生成并存储 KEM 密钥。
    let (pk_kem, sk_kem) = Kem::generate_keypair()?;
    let kem_key_id = "hybrid-kem-key-01".to_string();
    provider.add_asymmetric_private_key(kem_key_id.clone(), AsymmetricPrivateKey::new(sk_kem.to_bytes()));

    // Generate and store signing keys for the sender. The provider only needs the public key for verification.
    // 为发送方生成并存储签名密钥。验证时，provider 只需要公钥。
    let (pk_sig, sk_sig) = Sig::generate_keypair()?;
    let sig_key_id = "hybrid-sig-key-01".to_string();
    provider.add_signature_public_key(sig_key_id.clone(), SignaturePublicKey::new(pk_sig.to_bytes()));

    let plaintext = b"This hybrid message is signed and will be decrypted via KeyProvider.";

    // 2. Encrypt and Sign (Sender's Side)
    // 2. 加密和签名（发送方）
    let ciphertext = seal
        .encrypt::<Dek>(AsymmetricPublicKey::new(pk_kem.to_bytes()), kem_key_id)
        .with_signer::<Sig>(AsymmetricPrivateKey::new(sk_sig.to_bytes()), sig_key_id)
        .to_vec::<Kem>(plaintext)?;
    println!("Encryption and signing successful.");

    // 3. Decrypt and Verify using the KeyProvider (Recipient's Side)
    // 3. 使用 KeyProvider 进行解密和验证（接收方）
    //
    // The `resolve_and_decrypt` method will automatically:
    //  a. Read the signer_key_id from the header.
    //  b. Use the provider to get the public verification key.
    //  c. Read the kek_id from the header.
    //  d. Use the provider to get the private decryption key.
    //  e. Perform verification and decryption.
    // `resolve_and_decrypt` 方法会自动完成以下操作：
    //  a. 从头部读取 signer_key_id。
    //  b. 使用 provider 获取用于验证的公钥。
    //  c. 从头部读取 kek_id。
    //  d. 使用 provider 获取用于解密的私钥。
    //  e. 执行验证和解密。
    println!("Decrypting and verifying with resolve_and_decrypt()...");
    let decrypted = seal
        .decrypt()
        .with_key_provider(Arc::new(provider))
        .slice(&ciphertext)?
        .resolve_and_decrypt()?;

    assert_eq!(plaintext, &decrypted[..]);
    println!("Decryption and signature verification successful! The KeyProvider workflow works for hybrid encryption.");

    Ok(())
} 