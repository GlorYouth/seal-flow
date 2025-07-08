use seal_flow::algorithms::asymmetric::Rsa2048;
use seal_flow::algorithms::hash::Sha256;
use seal_flow::algorithms::signature::Ed25519;
use seal_flow::algorithms::symmetric::Aes256Gcm;
use seal_flow::prelude::*;
use std::collections::HashMap;

// Define the asymmetric algorithm for Key Encapsulation (KEM).
// 定义用于密钥封装 (KEM) 的非对称算法。
type Kem = Rsa2048<Sha256>;
// Define the symmetric algorithm for Data Encapsulation (DEK).
// 定义用于数据封装 (DEK) 的对称算法。
type Dek = Aes256Gcm;
// Define the algorithm for digital signatures.
// 定义用于数字签名的算法。
type Sig = Ed25519;

// A simple in-memory key provider for demonstration purposes.
// 用于演示的简单内存中密钥提供程序。
struct InMemoryKeyProvider {
    asymmetric_private_keys: HashMap<String, AsymmetricPrivateKey>,
    asymmetric_public_keys: HashMap<String, AsymmetricPublicKey>,
    signature_public_keys: HashMap<String, SignaturePublicKey>,
}

impl KeyProvider for InMemoryKeyProvider {
    fn get_symmetric_key(&self, _key_id: &str) -> Result<SymmetricKey, KeyProviderError> {
        unimplemented!()
    }

    fn get_asymmetric_private_key(
        &self,
        key_id: &str,
    ) -> Result<AsymmetricPrivateKey, KeyProviderError> {
        self.asymmetric_private_keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| KeyProviderError::KeyNotFound(key_id.to_string()))
    }

    fn get_signature_public_key(
        &self,
        key_id: &str,
    ) -> Result<SignaturePublicKey, KeyProviderError> {
        self.signature_public_keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| KeyProviderError::KeyNotFound(key_id.to_string()))
    }
}

impl EncryptionKeyProvider for InMemoryKeyProvider {
    fn get_asymmetric_public_key(
        &self,
        key_id: &str,
    ) -> Result<AsymmetricPublicKey, KeyProviderError> {
        self.asymmetric_public_keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| KeyProviderError::KeyNotFound(key_id.to_string()))
    }

    fn get_signing_private_key(
        &self,
        key_id: &str,
    ) -> Result<AsymmetricPrivateKey, KeyProviderError> {
        self.asymmetric_private_keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| KeyProviderError::KeyNotFound(key_id.to_string()))
    }
}

fn main() -> seal_flow::error::Result<()> {
    // 1. Generate and store keys in the provider.
    // 1. 生成密钥并将其存储在提供程序中。
    let (pk_kem, sk_kem) = Kem::generate_keypair()?;
    let (pk_sig, sk_sig) = Sig::generate_keypair()?;

    let kem_key_id = "kem-key-id";
    let sig_key_id = "sig-key-id";

    let mut key_provider = InMemoryKeyProvider {
        asymmetric_private_keys: HashMap::new(),
        asymmetric_public_keys: HashMap::new(),
        signature_public_keys: HashMap::new(),
    };
    key_provider.asymmetric_public_keys.insert(
        kem_key_id.to_string(),
        AsymmetricPublicKey::new(pk_kem.to_bytes()),
    );
    key_provider.asymmetric_private_keys.insert(
        kem_key_id.to_string(),
        AsymmetricPrivateKey::new(sk_kem.to_bytes()),
    );
    key_provider.asymmetric_private_keys.insert(
        sig_key_id.to_string(),
        AsymmetricPrivateKey::new(sk_sig.to_bytes()),
    );
    key_provider.signature_public_keys.insert(
        sig_key_id.to_string(),
        SignaturePublicKey::new(pk_sig.to_bytes()),
    );

    let key_provider = std::sync::Arc::new(key_provider);

    let plaintext = b"this data will be signed and encrypted";

    // The high-level API factory is stateless and reusable.
    // 高级 API 工厂是无状态且可重用的。
    let seal = HybridSeal::new();

    // 2. Encrypt and Sign using Key IDs (Sender's Side)
    // 2. 使用密钥 ID 加密和签名（发送方）
    let ciphertext = seal
        .encrypt_builder::<Dek>()
        .with_key_provider(key_provider.clone())
        .with_recipient_id(kem_key_id)?
        .with_signer_id::<Sig>(sig_key_id)?
        .with_algorithm::<Kem>()
        .to_vec(plaintext)?;

    // 3. Decrypt and Verify using KeyProvider (Recipient's Side)
    // 3. 使用 KeyProvider 解密和验证（接收方）
    let decrypted_text = seal
        .decrypt()
        .with_key_provider(key_provider)
        .slice(&ciphertext)?
        .resolve_and_decrypt()?;

    assert_eq!(plaintext, &decrypted_text[..]);
    println!("Successfully signed, encrypted, decrypted, and verified data using KeyProvider!");
    Ok(())
}
