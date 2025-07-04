use seal_crypto::{
    prelude::*,
    schemes::{asymmetric::traditional::rsa::Rsa2048, hash::Sha256, symmetric::aes_gcm::Aes256Gcm},
};
use seal_flow::prelude::*;
use std::collections::HashMap;

// --- Algorithm Configuration ---
// --- 算法配置 ---

// Define the asymmetric algorithm used for Key Encapsulation (KEM).
// This algorithm protects the Data Encryption Key (DEK).
// 定义用于密钥封装 (KEM) 的非对称算法。
// 该算法用于保护数据加密密钥 (DEK)。
type Kem = Rsa2048<Sha256>;
// Define the symmetric algorithm used for Data Encapsulation.
// This algorithm encrypts the actual plaintext data.
// 定义用于数据封装的对称算法。
// 该算法用于加密实际的明文数据。
type Dek = Aes256Gcm;

fn main() -> Result<()> {
    // --- Setup ---
    // --- 准备工作 ---

    // 1. Generate an asymmetric key pair for the recipient.
    //    In a real application, the public key would be distributed,
    //    and the private key would be securely stored by the recipient.
    // 1. 为接收方生成一个非对称密钥对。
    //    在实际应用中，公钥会被分发出去，
    //    而私钥则由接收方安全地存储。
    let (pk, sk) = Kem::generate_keypair()?;

    // 2. Simulate a private key store for the recipient.
    //    We store the private key bytes, identified by a Key ID.
    // 2. 为接收方模拟一个私钥存储。
    //    我们通过密钥 ID 来存储私钥的字节。
    let mut private_key_store = HashMap::new();
    let kek_id = "rsa-key-pair-001".to_string(); // Key Encryption Key ID
    private_key_store.insert(kek_id.clone(), sk.to_bytes());

    let plaintext = b"This is a secret message for hybrid encryption.";

    // The high-level API factory is stateless and reusable.
    // 高级 API 工厂是无状态且可重用的。
    let seal = HybridSeal::new();

    // --- 1. Encryption (Sender's side) ---
    // --- 1. 加密（发送方） ---

    // The sender uses the recipient's public key to encrypt.
    // 发送方使用接收方的公钥进行加密。
    let pk_wrapped = AsymmetricPublicKey::new(pk.to_bytes());
    let ciphertext = seal
        // Specify the symmetric algorithm (Dek) for encrypting the data.
        // A new random key for this algorithm will be generated internally.
        // 指定用于加密数据的对称算法 (Dek)。
        // 一个用于此算法的新的随机密钥将在内部生成。
        .encrypt::<Dek>(pk_wrapped, kek_id)
        // Specify the asymmetric algorithm (Kem) to encrypt the generated symmetric key.
        // This executes the hybrid encryption.
        // 指定用于加密所生成的对称密钥的非对称算法 (Kem)。
        // 这将执行混合加密。
        .to_vec::<Kem>(plaintext)?;

    // --- 2. Decryption (Recipient's side) ---
    // --- 2. 解密（接收方） ---

    // a. The recipient first inspects the ciphertext header to find which private key is needed.
    //    This is a safe and cheap operation.
    // a. 接收方首先检查密文头部，以确定需要哪个私钥。
    //    这是一个安全且低成本的操作。
    let pending_decryptor = seal.decrypt().slice(&ciphertext)?;
    let found_kek_id = pending_decryptor.kek_id().unwrap();

    // b. Fetch the corresponding private key from the key store.
    // b. 从密钥存储中获取对应的私钥。
    let sk_bytes = private_key_store.get(found_kek_id).unwrap();
    let sk_wrapped = AsymmetricPrivateKey::new(sk_bytes.clone());

    // c. Provide the private key to decrypt the DEK and then the plaintext.
    //    The symmetric algorithm is automatically inferred from the header.
    // c. 提供私钥以解密 DEK，进而解密明文。
    //    对称算法会自动从头部信息中推断出来。
    let decrypted_text = pending_decryptor.with_key(sk_wrapped)?;

    assert_eq!(plaintext, &decrypted_text[..]);
    println!("Successfully performed hybrid encryption and decryption!");
    Ok(())
}
