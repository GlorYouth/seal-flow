use seal_flow::prelude::SymmetricKeyGenerator;
use seal_flow::algorithms::symmetric::Aes256Gcm;
use seal_flow::prelude::*;
use std::collections::HashMap;

fn main() -> seal_flow::error::Result<()> {
    // --- Setup ---
    // --- 准备工作 ---

    // In a real app, you'd manage keys in a KMS or secure storage.
    // For this example, we use a HashMap to simulate a key store.
    // 在真实应用中，您应该在 KMS 或其他安全存储中管理密钥。
    // 在本示例中，我们使用 HashMap 模拟一个密钥存储。
    let mut key_store = HashMap::new();
    let key = Aes256Gcm::generate_key()?;
    let key_id = "my-encryption-key-v1".to_string();
    key_store.insert(key_id.clone(), key.clone());

    // This is the data we want to encrypt.
    // 这是我们想要加密的数据。
    let plaintext = b"Data that is being protected.";
    // Associated Data (AAD) is authenticated but not encrypted.
    // It binds the ciphertext to its context, preventing certain attacks.
    // 关联数据 (AAD) 只被认证，不被加密。
    // 它将密文与上下文绑定，以防止某些类型的攻击。
    let aad = b"Context metadata, like a request ID or version.";

    // The high-level API factory is stateless and reusable.
    // 高级 API 工厂是无状态且可重用的。
    let seal = SymmetricSeal::new();

    // --- 1. Encryption ---
    // --- 1. 加密 ---

    // The key is wrapped in `SymmetricKey` for type safety and to carry metadata.
    // 密钥被包装在 `SymmetricKey` 中，以确保类型安全并携带元数据。
    let key_wrapped = SymmetricKey::new(key);
    let ciphertext = seal
        .encrypt(key_wrapped, key_id)
        // Bind the ciphertext to the AAD. The same AAD must be provided during decryption.
        // 将密文与 AAD 绑定。解密时必须提供完全相同的 AAD。
        .with_aad(aad)
        // Specify the encryption algorithm and execute the encryption.
        // This consumes the builder and returns the ciphertext.
        // 指定加密算法并执行加密操作。
        // 这会消耗构建器并返回密文。
        .to_vec::<Aes256Gcm>(plaintext)?;

    println!("Encryption successful!");

    // --- 2. Decryption (Safe Key-Lookup Workflow) ---
    // --- 2. 解密（安全的密钥查找工作流）---

    // a. Create a "Pending Decryptor" to inspect metadata without decrypting.
    //    This is a safe operation that doesn't process the encrypted data.
    // a. 创建一个"待定解密器"来检查元数据，而无需实际解密。
    //    这是一个安全的操作，不会处理加密数据。
    let pending_decryptor = seal.decrypt().slice(&ciphertext)?;

    // b. Get the key ID from the header. This is a cheap and safe operation.
    // b. 从头部获取密钥 ID。这是一个低成本且安全的操作。
    let found_key_id = pending_decryptor
        .key_id()
        .expect("Header must contain a key ID.");
    println!("Found key ID: '{}'. Now retrieving the key.", found_key_id);

    // c. Use the ID to fetch the correct key from your key store.
    // c. 使用该 ID 从您的密钥存储中获取正确的密钥。
    let decryption_key_bytes = key_store.get(found_key_id).unwrap();
    let decryption_key_wrapped = SymmetricKey::new(decryption_key_bytes.clone());

    // d. Provide the key and AAD to complete decryption.
    //    The `with_key` method automatically infers the algorithm from the header.
    // d. 提供密钥和 AAD 以完成解密。
    //    `with_key` 方法会自动从头部推断出加密算法。
    let decrypted_text = pending_decryptor
        .with_aad(aad) // You must provide the same AAD used for encryption. / 必须提供与加密时相同的 AAD。
        .with_key(decryption_key_wrapped)?;

    assert_eq!(plaintext, &decrypted_text[..]);
    println!("Successfully decrypted data!");
    Ok(())
}
