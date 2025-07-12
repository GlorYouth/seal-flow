use seal_flow::base::keys::TypedSymmetricKey;
use seal_flow::prelude::*;
use std::collections::HashMap;

fn main() -> seal_flow::error::Result<()> {
    // --- Setup ---
    // --- 准备工作 ---

    // In a real app, you'd manage keys in a KMS or secure storage.
    // For this example, we use a HashMap to simulate a key store.
    // 在真实应用中，您应该在 KMS 或其他安全存储中管理密钥。
    // 在本示例中，我们使用 HashMap 模拟一个密钥存储。
    let mut key_store: HashMap<String, TypedSymmetricKey> = HashMap::new();
    let algo = SymmetricAlgorithmEnum::Aes256Gcm;
    let key = algo.into_symmetric_wrapper().generate_typed_key()?;
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
    let seal = SymmetricSeal::default();

    // --- 1. Encryption ---
    // --- 1. 加密 ---

    // The key is a `TypedSymmetricKey` which carries algorithm information.
    // 密钥是一个 `TypedSymmetricKey`，它携带了算法信息。
    let ciphertext = seal
        .encrypt(key, key_id)
        // Bind the ciphertext to the AAD. The same AAD must be provided during decryption.
        // 将密文与 AAD 绑定。解密时必须提供完全相同的 AAD。
        .with_aad(aad)
        // The algorithm is inferred from the key, so we just execute `to_vec`.
        // This consumes the builder and returns the ciphertext.
        // 算法是从密钥中推断出来的，所以我们直接执行 `to_vec`。
        // 这会消耗构建器并返回密文。
        .to_vec(plaintext)?;

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
    let decryption_key = key_store.get(found_key_id).unwrap();

    // d. Provide the key and AAD to complete decryption.
    //    The `with_key_to_vec` method automatically infers the algorithm from the header
    //    and verifies it matches the provided key's type.
    // d. 提供密钥和 AAD 以完成解密。
    //    `with_key_to_vec` 方法会自动从头部推断出加密算法，
    //    并验证它与所提供密钥的类型相匹配。
    let decrypted_text = pending_decryptor
        .with_aad(aad) // You must provide the same AAD used for encryption. / 必须提供与加密时相同的 AAD。
        .with_key_to_vec(decryption_key)?;

    assert_eq!(plaintext, &decrypted_text[..]);
    println!("Successfully decrypted data!");
    Ok(())
}
