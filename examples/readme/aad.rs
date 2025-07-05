use seal_flow::algorithms::symmetric::Aes256Gcm;
use seal_flow::prelude::*;

fn main() -> seal_flow::error::Result<()> {
    // --- Setup ---
    // --- 准备工作 ---
    let key = Aes256Gcm::generate_key()?;
    let key_wrapped = SymmetricKey::new(key);
    let key_id = "my-aad-key".to_string();
    let plaintext = b"This data is secret and needs integrity protection.";

    // Associated Data (AAD) is data that is authenticated but not encrypted.
    // It's useful for binding ciphertext to its context, such as user IDs,
    // version numbers, or other metadata. If the AAD changes, decryption will fail.
    // 关联数据 (AAD) 是指被认证但未被加密的数据。
    // 它对于将密文与其上下文（如用户 ID、版本号或其他元数据）绑定非常有用。
    // 如果 AAD 发生变化，解密将会失败。
    let aad = b"user-id:123,request-id:xyz-789";

    // The high-level API factory is stateless and reusable.
    // 高级 API 工厂是无状态且可重用的。
    let seal = SymmetricSeal::new();

    // --- Encrypt with AAD ---
    // --- 使用 AAD 加密 ---
    println!(
        "Encrypting data with AAD: '{}'",
        String::from_utf8_lossy(aad)
    );
    let ciphertext = seal
        .encrypt(key_wrapped.clone(), key_id)
        .with_aad(aad)
        .to_vec::<Aes256Gcm>(plaintext)?;

    // --- Decryption Success ---
    // --- 解密成功场景 ---
    // To decrypt, you MUST provide the exact same AAD.
    // The library cryptographically verifies that the AAD matches.
    // 要成功解密，您必须提供与加密时完全相同的 AAD。
    // 本库会通过密码学手段验证 AAD 是否匹配。
    println!("Attempting decryption with the correct AAD...");
    let pending_decryptor = seal.decrypt().slice(&ciphertext)?;
    let decrypted_text = pending_decryptor
        .with_aad(aad)
        .with_key(key_wrapped.clone())?;

    assert_eq!(plaintext, &decrypted_text[..]);
    println!("Successfully decrypted with correct AAD!");

    // --- Decryption Failures ---
    // --- 解密失败场景 ---

    // 1. Attempting to decrypt with the wrong AAD will fail.
    //    This prevents an attacker from taking a valid ciphertext and using it
    //    in a different context (e.g., for a different user).
    // 1. 尝试使用错误的 AAD 进行解密将会失败。
    //    这可以防止攻击者将一个有效的密文用于不同的上下文（例如，用于另一个用户）。
    let wrong_aad = b"user-id:456,request-id:abc-123";
    println!(
        "\nAttempting decryption with WRONG AAD: '{}'",
        String::from_utf8_lossy(wrong_aad)
    );
    let pending_fail = seal.decrypt().slice(&ciphertext)?;
    let result_fail = pending_fail
        .with_aad(wrong_aad)
        .with_key(key_wrapped.clone());

    assert!(result_fail.is_err());
    if let Err(e) = result_fail {
        println!("Correctly failed with error: {}", e);
    }

    // 2. Attempting to decrypt without providing the AAD (when it was used for encryption)
    //    will also fail.
    // 2. 如果加密时使用了 AAD，解密时却不提供，同样会导致解密失败。
    println!("\nAttempting decryption with MISSING AAD...");
    let pending_fail2 = seal.decrypt().slice(&ciphertext)?;
    let result_fail2 = pending_fail2.with_key(key_wrapped);

    assert!(result_fail2.is_err());
    if let Err(e) = result_fail2 {
        println!("Correctly failed with error: {}", e);
    }

    Ok(())
}
