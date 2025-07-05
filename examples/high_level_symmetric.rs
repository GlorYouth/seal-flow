use seal_flow::algorithms::kdf::HkdfSha256;
use seal_flow::algorithms::kdf::passwd::Pbkdf2Sha256;
use seal_flow::algorithms::symmetric::Aes256Gcm;
use seal_flow::prelude::*;
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type TheAlgorithm = Aes256Gcm;
const KEY_ID: &str = "high-level-symmetric-key";

// 使用HashMap存储密钥，以便通过key_id查找
struct KeyStore {
    keys: HashMap<String, Vec<u8>>,
}

impl KeyStore {
    fn get_key(&self, key_id: &str) -> Option<SymmetricKey> {
        self.keys.get(key_id).map(|k| SymmetricKey::new(k.clone()))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Setup
    // 创建密钥并存储在我们的KeyStore中
    let key = TheAlgorithm::generate_key()?;
    let key_bytes = key.to_bytes();
    let mut keys = HashMap::new();
    keys.insert(KEY_ID.to_string(), key_bytes.to_vec());
    let key_store = KeyStore { keys };

    let plaintext = b"This is a test message for interoperability across different modes.";
    let seal = SymmetricSeal::new();

    // --- Mode 1: In-Memory (Ordinary) ---
    println!("--- Testing Mode: In-Memory (Ordinary) ---");
    let ciphertext1 = seal
        .encrypt(SymmetricKey::new(key.to_bytes()), KEY_ID.to_string())
        .to_vec::<TheAlgorithm>(plaintext)?;
    let pending_decryptor1 = seal.decrypt().slice(&ciphertext1)?;
    let key_id = pending_decryptor1.key_id().unwrap();
    let key_to_decrypt = key_store.get_key(key_id).unwrap();
    let decrypted1 = pending_decryptor1.with_key(key_to_decrypt)?;
    assert_eq!(plaintext, &decrypted1[..]);
    println!("In-Memory (Ordinary) roundtrip successful!");

    // --- Mode 2: In-Memory Parallel ---
    println!("\n--- Testing Mode: In-Memory Parallel ---");
    let ciphertext2 = seal
        .encrypt(SymmetricKey::new(key.to_bytes()), KEY_ID.to_string())
        .to_vec_parallel::<TheAlgorithm>(plaintext)?;
    let pending_decryptor2 = seal.decrypt().slice_parallel(&ciphertext2)?;
    let key_id = pending_decryptor2.key_id().unwrap();
    let key_to_decrypt = key_store.get_key(key_id).unwrap();
    let decrypted2 = pending_decryptor2.with_key(key_to_decrypt)?;
    assert_eq!(plaintext, &decrypted2[..]);
    println!("In-Memory Parallel roundtrip successful!");

    // --- Mode 3: Synchronous Streaming ---
    println!("\n--- Testing Mode: Synchronous Streaming ---");
    let mut ciphertext3 = Vec::new();
    let mut encryptor3 = seal
        .encrypt(SymmetricKey::new(key.to_bytes()), KEY_ID.to_string())
        .into_writer::<TheAlgorithm, _>(&mut ciphertext3)?;
    encryptor3.write_all(plaintext)?;
    encryptor3.finish()?;

    let pending_decryptor3 = seal.decrypt().reader(Cursor::new(&ciphertext3))?;
    println!(
        "Found key ID in stream: '{}'",
        pending_decryptor3.key_id().unwrap()
    );
    let key_id = pending_decryptor3.key_id().unwrap();
    let key_to_decrypt = key_store.get_key(key_id).unwrap();
    let mut decryptor3 = pending_decryptor3.with_key(key_to_decrypt)?;

    let mut decrypted3 = Vec::new();
    decryptor3.read_to_end(&mut decrypted3)?;
    assert_eq!(plaintext, &decrypted3[..]);
    println!("Synchronous Streaming roundtrip successful!");

    // --- Mode 4: Asynchronous Streaming ---
    println!("\n--- Testing Mode: Asynchronous Streaming ---");
    let mut ciphertext4 = Vec::new();
    let mut encryptor4 = seal
        .encrypt(SymmetricKey::new(key.to_bytes()), KEY_ID.to_string())
        .into_async_writer::<TheAlgorithm, _>(&mut ciphertext4)
        .await?;
    encryptor4.write_all(plaintext).await?;
    encryptor4.shutdown().await?;

    let pending_decryptor4 = seal
        .decrypt()
        .async_reader(Cursor::new(&ciphertext4))
        .await?;
    println!(
        "Found key ID in async stream: '{}'",
        pending_decryptor4.key_id().unwrap()
    );
    let key_id = pending_decryptor4.key_id().unwrap();
    let key_to_decrypt = key_store.get_key(key_id).unwrap();
    let mut decryptor4 = pending_decryptor4.with_key(key_to_decrypt)?;

    let mut decrypted4 = Vec::new();
    decryptor4.read_to_end(&mut decrypted4).await?;
    assert_eq!(plaintext, &decrypted4[..]);
    println!("Asynchronous Streaming roundtrip successful!");

    // --- Mode 5: Parallel Streaming ---
    println!("\n--- Testing Mode: Parallel Streaming ---");
    let mut ciphertext5 = Vec::new();
    seal.encrypt(SymmetricKey::new(key.to_bytes()), KEY_ID.to_string())
        .pipe_parallel::<TheAlgorithm, _, _>(Cursor::new(plaintext), &mut ciphertext5)?;

    let mut decrypted5 = Vec::new();
    let pending_decryptor5 = seal.decrypt().reader_parallel(Cursor::new(&ciphertext5))?;
    println!(
        "Found key ID in parallel stream: '{}'",
        pending_decryptor5.key_id().unwrap()
    );
    let key_id = pending_decryptor5.key_id().unwrap();
    let key_to_decrypt = key_store.get_key(key_id).unwrap();
    pending_decryptor5.with_key_to_writer(key_to_decrypt, &mut decrypted5)?;
    assert_eq!(plaintext, &decrypted5[..]);
    println!("Parallel Streaming roundtrip successful!");

    println!("\nAll high-level symmetric modes are interoperable and successful.");

    // --- Mode 6: In-Memory with AAD ---
    println!("\n--- Testing Mode: In-Memory with AAD ---");
    let aad = b"Authenticated but not encrypted data";
    let ciphertext6 = seal
        .encrypt(SymmetricKey::new(key.to_bytes()), KEY_ID.to_string())
        .with_aad(aad)
        .to_vec::<TheAlgorithm>(plaintext)?;

    // Decrypt with correct AAD
    let pending_decryptor6 = seal.decrypt().slice(&ciphertext6)?;
    let key_id = pending_decryptor6.key_id().unwrap();
    let key_to_decrypt = key_store.get_key(key_id).unwrap();
    let decrypted6 = pending_decryptor6.with_aad(aad).with_key(key_to_decrypt)?;
    assert_eq!(plaintext, &decrypted6[..]);
    println!("In-Memory with AAD roundtrip successful!");

    // Decrypt with wrong AAD should fail
    let pending_fail = seal.decrypt().slice(&ciphertext6)?;
    let key_id = pending_fail.key_id().unwrap();
    let key_to_decrypt = key_store.get_key(key_id).unwrap();
    let result_fail = pending_fail.with_aad(b"wrong aad").with_key(key_to_decrypt);
    assert!(result_fail.is_err());
    println!("In-Memory with wrong AAD correctly failed!");

    // Decrypt with no AAD should also fail
    let pending_fail2 = seal.decrypt().slice(&ciphertext6)?;
    let key_id = pending_fail2.key_id().unwrap();
    let key_to_decrypt = key_store.get_key(key_id).unwrap();
    let result_fail2 = pending_fail2.with_key(key_to_decrypt);
    assert!(result_fail2.is_err());
    println!("In-Memory with no AAD correctly failed!");

    // --- Mode 7: 密钥派生功能 ---
    println!("\n--- Testing Key Derivation ---");

    // 从主密钥派生子密钥
    let master_key = key_store.get_key(KEY_ID).unwrap();
    let deriver = HkdfSha256::default();

    // 使用不同上下文信息派生不同用途的子密钥
    let salt = b"key-rotation-salt-2023";
    let info_enc = b"encryption-key";
    let info_auth = b"authentication-key";

    let derived_enc_key = master_key.derive_key(&deriver, Some(salt), Some(info_enc), 32)?;

    let _derived_auth_key = master_key.derive_key(&deriver, Some(salt), Some(info_auth), 32)?;

    println!("成功从主密钥派生子密钥！");

    // 使用派生的加密密钥加密数据
    let derived_key_id = "derived-encryption-key";
    let ciphertext7 = seal
        .encrypt(derived_enc_key.clone(), derived_key_id.to_string())
        .to_vec::<TheAlgorithm>(plaintext)?;

    // 解密数据
    let pending_decryptor7 = seal.decrypt().slice(&ciphertext7)?;
    let found_key_id = pending_decryptor7.key_id().unwrap();
    println!("从密文中读取的派生密钥ID: '{}'", found_key_id);
    assert_eq!(found_key_id, derived_key_id);

    // 使用同一个派生密钥解密
    let decrypted7 = pending_decryptor7.with_key(derived_enc_key)?;
    assert_eq!(plaintext, &decrypted7[..]);
    println!("使用派生密钥加密/解密成功！");

    // --- Mode 8: 从密码派生密钥 ---
    println!("\n--- Testing Password-Based Key Derivation ---");

    // 模拟用户密码
    let password = b"secure-user-password-example";
    let salt = b"random-salt-value";

    // 在实际应用中应使用更高的迭代次数（至少100,000）
    let pbkdf2_deriver = Pbkdf2Sha256::new(100_000);

    // 从密码派生加密密钥
    let password_derived_key =
        SymmetricKey::derive_from_password(password, &pbkdf2_deriver, salt, 32)?;

    // 使用密码派生的密钥加密数据
    let password_key_id = "password-derived-key";
    let ciphertext8 = seal
        .encrypt(password_derived_key.clone(), password_key_id.to_string())
        .to_vec::<TheAlgorithm>(plaintext)?;

    // 解密数据
    let pending_decryptor8 = seal.decrypt().slice(&ciphertext8)?;
    let found_key_id = pending_decryptor8.key_id().unwrap();
    println!("从密文中读取的密码派生密钥ID: '{}'", found_key_id);
    assert_eq!(found_key_id, password_key_id);

    // 在另一个环境中，我们可以从相同的密码和盐值重新派生出相同的密钥
    let password_derived_key2 =
        SymmetricKey::derive_from_password(password, &pbkdf2_deriver, salt, 32)?;

    // 使用重新派生的密钥解密
    let decrypted8 = pending_decryptor8.with_key(password_derived_key2)?;
    assert_eq!(plaintext, &decrypted8[..]);
    println!("使用从密码派生的密钥加密/解密成功！");

    // --- 多级密钥派生示例 ---
    println!("\n--- Testing Multi-Level Key Derivation ---");

    // 从密码派生主密钥
    let master_password = b"master-password";
    let master_salt = b"master-salt";
    let master_key_material = SymmetricKey::derive_from_password(
        master_password,
        &pbkdf2_deriver,
        master_salt,
        64, // 更长的密钥，用于进一步派生
    )?;

    // 然后使用HKDF从主密钥派生多个特定用途的子密钥
    let app_salt = b"application-salt";

    // 派生数据库加密密钥
    let db_key = master_key_material.derive_key(
        &deriver,
        Some(app_salt),
        Some(b"database-encryption"),
        32,
    )?;

    // 派生文件加密密钥
    let file_key =
        master_key_material.derive_key(&deriver, Some(app_salt), Some(b"file-encryption"), 32)?;

    // 派生API通信密钥
    let api_key =
        master_key_material.derive_key(&deriver, Some(app_salt), Some(b"api-communication"), 32)?;

    println!("从主密码成功派生多级子密钥！");
    println!("  - 数据库密钥长度: {} 字节", db_key.as_bytes().len());
    println!("  - 文件密钥长度: {} 字节", file_key.as_bytes().len());
    println!("  - API密钥长度: {} 字节", api_key.as_bytes().len());

    // 使用数据库密钥加密
    let db_key_id = "db-encryption-key";
    let db_plaintext = b"Sensitive database content";
    let _db_ciphertext = seal
        .encrypt(db_key.clone(), db_key_id.to_string())
        .to_vec::<TheAlgorithm>(db_plaintext)?;

    // 使用文件密钥加密
    let file_key_id = "file-encryption-key";
    let file_plaintext = b"Sensitive file content";
    let _file_ciphertext = seal
        .encrypt(file_key.clone(), file_key_id.to_string())
        .to_vec::<TheAlgorithm>(file_plaintext)?;

    println!("使用派生的特定用途子密钥加密成功！");

    Ok(())
}
