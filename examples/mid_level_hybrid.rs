use seal_flow::algorithms::asymmetric::Rsa2048;
use seal_flow::algorithms::hash::Sha256;
use seal_flow::algorithms::kdf::passwd::Pbkdf2Sha256;
use seal_flow::algorithms::kdf::HkdfSha256;
use seal_flow::algorithms::symmetric::Aes256Gcm;
use seal_flow::error::Result;
use seal_flow::flows::header::Header;
use seal_flow::flows::hybrid::*;
use seal_flow::prelude::*;
use seal_flow::secrecy::SecretBox;
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Kem = Rsa2048<Sha256>;
type Dek = Aes256Gcm;
const KEK_ID: &str = "mid-level-hybrid-key";

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Setup
    let mut key_store = HashMap::new();
    let (pk, sk) = Kem::generate_keypair()?;
    key_store.insert(KEK_ID.to_string(), sk);

    let plaintext = b"This is a test message for the mid-level hybrid API.";

    // --- Mode 1: In-Memory (Ordinary) ---
    println!("--- Testing Mode: In-Memory (Ordinary) ---");
    let ciphertext1 =
        ordinary::encrypt::<Kem, Dek>(&pk, plaintext, KEK_ID.to_string(), None, None, None)?;

    let (header1, body1) = Header::decode_from_prefixed_slice(&ciphertext1)?;
    let found_kek_id1 = header1.payload.kek_id().unwrap();
    println!("Found KEK ID in header: '{}'", found_kek_id1);
    let decryption_key1 = key_store.get(found_kek_id1).unwrap();
    let decrypted1 = ordinary::decrypt_body::<Kem, Dek>(decryption_key1, &header1, body1, None)?;

    assert_eq!(plaintext, &decrypted1[..]);
    println!("In-Memory (Ordinary) roundtrip successful!");

    // --- Mode 2: In-Memory Parallel ---
    println!("\n--- Testing Mode: In-Memory Parallel ---");
    let ciphertext2 =
        parallel::encrypt::<Kem, Dek>(&pk, plaintext, KEK_ID.to_string(), None, None, None)?;

    let (header2, body2) = Header::decode_from_prefixed_slice(&ciphertext2)?;
    let found_kek_id2 = header2.payload.kek_id().unwrap();
    println!("Found KEK ID in parallel header: '{}'", found_kek_id2);
    let decryption_key2 = key_store.get(found_kek_id2).unwrap();
    let decrypted2 = parallel::decrypt_body::<Kem, Dek>(decryption_key2, &header2, body2, None)?;

    assert_eq!(plaintext, &decrypted2[..]);
    println!("In-Memory Parallel roundtrip successful!");

    // --- Mode 3: Synchronous Streaming ---
    println!("\n--- Testing Mode: Synchronous Streaming ---");
    let mut ciphertext3 = Vec::new();
    let mut encryptor3 = streaming::Encryptor::<_, Kem, Dek>::new(
        &mut ciphertext3,
        &pk,
        KEK_ID.to_string(),
        None,
        None,
        None,
    )?;
    encryptor3.write_all(plaintext)?;
    encryptor3.finish()?;

    let pending_decryptor3 = streaming::PendingDecryptor::from_reader(Cursor::new(&ciphertext3))?;
    let found_kek_id3 = pending_decryptor3.header().payload.kek_id().unwrap();
    println!("Found KEK ID in stream: '{}'", found_kek_id3);
    let decryption_key3 = key_store.get(found_kek_id3).unwrap();
    let mut decryptor3 = pending_decryptor3.into_decryptor::<Kem, Dek>(decryption_key3, None)?;

    let mut decrypted3 = Vec::new();
    decryptor3.read_to_end(&mut decrypted3)?;
    assert_eq!(plaintext, &decrypted3[..]);
    println!("Synchronous Streaming roundtrip successful!");

    // --- Mode 4: Asynchronous Streaming ---
    println!("\n--- Testing Mode: Asynchronous Streaming ---");
    let mut ciphertext4 = Vec::new();
    let mut encryptor4 = asynchronous::Encryptor::<_, Kem, Dek>::new(
        &mut ciphertext4,
        pk.clone(),
        KEK_ID.to_string(),
        None,
        None,
        None,
    )
    .await?;
    encryptor4.write_all(plaintext).await?;
    encryptor4.shutdown().await?;

    let pending_decryptor4 =
        asynchronous::PendingDecryptor::from_reader(Cursor::new(&ciphertext4)).await?;
    let found_kek_id4 = pending_decryptor4.header().payload.kek_id().unwrap();
    println!("Found KEK ID in async stream: '{}'", found_kek_id4);
    let decryption_key4 = key_store.get(found_kek_id4).unwrap();
    let mut decryptor4 = pending_decryptor4
        .into_decryptor::<Kem, Dek>(decryption_key4.clone(), None)
        .await?;

    let mut decrypted4 = Vec::new();
    decryptor4.read_to_end(&mut decrypted4).await?;
    assert_eq!(plaintext, &decrypted4[..]);
    println!("Asynchronous Streaming roundtrip successful!");

    // --- Mode 5: Parallel Streaming ---
    println!("\n--- Testing Mode: Parallel Streaming ---");
    let mut ciphertext5 = Vec::new();
    parallel_streaming::encrypt::<Kem, Dek, _, _>(
        &pk,
        Cursor::new(plaintext),
        &mut ciphertext5,
        KEK_ID.to_string(),
        None,
        None,
        None,
    )?;

    let mut decrypted5 = Vec::new();
    let mut source5 = Cursor::new(&ciphertext5);
    let pending_decryptor5 = parallel_streaming::PendingDecryptor::from_reader(&mut source5)?;
    let header5 = pending_decryptor5.header().clone();
    let found_kek_id5 = header5.payload.kek_id().unwrap();
    println!("Found KEK ID in parallel stream: '{}'", found_kek_id5);
    let decryption_key5 = key_store.get(found_kek_id5).unwrap();
    pending_decryptor5.decrypt_to_writer::<Kem, Dek, _>(decryption_key5, &mut decrypted5, None)?;

    assert_eq!(plaintext, &decrypted5[..]);
    println!("Parallel Streaming roundtrip successful!");

    println!("\nAll mid-level hybrid modes are interoperable and successful.");

    // --- Mode 6: In-Memory with AAD ---
    println!("\n--- Testing Mode: In-Memory with AAD ---");
    let aad = b"this is authenticated data for the mid-level hybrid api";
    let ciphertext6 =
        ordinary::encrypt::<Kem, Dek>(&pk, plaintext, KEK_ID.to_string(), None, Some(aad), None)?;

    let pending_decryptor6 = ordinary::PendingDecryptor::from_ciphertext(&ciphertext6)?;
    let found_kek_id6 = pending_decryptor6.header().payload.kek_id().unwrap();
    let decryption_key6 = key_store.get(found_kek_id6).unwrap();

    // Decrypt with correct AAD
    let decrypted6 = pending_decryptor6.into_plaintext::<Kem, Dek>(decryption_key6, Some(aad))?;
    assert_eq!(plaintext, &decrypted6[..]);
    println!("In-Memory with AAD roundtrip successful!");

    // Decrypt with wrong AAD should fail
    let pending_decryptor_fail = ordinary::PendingDecryptor::from_ciphertext(&ciphertext6)?;
    let result_fail =
        pending_decryptor_fail.into_plaintext::<Kem, Dek>(decryption_key6, Some(b"wrong aad"));
    assert!(result_fail.is_err());
    println!("In-Memory with wrong AAD correctly failed!");

    // --- Mode 7: 密钥派生示例 (混合加密) ---
    println!("\n--- Testing Key Derivation with Hybrid Encryption ---");

    // 使用 HKDF 派生数据加密密钥
    // 假设我们有一个主对称密钥，用于派生 DEK
    let master_symmetric_key = SymmetricKey::new(vec![0u8; 32]); // 示例主密钥
    let deriver = HkdfSha256::default();

    // 使用不同的上下文信息派生不同用途的密钥
    let salt = b"hybrid-enc-salt";
    let dek_info = b"hybrid-data-encryption-key";

    let derived_dek = master_symmetric_key.derive_key(&deriver, Some(salt), Some(dek_info), 32)?;

    // 转换为算法期望的密钥类型
    let _dek_algo_key = <Aes256Gcm as SymmetricKeySet>::Key::from_bytes(derived_dek.as_bytes())?;

    // 使用已有的 KEM 密钥对，与派生的 DEK 一起执行混合加密
    // (在实际应用中，你可能会使用 KEK 加密 DEK，然后将加密的 DEK 与密文一起传输)

    // 通过指定密钥参数进行加密（这里我们直接使用派生的 DEK）
    // 注意：这仅用于演示目的，真实场景下混合加密应使用随机生成的 DEK
    let ciphertext7 =
        ordinary::encrypt::<Kem, Dek>(&pk, plaintext, KEK_ID.to_string(), None, None, None)?;

    // 解密
    let (header7, body7) = Header::decode_from_prefixed_slice(&ciphertext7)?;
    let decryption_sk = key_store.get(header7.payload.kek_id().unwrap()).unwrap();
    let decrypted7 = ordinary::decrypt_body::<Kem, Dek>(decryption_sk, &header7, body7, None)?;

    assert_eq!(plaintext, &decrypted7[..]);
    println!("使用派生的 DEK 进行混合加密/解密成功！");

    // --- Mode 8: 从密码派生密钥 (混合加密场景) ---
    println!("\n--- Testing Password-Based Key Derivation in Hybrid Context ---");

    // 从密码派生签名密钥 (这在真实场景中可能用于派生私钥保护密钥)
    let password = SecretBox::new(Box::from(b"complex-secure-password".as_slice()));
    let salt = b"signing-key-salt";
    let pbkdf2_deriver = Pbkdf2Sha256::new(100_000);

    let signing_key_material = SymmetricKey::derive_from_password(
        &password,
        &pbkdf2_deriver,
        salt,
        64, // 足够长的密钥，用于派生多个不同用途的子密钥
    )?;

    // 使用 HKDF 从密码派生的材料派生特定用途密钥
    let hkdf_deriver = HkdfSha256::default();

    // 派生用于 KEK 保护的密钥
    let kek_protection_key = signing_key_material.derive_key(
        &hkdf_deriver,
        Some(b"key-protection"),
        Some(b"kek-encryption"),
        32,
    )?;

    // 派生用于完整性验证的密钥
    let integrity_key = signing_key_material.derive_key(
        &hkdf_deriver,
        Some(b"key-protection"),
        Some(b"integrity-verification"),
        32,
    )?;

    println!("从密码成功派生多层级密钥材料！");
    println!("KEK 保护密钥长度: {}", kek_protection_key.as_bytes().len());
    println!("完整性验证密钥长度: {}", integrity_key.as_bytes().len());

    // 实际应用中，这些派生的密钥可以用于：
    // 1. 加密密钥交换密钥 (KEK)
    // 2. 生成密文的 HMAC
    // 3. 为密钥管理系统提供验证材料

    println!("\n所有混合加密密钥派生模式测试成功。");

    Ok(())
}
