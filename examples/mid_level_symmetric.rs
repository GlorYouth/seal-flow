//! An example demonstrating the mid-level symmetric encryption APIs.
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};

use seal_flow::mid_level::common::config::ArcConfig;
use seal_flow::error::Result;
use seal_flow::base::keys::TypedSymmetricKey;
use seal_flow::mid_level::symmetric::{
    asynchronous::Asynchronous,
    ordinary::Ordinary,
    parallel::Parallel,
    parallel_streaming::ParallelStreaming,
    streaming::Streaming,
    traits::{
        SymmetricAsynchronousProcessor, SymmetricOrdinaryProcessor, SymmetricParallelProcessor,
        SymmetricParallelStreamingProcessor, SymmetricStreamingProcessor,
    },
};
use seal_flow::prelude::*;
use seal_crypto::secrecy::SecretBox;
use seal_flow::base::algorithms::kdf::passwd::{KdfPasswordWrapper, Pbkdf2Sha256Wrapper};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type TheAlgorithmEnum = SymmetricAlgorithmEnum;
const KEY_ID: &str = "mid-level-symmetric-key";

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Setup
    let mut key_store = HashMap::new();
    let algo = TheAlgorithmEnum::Aes256Gcm.into_symmetric_wrapper();
    let key = algo.generate_typed_key()?;
    key_store.insert(KEY_ID.to_string(), key);

    let plaintext = b"This is a test message for the mid-level API.";

    // --- Mode 1: In-Memory (Ordinary) ---
    println!("--- Testing Mode: In-Memory (Ordinary) ---");
    let key1 = key_store.get(KEY_ID).unwrap();
    let ordinary_processor = Ordinary::new();
    let ciphertext1 = ordinary_processor.encrypt_symmetric_in_memory(
        plaintext,
        seal_flow::mid_level::symmetric::config::SymmetricConfig {
            algorithm: Cow::Borrowed(&algo),
            key: Cow::Borrowed(key1),
            key_id: KEY_ID.to_string(),
            aad: None,
            config: ArcConfig::default(),
        },
    )?;

    // Demonstrate two-stage decryption
    let pending_decryptor1 = ordinary_processor
        .begin_decrypt_symmetric_in_memory(&ciphertext1, ArcConfig::default())?;
    let found_key_id1 = pending_decryptor1.header().payload.key_id().unwrap();
    println!("Found key ID in header: '{}'", found_key_id1);
    let decryption_key1 = key_store.get(found_key_id1).unwrap();
    let decrypted1 = pending_decryptor1.into_plaintext(decryption_key1, None)?;

    assert_eq!(plaintext, &decrypted1[..]);
    println!("In-Memory (Ordinary) roundtrip successful!");

    // --- Mode 2: In-Memory Parallel ---
    println!("\n--- Testing Mode: In-Memory Parallel ---");
    let key2 = key_store.get(KEY_ID).unwrap();
    let parallel_processor = Parallel::new();
    let ciphertext2 = parallel_processor.encrypt_symmetric_parallel(
        plaintext,
        seal_flow::mid_level::symmetric::config::SymmetricConfig {
            algorithm: Cow::Borrowed(&algo),
            key: Cow::Borrowed(key2),
            key_id: KEY_ID.to_string(),
            aad: None,
            config: ArcConfig::default(),
        },
    )?;

    let pending_decryptor2 = parallel_processor
        .begin_decrypt_symmetric_parallel(&ciphertext2, ArcConfig::default())?;
    let found_key_id2 = pending_decryptor2.header().payload.key_id().unwrap();
    println!("Found key ID in parallel header: '{}'", found_key_id2);
    let decryption_key2 = key_store.get(found_key_id2).unwrap();
    let decrypted2 = pending_decryptor2.into_plaintext(decryption_key2, None)?;

    assert_eq!(plaintext, &decrypted2[..]);
    println!("In-Memory Parallel roundtrip successful!");

    // --- Mode 3: Synchronous Streaming ---
    println!("\n--- Testing Mode: Synchronous Streaming ---");
    let mut ciphertext3 = Vec::new();
    let key3 = key_store.get(KEY_ID).unwrap();
    let streaming_processor = Streaming::new();
    let mut encryptor3 = streaming_processor.encrypt_symmetric_to_stream(
        Box::new(&mut ciphertext3),
        seal_flow::mid_level::symmetric::config::SymmetricConfig {
            algorithm: Cow::Borrowed(&algo),
            key: Cow::Borrowed(key3),
            key_id: KEY_ID.to_string(),
            aad: None,
            config: ArcConfig::default(),
        },
    )?;
    encryptor3.write_all(plaintext)?;
    encryptor3.finish()?;

    let pending_decryptor3 = streaming_processor
        .begin_decrypt_symmetric_from_stream(Box::new(Cursor::new(&ciphertext3)), ArcConfig::default())?;
    let found_key_id3 = pending_decryptor3.header().payload.key_id().unwrap();
    println!("Found key ID in stream: '{}'", found_key_id3);
    let decryption_key3 = key_store.get(found_key_id3).unwrap();
    let mut decryptor3 = pending_decryptor3.into_decryptor(decryption_key3, None)?;

    let mut decrypted3 = Vec::new();
    decryptor3.read_to_end(&mut decrypted3)?;
    assert_eq!(plaintext, &decrypted3[..]);
    println!("Synchronous Streaming roundtrip successful!");

    // --- Mode 4: Asynchronous Streaming ---
    println!("\n--- Testing Mode: Asynchronous Streaming ---");
    let mut ciphertext4 = Vec::new();
    let key4 = key_store.get(KEY_ID).unwrap();
    let async_processor = Asynchronous::new();
    {
        let mut encryptor4 = async_processor
            .encrypt_symmetric_async(
                Box::new(&mut ciphertext4),
                seal_flow::mid_level::symmetric::config::SymmetricConfig {
                    algorithm: Cow::Borrowed(&algo),
                    key: Cow::Borrowed(key4),
                    key_id: KEY_ID.to_string(),
                    aad: None,
                    config: ArcConfig::default(),
                },
            )
            .await?;
        encryptor4.write_all(plaintext).await?;
        encryptor4.shutdown().await?;
    }

    let pending_decryptor4 = async_processor
        .begin_decrypt_symmetric_async(Box::new(Cursor::new(&ciphertext4)), ArcConfig::default())
        .await?;
    let found_key_id4 = pending_decryptor4.header().payload.key_id().unwrap();
    println!("Found key ID in async stream: '{}'", found_key_id4);
    let decryption_key4 = key_store.get(found_key_id4).unwrap();
    let mut decryptor4 = pending_decryptor4
        .into_decryptor(decryption_key4, None)
        .await?;

    let mut decrypted4 = Vec::new();
    decryptor4.read_to_end(&mut decrypted4).await?;
    assert_eq!(plaintext, &decrypted4[..]);
    println!("Asynchronous Streaming roundtrip successful!");

    // --- Mode 5: Parallel Streaming ---
    println!("\n--- Testing Mode: Parallel Streaming ---");
    let mut ciphertext5 = Vec::new();
    let key5 = key_store.get(KEY_ID).unwrap();
    let parallel_streaming_processor = ParallelStreaming::new();
    parallel_streaming_processor.encrypt_symmetric_pipeline(
        Box::new(Cursor::new(plaintext)),
        Box::new(&mut ciphertext5),
        seal_flow::mid_level::symmetric::config::SymmetricConfig {
            algorithm: Cow::Borrowed(&algo),
            key: Cow::Borrowed(key5),
            key_id: KEY_ID.to_string(),
            aad: None,
            config: ArcConfig::default(),
        },
    )?;

    let mut decrypted5 = Vec::new();
    let mut source5 = Cursor::new(&ciphertext5);
    let pending_decryptor5 = parallel_streaming_processor
        .begin_decrypt_symmetric_pipeline(Box::new(&mut source5), ArcConfig::default())?;
    let header5 = pending_decryptor5.header().clone();
    let found_key_id5 = header5.payload.key_id().unwrap();
    println!("Found key ID in parallel stream: '{}'", found_key_id5);
    let decryption_key5 = key_store.get(found_key_id5).unwrap();
    pending_decryptor5.decrypt_to_writer(decryption_key5, Box::new(&mut decrypted5), None)?;

    assert_eq!(plaintext, &decrypted5[..]);
    println!("Parallel Streaming roundtrip successful!");

    println!("\nAll mid-level symmetric modes are interoperable and successful.");

    // --- Mode 6: In-Memory with AAD ---
    println!("\n--- Testing Mode: In-Memory with AAD ---");
    let aad = b"this is authenticated data for the mid-level symmetric api";
    let key6 = key_store.get(KEY_ID).unwrap();
    let ciphertext6 = ordinary_processor.encrypt_symmetric_in_memory(
        plaintext,
        seal_flow::mid_level::symmetric::config::SymmetricConfig {
            algorithm: Cow::Borrowed(&algo),
            key: Cow::Borrowed(key6),
            key_id: KEY_ID.to_string(),
            aad: Some(aad.to_vec()),
            config: ArcConfig::default(),
        },
    )?;

    let pending_decryptor6 = ordinary_processor
        .begin_decrypt_symmetric_in_memory(&ciphertext6, ArcConfig::default())?;
    let found_key_id6 = pending_decryptor6.header().payload.key_id().unwrap();
    let decryption_key6 = key_store.get(found_key_id6).unwrap();

    // Decrypt with correct AAD
    let decrypted6 = pending_decryptor6.into_plaintext(decryption_key6, Some(aad.to_vec()))?;
    assert_eq!(plaintext, &decrypted6[..]);
    println!("In-Memory with AAD roundtrip successful!");

    // Decrypt with wrong AAD should fail
    let pending_decryptor_fail = ordinary_processor
        .begin_decrypt_symmetric_in_memory(&ciphertext6, ArcConfig::default())?;
    let result_fail =
        pending_decryptor_fail.into_plaintext(decryption_key6, Some(b"wrong aad".to_vec()));
    assert!(result_fail.is_err());
    println!("In-Memory with wrong AAD correctly failed!");

    // --- Mode 7: 密钥派生示例 ---
    println!("\n--- Testing Key Derivation ---");

    // 从主密钥派生子密钥 - 使用 HKDF
    let master_key_bytes = key_store.get(KEY_ID).unwrap().as_ref().to_vec();
    let master_key = SymmetricKey::new(master_key_bytes);
    let deriver = KdfKeyAlgorithmEnum::HkdfSha256;

    // 使用不同的上下文信息派生不同用途的子密钥
    let salt = b"rotation-salt-2023";
    let encryption_info = b"data-encryption-key";
    let signing_info = b"signing-key";

    let encryption_key = master_key.derive_key(deriver, Some(salt), Some(encryption_info), 32)?;

    let _signing_key = master_key.derive_key(deriver, Some(salt), Some(signing_info), 32)?;

    println!("成功从主密钥派生子密钥！");

    // 使用派生的密钥进行加密
    let derived_key_bytes = encryption_key.as_bytes();
    let derived_key_id = "derived-encryption-key";

    // 将派生的字节转换为算法密钥
    let algo_key =
        TypedSymmetricKey::from_bytes(derived_key_bytes, TheAlgorithmEnum::Aes256Gcm)?;

    let ciphertext7 = ordinary_processor.encrypt_symmetric_in_memory(
        plaintext,
        seal_flow::mid_level::symmetric::config::SymmetricConfig {
            algorithm: Cow::Borrowed(&algo),
            key: Cow::Borrowed(&algo_key),
            key_id: derived_key_id.to_string(),
            aad: None,
            config: ArcConfig::default(),
        },
    )?;

    // 使用派生的密钥进行解密
    let pending_decryptor7 = ordinary_processor
        .begin_decrypt_symmetric_in_memory(&ciphertext7, ArcConfig::default())?;
    let algo_key2 =
        TypedSymmetricKey::from_bytes(derived_key_bytes, TheAlgorithmEnum::Aes256Gcm)?;
    let decrypted7 = pending_decryptor7.into_plaintext(&algo_key2, None)?;

    assert_eq!(plaintext, &decrypted7[..]);
    println!("使用派生密钥加密/解密成功！");

    // --- Mode 8: 从密码派生密钥 ---
    println!("\n--- Testing Password-Based Key Derivation ---");

    let password = SecretBox::new(Box::from(b"user-secure-password".as_slice()));
    let salt = b"random-salt-value";

    // 在实际应用中应使用更高的迭代次数 (至少 100,000)
    let pbkdf2_deriver = KdfPasswordWrapper::new(Box::new(Pbkdf2Sha256Wrapper::new(100_000)));

    // 从用户密码派生加密密钥
    let password_derived_key =
        SymmetricKey::derive_from_password(&password, pbkdf2_deriver.clone(), salt, 32)?;

    // 使用从密码派生的密钥加密数据
    let password_key_id = "password-derived-key";
    let password_key = TypedSymmetricKey::from_bytes(
        password_derived_key.as_bytes(),
        TheAlgorithmEnum::Aes256Gcm,
    )?;
    let ciphertext8 = ordinary_processor.encrypt_symmetric_in_memory(
        plaintext,
        seal_flow::mid_level::symmetric::config::SymmetricConfig {
            algorithm: Cow::Borrowed(&algo),
            key: Cow::Borrowed(&password_key),
            key_id: password_key_id.to_string(),
            aad: None,
            config: ArcConfig::default(),
        },
    )?;

    // 模拟另一个位置：重新从相同密码派生相同密钥进行解密
    let password_derived_key2 =
        SymmetricKey::derive_from_password(&password, pbkdf2_deriver, salt, 32)?;

    let pending_decryptor8 = ordinary_processor
        .begin_decrypt_symmetric_in_memory(&ciphertext8, ArcConfig::default())?;
    let password_key2 = TypedSymmetricKey::from_bytes(
        password_derived_key2.as_bytes(),
        TheAlgorithmEnum::Aes256Gcm,
    )?;
    let decrypted8 = pending_decryptor8.into_plaintext(&password_key2, None)?;

    assert_eq!(plaintext, &decrypted8[..]);
    println!("从密码派生密钥并成功加密/解密数据！");

    println!("\n所有密钥派生模式测试成功。");

    Ok(())
}
