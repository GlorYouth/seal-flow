use seal_flow::algorithms::asymmetric::Kyber512;
use seal_flow::algorithms::asymmetric::Rsa2048;
use seal_flow::algorithms::hash::Sha256;
use seal_flow::algorithms::kdf::passwd::Pbkdf2Sha256;
use seal_flow::algorithms::kdf::HkdfSha256;
use seal_flow::algorithms::signature::Dilithium2;
use seal_flow::algorithms::symmetric::Aes256Gcm;
use seal_flow::prelude::*;
use seal_flow::secrecy::SecretBox;
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Kem = Rsa2048<Sha256>;
type Dek = Aes256Gcm;
type Signer = Dilithium2;
const KEK_ID: &str = "high-level-hybrid-key";
const SIGNER_KEY_ID: &str = "high-level-signer-key";

// 使用HashMap存储密钥，以便通过key_id查找
struct KeyStore {
    private_keys: HashMap<String, Vec<u8>>,
    public_keys: HashMap<String, Vec<u8>>,
}

impl KeyStore {
    fn get_private_key(&self, key_id: &str) -> Option<AsymmetricPrivateKey> {
        self.private_keys
            .get(key_id)
            .map(|k| AsymmetricPrivateKey::new(k.clone()))
    }

    fn get_public_key(&self, key_id: &str) -> Option<SignaturePublicKey> {
        self.public_keys
            .get(key_id)
            .map(|k| SignaturePublicKey::new(k.clone()))
    }
}

#[tokio::main]
async fn main() -> seal_flow::error::Result<()> {
    // 1. Setup
    // 创建密钥对并将私钥存储在KeyStore中
    let (pk, sk) = Kem::generate_keypair()?;
    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();

    // 创建签名密钥对
    let (sig_pk, sig_sk) = Signer::generate_keypair()?;
    let sig_pk_bytes = sig_pk.to_bytes();
    let sig_sk_wrapped = AsymmetricPrivateKey::new(sig_sk.to_bytes());

    let mut private_keys = HashMap::new();
    private_keys.insert(KEK_ID.to_string(), sk_bytes.to_vec());

    let mut public_keys = HashMap::new();
    public_keys.insert(SIGNER_KEY_ID.to_string(), sig_pk_bytes.to_vec());

    let mut key_store = KeyStore {
        private_keys,
        public_keys,
    };

    let plaintext = b"This is a test message for hybrid interoperability.";

    // 每次需要时重新创建公钥包装
    let get_pk_wrapped = || AsymmetricPublicKey::new(pk_bytes.clone());

    // --- Mode 1: In-Memory (Ordinary) ---
    println!("--- Testing Mode: In-Memory (Ordinary) ---");
    let ciphertext1 = HybridSeal
        .encrypt::<Dek>(get_pk_wrapped(), KEK_ID.to_string())
        .with_algorithm::<Kem>()
        .to_vec(plaintext)?;
    let pending_decryptor1 = HybridSeal.decrypt().slice(&ciphertext1)?;
    let kek_id = pending_decryptor1.kek_id().unwrap();
    let sk_wrapped = key_store.get_private_key(kek_id).unwrap();
    let decrypted1 = pending_decryptor1.with_key(sk_wrapped)?;
    assert_eq!(plaintext, &decrypted1[..]);
    println!("In-Memory (Ordinary) roundtrip successful!");

    // --- Mode 2: In-Memory Parallel ---
    println!("\n--- Testing Mode: In-Memory Parallel ---");
    let ciphertext2 = HybridSeal
        .encrypt::<Dek>(get_pk_wrapped(), KEK_ID.to_string())
        .with_algorithm::<Kem>()
        .to_vec_parallel(plaintext)?;
    let pending_decryptor2 = HybridSeal.decrypt().slice_parallel(&ciphertext2)?;
    let kek_id = pending_decryptor2.kek_id().unwrap();
    let sk_wrapped = key_store.get_private_key(kek_id).unwrap();
    let decrypted2 = pending_decryptor2.with_key(sk_wrapped)?;
    assert_eq!(plaintext, &decrypted2[..]);
    println!("In-Memory Parallel roundtrip successful!");

    // --- Mode 3: Synchronous Streaming ---
    println!("\n--- Testing Mode: Synchronous Streaming ---");
    let mut ciphertext3 = Vec::new();
    let mut encryptor = HybridSeal
        .encrypt::<Dek>(get_pk_wrapped(), KEK_ID.to_string())
        .with_algorithm::<Kem>()
        .into_writer(&mut ciphertext3)?;
    encryptor.write_all(plaintext)?;
    encryptor.finish()?;

    let pending_decryptor3 = HybridSeal.decrypt().reader(Cursor::new(ciphertext3))?;
    println!(
        "Found KEK ID in stream: '{}'",
        pending_decryptor3.kek_id().unwrap()
    );
    let kek_id = pending_decryptor3.kek_id().unwrap();
    let sk_wrapped = key_store.get_private_key(kek_id).unwrap();
    let mut decryptor3 = pending_decryptor3.with_key(sk_wrapped)?;

    let mut decrypted3 = Vec::new();
    decryptor3.read_to_end(&mut decrypted3)?;
    assert_eq!(plaintext, &decrypted3[..]);
    println!("Synchronous Streaming roundtrip successful!");

    // --- Mode 4: Asynchronous Streaming ---
    println!("\n--- Testing Mode: Asynchronous Streaming ---");
    let mut ciphertext4 = Vec::new();
    let mut encryptor = HybridSeal
        .encrypt::<Dek>(get_pk_wrapped(), KEK_ID.to_string())
        .with_algorithm::<Kem>()
        .into_async_writer(&mut ciphertext4)
        .await?;
    encryptor.write_all(plaintext).await?;
    encryptor.shutdown().await?;

    let pending_decryptor4 = HybridSeal
        .decrypt()
        .async_reader(Cursor::new(&ciphertext4))
        .await?;
    println!(
        "Found KEK ID in async stream: '{}'",
        pending_decryptor4.kek_id().unwrap()
    );
    let kek_id = pending_decryptor4.kek_id().unwrap();
    let sk_wrapped = key_store.get_private_key(kek_id).unwrap();
    let mut decryptor4 = pending_decryptor4.with_key(sk_wrapped).await?;

    let mut decrypted4 = Vec::new();
    decryptor4.read_to_end(&mut decrypted4).await?;
    assert_eq!(plaintext, &decrypted4[..]);
    println!("Asynchronous Streaming roundtrip successful!");

    // --- Mode 5: Parallel Streaming ---
    println!("\n--- Testing Mode: Parallel Streaming ---");
    let mut ciphertext5 = Vec::new();
    HybridSeal
        .encrypt::<Dek>(get_pk_wrapped(), KEK_ID.to_string())
        .with_algorithm::<Kem>()
        .pipe_parallel(Cursor::new(plaintext), &mut ciphertext5)?;

    let mut decrypted5 = Vec::new();
    let pending_decryptor5 = HybridSeal
        .decrypt()
        .reader_parallel(Cursor::new(&ciphertext5))?;
    println!(
        "Found KEK ID in parallel stream: '{}'",
        pending_decryptor5.kek_id().unwrap()
    );
    let kek_id = pending_decryptor5.kek_id().unwrap();
    let sk_wrapped = key_store.get_private_key(kek_id).unwrap();
    pending_decryptor5.with_key_to_writer(sk_wrapped, &mut decrypted5)?;
    assert_eq!(plaintext, &decrypted5[..]);
    println!("Parallel Streaming roundtrip successful!");

    println!("\nAll high-level hybrid modes are interoperable and successful.");

    // --- Mode 6: In-Memory with AAD ---
    println!("\n--- Testing Mode: In-Memory with AAD ---");
    let aad = b"Authenticated but not encrypted hybrid data";
    let ciphertext6 = HybridSeal
        .encrypt::<Dek>(get_pk_wrapped(), KEK_ID.to_string())
        .with_aad(aad)
        .with_algorithm::<Kem>()
        .to_vec(plaintext)?;

    // Decrypt with correct AAD
    let pending_decryptor6 = HybridSeal.decrypt().slice(&ciphertext6)?;
    let kek_id = pending_decryptor6.kek_id().unwrap();
    let sk_wrapped = key_store.get_private_key(kek_id).unwrap();
    let decrypted6 = pending_decryptor6.with_aad(aad).with_key(sk_wrapped)?;
    assert_eq!(plaintext, &decrypted6[..]);
    println!("In-Memory with AAD roundtrip successful!");

    // Decrypt with wrong AAD should fail
    let pending_fail = HybridSeal.decrypt().slice(&ciphertext6)?;
    let kek_id = pending_fail.kek_id().unwrap();
    let sk_wrapped = key_store.get_private_key(kek_id).unwrap();
    let result_fail = pending_fail.with_aad(b"wrong aad").with_key(sk_wrapped);
    assert!(result_fail.is_err());
    println!("In-Memory with wrong AAD correctly failed!");

    // Decrypt with no AAD should also fail
    let pending_fail2 = HybridSeal.decrypt().slice(&ciphertext6)?;
    let kek_id = pending_fail2.kek_id().unwrap();
    let sk_wrapped = key_store.get_private_key(kek_id).unwrap();
    let result_fail2 = pending_fail2.with_key(sk_wrapped);
    assert!(result_fail2.is_err());
    println!("In-Memory with no AAD correctly failed!");

    // --- Mode 7: Signed Encryption ---
    println!("\n--- Testing Mode: Signed Encryption ---");
    let aad = b"AAD with signature";
    let ciphertext7 = HybridSeal
        .encrypt::<Dek>(get_pk_wrapped(), KEK_ID.to_string())
        .with_aad(aad)
        .with_signer::<Signer>(sig_sk_wrapped, SIGNER_KEY_ID.to_string())
        .with_algorithm::<Kem>()
        .to_vec(plaintext)?;

    // 解密 - 使用正确的签名验证密钥和AAD
    let pending_decryptor7 = HybridSeal.decrypt().slice(&ciphertext7)?;
    let verification_key = key_store.get_public_key(SIGNER_KEY_ID).unwrap();

    let kek_id = pending_decryptor7.kek_id().unwrap();
    let sk_wrapped = key_store.get_private_key(kek_id).unwrap();

    let decrypted7 = pending_decryptor7
        .with_aad(aad)
        .with_verification_key(verification_key)
        .with_key(sk_wrapped)?;

    assert_eq!(plaintext, &decrypted7[..]);
    println!("Signed encryption with AAD roundtrip successful!");

    // --- Mode 8: 从密码派生密钥保护 KEK ---
    println!("\n--- Testing Password Protection for KEK ---");

    // 1. 模拟从用户密码派生密钥保护材料
    let user_password = SecretBox::new(Box::from(b"complex-secure-password".as_slice()));
    let user_salt = b"kek-protection-salt";
    let pbkdf2_deriver = Pbkdf2Sha256::new(100_000);

    let kek_protection_key =
        SymmetricKey::derive_from_password(&user_password, &pbkdf2_deriver, user_salt, 32)?;

    println!("从用户密码成功派生 KEK 保护密钥");

    // 2. 使用派生的密钥生成对称加密密钥（在实际场景中，这可能用于加密 KEK）
    let hkdf_deriver = HkdfSha256::default();

    // 派生用于加密 KEK 的密钥
    let wrapping_key = kek_protection_key.derive_key(
        &hkdf_deriver,
        Some(b"kek-wrapping"),
        Some(b"encryption-context"),
        32,
    )?;

    // 派生用于认证的密钥
    let auth_key = kek_protection_key.derive_key(
        &hkdf_deriver,
        Some(b"kek-wrapping"),
        Some(b"authentication-context"),
        32,
    )?;

    println!("成功派生 KEK 保护子密钥:");
    println!("  - 包装密钥长度: {} 字节", wrapping_key.as_bytes().len());
    println!("  - 认证密钥长度: {} 字节", auth_key.as_bytes().len());

    // --- Mode 9: 使用派生密钥在多层加密系统中 ---
    println!("\n--- Testing Multi-Layer Encryption with Derived Keys ---");

    // 1. 模拟生成密钥派生材料
    let master_key = SymmetricKey::new(vec![0u8; 64]); // 模拟主密钥

    // 2. 从主密钥派生混合加密中的密钥加密密钥(KEK)和数据加密密钥(DEK)材料
    // 注意：在真实混合加密中，KEK 通常是非对称密钥对，这里只是演示派生过程
    let _kek_material = master_key.derive_key(
        &hkdf_deriver,
        Some(b"hybrid-keys"),
        Some(b"kek-material"),
        32,
    )?;

    let _dek_material = master_key.derive_key(
        &hkdf_deriver,
        Some(b"hybrid-keys"),
        Some(b"dek-material"),
        32,
    )?;

    // 3. 模拟派生/生成一个新的非对称密钥对用于此消息
    let derived_key_id = "derived-hybrid-key";
    let (derived_pk, derived_sk) = Kem::generate_keypair()?;
    let derived_pk_wrapped = AsymmetricPublicKey::new(derived_pk.to_bytes());
    key_store
        .private_keys
        .insert(derived_key_id.to_string(), derived_sk.to_bytes().to_vec());

    let sensitive_data = b"This message is protected by a derived DEK in hybrid encryption.";

    // 4. 使用派生的公钥加密
    let ciphertext9 = HybridSeal
        .encrypt::<Dek>(derived_pk_wrapped, derived_key_id.to_string())
        .with_aad(b"Protected with derived keys")
        .with_algorithm::<Kem>()
        .to_vec(sensitive_data)?;

    // 5. 解密
    let pending_decryptor9 = HybridSeal.decrypt().slice(&ciphertext9)?;
    let found_key_id = pending_decryptor9.kek_id().unwrap();
    println!("从密文中读取的派生混合密钥ID: '{}'", found_key_id);
    assert_eq!(found_key_id, derived_key_id);

    // 使用存储的派生私钥解密
    let sk_wrapped = key_store.get_private_key(found_key_id).unwrap();
    let decrypted9 = pending_decryptor9
        .with_aad(b"Protected with derived keys")
        .with_key(sk_wrapped)?;

    assert_eq!(sensitive_data, &decrypted9[..]);
    println!("在混合加密场景中使用派生密钥成功！");

    // --- Mode 10: 密钥轮换场景 ---
    println!("\n--- Testing Key Rotation Scenario ---");

    // 1. 模拟密钥轮换：派生新版本的密钥
    let rotation_master_key = SymmetricKey::new(vec![1u8; 32]); // 模拟主密钥

    // 2. 派生不同版本的密钥
    let key_v1_info = b"key-version-1";
    let key_v2_info = b"key-version-2";
    let rotation_salt = b"key-rotation-salt";

    let key_v1 = rotation_master_key.derive_key(
        &hkdf_deriver,
        Some(rotation_salt),
        Some(key_v1_info),
        32,
    )?;

    let key_v2 = rotation_master_key.derive_key(
        &hkdf_deriver,
        Some(rotation_salt),
        Some(key_v2_info),
        32,
    )?;

    println!("成功派生不同版本的密钥用于密钥轮换");
    println!("  - 密钥 V1 长度: {} 字节", key_v1.as_bytes().len());
    println!("  - 密钥 V2 长度: {} 字节", key_v2.as_bytes().len());

    // 比较两个派生的密钥是否不同
    assert_ne!(key_v1.as_bytes(), key_v2.as_bytes());
    println!("确认不同版本派生的密钥内容不同");

    // --- Mode 11: Hybrid Encryption with KDF (Kyber + HkdfSha256) ---
    println!("\n--- Testing Mode: Hybrid Encryption with KDF (Kyber + HkdfSha256) ---");

    type KemKdf = Kyber512;
    type DemKdf = Aes256Gcm;
    type KdfAlgo = HkdfSha256;

    // 1. Setup keys for the KDF scenario
    let kdf_key_id = "kyber-key-for-kdf";
    let (kdf_pk, kdf_sk) = KemKdf::generate_keypair()?;
    key_store
        .private_keys
        .insert(kdf_key_id.to_string(), kdf_sk.to_bytes().to_vec());
    let kdf_pk_wrapped = AsymmetricPublicKey::new(kdf_pk.to_bytes());
    let kdf_plaintext =
        b"This message is protected by a KEM/KDF hybrid scheme with Kyber and HkdfSha256.";

    // 2. Encrypt using with_kdf
    println!("Alice: Encrypting data with Kyber and deriving DEK with HkdfSha256.");
    let kdf_ciphertext = HybridSeal
        .encrypt::<DemKdf>(kdf_pk_wrapped, kdf_key_id.to_string())
        .with_kdf(
            KdfAlgo::default(),
            Some(b"kdf-salt"), // Using a salt is good practice
            Some(b"kdf-info"), // Contextual info
            <DemKdf as SymmetricCipher>::KEY_SIZE as u32,
        )
        .with_algorithm::<KemKdf>()
        .to_vec(kdf_plaintext)?;

    println!(
        "Ciphertext generated. Size: {} bytes.",
        kdf_ciphertext.len()
    );

    // 3. Decrypt
    println!("Bob: Decrypting data. The library will handle KDF internally.");
    let pending_decryptor_kdf = HybridSeal.decrypt().slice(&kdf_ciphertext)?;
    let found_kdf_key_id = pending_decryptor_kdf.kek_id().unwrap();
    assert_eq!(found_kdf_key_id, kdf_key_id);

    let kdf_sk_wrapped = key_store.get_private_key(found_kdf_key_id).unwrap();
    let kdf_decrypted = pending_decryptor_kdf.with_key(kdf_sk_wrapped)?;

    // 4. Verify
    assert_eq!(kdf_plaintext.as_ref(), kdf_decrypted.as_slice());
    println!("Successfully decrypted data using KDF-derived key.");
    println!("Kyber + HkdfSha256 + AES-256-GCM roundtrip successful!");

    Ok(())
}
