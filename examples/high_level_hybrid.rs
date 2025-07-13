use seal_flow::base::keys::{SymmetricKey, TypedAsymmetricPrivateKey, TypedSignaturePublicKey};
use seal_flow::prelude::*;
use seal_crypto::secrecy::SecretBox;
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const KEM: AsymmetricAlgorithmEnum = AsymmetricAlgorithmEnum::Rsa2048Sha256;
const DEM: SymmetricAlgorithmEnum = SymmetricAlgorithmEnum::Aes256Gcm;
const SIGNER: SignatureAlgorithmEnum = SignatureAlgorithmEnum::Dilithium2;

const KEK_ID: &str = "high-level-hybrid-key";
const SIGNER_KEY_ID: &str = "high-level-signer-key";

// 使用HashMap存储密钥，以便通过key_id查找
struct KeyStore {
    private_keys: HashMap<String, TypedAsymmetricPrivateKey>,
    public_keys: HashMap<String, TypedSignaturePublicKey>,
}

impl KeyStore {
    fn new() -> Self {
        Self {
            private_keys: HashMap::new(),
            public_keys: HashMap::new(),
        }
    }

    fn add_private_key(&mut self, key_id: String, key: TypedAsymmetricPrivateKey) {
        self.private_keys.insert(key_id, key);
    }

    fn add_public_key(&mut self, key_id: String, key: TypedSignaturePublicKey) {
        self.public_keys.insert(key_id, key);
    }

    fn get_private_key(&self, key_id: &str) -> Option<TypedAsymmetricPrivateKey> {
        self.private_keys.get(key_id).cloned()
    }

    fn get_public_key(&self, key_id: &str) -> Option<TypedSignaturePublicKey> {
        self.public_keys.get(key_id).cloned()
    }
}

#[tokio::main]
async fn main() -> seal_flow::error::Result<()> {
    // 1. Setup
    let seal = HybridSeal::default();

    // 创建密钥对并将私钥存储在KeyStore中
    let (pk, sk) = KEM
        .into_asymmetric_wrapper()
        .generate_keypair()?
        .into_keypair();

    // 创建签名密钥对
    let (sig_pk, sig_sk) = SIGNER
        .into_signature_wrapper()
        .generate_keypair()?
        .into_keypair();

    let mut key_store = KeyStore::new();
    key_store.add_private_key(KEK_ID.to_string(), sk);
    key_store.add_public_key(SIGNER_KEY_ID.to_string(), sig_pk);

    let plaintext = b"This is a test message for hybrid interoperability.";
    let pk_typed = pk;

    // --- Mode 1: In-Memory (Ordinary) ---
    println!("--- Testing Mode: In-Memory (Ordinary) ---");
    let ciphertext1 = seal
        .encrypt(pk_typed.clone(), KEK_ID.to_string())
        .execute_with(DEM)
        .to_vec(plaintext)?;
    let pending_decryptor1 = seal.decrypt().slice(&ciphertext1)?;
    let kek_id = pending_decryptor1.kek_id().unwrap();
    let sk_wrapped = key_store.get_private_key(kek_id).unwrap();
    let decrypted1 = pending_decryptor1.with_key_to_vec(&sk_wrapped)?;
    assert_eq!(plaintext, &decrypted1[..]);
    println!("In-Memory (Ordinary) roundtrip successful!");

    // --- Mode 2: In-Memory Parallel ---
    println!("\n--- Testing Mode: In-Memory Parallel ---");
    let ciphertext2 = seal
        .encrypt(pk_typed.clone(), KEK_ID.to_string())
        .execute_with(DEM)
        .to_vec_parallel(plaintext)?;
    let pending_decryptor2 = seal.decrypt().slice_parallel(&ciphertext2)?;
    let kek_id = pending_decryptor2.kek_id().unwrap();
    let sk_wrapped = key_store.get_private_key(kek_id).unwrap();
    let decrypted2 = pending_decryptor2.with_key_to_vec(&sk_wrapped)?;
    assert_eq!(plaintext, &decrypted2[..]);
    println!("In-Memory Parallel roundtrip successful!");

    // --- Mode 3: Synchronous Streaming ---
    println!("\n--- Testing Mode: Synchronous Streaming ---");
    let mut ciphertext3 = Vec::new();
    let mut encryptor = seal
        .encrypt(pk_typed.clone(), KEK_ID.to_string())
        .execute_with(DEM)
        .into_writer(&mut ciphertext3)?;
    encryptor.write_all(plaintext)?;
    encryptor.finish()?; // Dropping the writer finalizes encryption

    let pending_decryptor3 = seal.decrypt().reader(Cursor::new(ciphertext3))?;
    println!(
        "Found KEK ID in stream: '{}'",
        pending_decryptor3.kek_id().unwrap()
    );
    let kek_id = pending_decryptor3.kek_id().unwrap();
    let sk_wrapped = key_store.get_private_key(kek_id).unwrap();
    let mut decryptor3 = pending_decryptor3.with_key_to_reader(&sk_wrapped)?;

    let mut decrypted3 = Vec::new();
    decryptor3.read_to_end(&mut decrypted3)?;
    assert_eq!(plaintext, &decrypted3[..]);
    println!("Synchronous Streaming roundtrip successful!");

    // --- Mode 4: Asynchronous Streaming ---
    println!("\n--- Testing Mode: Asynchronous Streaming ---");
    let mut ciphertext4 = Vec::new();
    {
        let mut encryptor = seal
            .encrypt(pk_typed.clone(), KEK_ID.to_string())
            .execute_with(DEM)
            .into_async_writer(&mut ciphertext4)
            .await?;
        encryptor.write_all(plaintext).await?;
        encryptor.shutdown().await?;
    }

    let pending_decryptor4 = seal
        .decrypt()
        .async_reader(Cursor::new(&ciphertext4))
        .await?;
    println!(
        "Found KEK ID in async stream: '{}'",
        pending_decryptor4.kek_id().unwrap()
    );
    let kek_id = pending_decryptor4.kek_id().unwrap();
    let sk_wrapped = key_store.get_private_key(kek_id).unwrap();
    let mut decryptor4 = pending_decryptor4
        .with_key_to_reader(&sk_wrapped)
        .await?;

    let mut decrypted4 = Vec::new();
    decryptor4.read_to_end(&mut decrypted4).await?;
    assert_eq!(plaintext, &decrypted4[..]);
    println!("Asynchronous Streaming roundtrip successful!");

    // --- Mode 5: Parallel Streaming ---
    println!("\n--- Testing Mode: Parallel Streaming ---");
    let mut ciphertext5 = Vec::new();
    seal.encrypt(pk_typed.clone(), KEK_ID.to_string())
        .execute_with(DEM)
        .pipe_parallel(Cursor::new(plaintext), &mut ciphertext5)?;

    let mut decrypted5 = Vec::new();
    let pending_decryptor5 = seal
        .decrypt()
        .reader_parallel(Cursor::new(&ciphertext5))?;
    println!(
        "Found KEK ID in parallel stream: '{}'",
        pending_decryptor5.kek_id().unwrap()
    );
    let kek_id = pending_decryptor5.kek_id().unwrap();
    let sk_wrapped = key_store.get_private_key(kek_id).unwrap();
    pending_decryptor5.with_key_to_writer(&sk_wrapped, &mut decrypted5)?;
    assert_eq!(plaintext, &decrypted5[..]);
    println!("Parallel Streaming roundtrip successful!");

    println!("\nAll high-level hybrid modes are interoperable and successful.");

    // --- Mode 6: In-Memory with AAD ---
    println!("\n--- Testing Mode: In-Memory with AAD ---");
    let aad = b"Authenticated but not encrypted hybrid data";
    let ciphertext6 = seal
        .encrypt(pk_typed.clone(), KEK_ID.to_string())
        .with_aad(aad)
        .execute_with(DEM)
        .to_vec(plaintext)?;

    // Decrypt with correct AAD
    let pending_decryptor6 = seal.decrypt().slice(&ciphertext6)?;
    let kek_id = pending_decryptor6.kek_id().unwrap();
    let sk_wrapped = key_store.get_private_key(kek_id).unwrap();
    let decrypted6 = pending_decryptor6
        .with_aad(aad)
        .with_key_to_vec(&sk_wrapped)?;
    assert_eq!(plaintext, &decrypted6[..]);
    println!("In-Memory with AAD roundtrip successful!");

    // Decrypt with wrong AAD should fail
    let pending_fail = seal.decrypt().slice(&ciphertext6)?;
    let kek_id = pending_fail.kek_id().unwrap();
    let sk_wrapped = key_store.get_private_key(kek_id).unwrap();
    let result_fail = pending_fail.with_aad(b"wrong aad").with_key_to_vec(&sk_wrapped);
    assert!(result_fail.is_err());
    println!("In-Memory with wrong AAD correctly failed!");

    // Decrypt with no AAD should also fail
    let pending_fail2 = seal.decrypt().slice(&ciphertext6)?;
    let kek_id = pending_fail2.kek_id().unwrap();
    let sk_wrapped = key_store.get_private_key(kek_id).unwrap();
    let result_fail2 = pending_fail2.with_key_to_vec(&sk_wrapped);
    assert!(result_fail2.is_err());
    println!("In-Memory with no AAD correctly failed!");

    // --- Mode 7: Signed Encryption ---
    println!("\n--- Testing Mode: Signed Encryption ---");
    let aad = b"AAD with signature";
    let ciphertext7 = seal
        .encrypt(pk_typed.clone(), KEK_ID.to_string())
        .with_aad(aad)
        .with_signer(sig_sk, SIGNER_KEY_ID.to_string())?
        .execute_with(DEM)
        .to_vec(plaintext)?;

    // 解密 - 使用正确的签名验证密钥和AAD
    let pending_decryptor7 = seal.decrypt().slice(&ciphertext7)?;
    let verification_key_from_store = key_store.get_public_key(SIGNER_KEY_ID).unwrap();

    let kek_id = pending_decryptor7.kek_id().unwrap();
    let sk_wrapped = key_store.get_private_key(kek_id).unwrap();

    let decrypted7 = pending_decryptor7
        .with_aad(aad)
        .with_verification_key(verification_key_from_store)
        .with_key_to_vec(&sk_wrapped)?;

    assert_eq!(plaintext, &decrypted7[..]);
    println!("Signed encryption with AAD roundtrip successful!");

    // --- Mode 8: 从密码派生密钥保护私钥（本地存储） ---
    println!("\n--- Testing Password Protection for Private Key (At-Rest) ---");
    
    // 1. 模拟从用户密码派生密钥，用于加密存储在本地的私钥
    let user_password = SecretBox::new(Box::from(b"complex-secure-password".as_slice()));
    let user_salt = b"kek-protection-salt";
    let pbkdf2_deriver = KdfPasswordAlgorithmEnum::Pbkdf2Sha256;

    let kek_protection_key_untyped = SymmetricKey::derive_from_password(
        &user_password,
        pbkdf2_deriver.into_kdf_password_wrapper(),
        user_salt,
        32,
    )?;
    let kek_protection_key = kek_protection_key_untyped.into_typed(DEM)?;
    println!("从用户密码成功派生用于本地私钥加密的对称密钥");
    
    // 2. 在实际应用中，可以使用此 `kek_protection_key` 和 `SymmetricSeal`
    // 来加密 KEM 的私钥 `sk`，然后将其存储在磁盘上。
    // 这里我们只演示派生过程。
    let symmetric_seal = SymmetricSeal::default();
    let private_key_bytes = key_store.get_private_key(KEK_ID).unwrap().to_bytes();
    let encrypted_sk = symmetric_seal
        .encrypt(kek_protection_key, "password-derived-wrapper".to_string())
        .to_vec(&private_key_bytes)?;
        
    println!("成功使用派生密钥加密了 KEM 私钥 ({} 字节 -> {} 字节)", private_key_bytes.len(), encrypted_sk.len());


    // --- Mode 9: 使用派生密钥在多层加密系统中 ---
    println!("\n--- Testing Multi-Layer Encryption with Derived Keys ---");

    // 1. 模拟生成密钥派生材料
    let master_key = SymmetricKey::new(vec![0u8; 64]); // 模拟主密钥
    let kdf_deriver = KdfKeyAlgorithmEnum::HkdfSha256;

    // 2. 从主密钥派生用于新消息的非对称密钥对的“种子”
    // 注意：在实际应用中，可以直接派生对称密钥，或使用派生材料生成非对称密钥。
    // 这里为了演示，我们模拟派生信息然后生成一个全新的密钥对。
    let derived_key_id = "derived-hybrid-key";
    let _key_seed_v1 =
        master_key.derive_key(kdf_deriver, Some(b"hybrid-keys"), Some(b"key-seed-v1"), 32)?;
    
    // 3. 基于派生信息生成一个新的非对称密钥对
    let (derived_pk, derived_sk) = KEM
        .into_asymmetric_wrapper()
        .generate_keypair()?
        .into_keypair();
    key_store.add_private_key(derived_key_id.to_string(), derived_sk);

    let sensitive_data = b"This message is protected by a derived DEK in hybrid encryption.";

    // 4. 使用派生的公钥加密
    let ciphertext9 = seal
        .encrypt(derived_pk, derived_key_id.to_string())
        .with_aad(b"Protected with derived keys")
        .execute_with(DEM)
        .to_vec(sensitive_data)?;

    // 5. 解密
    let pending_decryptor9 = seal.decrypt().slice(&ciphertext9)?;
    let found_key_id = pending_decryptor9.kek_id().unwrap();
    println!("从密文中读取的派生混合密钥ID: '{}'", found_key_id);
    assert_eq!(found_key_id, derived_key_id);

    // 使用存储的派生私钥解密
    let sk_wrapped = key_store.get_private_key(found_key_id).unwrap();
    let decrypted9 = pending_decryptor9
        .with_aad(b"Protected with derived keys")
        .with_key_to_vec(&sk_wrapped)?;

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
        kdf_deriver,
        Some(rotation_salt),
        Some(key_v1_info),
        32,
    )?;

    let key_v2 = rotation_master_key.derive_key(
        kdf_deriver,
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

    let kem_kdf = AsymmetricAlgorithmEnum::Kyber768;
    let dem_kdf = SymmetricAlgorithmEnum::Aes256Gcm;
    let kdf_algo = KdfKeyAlgorithmEnum::HkdfSha256;

    // 1. Setup keys for the KDF scenario
    let kdf_key_id = "kyber-key-for-kdf";
    let (kdf_pk, kdf_sk) = kem_kdf
        .into_asymmetric_wrapper()
        .generate_keypair()?
        .into_keypair();
    key_store.add_private_key(kdf_key_id.to_string(), kdf_sk.clone());
    let kdf_plaintext =
        b"This message is protected by a KEM/KDF hybrid scheme with Kyber and HkdfSha256.";

    // 2. Encrypt using with_kdf
    println!("Alice: Encrypting data with Kyber and deriving DEK with HkdfSha256.");
    let kdf_ciphertext = seal
        .encrypt(kdf_pk, kdf_key_id.to_string())
        .with_kdf(
            kdf_algo,
            Some(b"kdf-salt"), // Using a salt is good practice
            Some(b"kdf-info"), // Contextual info
        )
        .execute_with(dem_kdf)
        .to_vec(kdf_plaintext)?;

    println!(
        "Ciphertext generated. Size: {} bytes.",
        kdf_ciphertext.len()
    );

    // 3. Decrypt
    println!("Bob: Decrypting data. The library will handle KDF internally.");
    let pending_decryptor_kdf = seal.decrypt().slice(&kdf_ciphertext)?;
    let found_kdf_key_id = pending_decryptor_kdf.kek_id().unwrap();
    assert_eq!(found_kdf_key_id, kdf_key_id);

    let kdf_sk_wrapped = key_store.get_private_key(found_kdf_key_id).unwrap();
    let kdf_decrypted = pending_decryptor_kdf.with_key_to_vec(&kdf_sk_wrapped)?;

    // 4. Verify
    assert_eq!(kdf_plaintext.as_ref(), kdf_decrypted.as_slice());
    println!("Successfully decrypted data using KDF-derived key.");
    println!("Kyber + HkdfSha256 + AES-256-GCM roundtrip successful!");

    Ok(())
}
