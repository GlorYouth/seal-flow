use seal_crypto::prelude::*;
use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
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

    Ok(())
}
