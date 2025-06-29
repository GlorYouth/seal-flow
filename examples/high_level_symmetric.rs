use seal_crypto::prelude::*;
use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
use seal_flow::prelude::*;
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type TheAlgorithm = Aes256Gcm;
const KEY_ID: &str = "high-level-symmetric-key";

// 1. Define a struct to act as our key provider.
// In a real application, this might connect to a KMS, a database, or a config file.
struct MyKeyProvider {
    // For this example, we'll just use a HashMap.
    keys: HashMap<String, <TheAlgorithm as SymmetricKeySet>::Key>,
}

impl SymmetricKeyProvider for MyKeyProvider {
    fn get_symmetric_key(&self, key_id: &str) -> Option<SymmetricKey> {
        // Find the key and wrap it in the `SymmetricKey` enum.
        self.keys
            .get(key_id)
            .map(|k| SymmetricKey::Aes256Gcm(k.clone()))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Setup
    // Create a key and store it in our provider.
    let key = TheAlgorithm::generate_key()?;
    let mut keys = HashMap::new();
    keys.insert(KEY_ID.to_string(), key);
    let provider = MyKeyProvider { keys };

    let plaintext = b"This is a test message for interoperability across different modes.";
    let seal = SymmetricSeal::new();

    // In a real app, the encryptor and decryptor might be in different processes.
    // The encryptor only needs the key, while the decryptor can use the provider.
    let encryption_key = provider.keys.get(KEY_ID).unwrap();

    // --- Mode 1: In-Memory (Ordinary) ---
    println!("--- Testing Mode: In-Memory (Ordinary) ---");
    let ciphertext1 = seal
        .encrypt::<TheAlgorithm>(encryption_key, KEY_ID.to_string())
        .to_vec(plaintext)?;
    let pending_decryptor1 = seal.decrypt().slice(&ciphertext1)?;
    let decrypted1 = pending_decryptor1.with_provider(&provider)?;
    assert_eq!(plaintext, &decrypted1[..]);
    println!("In-Memory (Ordinary) roundtrip successful!");

    // --- Mode 2: In-Memory Parallel ---
    println!("\n--- Testing Mode: In-Memory Parallel ---");
    let ciphertext2 = seal
        .encrypt::<TheAlgorithm>(encryption_key, KEY_ID.to_string())
        .to_vec_parallel(plaintext)?;
    let pending_decryptor2 = seal.decrypt().slice_parallel(&ciphertext2)?;
    let decrypted2 = pending_decryptor2.with_provider(&provider)?;
    assert_eq!(plaintext, &decrypted2[..]);
    println!("In-Memory Parallel roundtrip successful!");

    // --- Mode 3: Synchronous Streaming ---
    println!("\n--- Testing Mode: Synchronous Streaming ---");
    let mut ciphertext3 = Vec::new();
    let mut encryptor3 = seal
        .encrypt::<TheAlgorithm>(encryption_key, KEY_ID.to_string())
        .into_writer(&mut ciphertext3)?;
    encryptor3.write_all(plaintext)?;
    encryptor3.finish()?;

    let pending_decryptor3 = seal.decrypt().reader(Cursor::new(&ciphertext3))?;
    println!(
        "Found key ID in stream: '{}'",
        pending_decryptor3.key_id().unwrap()
    );
    let mut decryptor3 = pending_decryptor3.with_provider(&provider)?;

    let mut decrypted3 = Vec::new();
    decryptor3.read_to_end(&mut decrypted3)?;
    assert_eq!(plaintext, &decrypted3[..]);
    println!("Synchronous Streaming roundtrip successful!");

    // --- Mode 4: Asynchronous Streaming ---
    println!("\n--- Testing Mode: Asynchronous Streaming ---");
    let mut ciphertext4 = Vec::new();
    let mut encryptor4 = seal
        .encrypt::<TheAlgorithm>(encryption_key, KEY_ID.to_string())
        .into_async_writer(&mut ciphertext4)
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
    let mut decryptor4 = pending_decryptor4.with_provider(&provider)?;

    let mut decrypted4 = Vec::new();
    decryptor4.read_to_end(&mut decrypted4).await?;
    assert_eq!(plaintext, &decrypted4[..]);
    println!("Asynchronous Streaming roundtrip successful!");

    // --- Mode 5: Parallel Streaming ---
    println!("\n--- Testing Mode: Parallel Streaming ---");
    let mut ciphertext5 = Vec::new();
    seal.encrypt::<TheAlgorithm>(encryption_key, KEY_ID.to_string())
        .pipe_parallel(Cursor::new(plaintext), &mut ciphertext5)?;

    let mut decrypted5 = Vec::new();
    let pending_decryptor5 = seal.decrypt().reader_parallel(Cursor::new(&ciphertext5))?;
    println!(
        "Found key ID in parallel stream: '{}'",
        pending_decryptor5.key_id().unwrap()
    );
    pending_decryptor5.with_provider(&provider, &mut decrypted5)?;
    assert_eq!(plaintext, &decrypted5[..]);
    println!("Parallel Streaming roundtrip successful!");

    println!("\nAll high-level symmetric modes are interoperable and successful.");

    // --- Mode 6: In-Memory with AAD ---
    println!("\n--- Testing Mode: In-Memory with AAD ---");
    let aad = b"Authenticated but not encrypted data";
    let ciphertext6 = seal
        .encrypt::<TheAlgorithm>(encryption_key, KEY_ID.to_string())
        .with_aad(aad)
        .to_vec(plaintext)?;

    // Decrypt with correct AAD
    let pending_decryptor6 = seal.decrypt().slice(&ciphertext6)?;
    let decrypted6 = pending_decryptor6.with_aad(aad).with_provider(&provider)?;
    assert_eq!(plaintext, &decrypted6[..]);
    println!("In-Memory with AAD roundtrip successful!");

    // Decrypt with wrong AAD should fail
    let pending_fail = seal.decrypt().slice(&ciphertext6)?;
    let result_fail = pending_fail.with_aad(b"wrong aad").with_provider(&provider);
    assert!(result_fail.is_err());
    println!("In-Memory with wrong AAD correctly failed!");

    // Decrypt with no AAD should also fail
    let pending_fail2 = seal.decrypt().slice(&ciphertext6)?;
    let result_fail2 = pending_fail2.with_provider(&provider);
    assert!(result_fail2.is_err());
    println!("In-Memory with no AAD correctly failed!");

    Ok(())
}
