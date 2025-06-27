use seal_crypto::prelude::*;
use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
use seal_flow::prelude::*;
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type TheAlgorithm = Aes256Gcm;
const KEY_ID: &str = "high-level-symmetric-key";

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Setup
    // In a real application, you would have a secure way to store and retrieve keys.
    // Here, we use a HashMap to simulate a key store.
    let mut key_store = HashMap::new();
    let key = TheAlgorithm::generate_key()?;
    key_store.insert(KEY_ID.to_string(), key);

    let plaintext = b"This is a test message for interoperability across different modes.";
    let seal = SymmetricSeal::new();

    // --- Mode 1: In-Memory (Ordinary) ---
    println!("--- Testing Mode: In-Memory (Ordinary) ---");
    let ciphertext1 = seal
        .in_memory::<TheAlgorithm>()
        .encrypt(key_store.get(KEY_ID).unwrap(), plaintext, KEY_ID.to_string())?;
    let pending_decryptor1 = seal.in_memory::<TheAlgorithm>().decrypt(&ciphertext1)?;
    let found_key_id = pending_decryptor1.key_id().unwrap();
    let decryption_key = key_store.get(found_key_id).unwrap();
    let decrypted1 = pending_decryptor1.with_key::<TheAlgorithm>(decryption_key)?;
    assert_eq!(plaintext, &decrypted1[..]);
    println!("In-Memory (Ordinary) roundtrip successful!");

    // --- Mode 2: In-Memory Parallel ---
    println!("\n--- Testing Mode: In-Memory Parallel ---");
    let ciphertext2 = seal
        .in_memory_parallel::<TheAlgorithm>()
        .encrypt(key_store.get(KEY_ID).unwrap(), plaintext, KEY_ID.to_string())?;
    let pending_decryptor2 = seal
        .in_memory_parallel::<TheAlgorithm>()
        .decrypt(&ciphertext2)?;
    let found_key_id = pending_decryptor2.key_id().unwrap();
    let decryption_key = key_store.get(found_key_id).unwrap();
    let decrypted2 = pending_decryptor2.with_key::<TheAlgorithm>(decryption_key)?;
    assert_eq!(plaintext, &decrypted2[..]);
    println!("In-Memory Parallel roundtrip successful!");

    // --- Mode 3: Synchronous Streaming ---
    println!("\n--- Testing Mode: Synchronous Streaming ---");
    let mut ciphertext3 = Vec::new();
    let mut encryptor3 = seal.streaming_encryptor::<TheAlgorithm, _>(
        &mut ciphertext3,
        key_store.get(KEY_ID).unwrap(),
        KEY_ID.to_string(),
    )?;
    encryptor3.write_all(plaintext)?;
    encryptor3.finish()?;

    let pending_decryptor3 =
        seal.streaming_decryptor_from_reader(Cursor::new(&ciphertext3))?;
    let found_key_id = pending_decryptor3.key_id().unwrap();
    println!("Found key ID in stream: '{}'", found_key_id);
    let decryption_key = key_store.get(found_key_id).unwrap();
    let mut decryptor3 = pending_decryptor3.with_key::<TheAlgorithm>(decryption_key)?;

    let mut decrypted3 = Vec::new();
    decryptor3.read_to_end(&mut decrypted3)?;
    assert_eq!(plaintext, &decrypted3[..]);
    println!("Synchronous Streaming roundtrip successful!");

    // --- Mode 4: Asynchronous Streaming ---
    println!("\n--- Testing Mode: Asynchronous Streaming ---");
    let mut ciphertext4 = Vec::new();
    let mut encryptor4 = seal
        .asynchronous_encryptor::<TheAlgorithm, _>(
            &mut ciphertext4,
            key_store.get(KEY_ID).unwrap(),
            KEY_ID.to_string(),
        )
        .await?;
    encryptor4.write_all(plaintext).await?;
    encryptor4.shutdown().await?;

    let pending_decryptor4 = seal
        .asynchronous_decryptor_from_reader(Cursor::new(&ciphertext4))
        .await?;
    let found_key_id_async = pending_decryptor4.key_id().unwrap();
    println!("Found key ID in async stream: '{}'", found_key_id_async);
    let decryption_key_async = key_store.get(found_key_id_async).unwrap();
    let mut decryptor4 = pending_decryptor4.with_key::<TheAlgorithm>(decryption_key_async)?;

    let mut decrypted4 = Vec::new();
    decryptor4.read_to_end(&mut decrypted4).await?;
    assert_eq!(plaintext, &decrypted4[..]);
    println!("Asynchronous Streaming roundtrip successful!");

    // --- Mode 5: Parallel Streaming ---
    println!("\n--- Testing Mode: Parallel Streaming ---");
    let mut ciphertext5 = Vec::new();
    seal.parallel_streaming::<TheAlgorithm>().encrypt(
        key_store.get(KEY_ID).unwrap(),
        Cursor::new(plaintext),
        &mut ciphertext5,
        KEY_ID.to_string(),
    )?;

    let mut decrypted5 = Vec::new();
    let pending_decryptor5 = seal
        .parallel_streaming::<TheAlgorithm>()
        .decrypt(Cursor::new(&ciphertext5))?;
    let found_key_id = pending_decryptor5.key_id().unwrap();
    println!("Found key ID in parallel stream: '{}'", found_key_id);
    let decryption_key = key_store.get(found_key_id).unwrap();
    pending_decryptor5.with_key_to_writer::<TheAlgorithm, _>(decryption_key, &mut decrypted5)?;
    assert_eq!(plaintext, &decrypted5[..]);
    println!("Parallel Streaming roundtrip successful!");

    println!("\nAll high-level symmetric modes are interoperable and successful.");
    Ok(())
} 