use seal_crypto::prelude::*;
use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
use seal_flow::error::Result;
use seal_flow::flows::symmetric::*;
use std::io::{Cursor, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type TheAlgorithm = Aes256Gcm;
const KEY_ID: &str = "mid-level-symmetric-key";

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Setup
    let key = TheAlgorithm::generate_key()?;
    let plaintext = b"This is a test message for the mid-level API.";

    // --- Mode 1: In-Memory (Ordinary) ---
    println!("--- Testing Mode: In-Memory (Ordinary) ---");
    let ciphertext1 = ordinary::encrypt::<TheAlgorithm>(&key, plaintext, KEY_ID.to_string())?;
    let decrypted1 = ordinary::decrypt::<TheAlgorithm>(&key, &ciphertext1)?;
    assert_eq!(plaintext, &decrypted1[..]);
    println!("In-Memory (Ordinary) roundtrip successful!");

    // --- Mode 2: In-Memory Parallel ---
    println!("\n--- Testing Mode: In-Memory Parallel ---");
    let ciphertext2 = parallel::encrypt::<TheAlgorithm>(&key, plaintext, KEY_ID.to_string())?;
    let decrypted2 = parallel::decrypt::<TheAlgorithm>(&key, &ciphertext2)?;
    assert_eq!(plaintext, &decrypted2[..]);
    println!("In-Memory Parallel roundtrip successful!");

    // --- Mode 3: Synchronous Streaming ---
    println!("\n--- Testing Mode: Synchronous Streaming ---");
    let mut ciphertext3 = Vec::new();
    let mut encryptor3 =
        streaming::Encryptor::<_, TheAlgorithm>::new(&mut ciphertext3, key.clone(), KEY_ID.to_string())?;
    encryptor3.write_all(plaintext)?;
    encryptor3.finish()?;

    let mut decryptor3 = streaming::Decryptor::<_, TheAlgorithm>::new(Cursor::new(&ciphertext3), &key)?;
    let mut decrypted3 = Vec::new();
    decryptor3.read_to_end(&mut decrypted3)?;
    assert_eq!(plaintext, &decrypted3[..]);
    println!("Synchronous Streaming roundtrip successful!");

    // --- Mode 4: Asynchronous Streaming ---
    println!("\n--- Testing Mode: Asynchronous Streaming ---");
    let mut ciphertext4 = Vec::new();
    let mut encryptor4 = asynchronous::Encryptor::<_, TheAlgorithm>::new(
        &mut ciphertext4,
        key.clone(),
        KEY_ID.to_string(),
    )
    .await?;
    encryptor4.write_all(plaintext).await?;
    encryptor4.shutdown().await?;

    let mut decryptor4 =
        asynchronous::Decryptor::<_, TheAlgorithm>::new(Cursor::new(&ciphertext4), &key).await?;
    let mut decrypted4 = Vec::new();
    decryptor4.read_to_end(&mut decrypted4).await?;
    assert_eq!(plaintext, &decrypted4[..]);
    println!("Asynchronous Streaming roundtrip successful!");

    // --- Mode 5: Parallel Streaming ---
    println!("\n--- Testing Mode: Parallel Streaming ---");
    let mut ciphertext5 = Vec::new();
    parallel_streaming::encrypt::<TheAlgorithm, _, _>(
        &key,
        Cursor::new(plaintext),
        &mut ciphertext5,
        KEY_ID.to_string(),
    )?;

    let mut decrypted5 = Vec::new();
    parallel_streaming::decrypt::<TheAlgorithm, _, _>(&key, Cursor::new(&ciphertext5), &mut decrypted5)?;
    assert_eq!(plaintext, &decrypted5[..]);
    println!("Parallel Streaming roundtrip successful!");

    println!("\nAll mid-level symmetric modes are interoperable and successful.");
    Ok(())
} 