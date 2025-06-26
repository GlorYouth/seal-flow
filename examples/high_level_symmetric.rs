use seal_crypto::prelude::*;
use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
use seal_flow::prelude::*;
use std::io::{Cursor, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type TheAlgorithm = Aes256Gcm;
const KEY_ID: &str = "high-level-symmetric-key";

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Setup
    let key = TheAlgorithm::generate_key()?;
    let plaintext = b"This is a test message for interoperability across different modes.";
    let seal = SymmetricSeal::new(&key);

    // --- Mode 1: In-Memory (Ordinary) ---
    println!("--- Testing Mode: In-Memory (Ordinary) ---");
    let ciphertext1 = seal
        .in_memory::<TheAlgorithm>()
        .encrypt(plaintext, KEY_ID.to_string())?;
    let decrypted1 = seal.in_memory::<TheAlgorithm>().decrypt(&ciphertext1)?;
    assert_eq!(plaintext, &decrypted1[..]);
    println!("In-Memory (Ordinary) roundtrip successful!");

    // --- Mode 2: In-Memory Parallel ---
    println!("\n--- Testing Mode: In-Memory Parallel ---");
    let ciphertext2 = seal
        .in_memory_parallel::<TheAlgorithm>()
        .encrypt(plaintext, KEY_ID.to_string())?;
    let decrypted2 = seal
        .in_memory_parallel::<TheAlgorithm>()
        .decrypt(&ciphertext2)?;
    assert_eq!(plaintext, &decrypted2[..]);
    println!("In-Memory Parallel roundtrip successful!");

    // --- Mode 3: Synchronous Streaming ---
    println!("\n--- Testing Mode: Synchronous Streaming ---");
    let mut ciphertext3 = Vec::new();
    let mut encryptor3 = seal
        .streaming::<TheAlgorithm>()
        .encryptor(&mut ciphertext3, KEY_ID.to_string())?;
    encryptor3.write_all(plaintext)?;
    encryptor3.finish()?;

    let mut decryptor3 = seal
        .streaming::<TheAlgorithm>()
        .decryptor(Cursor::new(&ciphertext3))?;
    let mut decrypted3 = Vec::new();
    decryptor3.read_to_end(&mut decrypted3)?;
    assert_eq!(plaintext, &decrypted3[..]);
    println!("Synchronous Streaming roundtrip successful!");

    // --- Mode 4: Asynchronous Streaming ---
    println!("\n--- Testing Mode: Asynchronous Streaming ---");
    let mut ciphertext4 = Vec::new();
    let mut encryptor4 = seal
        .asynchronous::<TheAlgorithm>()
        .encryptor(&mut ciphertext4, KEY_ID.to_string())
        .await?;
    encryptor4.write_all(plaintext).await?;
    encryptor4.shutdown().await?;

    let mut decryptor4 = seal
        .asynchronous::<TheAlgorithm>()
        .decryptor(Cursor::new(&ciphertext4))
        .await?;
    let mut decrypted4 = Vec::new();
    decryptor4.read_to_end(&mut decrypted4).await?;
    assert_eq!(plaintext, &decrypted4[..]);
    println!("Asynchronous Streaming roundtrip successful!");

    // --- Mode 5: Parallel Streaming ---
    println!("\n--- Testing Mode: Parallel Streaming ---");
    let mut ciphertext5 = Vec::new();
    seal.parallel_streaming::<TheAlgorithm>().encrypt(
        Cursor::new(plaintext),
        &mut ciphertext5,
        KEY_ID.to_string(),
    )?;

    let mut decrypted5 = Vec::new();
    seal.parallel_streaming::<TheAlgorithm>()
        .decrypt(Cursor::new(&ciphertext5), &mut decrypted5)?;
    assert_eq!(plaintext, &decrypted5[..]);
    println!("Parallel Streaming roundtrip successful!");

    println!("\nAll high-level symmetric modes are interoperable and successful.");
    Ok(())
} 