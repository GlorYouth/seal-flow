use seal_crypto::{prelude::*, schemes::asymmetric::traditional::rsa::Rsa2048};
use seal_crypto::{schemes::hash::Sha256, schemes::symmetric::aes_gcm::Aes256Gcm};
use seal_flow::prelude::*;
use seal_flow::seal::{peek_hybrid_kek_id, peek_hybrid_kek_id_async};
use std::io::{Cursor, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Kem = Rsa2048<Sha256>;
type Dek = Aes256Gcm;
const KEK_ID: &str = "high-level-hybrid-key";

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Setup
    let (pk, sk) = Kem::generate_keypair()?;
    let plaintext = b"This is a test message for hybrid interoperability.";
    let encrypt_seal = HybridSeal::<Kem>::new_encrypt(&pk);
    let decrypt_seal = HybridSeal::<Kem>::new_decrypt(&sk);

    // --- Mode 1: In-Memory (Ordinary) ---
    println!("--- Testing Mode: In-Memory (Ordinary) ---");
    let ciphertext1 = encrypt_seal
        .in_memory::<Dek>()
        .encrypt(plaintext, KEK_ID.to_string())?;
    let decrypted1 = decrypt_seal.in_memory::<Dek>().decrypt(&ciphertext1)?;
    assert_eq!(plaintext, &decrypted1[..]);
    println!("In-Memory (Ordinary) roundtrip successful!");

    // --- Mode 2: In-Memory Parallel ---
    println!("\n--- Testing Mode: In-Memory Parallel ---");
    let ciphertext2 = encrypt_seal
        .in_memory_parallel::<Dek>()
        .encrypt(plaintext, KEK_ID.to_string())?;
    let decrypted2 = decrypt_seal
        .in_memory_parallel::<Dek>()
        .decrypt(&ciphertext2)?;
    assert_eq!(plaintext, &decrypted2[..]);
    println!("In-Memory Parallel roundtrip successful!");

    // --- Mode 3: Synchronous Streaming ---
    println!("\n--- Testing Mode: Synchronous Streaming ---");
    let mut ciphertext3 = Vec::new();
    let mut encryptor3 = encrypt_seal
        .streaming::<Dek>()
        .encryptor(&mut ciphertext3, KEK_ID.to_string())?;
    encryptor3.write_all(plaintext)?;
    encryptor3.finish()?;

    let mut decryptor3 = decrypt_seal
        .streaming::<Dek>()
        .decryptor(Cursor::new(&ciphertext3))?;
    let mut decrypted3 = Vec::new();
    decryptor3.read_to_end(&mut decrypted3)?;
    assert_eq!(plaintext, &decrypted3[..]);
    println!("Synchronous Streaming roundtrip successful!");

    // --- Mode 4: Asynchronous Streaming ---
    println!("\n--- Testing Mode: Asynchronous Streaming ---");
    let mut ciphertext4 = Vec::new();
    let mut encryptor4 = encrypt_seal
        .asynchronous::<Dek>()
        .encryptor(&mut ciphertext4, KEK_ID.to_string())
        .await?;
    encryptor4.write_all(plaintext).await?;
    encryptor4.shutdown().await?;

    let mut decryptor4 = decrypt_seal
        .asynchronous::<Dek>()
        .decryptor(Cursor::new(&ciphertext4))
        .await?;
    let mut decrypted4 = Vec::new();
    decryptor4.read_to_end(&mut decrypted4).await?;
    assert_eq!(plaintext, &decrypted4[..]);
    println!("Asynchronous Streaming roundtrip successful!");

    // --- Mode 5: Parallel Streaming ---
    println!("\n--- Testing Mode: Parallel Streaming ---");
    let mut ciphertext5 = Vec::new();
    encrypt_seal.parallel_streaming::<Dek>().encrypt(
        Cursor::new(plaintext),
        &mut ciphertext5,
        KEK_ID.to_string(),
    )?;

    let mut decrypted5 = Vec::new();
    decrypt_seal
        .parallel_streaming::<Dek>()
        .decrypt(Cursor::new(&ciphertext5), &mut decrypted5)?;
    assert_eq!(plaintext, &decrypted5[..]);
    println!("Parallel Streaming roundtrip successful!");

    // --- Demonstrate Peeking ---
    println!("\n--- Testing KEK ID Peeking ---");
    // We use the ciphertext from the first mode for this demonstration.
    // Sync peeking
    let peeked_id_sync = peek_hybrid_kek_id(Cursor::new(&ciphertext1))?;
    assert_eq!(peeked_id_sync, KEK_ID);
    println!("Sync peeking successful: found KEK ID '{}'", peeked_id_sync);

    // Async peeking
    let peeked_id_async = peek_hybrid_kek_id_async(Cursor::new(&ciphertext1)).await?;
    assert_eq!(peeked_id_async, KEK_ID);
    println!(
        "Async peeking successful: found KEK ID '{}'",
        peeked_id_async
    );

    println!("\nAll high-level hybrid modes are interoperable and successful.");
    Ok(())
} 