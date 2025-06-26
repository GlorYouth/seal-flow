use seal_crypto::{prelude::*, schemes::asymmetric::traditional::rsa::Rsa2048};
use seal_crypto::{schemes::hash::Sha256, schemes::symmetric::aes_gcm::Aes256Gcm};
use seal_flow::error::Result;
use seal_flow::flows::hybrid::*;
use std::io::{Cursor, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Kem = Rsa2048<Sha256>;
type Dek = Aes256Gcm;
const KEK_ID: &str = "mid-level-hybrid-key";

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Setup
    let (pk, sk) = Kem::generate_keypair()?;
    let plaintext = b"This is a test message for the mid-level hybrid API.";

    // --- Mode 1: In-Memory (Ordinary) ---
    println!("--- Testing Mode: In-Memory (Ordinary) ---");
    let ciphertext1 = ordinary::encrypt::<Kem, Dek>(&pk, plaintext, KEK_ID.to_string())?;
    let decrypted1 = ordinary::decrypt::<Kem, Dek>(&sk, &ciphertext1)?;
    assert_eq!(plaintext, &decrypted1[..]);
    println!("In-Memory (Ordinary) roundtrip successful!");

    // --- Mode 2: In-Memory Parallel ---
    println!("\n--- Testing Mode: In-Memory Parallel ---");
    let ciphertext2 = parallel::encrypt::<Kem, Dek>(&pk, plaintext, KEK_ID.to_string())?;
    let decrypted2 = parallel::decrypt::<Kem, Dek>(&sk, &ciphertext2)?;
    assert_eq!(plaintext, &decrypted2[..]);
    println!("In-Memory Parallel roundtrip successful!");

    // --- Mode 3: Synchronous Streaming ---
    println!("\n--- Testing Mode: Synchronous Streaming ---");
    let mut ciphertext3 = Vec::new();
    let mut encryptor3 =
        streaming::Encryptor::<_, Kem, Dek>::new(&mut ciphertext3, &pk, KEK_ID.to_string())?;
    encryptor3.write_all(plaintext)?;
    encryptor3.finish()?;

    let mut decryptor3 =
        streaming::Decryptor::<_, Kem, Dek>::new(Cursor::new(&ciphertext3), &sk)?;
    let mut decrypted3 = Vec::new();
    decryptor3.read_to_end(&mut decrypted3)?;
    assert_eq!(plaintext, &decrypted3[..]);
    println!("Synchronous Streaming roundtrip successful!");

    // --- Mode 4: Asynchronous Streaming ---
    println!("\n--- Testing Mode: Asynchronous Streaming ---");
    let mut ciphertext4 = Vec::new();
    let mut encryptor4 =
        asynchronous::Encryptor::<_, Kem, Dek>::new(&mut ciphertext4, pk.clone(), KEK_ID.to_string())
            .await?;
    encryptor4.write_all(plaintext).await?;
    encryptor4.shutdown().await?;

    let mut decryptor4 =
        asynchronous::Decryptor::<_, Kem, Dek>::new(Cursor::new(&ciphertext4), sk.clone()).await?;
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
    )?;

    let mut decrypted5 = Vec::new();
    parallel_streaming::decrypt::<Kem, Dek, _, _>(&sk, Cursor::new(&ciphertext5), &mut decrypted5)?;
    assert_eq!(plaintext, &decrypted5[..]);
    println!("Parallel Streaming roundtrip successful!");

    println!("\nAll mid-level hybrid modes are interoperable and successful.");
    Ok(())
} 