use seal_crypto::{prelude::*, schemes::asymmetric::traditional::rsa::Rsa2048};
use seal_crypto::{schemes::hash::Sha256, schemes::symmetric::aes_gcm::Aes256Gcm};
use seal_flow::prelude::*;
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Kem = Rsa2048<Sha256>;
type Dek = Aes256Gcm;
const KEK_ID: &str = "high-level-hybrid-key";

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Setup
    // In a real application, you would have a secure way to store and retrieve private keys.
    // Here, we use a HashMap to simulate a key store.
    let mut key_store = HashMap::new();
    let (pk, sk) = Kem::generate_keypair()?;
    key_store.insert(KEK_ID.to_string(), sk);

    let plaintext = b"This is a test message for hybrid interoperability.";
    let seal = HybridSeal::new();

    // --- Mode 1: In-Memory (Ordinary) ---
    println!("--- Testing Mode: In-Memory (Ordinary) ---");
    let ciphertext1 = seal
        .encrypt::<Kem, Dek>(&pk, KEK_ID.to_string())
        .to_vec(plaintext)?;
    let pending_decryptor1 = seal.decrypt().from_slice(&ciphertext1)?;
    let found_kek_id = pending_decryptor1.kek_id().unwrap();
    let decryption_key1 = key_store.get(found_kek_id).unwrap();
    let decrypted1 = pending_decryptor1.with_private_key::<Kem, Dek>(decryption_key1)?;
    assert_eq!(plaintext, &decrypted1[..]);
    println!("In-Memory (Ordinary) roundtrip successful!");

    // --- Mode 2: In-Memory Parallel ---
    println!("\n--- Testing Mode: In-Memory Parallel ---");
    let ciphertext2 = seal
        .encrypt::<Kem, Dek>(&pk, KEK_ID.to_string())
        .to_vec_parallel(plaintext)?;
    let pending_decryptor2 = seal.decrypt().from_slice_parallel(&ciphertext2)?;
    let found_kek_id = pending_decryptor2.kek_id().unwrap();
    let decryption_key2 = key_store.get(found_kek_id).unwrap();
    let decrypted2 = pending_decryptor2.with_private_key::<Kem, Dek>(decryption_key2)?;
    assert_eq!(plaintext, &decrypted2[..]);
    println!("In-Memory Parallel roundtrip successful!");

    // --- Mode 3: Synchronous Streaming ---
    println!("\n--- Testing Mode: Synchronous Streaming ---");
    let mut ciphertext3 = Vec::new();
    let mut encryptor = seal
        .encrypt::<Kem, Dek>(&pk, KEK_ID.to_string())
        .into_writer(&mut ciphertext3)?;
    encryptor.write_all(plaintext)?;
    encryptor.finish()?;

    let pending_decryptor3 = seal.decrypt().from_reader(Cursor::new(&ciphertext3))?;
    let found_kek_id = pending_decryptor3.kek_id().unwrap();
    println!("Found KEK ID in stream: '{}'", found_kek_id);
    let decryption_key3 = key_store.get(found_kek_id).unwrap();
    let mut decryptor3 = pending_decryptor3.with_private_key::<Kem, Dek>(decryption_key3)?;

    let mut decrypted3 = Vec::new();
    decryptor3.read_to_end(&mut decrypted3)?;
    assert_eq!(plaintext, &decrypted3[..]);
    println!("Synchronous Streaming roundtrip successful!");

    // --- Mode 4: Asynchronous Streaming ---
    println!("\n--- Testing Mode: Asynchronous Streaming ---");
    let mut ciphertext4 = Vec::new();
    let mut encryptor = seal
        .encrypt::<Kem, Dek>(&pk, KEK_ID.to_string())
        .into_async_writer(&mut ciphertext4)
        .await?;
    encryptor.write_all(plaintext).await?;
    encryptor.shutdown().await?;

    let pending_decryptor4 = seal
        .decrypt()
        .from_async_reader(Cursor::new(&ciphertext4))
        .await?;
    let found_kek_id_async = pending_decryptor4.kek_id().unwrap();
    println!("Found KEK ID in async stream: '{}'", found_kek_id_async);
    let decryption_key4 = key_store.get(found_kek_id_async).unwrap();
    let mut decryptor4 = pending_decryptor4
        .with_private_key::<Kem, Dek>(decryption_key4.clone())
        .await?;

    let mut decrypted4 = Vec::new();
    decryptor4.read_to_end(&mut decrypted4).await?;
    assert_eq!(plaintext, &decrypted4[..]);
    println!("Asynchronous Streaming roundtrip successful!");

    // --- Mode 5: Parallel Streaming ---
    println!("\n--- Testing Mode: Parallel Streaming ---");
    let mut ciphertext5 = Vec::new();
    seal.encrypt::<Kem, Dek>(&pk, KEK_ID.to_string())
        .pipe_parallel(Cursor::new(plaintext), &mut ciphertext5)?;

    let mut decrypted5 = Vec::new();
    let pending_decryptor5 = seal
        .decrypt()
        .from_reader_parallel(Cursor::new(&ciphertext5))?;
    let found_kek_id = pending_decryptor5.kek_id().unwrap();
    println!("Found KEK ID in parallel stream: '{}'", found_kek_id);
    let decryption_key5 = key_store.get(found_kek_id).unwrap();
    pending_decryptor5.with_private_key_to_writer::<Kem, Dek, _>(decryption_key5, &mut decrypted5)?;
    assert_eq!(plaintext, &decrypted5[..]);
    println!("Parallel Streaming roundtrip successful!");

    println!("\nAll high-level hybrid modes are interoperable and successful.");
    Ok(())
} 