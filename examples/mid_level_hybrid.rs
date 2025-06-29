use seal_crypto::{prelude::*, schemes::asymmetric::traditional::rsa::Rsa2048};
use seal_crypto::{schemes::hash::Sha256, schemes::symmetric::aes_gcm::Aes256Gcm};
use seal_flow::common::header::Header;
use seal_flow::error::Result;
use seal_flow::flows::hybrid::*;
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Kem = Rsa2048<Sha256>;
type Dek = Aes256Gcm;
const KEK_ID: &str = "mid-level-hybrid-key";

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Setup
    let mut key_store = HashMap::new();
    let (pk, sk) = Kem::generate_keypair()?;
    key_store.insert(KEK_ID.to_string(), sk);

    let plaintext = b"This is a test message for the mid-level hybrid API.";

    // --- Mode 1: In-Memory (Ordinary) ---
    println!("--- Testing Mode: In-Memory (Ordinary) ---");
    let ciphertext1 = ordinary::encrypt::<Kem, Dek>(&pk, plaintext, KEK_ID.to_string(), None, None)?;

    let (header1, body1) = Header::decode_from_prefixed_slice(&ciphertext1)?;
    let found_kek_id1 = header1.payload.kek_id().unwrap();
    println!("Found KEK ID in header: '{}'", found_kek_id1);
    let decryption_key1 = key_store.get(found_kek_id1).unwrap();
    let decrypted1 = ordinary::decrypt_body::<Kem, Dek>(decryption_key1, &header1, body1, None)?;

    assert_eq!(plaintext, &decrypted1[..]);
    println!("In-Memory (Ordinary) roundtrip successful!");

    // --- Mode 2: In-Memory Parallel ---
    println!("\n--- Testing Mode: In-Memory Parallel ---");
    let ciphertext2 = parallel::encrypt::<Kem, Dek>(&pk, plaintext, KEK_ID.to_string(), None, None)?;

    let (header2, body2) = Header::decode_from_prefixed_slice(&ciphertext2)?;
    let found_kek_id2 = header2.payload.kek_id().unwrap();
    println!("Found KEK ID in parallel header: '{}'", found_kek_id2);
    let decryption_key2 = key_store.get(found_kek_id2).unwrap();
    let decrypted2 = parallel::decrypt_body::<Kem, Dek>(decryption_key2, &header2, body2, None)?;

    assert_eq!(plaintext, &decrypted2[..]);
    println!("In-Memory Parallel roundtrip successful!");

    // --- Mode 3: Synchronous Streaming ---
    println!("\n--- Testing Mode: Synchronous Streaming ---");
    let mut ciphertext3 = Vec::new();
    let mut encryptor3 =
        streaming::Encryptor::<_, Kem, Dek>::new(&mut ciphertext3, &pk, KEK_ID.to_string(), None, None)?;
    encryptor3.write_all(plaintext)?;
    encryptor3.finish()?;

    let pending_decryptor3 = streaming::PendingDecryptor::from_reader(Cursor::new(&ciphertext3))?;
    let found_kek_id3 = pending_decryptor3.header().payload.kek_id().unwrap();
    println!("Found KEK ID in stream: '{}'", found_kek_id3);
    let decryption_key3 = key_store.get(found_kek_id3).unwrap();
    let mut decryptor3 = pending_decryptor3.into_decryptor::<Kem, Dek>(decryption_key3, None)?;

    let mut decrypted3 = Vec::new();
    decryptor3.read_to_end(&mut decrypted3)?;
    assert_eq!(plaintext, &decrypted3[..]);
    println!("Synchronous Streaming roundtrip successful!");

    // --- Mode 4: Asynchronous Streaming ---
    println!("\n--- Testing Mode: Asynchronous Streaming ---");
    let mut ciphertext4 = Vec::new();
    let mut encryptor4 = asynchronous::Encryptor::<_, Kem, Dek>::new(
        &mut ciphertext4,
        pk.clone(),
        KEK_ID.to_string(),
        None,
        None,
    )
    .await?;
    encryptor4.write_all(plaintext).await?;
    encryptor4.shutdown().await?;

    let pending_decryptor4 =
        asynchronous::PendingDecryptor::from_reader(Cursor::new(&ciphertext4)).await?;
    let found_kek_id4 = pending_decryptor4.header().payload.kek_id().unwrap();
    println!("Found KEK ID in async stream: '{}'", found_kek_id4);
    let decryption_key4 = key_store.get(found_kek_id4).unwrap();
    let mut decryptor4 = pending_decryptor4
        .into_decryptor::<Kem, Dek>(decryption_key4.clone(), None)
        .await?;

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
        None,
        None,
    )?;

    let mut decrypted5 = Vec::new();
    let mut source5 = Cursor::new(&ciphertext5);
    let pending_decryptor5 = parallel_streaming::PendingDecryptor::from_reader(&mut source5)?;
    let header5 = pending_decryptor5.header().clone();
    let found_kek_id5 = header5.payload.kek_id().unwrap();
    println!("Found KEK ID in parallel stream: '{}'", found_kek_id5);
    let decryption_key5 = key_store.get(found_kek_id5).unwrap();
    pending_decryptor5.decrypt_to_writer::<Kem, Dek, _>(decryption_key5, &mut decrypted5, None)?;

    assert_eq!(plaintext, &decrypted5[..]);
    println!("Parallel Streaming roundtrip successful!");

    println!("\nAll mid-level hybrid modes are interoperable and successful.");

    // --- Mode 6: In-Memory with AAD ---
    println!("\n--- Testing Mode: In-Memory with AAD ---");
    let aad = b"this is authenticated data for the mid-level hybrid api";
    let ciphertext6 = ordinary::encrypt::<Kem, Dek>(&pk, plaintext, KEK_ID.to_string(), None, Some(aad))?;

    let pending_decryptor6 = ordinary::PendingDecryptor::from_ciphertext(&ciphertext6)?;
    let found_kek_id6 = pending_decryptor6.header().payload.kek_id().unwrap();
    let decryption_key6 = key_store.get(found_kek_id6).unwrap();

    // Decrypt with correct AAD
    let decrypted6 = pending_decryptor6.into_plaintext::<Kem, Dek>(decryption_key6, Some(aad))?;
    assert_eq!(plaintext, &decrypted6[..]);
    println!("In-Memory with AAD roundtrip successful!");

    // Decrypt with wrong AAD should fail
    let pending_decryptor_fail = ordinary::PendingDecryptor::from_ciphertext(&ciphertext6)?;
    let result_fail =
        pending_decryptor_fail.into_plaintext::<Kem, Dek>(decryption_key6, Some(b"wrong aad"));
    assert!(result_fail.is_err());
    println!("In-Memory with wrong AAD correctly failed!");

    Ok(())
}
