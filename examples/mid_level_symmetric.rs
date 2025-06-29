use seal_crypto::prelude::*;
use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
use seal_flow::common::header::Header;
use seal_flow::error::Result;
use seal_flow::flows::symmetric::*;
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type TheAlgorithm = Aes256Gcm;
const KEY_ID: &str = "mid-level-symmetric-key";

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Setup
    let mut key_store = HashMap::new();
    let key = TheAlgorithm::generate_key()?;
    key_store.insert(KEY_ID.to_string(), key);

    let plaintext = b"This is a test message for the mid-level API.";

    // --- Mode 1: In-Memory (Ordinary) ---
    println!("--- Testing Mode: In-Memory (Ordinary) ---");
    let key1 = key_store.get(KEY_ID).unwrap();
    let ciphertext1 =
        ordinary::encrypt::<TheAlgorithm>(key1.clone(), plaintext, KEY_ID.to_string(), None)?;

    // Demonstrate two-stage decryption
    let (header1, body1) = Header::decode_from_prefixed_slice(&ciphertext1)?;
    let found_key_id1 = header1.payload.key_id().unwrap();
    println!("Found key ID in header: '{}'", found_key_id1);
    let decryption_key1 = key_store.get(found_key_id1).unwrap();
    let decrypted1 =
        ordinary::decrypt_body::<TheAlgorithm>(decryption_key1.clone(), &header1, body1, None)?;

    assert_eq!(plaintext, &decrypted1[..]);
    println!("In-Memory (Ordinary) roundtrip successful!");

    // --- Mode 2: In-Memory Parallel ---
    println!("\n--- Testing Mode: In-Memory Parallel ---");
    let key2 = key_store.get(KEY_ID).unwrap();
    let ciphertext2 =
        parallel::encrypt::<TheAlgorithm>(key2.clone(), plaintext, KEY_ID.to_string(), None)?;

    let (header2, body2) = Header::decode_from_prefixed_slice(&ciphertext2)?;
    let found_key_id2 = header2.payload.key_id().unwrap();
    println!("Found key ID in parallel header: '{}'", found_key_id2);
    let decryption_key2 = key_store.get(found_key_id2).unwrap();
    let decrypted2 =
        parallel::decrypt_body::<TheAlgorithm>(decryption_key2.clone(), &header2, body2, None)?;

    assert_eq!(plaintext, &decrypted2[..]);
    println!("In-Memory Parallel roundtrip successful!");

    // --- Mode 3: Synchronous Streaming ---
    println!("\n--- Testing Mode: Synchronous Streaming ---");
    let mut ciphertext3 = Vec::new();
    let key3 = key_store.get(KEY_ID).unwrap();
    let mut encryptor3 = streaming::Encryptor::<_, TheAlgorithm>::new(
        &mut ciphertext3,
        key3.clone(),
        KEY_ID.to_string(),
        None,
    )?;
    encryptor3.write_all(plaintext)?;
    encryptor3.finish()?;

    let pending_decryptor3 =
        streaming::PendingDecryptor::<_>::from_reader(Cursor::new(&ciphertext3))?;
    let found_key_id3 = pending_decryptor3.header().payload.key_id().unwrap();
    println!("Found key ID in stream: '{}'", found_key_id3);
    let decryption_key3 = key_store.get(found_key_id3).unwrap();
    let mut decryptor3 =
        pending_decryptor3.into_decryptor::<TheAlgorithm>(decryption_key3.clone(), None)?;

    let mut decrypted3 = Vec::new();
    decryptor3.read_to_end(&mut decrypted3)?;
    assert_eq!(plaintext, &decrypted3[..]);
    println!("Synchronous Streaming roundtrip successful!");

    // --- Mode 4: Asynchronous Streaming ---
    println!("\n--- Testing Mode: Asynchronous Streaming ---");
    let mut ciphertext4 = Vec::new();
    let key4 = key_store.get(KEY_ID).unwrap();
    let mut encryptor4 = asynchronous::Encryptor::<_, TheAlgorithm>::new(
        &mut ciphertext4,
        key4.clone(),
        KEY_ID.to_string(),
        None,
    )
    .await?;
    encryptor4.write_all(plaintext).await?;
    encryptor4.shutdown().await?;

    let pending_decryptor4 =
        asynchronous::PendingDecryptor::<_>::from_reader(Cursor::new(&ciphertext4)).await?;
    let found_key_id4 = pending_decryptor4.header().payload.key_id().unwrap();
    println!("Found key ID in async stream: '{}'", found_key_id4);
    let decryption_key4 = key_store.get(found_key_id4).unwrap();
    let mut decryptor4 =
        pending_decryptor4.into_decryptor::<TheAlgorithm>(decryption_key4.clone(), None)?;

    let mut decrypted4 = Vec::new();
    decryptor4.read_to_end(&mut decrypted4).await?;
    assert_eq!(plaintext, &decrypted4[..]);
    println!("Asynchronous Streaming roundtrip successful!");

    // --- Mode 5: Parallel Streaming ---
    println!("\n--- Testing Mode: Parallel Streaming ---");
    let mut ciphertext5 = Vec::new();
    let key5 = key_store.get(KEY_ID).unwrap();
    parallel_streaming::encrypt::<TheAlgorithm, _, _>(
        key5.clone(),
        Cursor::new(plaintext),
        &mut ciphertext5,
        KEY_ID.to_string(),
        None,
    )?;

    let mut decrypted5 = Vec::new();
    let mut source5 = Cursor::new(&ciphertext5);
    let pending_decryptor5 = parallel_streaming::PendingDecryptor::from_reader(&mut source5)?;
    let header5 = pending_decryptor5.header().clone();
    let found_key_id5 = header5.payload.key_id().unwrap();
    println!("Found key ID in parallel stream: '{}'", found_key_id5);
    let decryption_key5 = key_store.get(found_key_id5).unwrap();
    pending_decryptor5.decrypt_to_writer::<TheAlgorithm, _>(
        decryption_key5.clone(),
        &mut decrypted5,
        None,
    )?;

    assert_eq!(plaintext, &decrypted5[..]);
    println!("Parallel Streaming roundtrip successful!");

    println!("\nAll mid-level symmetric modes are interoperable and successful.");

    // --- Mode 6: In-Memory with AAD ---
    println!("\n--- Testing Mode: In-Memory with AAD ---");
    let aad = b"this is authenticated data for the mid-level symmetric api";
    let key6 = key_store.get(KEY_ID).unwrap();
    let ciphertext6 =
        ordinary::encrypt::<TheAlgorithm>(key6.clone(), plaintext, KEY_ID.to_string(), Some(aad))?;

    let pending_decryptor6 = ordinary::PendingDecryptor::from_ciphertext(&ciphertext6)?;
    let found_key_id6 = pending_decryptor6.header().payload.key_id().unwrap();
    let decryption_key6 = key_store.get(found_key_id6).unwrap();

    // Decrypt with correct AAD
    let decrypted6 =
        pending_decryptor6.into_plaintext::<TheAlgorithm>(decryption_key6.clone(), Some(aad))?;
    assert_eq!(plaintext, &decrypted6[..]);
    println!("In-Memory with AAD roundtrip successful!");

    // Decrypt with wrong AAD should fail
    let pending_decryptor_fail = ordinary::PendingDecryptor::from_ciphertext(&ciphertext6)?;
    let result_fail = pending_decryptor_fail
        .into_plaintext::<TheAlgorithm>(decryption_key6.clone(), Some(b"wrong aad"));
    assert!(result_fail.is_err());
    println!("In-Memory with wrong AAD correctly failed!");

    Ok(())
}
