use seal_flow::prelude::*;
use seal_crypto::prelude::SymmetricKeyGenerator;
use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
use std::collections::HashMap;

fn main() -> Result<()> {
    // --- Setup ---
    // In a real app, you'd manage keys in a KMS or secure storage.
    let mut key_store = HashMap::new();
    let key = Aes256Gcm::generate_key()?;
    let key_id = "my-encryption-key-v1".to_string();
    key_store.insert(key_id.clone(), key.clone());

    let plaintext = b"Data that is being protected.";
    let aad = b"Context metadata, like a request ID or version.";

    // The high-level API factory is stateless and reusable.
    let seal = SymmetricSeal::new();

    // --- 1. Encryption ---
    // The key is wrapped for type safety.
    let key_wrapped = SymmetricKey::new(key);
    let ciphertext = seal
        .encrypt(key_wrapped, key_id)
        .with_aad(aad) // Bind ciphertext to context
        .to_vec::<Aes256Gcm>(plaintext)?; // Execute encryption

    println!("Encryption successful!");

    // --- 2. Decryption (Safe Key-Lookup Workflow) ---

    // a. Create a "Pending Decryptor" to inspect metadata without decrypting.
    let pending_decryptor = seal.decrypt().slice(&ciphertext)?;

    // b. Get the key ID from the header. This is a cheap and safe operation.
    let found_key_id = pending_decryptor.key_id().expect("Header must contain a key ID.");
    println!("Found key ID: '{}'. Now retrieving the key.", found_key_id);

    // c. Use the ID to fetch the correct key from your key store.
    let decryption_key_bytes = key_store.get(found_key_id).unwrap();
    let decryption_key_wrapped = SymmetricKey::new(decryption_key_bytes.clone());
    
    // d. Provide the key and AAD to complete decryption.
    // `with_key` automatically infers the algorithm from the header.
    let decrypted_text = pending_decryptor
        .with_aad(aad) // Must provide the same AAD
        .with_key(decryption_key_wrapped)?;

    assert_eq!(plaintext, &decrypted_text[..]);
    println!("Successfully decrypted data!");
    Ok(())
} 