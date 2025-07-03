use seal_flow::prelude::*;
use seal_crypto::prelude::SymmetricKeyGenerator;
use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;

fn main() -> Result<()> {
    let key = Aes256Gcm::generate_key()?;
    let key_wrapped = SymmetricKey::new(key);
    let key_id = "my-aad-key".to_string();
    let plaintext = b"This data is secret and needs integrity protection.";
    
    // Associated Data (AAD) is data that is authenticated but not encrypted.
    // It's useful for binding ciphertext to its context.
    let aad = b"user-id:123,request-id:xyz-789";

    let seal = SymmetricSeal::new();

    // --- Encrypt with AAD ---
    println!("Encrypting data with AAD: '{}'", String::from_utf8_lossy(aad));
    let ciphertext = seal
        .encrypt(key_wrapped.clone(), key_id)
        .with_aad(aad)
        .to_vec::<Aes256Gcm>(plaintext)?;

    // --- Decryption Success ---
    // To decrypt, you MUST provide the exact same AAD.
    println!("Attempting decryption with the correct AAD...");
    let pending_decryptor = seal.decrypt().slice(&ciphertext)?;
    let decrypted_text = pending_decryptor
        .with_aad(aad)
        .with_key(key_wrapped.clone())?;
    
    assert_eq!(plaintext, &decrypted_text[..]);
    println!("Successfully decrypted with correct AAD!");

    // --- Decryption Failures ---

    // 1. Attempting to decrypt with wrong AAD will fail.
    let wrong_aad = b"user-id:456,request-id:abc-123";
    println!("\nAttempting decryption with WRONG AAD: '{}'", String::from_utf8_lossy(wrong_aad));
    let pending_fail = seal.decrypt().slice(&ciphertext)?;
    let result_fail = pending_fail.with_aad(wrong_aad).with_key(key_wrapped.clone());
    
    assert!(result_fail.is_err());
    if let Err(e) = result_fail {
        println!("Correctly failed with error: {}", e);
    }

    // 2. Attempting to decrypt without AAD will also fail.
    println!("\nAttempting decryption with MISSING AAD...");
    let pending_fail2 = seal.decrypt().slice(&ciphertext)?;
    let result_fail2 = pending_fail2.with_key(key_wrapped);
    
    assert!(result_fail2.is_err());
    if let Err(e) = result_fail2 {
        println!("Correctly failed with error: {}", e);
    }

    Ok(())
} 