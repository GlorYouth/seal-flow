use seal_flow::prelude::*;
use seal_crypto::{
    prelude::*,
    schemes::{asymmetric::traditional::rsa::Rsa2048, hash::Sha256, symmetric::aes_gcm::Aes256Gcm},
};
use std::collections::HashMap;

type Kem = Rsa2048<Sha256>; // Key Encapsulation Mechanism
type Dek = Aes256Gcm;       // Data Encapsulation Key

fn main() -> Result<()> {
    // --- Setup ---
    let (pk, sk) = Kem::generate_keypair()?;
    let mut private_key_store = HashMap::new();
    let kek_id = "rsa-key-pair-001".to_string(); // Key Encryption Key ID
    private_key_store.insert(kek_id.clone(), sk.to_bytes());

    let plaintext = b"This is a secret message for hybrid encryption.";
    let seal = HybridSeal::new();

    // --- 1. Encryption ---
    // Encrypt using the public key.
    let pk_wrapped = AsymmetricPublicKey::new(pk.to_bytes());
    let ciphertext = seal
        .encrypt::<Dek>(pk_wrapped, kek_id) // Specify the symmetric algorithm (DEK)
        .to_vec::<Kem>(plaintext)?;          // Specify the asymmetric algorithm (KEM)

    // --- 2. Decryption ---
    // Inspect header to find which private key to use.
    let pending_decryptor = seal.decrypt().slice(&ciphertext)?;
    let found_kek_id = pending_decryptor.kek_id().unwrap();

    // Fetch and wrap the private key bytes.
    let sk_bytes = private_key_store.get(found_kek_id).unwrap();
    let sk_wrapped = AsymmetricPrivateKey::new(sk_bytes.clone());

    // Provide the key to decrypt.
    let decrypted_text = pending_decryptor.with_key(sk_wrapped)?;

    assert_eq!(plaintext, &decrypted_text[..]);
    println!("Successfully performed hybrid encryption and decryption!");
    Ok(())
} 