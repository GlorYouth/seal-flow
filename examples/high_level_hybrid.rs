use seal_crypto::schemes::asymmetric::post_quantum::dilithium::Dilithium2;
use seal_crypto::{prelude::*, schemes::asymmetric::traditional::rsa::Rsa2048};
use seal_crypto::{schemes::hash::Sha256, schemes::symmetric::aes_gcm::Aes256Gcm};
use seal_flow::prelude::*;
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Kem = Rsa2048<Sha256>;
type Dek = Aes256Gcm;
type Signer = Dilithium2;
const KEK_ID: &str = "high-level-hybrid-key";
const SIGNER_KEY_ID: &str = "high-level-signer-key";

// 使用HashMap存储密钥，以便通过key_id查找
struct KeyStore {
    private_keys: HashMap<String, Vec<u8>>,
    public_keys: HashMap<String, Vec<u8>>,
}

impl KeyStore {
    fn get_private_key(&self, key_id: &str) -> Option<&[u8]> {
        self.private_keys.get(key_id).map(|k| k.as_slice())
    }

    fn get_public_key(&self, key_id: &str) -> Option<SignaturePublicKey> {
        self.public_keys
            .get(key_id)
            .map(|k| SignaturePublicKey::new(k.clone()))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Setup
    // 创建密钥对并将私钥存储在KeyStore中
    let (pk, sk) = Kem::generate_keypair()?;
    let sk_bytes = sk.to_bytes();

    // 创建签名密钥对
    let (sig_pk, sig_sk) = Signer::generate_keypair()?;
    let sig_pk_bytes = sig_pk.to_bytes();

    let mut private_keys = HashMap::new();
    private_keys.insert(KEK_ID.to_string(), sk_bytes);

    let mut public_keys = HashMap::new();
    public_keys.insert(SIGNER_KEY_ID.to_string(), sig_pk_bytes);

    let key_store = KeyStore {
        private_keys,
        public_keys,
    };

    let plaintext = b"This is a test message for hybrid interoperability.";
    let seal = HybridSeal::new();

    // --- Mode 1: In-Memory (Ordinary) ---
    println!("--- Testing Mode: In-Memory (Ordinary) ---");
    let ciphertext1 = seal
        .encrypt::<Kem, Dek>(&pk, KEK_ID.to_string())
        .to_vec(plaintext)?;
    let pending_decryptor1 = seal.decrypt().slice(&ciphertext1)?;
    let kek_id = pending_decryptor1.kek_id().unwrap();
    let sk_bytes = key_store.get_private_key(kek_id).unwrap();
    let decrypted1 = pending_decryptor1.with_key_bytes::<Dek>(sk_bytes)?;
    assert_eq!(plaintext, &decrypted1[..]);
    println!("In-Memory (Ordinary) roundtrip successful!");

    // --- Mode 2: In-Memory Parallel ---
    println!("\n--- Testing Mode: In-Memory Parallel ---");
    let ciphertext2 = seal
        .encrypt::<Kem, Dek>(&pk, KEK_ID.to_string())
        .to_vec_parallel(plaintext)?;
    let pending_decryptor2 = seal.decrypt().slice_parallel(&ciphertext2)?;
    let kek_id = pending_decryptor2.kek_id().unwrap();
    let sk_bytes = key_store.get_private_key(kek_id).unwrap();
    let decrypted2 = pending_decryptor2.with_key_bytes::<Dek>(sk_bytes)?;
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

    let pending_decryptor3 = seal.decrypt().reader(Cursor::new(ciphertext3))?;
    println!(
        "Found KEK ID in stream: '{}'",
        pending_decryptor3.kek_id().unwrap()
    );
    let kek_id = pending_decryptor3.kek_id().unwrap();
    let sk_bytes = key_store.get_private_key(kek_id).unwrap();
    let mut decryptor3 = pending_decryptor3.with_key_bytes::<Dek>(sk_bytes)?;

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
        .async_reader(Cursor::new(&ciphertext4))
        .await?;
    println!(
        "Found KEK ID in async stream: '{}'",
        pending_decryptor4.kek_id().unwrap()
    );
    let kek_id = pending_decryptor4.kek_id().unwrap();
    let sk_bytes = key_store.get_private_key(kek_id).unwrap();
    let mut decryptor4 = pending_decryptor4.with_key_bytes::<Dek>(sk_bytes).await?;

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
    let pending_decryptor5 = seal.decrypt().reader_parallel(Cursor::new(&ciphertext5))?;
    println!(
        "Found KEK ID in parallel stream: '{}'",
        pending_decryptor5.kek_id().unwrap()
    );
    let kek_id = pending_decryptor5.kek_id().unwrap();
    let sk_bytes = key_store.get_private_key(kek_id).unwrap();
    pending_decryptor5.with_key_bytes_to_writer::<Dek, _>(sk_bytes, &mut decrypted5)?;
    assert_eq!(plaintext, &decrypted5[..]);
    println!("Parallel Streaming roundtrip successful!");

    println!("\nAll high-level hybrid modes are interoperable and successful.");

    // --- Mode 6: In-Memory with AAD ---
    println!("\n--- Testing Mode: In-Memory with AAD ---");
    let aad = b"Authenticated but not encrypted hybrid data";
    let ciphertext6 = seal
        .encrypt::<Kem, Dek>(&pk, KEK_ID.to_string())
        .with_aad(aad)
        .to_vec(plaintext)?;

    // Decrypt with correct AAD
    let pending_decryptor6 = seal.decrypt().slice(&ciphertext6)?;
    let kek_id = pending_decryptor6.kek_id().unwrap();
    let sk_bytes = key_store.get_private_key(kek_id).unwrap();
    let decrypted6 = pending_decryptor6
        .with_aad(aad)
        .with_key_bytes::<Dek>(sk_bytes)?;
    assert_eq!(plaintext, &decrypted6[..]);
    println!("In-Memory with AAD roundtrip successful!");

    // Decrypt with wrong AAD should fail
    let pending_fail = seal.decrypt().slice(&ciphertext6)?;
    let kek_id = pending_fail.kek_id().unwrap();
    let sk_bytes = key_store.get_private_key(kek_id).unwrap();
    let result_fail = pending_fail
        .with_aad(b"wrong aad")
        .with_key_bytes::<Dek>(sk_bytes);
    assert!(result_fail.is_err());
    println!("In-Memory with wrong AAD correctly failed!");

    // Decrypt with no AAD should also fail
    let pending_fail2 = seal.decrypt().slice(&ciphertext6)?;
    let kek_id = pending_fail2.kek_id().unwrap();
    let sk_bytes = key_store.get_private_key(kek_id).unwrap();
    let result_fail2 = pending_fail2.with_key_bytes::<Dek>(sk_bytes);
    assert!(result_fail2.is_err());
    println!("In-Memory with no AAD correctly failed!");

    // --- Mode 7: Signed Encryption ---
    println!("\n--- Testing Mode: Signed Encryption ---");
    let aad = b"AAD with signature";
    let ciphertext7 = seal
        .encrypt::<Kem, Dek>(&pk, KEK_ID.to_string())
        .with_aad(aad)
        .with_signer::<Signer>(sig_sk, SIGNER_KEY_ID.to_string())
        .to_vec(plaintext)?;

    // 解密 - 使用正确的签名验证密钥和AAD
    let pending_decryptor7 = seal.decrypt().slice(&ciphertext7)?;
    let verification_key = key_store.get_public_key(SIGNER_KEY_ID).unwrap();

    let kek_id = pending_decryptor7.kek_id().unwrap();
    let sk_bytes = key_store.get_private_key(kek_id).unwrap();

    let decrypted7 = pending_decryptor7
        .with_aad(aad)
        .with_verification_key(verification_key)?
        .with_key_bytes::<Dek>(sk_bytes)?;

    assert_eq!(plaintext, &decrypted7[..]);
    println!("Signed encryption with AAD roundtrip successful!");

    Ok(())
}
