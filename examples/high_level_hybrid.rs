use seal_crypto::{prelude::*, schemes::asymmetric::traditional::rsa::Rsa2048};
use seal_crypto::{schemes::hash::Sha256, schemes::symmetric::aes_gcm::Aes256Gcm};
use seal_flow::prelude::*;
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Kem = Rsa2048<Sha256>;
type Dek = Aes256Gcm;
const KEK_ID: &str = "high-level-hybrid-key";

// 1. Define a struct to act as our key provider.
struct MyKeyProvider {
    keys: HashMap<String, <Kem as AsymmetricKeySet>::PrivateKey>,
}

impl AsymmetricKeyProvider for MyKeyProvider {
    fn get_asymmetric_key<'a>(&'a self, kek_id: &str) -> Option<AsymmetricPrivateKey<'a>> {
        self.keys
            .get(kek_id)
            .map(|k| AsymmetricPrivateKey::Rsa2048(k))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Setup
    // Create a key pair and store the private key in our provider.
    let (pk, sk) = Kem::generate_keypair()?;
    let mut keys = HashMap::new();
    keys.insert(KEK_ID.to_string(), sk);
    let provider = MyKeyProvider { keys };

    let plaintext = b"This is a test message for hybrid interoperability.";
    let seal = HybridSeal::new();

    // --- Mode 1: In-Memory (Ordinary) ---
    println!("--- Testing Mode: In-Memory (Ordinary) ---");
    let ciphertext1 = seal
        .encrypt::<Kem, Dek>(&pk, KEK_ID.to_string())
        .to_vec(plaintext)?;
    let pending_decryptor1 = seal.decrypt().from_slice(&ciphertext1)?;
    let decrypted1 = pending_decryptor1.with_provider::<_, Dek>(&provider)?;
    assert_eq!(plaintext, &decrypted1[..]);
    println!("In-Memory (Ordinary) roundtrip successful!");

    // --- Mode 2: In-Memory Parallel ---
    println!("\n--- Testing Mode: In-Memory Parallel ---");
    let ciphertext2 = seal
        .encrypt::<Kem, Dek>(&pk, KEK_ID.to_string())
        .to_vec_parallel(plaintext)?;
    let pending_decryptor2 = seal.decrypt().from_slice_parallel(&ciphertext2)?;
    let decrypted2 = pending_decryptor2.with_provider::<_, Dek>(&provider)?;
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
    println!(
        "Found KEK ID in stream: '{}'",
        pending_decryptor3.kek_id().unwrap()
    );
    let mut decryptor3 = pending_decryptor3.with_provider::<_, Dek>(&provider)?;

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
    println!(
        "Found KEK ID in async stream: '{}'",
        pending_decryptor4.kek_id().unwrap()
    );
    let mut decryptor4 = pending_decryptor4
        .with_provider::<_, Dek>(&provider)
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
    println!(
        "Found KEK ID in parallel stream: '{}'",
        pending_decryptor5.kek_id().unwrap()
    );
    pending_decryptor5.with_provider::<_, Dek, _>(&provider, &mut decrypted5)?;
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
    let pending_decryptor6 = seal.decrypt().from_slice(&ciphertext6)?;
    let decrypted6 = pending_decryptor6
        .with_aad(aad)
        .with_provider::<_, Dek>(&provider)?;
    assert_eq!(plaintext, &decrypted6[..]);
    println!("In-Memory with AAD roundtrip successful!");

    // Decrypt with wrong AAD should fail
    let pending_fail = seal.decrypt().from_slice(&ciphertext6)?;
    let result_fail = pending_fail
        .with_aad(b"wrong aad")
        .with_provider::<_, Dek>(&provider);
    assert!(result_fail.is_err());
    println!("In-Memory with wrong AAD correctly failed!");

    // Decrypt with no AAD should also fail
    let pending_fail2 = seal.decrypt().from_slice(&ciphertext6)?;
    let result_fail2 = pending_fail2.with_provider::<_, Dek>(&provider);
    assert!(result_fail2.is_err());
    println!("In-Memory with no AAD correctly failed!");

    Ok(())
}
