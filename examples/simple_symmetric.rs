//! An example demonstrating simple in-memory symmetric encryption and decryption.
//!
//! P对称加密/解密示例。
//!
//! To run this example:
//!
//! To run this example:
//! ```bash
//! cargo run --example simple_symmetric
//! ```

use anyhow::Result;
use seal_crypto_wrapper::algorithms::aead::AeadAlgorithm;
use seal_crypto_wrapper::bincode;
use seal_flow::common::header::{SealFlowHeader, SymmetricParams, SymmetricParamsBuilder};
use seal_flow::crypto::prelude::*;
use seal_flow::prelude::{EncryptionConfigurator, prepare_decryption_from_slice};
use seal_flow::sha2::{Digest, Sha256};
use std::borrow::Cow;

/// A custom header structure for our example.
/// It must implement the `SealFlowHeader` trait.
///
/// 我们示例的自定义标头结构。
/// 它必须实现 `SealFlowHeader` trait。
#[derive(Clone, bincode::Encode, bincode::Decode, serde::Serialize, serde::Deserialize, Debug)]
#[bincode(crate = "seal_crypto_wrapper::bincode")]
struct SimpleHeader {
    params: SymmetricParams,
    metadata: String,
}

impl SealFlowHeader for SimpleHeader {
    fn symmetric_params(&self) -> &SymmetricParams {
        &self.params
    }

    fn extra_data(&self) -> Option<&[u8]> {
        // This example doesn't use extra data, but it could be stored here.
        // 这个例子没有使用额外的数据，但它可以存储在这里。
        None
    }
}

fn main() -> Result<()> {
    println!("Running simple symmetric encryption/decryption example...");

    // 1. Setup: Define a key, AAD (Additional Authenticated Data), and plaintext.
    let key = TypedAeadKey::generate(AeadAlgorithm::build().aes256_gcm())?;
    let aad = b"additional authenticated data";
    let plaintext = b"this is a secret message that should be kept confidential";

    println!("  - Plaintext: \"{}\"", String::from_utf8_lossy(plaintext));
    println!("  - AAD: \"{}\"", String::from_utf8_lossy(aad));

    // 2. Encryption Flow
    let ciphertext = {
        println!("\n--- Encrypting ---");

        // Create symmetric parameters. The AAD is hashed and included for integrity.
        let params = SymmetricParamsBuilder::new(AeadAlgorithm::build().aes256_gcm(), 1024)
            .aad_hash(aad, Sha256::new())
            .base_nonce(|nonce| {
                nonce.fill(1);
                Ok(())
            })?
            .build();

        // Create our custom header instance.
        let header = SimpleHeader {
            params,
            metadata: "Example metadata".to_string(),
        };
        println!("  - Header created with metadata: \"{}\"", header.metadata);

        // Configure the encryption process.
        let configurator =
            EncryptionConfigurator::new(header, Cow::Borrowed(&key), Some(aad.to_vec()));

        // Encrypt the data in memory using the "ordinary" mode.
        // The header will be prepended to the ciphertext.
        let ciphertext = configurator
            .into_writer(Vec::new())?
            .encrypt_ordinary_to_vec(plaintext)?;

        println!("  - Encryption successful!");
        println!("  - Total ciphertext length: {} bytes", ciphertext.len());
        ciphertext
    };

    // 3. Decryption Flow
    let decrypted_plaintext = {
        println!("\n--- Decrypting ---");

        // Prepare for decryption by parsing the header from the ciphertext.
        let pending_decryption = prepare_decryption_from_slice::<SimpleHeader>(&ciphertext, None)?;

        println!(
            "  - Header parsed successfully. Found metadata: \"{}\"",
            pending_decryption.header().metadata
        );

        // Decrypt the remaining ciphertext body.
        let decrypted_plaintext =
            pending_decryption.decrypt_ordinary(Cow::Borrowed(&key), Some(aad.to_vec()))?;

        println!("  - Decryption successful!");
        println!(
            "  - Decrypted plaintext: \"{}\"",
            String::from_utf8_lossy(&decrypted_plaintext)
        );
        decrypted_plaintext
    };

    // 4. Verification
    println!("\n--- Verification ---");
    assert_eq!(plaintext.as_ref(), decrypted_plaintext.as_slice());
    println!("✅ Success: Decrypted data matches the original plaintext.");

    Ok(())
}
