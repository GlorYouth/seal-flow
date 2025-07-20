//! An example demonstrating streaming symmetric encryption and decryption,
//! suitable for large files or network streams.
//!
//! 流式对称加解密示例，适用于大文件或网络流。
//!
//! To run this example:
//! ```bash
//! cargo run --example streaming_symmetric
//! ```

use anyhow::Result;
use seal_crypto_wrapper::bincode;
use seal_flow::common::header::{SealFlowHeader, SymmetricParams, SymmetricParamsBuilder};
use seal_flow::crypto::prelude::*;
use seal_flow::processor::api::{EncryptionConfigurator, prepare_decryption_from_reader};
use seal_flow::sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::fs::File;
use std::io::{Read, Write};

/// A custom header structure for our streaming example.
///
/// 我们流式示例的自定义标头结构。
#[derive(Clone, bincode::Encode, bincode::Decode, serde::Serialize, serde::Deserialize, Debug)]
#[bincode(crate = "seal_crypto_wrapper::bincode")]
struct StreamHeader {
    params: SymmetricParams,
    filename: String,
    timestamp: u64,
}

impl SealFlowHeader for StreamHeader {
    fn symmetric_params(&self) -> &SymmetricParams {
        &self.params
    }

    fn extra_data(&self) -> Option<&[u8]> {
        None
    }
}

/// Creates a dummy file with a specified size in KB.
///
/// 创建一个指定大小（KB）的虚拟文件。
fn create_dummy_file(path: &str, size_kb: usize) -> Result<()> {
    let mut file = File::create(path)?;
    let data = vec![0u8; 1024]; // 1KB chunk
    for _ in 0..size_kb {
        file.write_all(&data)?;
    }
    // Write some unique data at the end to make it identifiable.
    // 在末尾写入一些唯一数据使其可识别。
    write!(&mut file, "end of dummy file: {}", path)?;
    Ok(())
}

fn main() -> Result<()> {
    println!("Running streaming symmetric encryption/decryption example...");

    // 1. Setup: Define file paths and generate a key.
    let key = TypedSymmetricKey::generate(SymmetricAlgorithm::build().aes256_gcm())?;
    let aad = b"streaming authenticated data";
    let input_file_path = "sample_input.bin";
    let encrypted_file_path = "sample_encrypted.bin";
    let decrypted_file_path = "sample_decrypted.bin";

    // Create a dummy file to be encrypted.
    println!("\n--- Setup ---");
    println!("  - Creating a dummy input file: {}", input_file_path);
    create_dummy_file(input_file_path, 1024 * 5)?; // 5 MB file

    // 2. Encryption Flow
    {
        println!("\n--- Encrypting Stream ---");

        let mut input_file = File::open(input_file_path)?;
        let mut encrypted_file = File::create(encrypted_file_path)?;

        // Create a header with relevant metadata.
        let params = SymmetricParamsBuilder::new(SymmetricAlgorithm::build().aes256_gcm(), 4096)
            .aad_hash(aad, Sha256::new())
            .base_nonce(|nonce| nonce.fill(2))
            .build();

        let header = StreamHeader {
            params,
            filename: input_file_path.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };

        println!(
            "  - Encrypting '{}' to '{}'",
            input_file_path, encrypted_file_path
        );
        println!("  - Header created with filename: \"{}\"", header.filename);

        // Configure the encryption and get a writer for the stream.
        let configurator =
            EncryptionConfigurator::new(header, Cow::Borrowed(&key), Some(aad.to_vec()));
        let flow = configurator.into_writer(&mut encrypted_file)?;

        // `start_streaming` returns a writer that encrypts data as it's written.
        let mut encryptor = flow.start_streaming()?;

        // Copy data from the input file to the encrypting writer. This is done in chunks.
        std::io::copy(&mut input_file, &mut encryptor)?;

        // Finalize encryption to write any remaining buffered data and the authentication tag.
        encryptor.finish()?;

        println!("  - Streaming encryption successful.");
    }

    // 3. Decryption Flow
    {
        println!("\n--- Decrypting Stream ---");

        let mut encrypted_file = File::open(encrypted_file_path)?;
        let mut decrypted_file = File::create(decrypted_file_path)?;

        // Prepare for decryption by reading the header from the start of the file.
        let pending_decryption =
            prepare_decryption_from_reader::<_, StreamHeader>(&mut encrypted_file)?;

        println!(
            "  - Header parsed successfully. Original filename: \"{}\"",
            pending_decryption.header().filename
        );

        // `decrypt_streaming` returns a reader that decrypts data as it's read.
        let mut decryptor =
            pending_decryption.decrypt_streaming(Cow::Borrowed(&key), Some(aad.to_vec()))?;

        // Copy the decrypted data to the output file.
        std::io::copy(&mut decryptor, &mut decrypted_file)?;

        println!("  - Streaming decryption successful.");
        println!("  - Decrypted content written to '{}'", decrypted_file_path);
    }

    // 4. Verification
    println!("\n--- Verification ---");
    let mut original_data = Vec::new();
    File::open(input_file_path)?.read_to_end(&mut original_data)?;

    let mut decrypted_data = Vec::new();
    File::open(decrypted_file_path)?.read_to_end(&mut decrypted_data)?;

    assert_eq!(original_data, decrypted_data);
    println!("✅ Success: Decrypted file content matches the original.");

    // 5. Cleanup
    println!("\n--- Cleanup ---");
    std::fs::remove_file(input_file_path)?;
    std::fs::remove_file(encrypted_file_path)?;
    std::fs::remove_file(decrypted_file_path)?;
    println!("  - Removed temporary files.");

    Ok(())
}
