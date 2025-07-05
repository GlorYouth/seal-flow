//! This example demonstrates a complete, robust workflow for protecting a large file
//! using hybrid encryption, digital signatures, and streaming I/O.
//！本示例演示了一个完整、健壮的工作流，用于通过混合加密、数字签名和流式 I/O 保护大文件。

use std::collections::HashMap;
use std::io::{Cursor, Read};

use seal_flow::algorithms::asymmetric::Kyber768;
use seal_flow::algorithms::signature::Ed25519;
use seal_flow::algorithms::symmetric::Aes256Gcm;
use seal_flow::prelude::*;
use seal_flow::error::KeyManagementError;

// --- Algorithm Configuration ---
// KEM: A post-quantum safe algorithm for key encapsulation.
type Kem = Kyber768;
// DEM: A fast, standardized symmetric cipher for bulk data encryption.
type Dek = Aes256Gcm;
// Signature: A standard, widely-used algorithm for digital signatures.
type Sig = Ed25519;

// --- Key ID Constants ---
const KEM_KEY_ID: &str = "kyber768-key-2023-10-27";
const SIGNER_KEY_ID: &str = "ed25519-sender-key-v1";

/// A mock `KeyProvider` for demonstration purposes.
/// In a real application, this would connect to a secure key store.
#[derive(Default)]
struct FileKeyProvider {
    asymmetric_private_keys: HashMap<String, AsymmetricPrivateKey>,
    signature_public_keys: HashMap<String, SignaturePublicKey>,
}

impl FileKeyProvider {
    fn add_asymmetric_private_key(&mut self, id: String, key: impl Into<AsymmetricPrivateKey>) {
        self.asymmetric_private_keys.insert(id, key.into());
    }
    fn add_signature_public_key(&mut self, id: String, key: impl Into<SignaturePublicKey>) {
        self.signature_public_keys.insert(id, key.into());
    }
}

impl KeyProvider for FileKeyProvider {
    fn get_symmetric_key(&self, _key_id: &str) -> Result<SymmetricKey> {
        unimplemented!("Not used in this hybrid example")
    }
    fn get_asymmetric_private_key(&self, key_id: &str) -> Result<AsymmetricPrivateKey> {
        self.asymmetric_private_keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| Error::KeyManagement(KeyManagementError::KeyNotFound(key_id.to_string())))
    }
    fn get_signature_public_key(&self, key_id: &str) -> Result<SignaturePublicKey> {
        self.signature_public_keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| Error::KeyManagement(KeyManagementError::KeyNotFound(key_id.to_string())))
    }
}

/// Simulates a large file by creating a readable stream of a specific size.
struct LargeFileStream {
    inner: Cursor<Vec<u8>>,
}

impl LargeFileStream {
    fn new(size_mb: usize) -> Self {
        let data = vec![0x42u8; size_mb * 1024 * 1024];
        Self {
            inner: Cursor::new(data),
        }
    }
}

impl Read for LargeFileStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

fn main() -> Result<()> {
    // --- 1. Setup ---
    println!("Setting up keys and provider...");

    let seal = HybridSeal::new();
    let mut key_provider = FileKeyProvider::default();

    // The recipient generates a KEM key pair and stores the private key.
    let (pk_kem, sk_kem) = Kem::generate_keypair()?;
    key_provider.add_asymmetric_private_key(KEM_KEY_ID.to_string(), AsymmetricPrivateKey::new(sk_kem.to_bytes()));

    // The sender generates a signing key pair. The recipient only needs the public key for verification.
    let (pk_sig, sk_sig) = Sig::generate_keypair()?;
    key_provider.add_signature_public_key(SIGNER_KEY_ID.to_string(), SignaturePublicKey::new(pk_sig.to_bytes()));

    // Simulate a large source file (e.g., 5 MB).
    let source_file_mb = 5;
    let mut source_file = LargeFileStream::new(source_file_mb);
    println!("Simulating a {} MB source file.", source_file_mb);

    // Buffers for input and output.
    let mut encrypted_file = Cursor::new(Vec::new());

    // --- 2. Streaming Encryption with Signature ---
    println!("\nEncrypting file with streaming and signature...");

    let pk_kem_wrapped = AsymmetricPublicKey::new(pk_kem.to_bytes());
    let sk_sig_wrapped = AsymmetricPrivateKey::new(sk_sig.to_bytes());

    // Create a streaming encryptor from the high-level API.
    let mut encryptor = seal
        .encrypt::<Dek>(pk_kem_wrapped, KEM_KEY_ID.to_string())
        .with_signer::<Sig>(sk_sig_wrapped, SIGNER_KEY_ID.to_string())
        .into_writer::<Kem, _>(&mut encrypted_file)?;

    // Process the file in chunks.
    std::io::copy(&mut source_file, &mut encryptor)?;
    encryptor.finish()?;

    let encrypted_size_mb = encrypted_file.get_ref().len() as f64 / 1024.0 / 1024.0;
    println!(
        "Encryption complete. Encrypted file size: {:.2} MB.",
        encrypted_size_mb
    );

    // --- 3. Streaming Decryption using KeyProvider ---
    println!("\nDecrypting file with streaming and KeyProvider...");

    // Reset the cursor position to the beginning for reading.
    encrypted_file.set_position(0);

    let mut decrypted_file_content = Vec::new();

    // Use the `KeyProvider` to simplify decryption.
    let pending_decryptor = seal
        .decrypt()
        .with_key_provider(&key_provider)
        .reader(encrypted_file)?;
    
    // The `resolve_and_decrypt` method handles everything:
    // - Finds the signer key ID in the header.
    // - Asks the provider for the public key.
    // - Verifies the signature.
    // - Finds the KEM key ID.
    // - Asks the provider for the private key.
    // - Creates a decrypting reader.
    let mut decrypting_reader = pending_decryptor.resolve_and_decrypt()?;

    std::io::copy(&mut decrypting_reader, &mut decrypted_file_content)?;

    println!("Decryption complete.");

    // --- 4. Verification ---
    println!("\nVerifying content...");
    // For simplicity, we just check the size. A full hash comparison would be better in a real test.
    assert_eq!(decrypted_file_content.len(), source_file_mb * 1024 * 1024);
    println!("File content size matches. Workflow successful!");

    Ok(())
} 