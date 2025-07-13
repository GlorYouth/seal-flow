//! This example demonstrates a complete, robust workflow for protecting a large file
//! using hybrid encryption, digital signatures, and streaming I/O.
//！本示例演示了一个完整、健壮的工作流，用于通过混合加密、数字签名和流式 I/O 保护大文件。

use std::collections::HashMap;
use std::io::{Cursor, Read};

use seal_flow::base::keys::{
    TypedAsymmetricPrivateKey, TypedSignaturePublicKey, TypedSymmetricKey,
};
use seal_flow::error::{KeyManagementError};
use seal_flow::prelude::*;

// --- Algorithm Configuration ---
// KEM: A post-quantum safe algorithm for key encapsulation.
const KEM_ALGO: AsymmetricAlgorithmEnum = AsymmetricAlgorithmEnum::Kyber768;
// DEM: A fast, standardized symmetric cipher for bulk data encryption.
const DEK_ALGO: SymmetricAlgorithmEnum = SymmetricAlgorithmEnum::Aes256Gcm;
// Signature: A standard, widely-used algorithm for digital signatures.
const SIG_ALGO: SignatureAlgorithmEnum = SignatureAlgorithmEnum::Ed25519;

// --- Key ID Constants ---
const KEM_KEY_ID: &str = "kyber768-key-2023-10-27";
const SIGNER_KEY_ID: &str = "ed25519-sender-key-v1";

/// A mock `KeyProvider` for demonstration purposes.
/// In a real application, this would connect to a secure key store.
#[derive(Default)]
struct FileKeyProvider {
    asymmetric_private_keys: HashMap<String, TypedAsymmetricPrivateKey>,
    signature_public_keys: HashMap<String, TypedSignaturePublicKey>,
}

impl FileKeyProvider {
    fn add_asymmetric_private_key(&mut self, id: String, key: TypedAsymmetricPrivateKey) {
        self.asymmetric_private_keys.insert(id, key);
    }
    fn add_signature_public_key(&mut self, id: String, key: TypedSignaturePublicKey) {
        self.signature_public_keys.insert(id, key);
    }
}

impl KeyProvider for FileKeyProvider {
    fn get_symmetric_key(&self, _key_id: &str) -> Result<TypedSymmetricKey, KeyProviderError> {
        unimplemented!("Not used in this hybrid example")
    }
    fn get_asymmetric_private_key(
        &self,
        key_id: &str,
    ) -> Result<TypedAsymmetricPrivateKey, KeyProviderError> {
        self.asymmetric_private_keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| KeyProviderError::KeyNotFound(key_id.to_string()))
    }
    fn get_signature_public_key(
        &self,
        key_id: &str,
    ) -> Result<TypedSignaturePublicKey, KeyProviderError> {
        self.signature_public_keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| KeyProviderError::KeyNotFound(key_id.to_string()))
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

fn main() -> seal_flow::error::Result<()> {
    // --- 1. Setup ---
    println!("Setting up keys and provider...");

    let seal = HybridSeal::default();
    let mut key_provider = FileKeyProvider::default();

    // The recipient generates a KEM key pair and stores the private key in the provider.
    let (pk_kem, sk_kem) = KEM_ALGO
        .into_asymmetric_wrapper()
        .generate_keypair()?
        .into_keypair();
    key_provider.add_asymmetric_private_key(KEM_KEY_ID.to_string(), sk_kem);

    // The sender generates a signing key pair. The recipient will need the public key for verification,
    // so we add it to the provider. The sender keeps the private key.
    let (pk_sig, sk_sig) = SIG_ALGO
        .into_signature_wrapper()
        .generate_keypair()?
        .into_keypair();
    key_provider.add_signature_public_key(SIGNER_KEY_ID.to_string(), pk_sig);

    // Simulate a large source file (e.g., 5 MB).
    let source_file_mb = 5;
    let mut source_file = LargeFileStream::new(source_file_mb);
    println!("Simulating a {} MB source file.", source_file_mb);

    // Buffer for the encrypted output.
    let mut encrypted_file = Cursor::new(Vec::new());

    // --- 2. Streaming Encryption with Signature ---
    println!("\nEncrypting file with streaming and signature...");

    // Create a streaming encryptor from the high-level API.
    // The sender uses the recipient's public key (pk_kem) and their own signing private key (sk_sig).
    let mut encryptor = seal
        .encrypt(pk_kem, KEM_KEY_ID.to_string())
        .with_signer(sk_sig, SIGNER_KEY_ID.to_string())?
        .execute_with(DEK_ALGO)
        .into_writer(&mut encrypted_file)?;

    // Process the file in chunks.
    std::io::copy(&mut source_file, &mut encryptor)?;
    // Finalize the encryption. Dropping the writer is sufficient.
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

    // Start decryption by creating a pending decryptor from the data source.
    let pending_decryptor = seal.decrypt().reader(encrypted_file)?;

    // Manually resolve keys using the provider, replicating the old `resolve_and_decrypt` logic.
    // 1. Find the signer key ID in the header and get the verification key.
    let signer_key_id = pending_decryptor.signer_key_id().ok_or_else(|| {
        KeyManagementError::KeyNotFound("Signer key ID not found in header".to_string())
    })?;
    let verification_key = key_provider.get_signature_public_key(signer_key_id)?;

    // 2. Find the KEM key ID and get the decryption key.
    let kek_id = pending_decryptor
        .kek_id()
        .ok_or_else(|| KeyManagementError::KeyNotFound("KEM key ID not found in header".to_string()))?;
    let decryption_key = key_provider.get_asymmetric_private_key(kek_id)?;

    // 3. Create a decrypting reader with the resolved keys.
    let mut decrypting_reader = pending_decryptor
        .with_verification_key(verification_key)
        .with_key_to_reader(&decryption_key)?;

    std::io::copy(&mut decrypting_reader, &mut decrypted_file_content)?;

    println!("Decryption complete.");

    // --- 4. Verification ---
    println!("\nVerifying content...");
    // For simplicity, we just check the size. A full hash comparison would be better in a real test.
    assert_eq!(decrypted_file_content.len(), source_file_mb * 1024 * 1024);
    println!("File content size matches. Workflow successful!");

    Ok(())
}
