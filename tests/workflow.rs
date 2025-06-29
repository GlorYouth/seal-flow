//! Integration tests for the complete encryption/decryption workflow.
//!
//! These tests simulate a real-world scenario where a key store is used
//! to look up keys based on the ID peeked from the ciphertext header.

use seal_crypto::schemes::asymmetric::traditional::rsa::Rsa2048;
use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm as TestDek;
use seal_crypto::{prelude::*, schemes::hash::Sha256};
use seal_flow::seal::{hybrid::HybridSeal, symmetric::SymmetricSeal};
use std::collections::HashMap;
use std::io::Cursor;
use tokio::io::AsyncReadExt;

type TestKem = Rsa2048<Sha256>;

// --- Mock Key Stores ---

/// A simple in-memory mock for a symmetric key store.
struct SymmetricKeyStore {
    keys: HashMap<String, <TestDek as SymmetricKeySet>::Key>,
}

impl SymmetricKeyStore {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }
    fn add_key(&mut self, id: String, key: <TestDek as SymmetricKeySet>::Key) {
        self.keys.insert(id, key);
    }
    fn get_key(&self, id: &str) -> Option<&<TestDek as SymmetricKeySet>::Key> {
        self.keys.get(id)
    }
}

/// A simple in-memory mock for an asymmetric key store.
struct AsymmetricKeyStore {
    keys: HashMap<String, <TestKem as AsymmetricKeySet>::PrivateKey>,
}

impl AsymmetricKeyStore {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }
    fn add_key(&mut self, id: String, key: <TestKem as AsymmetricKeySet>::PrivateKey) {
        self.keys.insert(id, key);
    }
    fn get_key(&self, id: &str) -> Option<&<TestKem as AsymmetricKeySet>::PrivateKey> {
        self.keys.get(id)
    }
}

// --- Workflow Tests ---

#[test]
fn test_symmetric_workflow() {
    // --- Setup ---
    let mut store = SymmetricKeyStore::new();
    let key_id = "symmetric-key-01".to_string();
    let key = TestDek::generate_key().unwrap();
    store.add_key(key_id.clone(), key.clone());

    let plaintext = b"This is the symmetric workflow test.";
    let seal = SymmetricSeal::new();

    // --- Encryption Side ---
    let encrypted = seal
        .encrypt::<TestDek>(&key, key_id.clone())
        .to_vec(plaintext)
        .unwrap();

    // --- Decryption Side (simulated) ---
    // 1. Create a pending decryptor to peek the key ID from the header.
    let pending_decryptor = seal.decrypt().slice(&encrypted).unwrap();
    let peeked_id = pending_decryptor.key_id().unwrap();
    assert_eq!(key_id, peeked_id);

    // 2. Use the ID to get the correct key from the store.
    let decryption_key = store.get_key(peeked_id).unwrap();

    // 3. Decrypt using the retrieved key.
    let decrypted = pending_decryptor
        .with_key::<TestDek>(decryption_key.clone())
        .unwrap();

    // --- Verification ---
    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn test_hybrid_workflow() {
    // --- Setup ---
    let mut store = AsymmetricKeyStore::new();
    let kek_id = "hybrid-key-01".to_string();
    let (pk, sk) = TestKem::generate_keypair().unwrap();
    store.add_key(kek_id.clone(), sk);

    let plaintext = b"This is the hybrid workflow test.";
    let seal = HybridSeal::new();

    // --- Encryption Side ---
    let encrypted = seal
        .encrypt::<TestKem, TestDek>(&pk, kek_id.clone())
        .to_vec(plaintext)
        .unwrap();

    // --- Decryption Side (simulated) ---
    // 1. Create a pending decryptor to peek the KEK ID from the header.
    let pending_decryptor = seal.decrypt().slice(&encrypted).unwrap();
    let peeked_id = pending_decryptor.kek_id().unwrap();
    assert_eq!(kek_id, peeked_id);

    // 2. Use the ID to get the correct private key from the store.
    let decryption_key = store.get_key(peeked_id).unwrap();

    // 3. Decrypt using the retrieved private key.
    let decrypted = pending_decryptor
        .with_private_key::<TestKem, TestDek>(decryption_key)
        .unwrap();

    // --- Verification ---
    assert_eq!(plaintext, decrypted.as_slice());
}

#[cfg(feature = "async")]
mod async_workflow_tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_symmetric_async_workflow() {
        // --- Setup ---
        let mut store = SymmetricKeyStore::new();
        let key_id = "async-symmetric-key-01".to_string();
        let key = TestDek::generate_key().unwrap();
        store.add_key(key_id.clone(), key.clone());

        let plaintext = b"This is the async symmetric workflow test.";
        let seal = SymmetricSeal::new();

        // --- Encryption Side ---
        let mut encrypted_data = Vec::new();
        let mut encryptor = seal
            .encrypt::<TestDek>(&key, key_id.clone())
            .into_async_writer(&mut encrypted_data)
            .await
            .unwrap();
        encryptor.write_all(plaintext).await.unwrap();
        encryptor.shutdown().await.unwrap();

        // --- Decryption Side (simulated) ---
        // 1. Peek the key ID asynchronously.
        let pending_decryptor = seal
            .decrypt()
            .async_reader(Cursor::new(&encrypted_data))
            .await
            .unwrap();
        let peeked_id = pending_decryptor.key_id().unwrap();
        assert_eq!(key_id, peeked_id);

        // 2. Get key from store.
        let decryption_key = store.get_key(peeked_id).unwrap();

        // 3. Decrypt asynchronously.
        let mut decrypted_data = Vec::new();
        let mut decryptor = pending_decryptor
            .with_key::<TestDek>(decryption_key.clone())
            .unwrap();
        decryptor.read_to_end(&mut decrypted_data).await.unwrap();

        // --- Verification ---
        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[tokio::test]
    async fn test_hybrid_async_workflow() {
        // --- Setup ---
        let mut store = AsymmetricKeyStore::new();
        let kek_id = "async-hybrid-key-01".to_string();
        let (pk, sk) = TestKem::generate_keypair().unwrap();
        store.add_key(kek_id.clone(), sk.clone());

        let plaintext = b"This is the async hybrid workflow test.";
        let seal = HybridSeal::new();

        // --- Encryption Side ---
        let mut encrypted_data = Vec::new();
        let mut encryptor = seal
            .encrypt::<TestKem, TestDek>(&pk, kek_id.clone())
            .into_async_writer(&mut encrypted_data)
            .await
            .unwrap();
        encryptor.write_all(plaintext).await.unwrap();
        encryptor.shutdown().await.unwrap();

        // --- Decryption Side (simulated) ---
        // 1. Peek the KEK ID asynchronously.
        let pending_decryptor = seal
            .decrypt()
            .async_reader(Cursor::new(&encrypted_data))
            .await
            .unwrap();
        let peeked_id = pending_decryptor.kek_id().unwrap();
        assert_eq!(kek_id, peeked_id);

        // 2. Get key from store.
        let decryption_key = store.get_key(peeked_id).unwrap();

        // 3. Decrypt asynchronously.
        let mut decrypted_data = Vec::new();
        let mut decryptor = pending_decryptor
            .with_private_key::<TestKem, TestDek>(decryption_key.clone())
            .await
            .unwrap();
        decryptor.read_to_end(&mut decrypted_data).await.unwrap();

        // --- Verification ---
        assert_eq!(plaintext, decrypted_data.as_slice());
    }
}
