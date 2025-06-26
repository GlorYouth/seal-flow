//! Integration tests for the complete encryption/decryption workflow.
//!
//! These tests simulate a real-world scenario where a key store is used
//! to look up keys based on the ID peeked from the ciphertext header.

use seal_crypto::schemes::asymmetric::traditional::rsa::Rsa2048;
use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm as TestDek;
use seal_crypto::{prelude::*, schemes::hash::Sha256};
use seal_flow::seal::{
    hybrid::HybridSeal, peek_hybrid_kek_id, peek_symmetric_key_id, symmetric::SymmetricSeal,
};
use std::collections::HashMap;
use std::io::Cursor;

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

    // --- Encryption Side ---
    let encrypted = SymmetricSeal::new(&key)
        .in_memory::<TestDek>()
        .encrypt(plaintext, key_id.clone())
        .unwrap();

    // --- Decryption Side (simulated) ---
    // 1. Peek the key ID from the header.
    let peeked_id = peek_symmetric_key_id(Cursor::new(&encrypted)).unwrap();
    assert_eq!(key_id, peeked_id);

    // 2. Use the ID to get the correct key from the store.
    let decryption_key = store.get_key(&peeked_id).unwrap();

    // 3. Decrypt using the retrieved key.
    let decrypted = SymmetricSeal::new(decryption_key)
        .in_memory::<TestDek>()
        .decrypt(&encrypted)
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

    // --- Encryption Side ---
    let encrypted = HybridSeal::<TestKem>::new_encrypt(&pk)
        .in_memory::<TestDek>()
        .encrypt(plaintext, kek_id.clone())
        .unwrap();

    // --- Decryption Side (simulated) ---
    // 1. Peek the KEK ID from the header.
    let peeked_id = peek_hybrid_kek_id(Cursor::new(&encrypted)).unwrap();
    assert_eq!(kek_id, peeked_id);

    // 2. Use the ID to get the correct private key from the store.
    let decryption_key = store.get_key(&peeked_id).unwrap();

    // 3. Decrypt using the retrieved private key.
    let decrypted = HybridSeal::<TestKem>::new_decrypt(decryption_key)
        .in_memory::<TestDek>()
        .decrypt(&encrypted)
        .unwrap();

    // --- Verification ---
    assert_eq!(plaintext, decrypted.as_slice());
}

#[cfg(feature = "async")]
mod async_workflow_tests {
    use super::*;
    use seal_flow::seal::{peek_hybrid_kek_id_async, peek_symmetric_key_id_async};
    use std::io::Cursor;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_symmetric_async_workflow() {
        // --- Setup ---
        let mut store = SymmetricKeyStore::new();
        let key_id = "async-symmetric-key-01".to_string();
        let key = TestDek::generate_key().unwrap();
        store.add_key(key_id.clone(), key.clone());

        let plaintext = b"This is the async symmetric workflow test.";

        // --- Encryption Side ---
        let mut encrypted_data = Vec::new();
        let mut encryptor = SymmetricSeal::new(&key)
            .asynchronous::<TestDek>()
            .encryptor(&mut encrypted_data, key_id.clone())
            .await
            .unwrap();
        tokio::io::copy(&mut Cursor::new(plaintext), &mut encryptor)
            .await
            .unwrap();
        encryptor.shutdown().await.unwrap();

        // --- Decryption Side (simulated) ---
        // 1. Peek the key ID asynchronously.
        let peeked_id = peek_symmetric_key_id_async(Cursor::new(&encrypted_data))
            .await
            .unwrap();
        assert_eq!(key_id, peeked_id);

        // 2. Get key from store.
        let decryption_key = store.get_key(&peeked_id).unwrap();

        // 3. Decrypt asynchronously.
        let mut decrypted_data = Vec::new();
        let mut decryptor = SymmetricSeal::new(decryption_key)
            .asynchronous::<TestDek>()
            .decryptor(Cursor::new(&encrypted_data))
            .await
            .unwrap();
        tokio::io::copy(&mut decryptor, &mut decrypted_data)
            .await
            .unwrap();

        // --- Verification ---
        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[tokio::test]
    async fn test_hybrid_async_workflow() {
        // --- Setup ---
        let mut store = AsymmetricKeyStore::new();
        let kek_id = "async-hybrid-key-01".to_string();
        let (pk, sk) = TestKem::generate_keypair().unwrap();
        store.add_key(kek_id.clone(), sk);

        let plaintext = b"This is the async hybrid workflow test.";

        // --- Encryption Side ---
        let mut encrypted_data = Vec::new();
        let mut encryptor = HybridSeal::<TestKem>::new_encrypt(&pk)
            .asynchronous::<TestDek>()
            .encryptor(&mut encrypted_data, kek_id.clone())
            .await
            .unwrap();
        tokio::io::copy(&mut Cursor::new(plaintext), &mut encryptor)
            .await
            .unwrap();
        encryptor.shutdown().await.unwrap();

        // --- Decryption Side (simulated) ---
        // 1. Peek the KEK ID asynchronously.
        let peeked_id = peek_hybrid_kek_id_async(Cursor::new(&encrypted_data))
            .await
            .unwrap();
        assert_eq!(kek_id, peeked_id);

        // 2. Get key from store.
        let decryption_key = store.get_key(&peeked_id).unwrap();

        // 3. Decrypt asynchronously.
        let mut decrypted_data = Vec::new();
        let mut decryptor = HybridSeal::<TestKem>::new_decrypt(decryption_key)
            .asynchronous::<TestDek>()
            .decryptor(Cursor::new(&encrypted_data))
            .await
            .unwrap();
        tokio::io::copy(&mut decryptor, &mut decrypted_data)
            .await
            .unwrap();

        // --- Verification ---
        assert_eq!(plaintext, decrypted_data.as_slice());
    }
}
