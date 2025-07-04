//! High-level API for symmetric encryption.
//!
//! This module provides a unified and user-friendly interface for symmetric
//! authenticated encryption (AEAD). It is the recommended entry point for most users
//! who need to encrypt data with a pre-shared key.
//!
//! ## Workflow
//!
//! The symmetric encryption workflow is straightforward:
//! 1.  **Encryption**: Provide a symmetric key, a key identifier, and the plaintext.
//!     The library encrypts the data and prepends a header containing metadata
//!     like the encryption algorithm and the key ID.
//! 2.  **Decryption**: The recipient first reads the header from the ciphertext to learn
//!     which key ID is required. They can then fetch the correct key and use it
//!     to decrypt the data. The library verifies the data's integrity and
//!     authenticity automatically.
//!
//! ## Key-Lookup Safety
//!
//! A key feature of this API is the "safe key-lookup" workflow for decryption.
//! Instead of immediately decrypting, calling `.decrypt()` returns a `pending`
//! decryptor. You can safely inspect this object to get the `key_id` before
//! supplying the actual key. This prevents using the wrong key and allows for
//! efficient key management.
//!
//! Alternatively, you can use a `KeyProvider` to automate the key lookup process.
//!
//! ## Execution Modes
//!
//! The API supports multiple execution modes, similar to the hybrid module:
//! - **In-Memory (Ordinary)**: For data that fits comfortably in memory. (`to_vec`, `slice`)
//! - **In-Memory (Parallel)**: A parallelized version for better performance on multi-core systems.
//!   (`to_vec_parallel`, `slice_parallel`)
//! - **Streaming**: For large files or network streams. (`into_writer`, `reader`)
//! - **Asynchronous Streaming**: For use with async runtimes like Tokio. (`into_async_writer`, `async_reader`)
//!
//! # Example
//!
//! ```no_run
//! use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
//! use seal_flow::prelude::*;
//!
//! // 1. Setup key
//! let key = Aes256Gcm::generate_key().unwrap();
//! let key_wrapped = SymmetricKey::new(key.to_bytes());
//! let key_id = "my-secret-key-v1".to_string();
//!
//! // 2. Encrypt
//! let seal = SymmetricSeal::new();
//! let plaintext = b"secret message";
//! let ciphertext = seal.encrypt(key_wrapped.clone(), key_id)
//!     .to_vec::<Aes256Gcm>(plaintext)
//!     .unwrap();
//!
//! // 3. Decrypt
//! let pending = seal.decrypt().slice(&ciphertext).unwrap();
//! assert_eq!(pending.key_id(), Some("my-secret-key-v1"));
//! let decrypted = pending.with_key(key_wrapped).unwrap();
//!
//! assert_eq!(plaintext, &decrypted[..]);
//! ```
use crate::keys::SymmetricKey;
use decryptor::SymmetricDecryptorBuilder;
use encryptor::SymmetricEncryptor;

pub mod decryptor;
pub mod encryptor;

/// A factory for creating symmetric encryption and decryption executors.
/// This struct is the main entry point for the high-level symmetric API.
/// It is stateless and can be reused for multiple operations.
#[derive(Default)]
pub struct SymmetricSeal;

impl SymmetricSeal {
    /// Creates a new `SymmetricSeal` factory.
    pub fn new() -> Self {
        Self
    }

    /// Begins a symmetric encryption operation.
    ///
    /// This method captures the essential encryption parameters: the `key` to be used
    /// for encryption and a `key_id` to identify it. The `key_id` is stored
    /// in the ciphertext header, allowing a decryptor to know which key to request.
    ///
    /// This returns a `SymmetricEncryptor` context object. You can then chain calls
    /// to configure options (like `.with_aad()`) or call an execution method
    /// (e.g., `.to_vec()`) to perform the encryption.
    pub fn encrypt(&self, key: SymmetricKey, key_id: String) -> SymmetricEncryptor {
        SymmetricEncryptor {
            key,
            key_id,
            aad: None,
        }
    }

    /// Begins a decryption operation.
    ///
    /// This returns a `SymmetricDecryptorBuilder`. You can then use this builder
    /// to specify the source of the ciphertext (e.g., `.slice()` or `.reader()`).
    ///
    /// The builder can also be configured with a `KeyProvider` to automate the
    /// key lookup process during decryption.
    pub fn decrypt(&self) -> SymmetricDecryptorBuilder<'_> {
        SymmetricDecryptorBuilder::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SymmetricKey;
    use seal_crypto::prelude::*;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
    use std::collections::HashMap;
    use std::io::{Cursor, Read, Write};
    #[cfg(feature = "async")]
    use tokio::io::AsyncReadExt;

    const TEST_KEY_ID: &str = "test-key";

    fn get_test_data() -> &'static [u8] {
        b"This is a reasonably long test message to ensure that we cross chunk boundaries."
    }

    #[test]
    fn test_in_memory_roundtrip() {
        let typed_key = Aes256Gcm::generate_key().unwrap();
        let key = SymmetricKey::new(typed_key.to_bytes());
        let plaintext = get_test_data();

        let seal = SymmetricSeal::new();
        let encrypted = seal
            .encrypt(key, TEST_KEY_ID.to_string())
            .to_vec::<Aes256Gcm>(plaintext)
            .unwrap();
        let pending = seal.decrypt().slice(&encrypted).unwrap();
        assert_eq!(pending.key_id(), Some(TEST_KEY_ID));
        let decrypted = pending
            .with_typed_key::<Aes256Gcm>(typed_key.clone())
            .unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_in_memory_parallel_roundtrip() -> crate::Result<()> {
        let typed_key = Aes256Gcm::generate_key()?;
        let key = SymmetricKey::new(typed_key.to_bytes());
        let plaintext = get_test_data();
        let key_id = "test-key-id-2".to_string();
        let seal = SymmetricSeal::new();

        let encrypted = seal
            .encrypt(key, key_id.clone())
            .to_vec_parallel::<Aes256Gcm>(plaintext)?;

        let pending = seal.decrypt().slice_parallel(&encrypted)?;
        assert_eq!(pending.key_id(), Some(key_id.as_str()));
        let decrypted = pending.with_typed_key::<Aes256Gcm>(typed_key.clone())?;

        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_streaming_roundtrip() {
        let mut key_store = HashMap::new();
        let typed_key = Aes256Gcm::generate_key().unwrap();
        let key = SymmetricKey::new(typed_key.to_bytes());
        key_store.insert(TEST_KEY_ID.to_string(), typed_key.clone());

        let plaintext = get_test_data();
        let seal = SymmetricSeal::new();

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor = seal
            .encrypt(key, TEST_KEY_ID.to_string())
            .into_writer::<Aes256Gcm, _>(&mut encrypted_data)
            .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt
        let pending = seal.decrypt().reader(Cursor::new(&encrypted_data)).unwrap();
        let key_id = pending.key_id().unwrap();
        let decryption_key = key_store.get(key_id).unwrap();
        let mut decryptor = pending
            .with_typed_key::<Aes256Gcm>(decryption_key.clone())
            .unwrap();

        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).unwrap();
        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[test]
    fn test_parallel_streaming_roundtrip() -> crate::Result<()> {
        let typed_key = Aes256Gcm::generate_key()?;
        let key = SymmetricKey::new(typed_key.to_bytes());
        let plaintext = get_test_data();
        let key_id = "test-key-id-p-streaming".to_string();
        let seal = SymmetricSeal::new();

        let mut encrypted = Vec::new();
        seal.encrypt(key, key_id.clone())
            .pipe_parallel::<Aes256Gcm, _, _>(Cursor::new(plaintext), &mut encrypted)?;

        let pending = seal.decrypt().reader_parallel(Cursor::new(&encrypted))?;
        assert_eq!(pending.key_id(), Some(key_id.as_str()));

        let mut decrypted = Vec::new();
        pending.with_typed_key_to_writer::<Aes256Gcm, _>(typed_key.clone(), &mut decrypted)?;

        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_with_bytes_roundtrip() -> crate::Result<()> {
        let typed_key = Aes256Gcm::generate_key()?;
        let key_bytes = typed_key.to_bytes();
        let key = SymmetricKey::new(typed_key.to_bytes());
        let plaintext = get_test_data();
        let key_id = "test-key-id-bytes".to_string();
        let seal = SymmetricSeal::new();

        // 使用原始密钥加密
        let encrypted = seal
            .encrypt(key, key_id.clone())
            .to_vec::<Aes256Gcm>(plaintext)?;

        // 使用密钥字节解密
        let pending = seal.decrypt().slice(&encrypted)?;
        assert_eq!(pending.key_id(), Some(key_id.as_str()));
        let decrypted = pending.with_key(SymmetricKey::new(key_bytes))?;

        assert_eq!(plaintext, &decrypted[..]);
        Ok(())
    }

    #[test]
    fn test_aad_in_memory_roundtrip() -> crate::Result<()> {
        let typed_key = Aes256Gcm::generate_key()?;
        let key = SymmetricKey::new(typed_key.to_bytes());
        let plaintext = get_test_data();
        let aad = b"test-associated-data";
        let key_id = "aad-key".to_string();
        let seal = SymmetricSeal::new();

        let encrypted = seal
            .encrypt(key, key_id.clone())
            .with_aad(aad)
            .to_vec::<Aes256Gcm>(plaintext)?;

        // Decrypt with correct AAD
        let pending = seal.decrypt().slice(&encrypted)?;
        assert_eq!(pending.key_id(), Some(key_id.as_str()));
        let decrypted = pending
            .with_aad(aad)
            .with_typed_key::<Aes256Gcm>(typed_key.clone())?;
        assert_eq!(plaintext, decrypted.as_slice());

        // Decrypt with wrong AAD fails
        let pending_fail = seal.decrypt().slice(&encrypted)?;
        let result = pending_fail
            .with_aad(b"wrong-aad")
            .with_typed_key::<Aes256Gcm>(typed_key.clone());
        assert!(result.is_err());

        // Decrypt with no AAD fails
        let pending_fail2 = seal.decrypt().slice(&encrypted)?;
        let result2 = pending_fail2.with_typed_key::<Aes256Gcm>(typed_key);
        assert!(result2.is_err());

        Ok(())
    }

    #[cfg(feature = "async")]
    mod async_tests {
        use super::*;
        use std::collections::HashMap;
        use tokio::io::AsyncWriteExt;

        #[tokio::test]
        async fn test_asynchronous_streaming_roundtrip() {
            let mut key_store = HashMap::new();
            let typed_key = Aes256Gcm::generate_key().unwrap();
            let key = SymmetricKey::new(typed_key.to_bytes());
            key_store.insert(TEST_KEY_ID.to_string(), typed_key.clone());
            let plaintext = get_test_data();

            let seal = SymmetricSeal::new();

            // Encrypt
            let mut encrypted_data = Vec::new();
            let mut encryptor = seal
                .encrypt(key, TEST_KEY_ID.to_string())
                .into_async_writer::<Aes256Gcm, _>(&mut encrypted_data)
                .await
                .unwrap();
            encryptor.write_all(plaintext).await.unwrap();
            encryptor.shutdown().await.unwrap();

            // Decrypt
            let pending = seal
                .decrypt()
                .async_reader(Cursor::new(&encrypted_data))
                .await
                .unwrap();
            let key_id = pending.key_id().unwrap();
            let decryption_key = key_store.get(key_id).unwrap();
            let mut decryptor = pending
                .with_typed_key::<Aes256Gcm>(decryption_key.clone())
                .unwrap();

            let mut decrypted_data = Vec::new();
            decryptor.read_to_end(&mut decrypted_data).await.unwrap();
            assert_eq!(plaintext, decrypted_data.as_slice());
        }
    }
}
