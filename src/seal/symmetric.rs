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
//! ``` ignore
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
//!
//! 对称加密的高级 API。
//!
//! 该模块为对称认证加密 (AEAD) 提供了一个统一且用户友好的界面。
//! 对于需要使用预共享密钥加密数据的大多数用户来说，这是推荐的入口点。
//!
//! ## 工作流程
//!
//! 对称加密的工作流程非常直接：
//! 1.  **加密**：提供一个对称密钥、一个密钥标识符和明文。
//!     库会加密数据，并在其前面附加一个包含元数据（如加密算法和密钥 ID）的标头。
//! 2.  **解密**：接收方首先从密文中读取标头，以了解需要哪个密钥 ID。
//!     然后，他们可以获取正确的密钥并用它来解密数据。库会自动验证数据的完整性和真实性。
//!
//! ## 密钥查找安全
//!
//! 该 API 的一个关键特性是用于解密的"安全密钥查找"工作流程。
//! 调用 `.decrypt()` 不会立即解密，而是返回一个 `pending`（待处理）解密器。
//! 您可以安全地检查此对象以获取 `key_id`，然后再提供实际的密钥。
//! 这可以防止使用错误的密钥，并实现高效的密钥管理。
//!
//! 或者，您可以使用 `KeyProvider` 来自动化密钥查找过程。
//!
//! ## 执行模式
//!
//! 该 API 支持多种执行模式，类似于混合加密模块：
//! - **内存中（普通）**：适用于可轻松容纳于内存的数据。(`to_vec`, `slice`)
//! - **内存中（并行）**：并行化版本，可在多核系统上提供更好的性能。
//!   (`to_vec_parallel`, `slice_parallel`)
//! - **流式**：适用于不应完全加载到内存中的大文件或网络流。(`into_writer`, `reader`)
//! - **异步流式**：用于与 Tokio 等异步运行时配合使用。(`into_async_writer`, `async_reader`)
//!
//! # 示例
//!
//! ``` ignore
//! use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
//! use seal_flow::prelude::*;
//!
//! // 1. 设置密钥
//! let key = Aes256Gcm::generate_key().unwrap();
//! let key_wrapped = SymmetricKey::new(key.to_bytes());
//! let key_id = "my-secret-key-v1".to_string();
//!
//! // 2. 加密
//! let seal = SymmetricSeal::new();
//! let plaintext = b"secret message";
//! let ciphertext = seal.encrypt(key_wrapped.clone(), key_id)
//!     .to_vec::<Aes256Gcm>(plaintext)
//!     .unwrap();
//!
//! // 3. 解密
//! let pending = seal.decrypt().slice(&ciphertext).unwrap();
//! assert_eq!(pending.key_id(), Some("my-secret-key-v1"));
//! let decrypted = pending.with_key(key_wrapped).unwrap();
//!
//! assert_eq!(plaintext, &decrypted[..]);
//! ```
use crate::{algorithms::symmetric::SymmetricAlgorithmWrapper, keys::SymmetricKey, prelude::SymmetricAlgorithmEnum};
use decryptor::SymmetricDecryptorBuilder;
use encryptor::SymmetricEncryptor;

pub mod decryptor;
pub mod encryptor;

/// A factory for creating symmetric encryption and decryption executors.
/// This struct is the main entry point for the high-level symmetric API.
/// It is stateless and can be reused for multiple operations.
///
/// 用于创建对称加密和解密执行器的工厂。
/// 这个结构体是高级对称 API 的主要入口点。
/// 它是无状态的，可以重复用于多个操作。
pub struct SymmetricSeal;

impl SymmetricSeal {
    /// Creates a new `SymmetricSeal` factory.
    ///
    /// 创建一个新的 `SymmetricSeal` 工厂。
    pub fn new(algorithm: SymmetricAlgorithmEnum) -> Self {
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
    ///
    /// 开始一个对称加密操作。
    ///
    /// 此方法捕获了基本的加密参数：用于加密的 `key` 和用于标识它的 `key_id`。
    /// `key_id` 存储在密文头部，允许解密器知道要请求哪个密钥。
    ///
    /// 这将返回一个 `SymmetricEncryptor` 上下文对象。然后，您可以链式调用以配置选项
    ///（如 `.with_aad()`）或调用执行方法（如 `.to_vec()`）来执行加密。
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
    ///
    /// 开始一个解密操作。
    ///
    /// 这将返回一个 `SymmetricDecryptorBuilder`。然后，您可以使用此构建器来指定
    /// 密文的来源（例如 `.slice()` 或 `.reader()`）。
    ///
    /// 该构建器还可以配置一个 `KeyProvider`，以在解密期间自动执行密钥查找过程。
    pub fn decrypt(&self) -> SymmetricDecryptorBuilder {
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
    use crate::prelude::{InMemoryEncryptor, StreamingEncryptor};
    use crate::seal::traits::{InMemoryDecryptor, WithAad};
    const TEST_KEY_ID: &str = "test-key";

    fn get_test_data() -> &'static [u8] {
        b"This is a reasonably long test message to ensure that we cross chunk boundaries."
    }

    #[test]
    fn test_in_memory_roundtrip() {
        let typed_key = Aes256Gcm::generate_key().unwrap();
        let key = SymmetricKey::new(typed_key.to_bytes());
        let plaintext = get_test_data();

        let seal = SymmetricSeal::new(SymmetricAlgorithmEnum::Aes256Gcm);
        let encrypted = seal
            .encrypt(key.clone(), TEST_KEY_ID.to_string())
            .execute_with(SymmetricAlgorithmEnum::Aes256Gcm)
            .to_vec(plaintext)
            .unwrap();
        let pending = seal.decrypt().slice(&encrypted).unwrap();
        assert_eq!(pending.key_id(), Some(TEST_KEY_ID));
        let decrypted = pending.with_key_to_vec(key).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_in_memory_parallel_roundtrip() -> crate::Result<()> {
        let typed_key = Aes256Gcm::generate_key()?;
        let key = SymmetricKey::new(typed_key.to_bytes());
        let plaintext = get_test_data();
        let key_id = "test-key-id-2".to_string();
        let seal = SymmetricSeal::new(SymmetricAlgorithmEnum::Aes256Gcm);

        let encrypted = seal
            .encrypt(key.clone(), key_id.clone())
            .execute_with(SymmetricAlgorithmEnum::Aes256Gcm)
            .to_vec_parallel(plaintext)?;

        let pending = seal.decrypt().slice_parallel(&encrypted)?;
        assert_eq!(pending.key_id(), Some(key_id.as_str()));
        let decrypted = pending.with_key_to_vec(key)?;

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
        let seal = SymmetricSeal::new(SymmetricAlgorithmEnum::Aes256Gcm);

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor = seal
            .encrypt(key.clone(), TEST_KEY_ID.to_string())
            .execute_with(SymmetricAlgorithmEnum::Aes256Gcm)
            .into_writer(&mut encrypted_data)
            .unwrap();
        encryptor.write_all(plaintext).unwrap();
        drop(encryptor);

        // Decrypt
        let pending = seal
            .decrypt()
            .reader(Cursor::new(&encrypted_data))
            .unwrap();
        let key_id = pending.key_id().unwrap();
        let _decryption_key = key_store.get(key_id).unwrap();
        let mut decryptor = pending.with_key_to_reader(key).unwrap();

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
        let seal = SymmetricSeal::new(SymmetricAlgorithmEnum::Aes256Gcm);

        let mut encrypted = Vec::new();
        seal.encrypt(key.clone(), key_id.clone())
            .execute_with(SymmetricAlgorithmEnum::Aes256Gcm)
            .pipe_parallel(Cursor::new(plaintext), &mut encrypted)?;

        let pending = seal
            .decrypt()
            .reader_parallel(Cursor::new(&encrypted))?;
        assert_eq!(pending.key_id(), Some(key_id.as_str()));

        let mut decrypted = Vec::new();
        pending.with_key_to_writer(key, &mut decrypted)?;

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
        let seal = SymmetricSeal::new(SymmetricAlgorithmEnum::Aes256Gcm);

        // 使用原始密钥加密
        let encrypted = seal
            .encrypt(key.clone(), key_id.clone())
            .execute_with(SymmetricAlgorithmEnum::Aes256Gcm)
            .to_vec(plaintext)?;

        // 使用密钥字节解密
        let pending = seal.decrypt().slice(&encrypted)?;
        assert_eq!(pending.key_id(), Some(key_id.as_str()));
        let decrypted = pending.with_key_to_vec(key)?;

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
        let seal = SymmetricSeal::new(SymmetricAlgorithmEnum::Aes256Gcm);

        let encrypted = seal
            .encrypt(key.clone(), key_id.clone())
            .with_aad(aad)
            .execute_with(SymmetricAlgorithmEnum::Aes256Gcm)
            .to_vec(plaintext)?;

        // Decrypt with correct AAD
        let pending = seal.decrypt().with_aad(aad).slice(&encrypted)?;
        assert_eq!(pending.key_id(), Some(key_id.as_str()));
        let decrypted = pending.with_key_to_vec(key.clone())?;
        assert_eq!(plaintext, decrypted.as_slice());

        // Decrypt with wrong AAD fails
        let pending_fail = seal
            .decrypt()
            .with_aad(b"wrong-aad")
            .slice(&encrypted)?;
        let result = pending_fail.with_key_to_vec(key.clone());
        assert!(result.is_err());

        // Decrypt with no AAD fails
        let pending_fail2 = seal.decrypt().slice(&encrypted)?;
        let result2 = pending_fail2.with_key_to_vec(key);
        assert!(result2.is_err());

        Ok(())
    }

    #[cfg(feature = "async")]
    mod async_tests {
        use super::*;
        use std::collections::HashMap;
        use tokio::io::AsyncWriteExt;
        use crate::prelude::AsyncStreamingEncryptor;

        #[tokio::test]
        async fn test_asynchronous_streaming_roundtrip() {
            let mut key_store = HashMap::new();
            let typed_key = Aes256Gcm::generate_key().unwrap();
            let key = SymmetricKey::new(typed_key.to_bytes());
            key_store.insert(TEST_KEY_ID.to_string(), typed_key.clone());
            let plaintext = get_test_data();

            let seal = SymmetricSeal::new(SymmetricAlgorithmEnum::Aes256Gcm);

            // Encrypt
            let mut encrypted_data = Vec::new();
            let mut encryptor = seal
                .encrypt(key.clone(), TEST_KEY_ID.to_string())
                .execute_with(SymmetricAlgorithmEnum::Aes256Gcm)
                .into_async_writer(&mut encrypted_data)
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
            let _decryption_key = key_store.get(key_id).unwrap();
            let mut decryptor = pending
                .with_key_to_async_reader(key)
                .await
                .unwrap();

            let mut decrypted_data = Vec::new();
            decryptor.read_to_end(&mut decrypted_data).await.unwrap();
            assert_eq!(plaintext, decrypted_data.as_slice());
        }
    }
}
