use crate::keys::SymmetricKey;
use decryptor::SymmetricDecryptorBuilder;
use encryptor::SymmetricEncryptor;

pub mod decryptor;
pub mod encryptor;

/// A factory for creating symmetric encryption and decryption executors.
/// This struct is the main entry point for the high-level symmetric API.
#[derive(Default)]
pub struct SymmetricSeal;

impl SymmetricSeal {
    /// Creates a new `SymmetricSeal` factory.
    pub fn new() -> Self {
        Self
    }

    /// Begins a symmetric encryption operation.
    ///
    /// This captures the essential encryption parameters (key, key ID)
    /// and returns a context object. You can then call methods on this context
    /// to select the desired execution mode (e.g., in-memory, streaming).
    pub fn encrypt(&self, key: SymmetricKey, key_id: String) -> SymmetricEncryptor {
        SymmetricEncryptor {
            key,
            key_id,
            aad: None,
        }
    }

    /// Begins a decryption operation.
    ///
    /// This returns a builder that you can use to configure the decryptor
    /// based on the source of the ciphertext (e.g., from a slice or a stream).
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
