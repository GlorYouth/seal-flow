use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};

use decryptor::HybridDecryptorBuilder;
use encryptor::HybridEncryptor;
use std::marker::PhantomData;

pub mod decryptor;
pub mod encryptor;

/// A factory for creating hybrid encryption and decryption executors.
#[derive(Default)]
pub struct HybridSeal;

impl HybridSeal {
    /// Creates a new `HybridSeal` factory.
    pub fn new() -> Self {
        Self
    }

    /// Begins a hybrid encryption operation.
    ///
    /// This captures the essential encryption parameters (algorithms, public key, KEK ID)
    /// and returns a context object. You can then call methods on this context
    /// to select the desired execution mode (e.g., in-memory, streaming).
    pub fn encrypt<'a, A, S>(
        &self,
        pk: &'a A::PublicKey,
        kek_id: String,
    ) -> HybridEncryptor<'a, A, S>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
    {
        HybridEncryptor {
            pk,
            kek_id,
            aad: None,
            signer: None,
            _phantom: PhantomData,
        }
    }

    /// Begins a hybrid decryption operation.
    ///
    /// This returns a builder that you can use to configure the decryptor
    /// based on the source of the ciphertext (e.g., from a slice or a stream).
    pub fn decrypt(&self) -> HybridDecryptorBuilder {
        HybridDecryptorBuilder::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{AsymmetricPrivateKey, SignaturePublicKey};
    use crate::provider::{AsymmetricKeyProvider, SignatureKeyProvider};
    use crate::Error;
    use once_cell::sync::Lazy;
    use seal_crypto::prelude::*;
    use seal_crypto::schemes::asymmetric::post_quantum::dilithium::Dilithium2;
    use seal_crypto::schemes::{
        asymmetric::traditional::rsa::Rsa2048, hash::Sha256, symmetric::aes_gcm::Aes256Gcm,
    };
    use std::collections::HashMap;
    use std::io::{Cursor, Read, Write};

    #[cfg(feature = "async")]
    const TEST_KEK_ID: &str = "test-kek";

    fn get_test_data() -> &'static [u8] {
        b"This is a reasonably long test message to ensure that we cross chunk boundaries."
    }

    type TestKem = Rsa2048<Sha256>;
    type TestDek = Aes256Gcm;
    type TestSigner = Dilithium2;

    static TEST_KEY_PAIR_RSA2048: Lazy<(
        <TestKem as AsymmetricKeySet>::PublicKey,
        <TestKem as AsymmetricKeySet>::PrivateKey,
    )> = Lazy::new(|| TestKem::generate_keypair().unwrap());

    struct TestKeyProvider {
        keys: HashMap<String, AsymmetricPrivateKey>,
    }

    impl TestKeyProvider {
        fn new() -> Self {
            let mut keys = HashMap::new();
            keys.insert(
                "test-provider-key".to_string(),
                AsymmetricPrivateKey::Rsa2048(TEST_KEY_PAIR_RSA2048.1.clone()),
            );
            Self { keys }
        }
    }

    impl AsymmetricKeyProvider for TestKeyProvider {
        fn get_asymmetric_key(&self, kek_id: &str) -> Option<AsymmetricPrivateKey> {
            self.keys.get(kek_id).cloned()
        }
    }

    struct TestSignatureProvider {
        keys: HashMap<String, SignaturePublicKey>,
    }

    impl TestSignatureProvider {
        fn new() -> Self {
            Self {
                keys: HashMap::new(),
            }
        }
        fn add_key(&mut self, id: String, key: SignaturePublicKey) {
            self.keys.insert(id, key);
        }
    }

    impl SignatureKeyProvider for TestSignatureProvider {
        fn get_signature_key(&self, signer_key_id: &str) -> Option<SignaturePublicKey> {
            self.keys.get(signer_key_id).cloned()
        }
    }

    #[test]
    fn test_in_memory_roundtrip() -> crate::Result<()> {
        let (pk, sk) = TestKem::generate_keypair()?;
        let plaintext = get_test_data();
        let kek_id = "test-kek-id".to_string();
        let seal = HybridSeal::new();

        let encrypted = seal
            .encrypt::<TestKem, TestDek>(&pk, kek_id.clone())
            .to_vec(plaintext)?;

        let pending = seal.decrypt().slice(&encrypted)?;
        assert_eq!(pending.kek_id(), Some(kek_id.as_str()));
        let decrypted = pending.with_private_key::<TestKem, TestDek>(&sk)?;

        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_in_memory_parallel_roundtrip() -> crate::Result<()> {
        let (pk, sk) = TestKem::generate_keypair()?;
        let plaintext = get_test_data();
        let kek_id = "test-kek-id-parallel".to_string();
        let seal = HybridSeal::new();

        let encrypted = seal
            .encrypt::<TestKem, TestDek>(&pk, kek_id.clone())
            .to_vec_parallel(plaintext)?;

        let pending = seal.decrypt().slice_parallel(&encrypted)?;
        assert_eq!(pending.kek_id(), Some(kek_id.as_str()));
        let decrypted = pending.with_private_key::<TestKem, TestDek>(&sk)?;

        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_streaming_roundtrip() {
        let mut key_store = HashMap::new();
        let (pk, sk) = TestKem::generate_keypair().unwrap();
        key_store.insert(TEST_KEK_ID.to_string(), sk);

        let plaintext = get_test_data();
        let seal = HybridSeal::new();

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor = seal
            .encrypt::<TestKem, TestDek>(&pk, TEST_KEK_ID.to_string())
            .into_writer(&mut encrypted_data)
            .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt
        let pending = seal.decrypt().reader(Cursor::new(encrypted_data)).unwrap();
        let kek_id = pending.kek_id().unwrap();
        let decryption_key = key_store.get(kek_id).unwrap();
        let mut decryptor = pending
            .with_private_key::<TestKem, TestDek>(decryption_key)
            .unwrap();

        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted_data);
    }

    #[test]
    fn test_parallel_streaming_roundtrip() -> crate::Result<()> {
        let (pk, sk) = TestKem::generate_keypair()?;
        let plaintext = get_test_data();
        let kek_id = "test-kek-id-p-streaming".to_string();
        let seal = HybridSeal::new();

        let mut encrypted = Vec::new();
        seal.encrypt::<TestKem, TestDek>(&pk, kek_id.clone())
            .pipe_parallel(Cursor::new(plaintext), &mut encrypted)?;

        let pending = seal.decrypt().reader_parallel(Cursor::new(&encrypted))?;
        assert_eq!(pending.kek_id(), Some(kek_id.as_str()));

        let mut decrypted = Vec::new();
        pending.with_private_key_to_writer::<TestKem, TestDek, _>(&sk, &mut decrypted)?;

        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_with_provider_roundtrip() -> crate::Result<()> {
        let provider = TestKeyProvider::new();
        let kek_id = "test-provider-key".to_string();

        let pk = &TEST_KEY_PAIR_RSA2048.0;

        let plaintext = get_test_data();
        let seal = HybridSeal::new();

        let encrypted = seal
            .encrypt::<TestKem, TestDek>(pk, kek_id.clone())
            .to_vec(plaintext)?;

        let pending = seal.decrypt().slice(&encrypted)?;
        assert_eq!(pending.kek_id(), Some(kek_id.as_str()));
        let decrypted = pending.with_provider::<_, TestDek>(&provider)?;

        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_aad_roundtrip() -> crate::Result<()> {
        let (pk, sk) = TestKem::generate_keypair()?;
        let plaintext = get_test_data();
        let aad = b"test-associated-data-for-hybrid";
        let kek_id = "aad-kek".to_string();
        let seal = HybridSeal::new();

        // Encrypt with AAD
        let encrypted = seal
            .encrypt::<TestKem, TestDek>(&pk, kek_id.clone())
            .with_aad(aad)
            .to_vec(plaintext)?;

        // Decrypt with correct AAD
        let pending = seal.decrypt().slice(&encrypted)?;
        assert_eq!(pending.kek_id(), Some(kek_id.as_str()));
        let decrypted = pending
            .with_aad(aad)
            .with_private_key::<TestKem, TestDek>(&sk)?;
        assert_eq!(plaintext, decrypted.as_slice());

        // Decrypt with wrong AAD fails
        let pending_fail = seal.decrypt().slice(&encrypted)?;
        let result = pending_fail
            .with_aad(b"wrong-aad")
            .with_private_key::<TestKem, TestDek>(&sk);
        assert!(result.is_err());

        // Decrypt with no AAD fails
        let pending_fail2 = seal.decrypt().slice(&encrypted)?;
        let result2 = pending_fail2.with_private_key::<TestKem, TestDek>(&sk);
        assert!(result2.is_err());

        Ok(())
    }

    #[test]
    fn test_signed_aad_tampering_fails() -> crate::Result<()> {
        // 1. Setup keys
        let (enc_pk, enc_sk) = TestKem::generate_keypair()?;
        let (sig_pk, sig_sk) = TestSigner::generate_keypair()?;

        // 2. Setup provider for verifier
        let signer_key_id = "test-signer-key-mem".to_string();
        let mut sig_provider = TestSignatureProvider::new();
        sig_provider.add_key(
            signer_key_id.clone(),
            SignaturePublicKey::Dilithium2(sig_pk),
        );

        let plaintext = get_test_data();
        let aad = b"test-signed-aad-memory";
        let kek_id = "test-signed-aad-kek-mem".to_string();
        let seal = HybridSeal::new();

        // 3. Encrypt with signer and AAD
        let encrypted = seal
            .encrypt::<TestKem, TestDek>(&enc_pk, kek_id)
            .with_aad(aad)
            .with_signer::<TestSigner>(sig_sk, signer_key_id.clone())
            .to_vec(plaintext)?;

        // 4. Successful roundtrip with correct verifier and AAD
        let decrypted = seal
            .decrypt()
            .slice(&encrypted)?
            .with_aad(aad)
            .with_verifier(&sig_provider)?
            .with_private_key::<TestKem, TestDek>(&enc_sk)?;
        assert_eq!(decrypted.as_slice(), plaintext);

        // 5. Fails with wrong AAD
        let res = seal
            .decrypt()
            .slice(&encrypted)?
            .with_aad(b"wrong aad")
            .with_verifier(&sig_provider)?
            .with_private_key::<TestKem, TestDek>(&enc_sk);
        assert!(res.is_err(), "Decryption should fail with wrong AAD");
        assert!(matches!(res.err(), Some(Error::Crypto(_))));

        // 6. Fails with no AAD
        let res2 = seal
            .decrypt()
            .slice(&encrypted)?
            .with_verifier(&sig_provider)?
            .with_private_key::<TestKem, TestDek>(&enc_sk);
        assert!(res2.is_err(), "Decryption should fail with no AAD");

        Ok(())
    }

    #[cfg(feature = "async")]
    mod async_tests {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        #[tokio::test]
        async fn test_asynchronous_streaming_roundtrip() {
            let mut key_store = HashMap::new();
            let (pk, sk) = TestKem::generate_keypair().unwrap();
            key_store.insert(TEST_KEK_ID.to_string(), sk.clone());

            let plaintext = get_test_data();
            let seal = HybridSeal::new();

            // Encrypt
            let mut encrypted_data = Vec::new();
            let mut encryptor = seal
                .encrypt::<TestKem, TestDek>(&pk, TEST_KEK_ID.to_string())
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
            let kek_id = pending.kek_id().unwrap();
            let decryption_key = key_store.get(kek_id).unwrap();
            let mut decryptor = pending
                .with_private_key::<TestKem, TestDek>(decryption_key.clone())
                .await
                .unwrap();

            let mut decrypted_data = Vec::new();
            decryptor.read_to_end(&mut decrypted_data).await.unwrap();
            assert_eq!(plaintext.to_vec(), decrypted_data);
        }

        #[tokio::test]
        async fn test_async_signed_aad_tampering_fails() -> crate::Result<()> {
            let (enc_pk, enc_sk) = TestKem::generate_keypair()?;
            let (sig_pk, sig_sk) = TestSigner::generate_keypair()?;

            let signer_key_id = "test-signer-key-async".to_string();
            let mut sig_provider = TestSignatureProvider::new();
            sig_provider.add_key(
                signer_key_id.clone(),
                SignaturePublicKey::Dilithium2(sig_pk),
            );

            let plaintext = get_test_data();
            let aad = b"test-signed-aad-async";
            let kek_id = "test-signed-aad-kek-async".to_string();
            let seal = HybridSeal::new();

            // Encrypt
            let mut encrypted = Vec::new();
            let mut encryptor = seal
                .encrypt::<TestKem, TestDek>(&enc_pk, kek_id)
                .with_aad(aad)
                .with_signer::<TestSigner>(sig_sk, signer_key_id)
                .into_async_writer(&mut encrypted)
                .await?;
            encryptor.write_all(plaintext).await?;
            encryptor.shutdown().await?;

            // Successful roundtrip
            let mut decryptor = seal
                .decrypt()
                .async_reader(Cursor::new(&encrypted))
                .await?
                .with_aad(aad)
                .with_verifier(&sig_provider)
                .await?
                .with_private_key::<TestKem, TestDek>(enc_sk.clone())
                .await?;
            let mut decrypted_ok = Vec::new();
            decryptor.read_to_end(&mut decrypted_ok).await?;
            assert_eq!(decrypted_ok, plaintext);

            // Fails with wrong AAD
            let res = seal
                .decrypt()
                .async_reader(Cursor::new(&encrypted))
                .await?
                .with_aad(b"wrong-aad")
                .with_verifier(&sig_provider)
                .await?
                .with_private_key::<TestKem, TestDek>(enc_sk.clone())
                .await;
            assert!(res.is_err());

            Ok(())
        }
    }
}
