use crate::algorithms::traits::SymmetricAlgorithm;
use crate::keys::AsymmetricPublicKey;

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
    pub fn encrypt<S>(&self, pk: AsymmetricPublicKey, kek_id: String) -> HybridEncryptor<S>
    where
        S: SymmetricAlgorithm,
    {
        HybridEncryptor {
            pk,
            kek_id,
            aad: None,
            signer: None,
            derivation_config: None,
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
    use crate::Error;
    use seal_crypto::prelude::*;
    use seal_crypto::schemes::asymmetric::post_quantum::dilithium::Dilithium2;
    use seal_crypto::schemes::kdf::hkdf::HkdfSha256;
    use seal_crypto::schemes::xof::shake::Shake256;
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

    #[test]
    fn test_in_memory_roundtrip() -> crate::Result<()> {
        let (pk, sk) = TestKem::generate_keypair()?;
        let pk_wrapped = AsymmetricPublicKey::new(pk.to_bytes());
        let plaintext = get_test_data();
        let kek_id = "test-kek-id".to_string();
        let seal = HybridSeal::new();

        let encrypted = seal
            .encrypt::<TestDek>(pk_wrapped, kek_id.clone())
            .to_vec::<TestKem>(plaintext)?;

        let pending = seal.decrypt().slice(&encrypted)?;
        assert_eq!(pending.kek_id(), Some(kek_id.as_str()));
        let decrypted = pending.with_typed_key::<TestKem, TestDek>(&sk)?;

        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_in_memory_parallel_roundtrip() -> crate::Result<()> {
        let (pk, sk) = TestKem::generate_keypair()?;
        let pk_wrapped = AsymmetricPublicKey::new(pk.to_bytes());
        let plaintext = get_test_data();
        let kek_id = "test-kek-id-parallel".to_string();
        let seal = HybridSeal::new();

        let encrypted = seal
            .encrypt::<TestDek>(pk_wrapped, kek_id.clone())
            .to_vec_parallel::<TestKem>(plaintext)?;

        let pending = seal.decrypt().slice_parallel(&encrypted)?;
        assert_eq!(pending.kek_id(), Some(kek_id.as_str()));
        let decrypted = pending.with_typed_key::<TestKem, TestDek>(&sk)?;

        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_streaming_roundtrip() {
        let mut key_store = HashMap::new();
        let (pk, sk) = TestKem::generate_keypair().unwrap();
        let pk_wrapped = AsymmetricPublicKey::new(pk.to_bytes());
        key_store.insert(TEST_KEK_ID.to_string(), sk);

        let plaintext = get_test_data();
        let seal = HybridSeal::new();

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor = seal
            .encrypt::<TestDek>(pk_wrapped, TEST_KEK_ID.to_string())
            .into_writer::<TestKem, _>(&mut encrypted_data)
            .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt
        let pending = seal.decrypt().reader(Cursor::new(encrypted_data)).unwrap();
        let kek_id = pending.kek_id().unwrap();
        let decryption_key = key_store.get(kek_id).unwrap();
        let mut decryptor = pending
            .with_typed_key::<TestKem, TestDek>(decryption_key)
            .unwrap();

        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted_data);
    }

    #[test]
    fn test_parallel_streaming_roundtrip() -> crate::Result<()> {
        let (pk, sk) = TestKem::generate_keypair()?;
        let pk_wrapped = AsymmetricPublicKey::new(pk.to_bytes());
        let plaintext = get_test_data();
        let kek_id = "test-kek-id-p-streaming".to_string();
        let seal = HybridSeal::new();

        let mut encrypted = Vec::new();
        seal.encrypt::<TestDek>(pk_wrapped, kek_id.clone())
            .pipe_parallel::<TestKem, _, _>(Cursor::new(plaintext), &mut encrypted)?;

        let pending = seal.decrypt().reader_parallel(Cursor::new(&encrypted))?;
        assert_eq!(pending.kek_id(), Some(kek_id.as_str()));

        let mut decrypted = Vec::new();
        pending.with_typed_key_to_writer::<TestKem, TestDek, _>(&sk, &mut decrypted)?;

        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_with_key_bytes_roundtrip() -> crate::Result<()> {
        let (pk, sk) = TestKem::generate_keypair()?;
        let pk_wrapped = AsymmetricPublicKey::new(pk.to_bytes());
        let sk_wrapped = AsymmetricPrivateKey::new(sk.to_bytes());
        let plaintext = get_test_data();
        let kek_id = "test-kek-id-bytes".to_string();
        let seal = HybridSeal::new();

        let encrypted = seal
            .encrypt::<TestDek>(pk_wrapped, kek_id.clone())
            .to_vec::<TestKem>(plaintext)?;

        let pending = seal.decrypt().slice(&encrypted)?;
        assert_eq!(pending.kek_id(), Some(kek_id.as_str()));
        let decrypted = pending.with_key::<TestDek>(sk_wrapped)?;

        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_aad_roundtrip() -> crate::Result<()> {
        let (pk, sk) = TestKem::generate_keypair()?;
        let pk_wrapped = AsymmetricPublicKey::new(pk.to_bytes());
        let plaintext = get_test_data();
        let aad = b"test-associated-data-for-hybrid";
        let kek_id = "aad-kek".to_string();
        let seal = HybridSeal::new();

        // Encrypt with AAD
        let encrypted = seal
            .encrypt::<TestDek>(pk_wrapped, kek_id.clone())
            .with_aad(aad)
            .to_vec::<TestKem>(plaintext)?;

        // Decrypt with correct AAD
        let pending = seal.decrypt().slice(&encrypted)?;
        assert_eq!(pending.kek_id(), Some(kek_id.as_str()));
        let decrypted = pending
            .with_aad(aad)
            .with_typed_key::<TestKem, TestDek>(&sk)?;
        assert_eq!(plaintext, decrypted.as_slice());

        // Decrypt with wrong AAD fails
        let pending_fail = seal.decrypt().slice(&encrypted)?;
        let result = pending_fail
            .with_aad(b"wrong-aad")
            .with_typed_key::<TestKem, TestDek>(&sk);
        assert!(result.is_err());

        // Decrypt with no AAD fails
        let pending_fail2 = seal.decrypt().slice(&encrypted)?;
        let result2 = pending_fail2.with_typed_key::<TestKem, TestDek>(&sk);
        assert!(result2.is_err());

        Ok(())
    }

    #[test]
    fn test_signed_aad_tampering_fails() -> crate::Result<()> {
        // 1. Setup keys
        let (enc_pk, enc_sk) = TestKem::generate_keypair()?;
        let enc_pk_wrapped = AsymmetricPublicKey::new(enc_pk.to_bytes());
        let (sig_pk, sig_sk) = TestSigner::generate_keypair()?;
        let sig_sk_wrapped = AsymmetricPrivateKey::new(sig_sk.to_bytes());
        let sig_pk_bytes = sig_pk.to_bytes();

        // 2. Setup verification key
        let signer_key_id = "test-signer-key-mem".to_string();
        let verification_key = SignaturePublicKey::new(sig_pk_bytes);

        let plaintext = get_test_data();
        let aad = b"test-signed-aad-memory";
        let kek_id = "test-signed-aad-kek-mem".to_string();
        let seal = HybridSeal::new();

        // 3. Encrypt with signer and AAD
        let encrypted = seal
            .encrypt::<TestDek>(enc_pk_wrapped, kek_id)
            .with_aad(aad)
            .with_signer::<TestSigner>(sig_sk_wrapped, signer_key_id.clone())
            .to_vec::<TestKem>(plaintext)?;

        // 4. Successful roundtrip with correct verifier and AAD
        let decrypted = seal
            .decrypt()
            .slice(&encrypted)?
            .with_aad(aad)
            .with_verification_key(verification_key.clone())?
            .with_typed_key::<TestKem, TestDek>(&enc_sk)?;
        assert_eq!(decrypted.as_slice(), plaintext);

        // 5. Fails with wrong AAD
        let res = seal
            .decrypt()
            .slice(&encrypted)?
            .with_aad(b"wrong aad")
            .with_verification_key(verification_key.clone())?
            .with_typed_key::<TestKem, TestDek>(&enc_sk);
        assert!(res.is_err(), "Decryption should fail with wrong AAD");
        assert!(matches!(res.err(), Some(Error::Crypto(_))));

        // 6. Fails with no AAD
        let res2 = seal
            .decrypt()
            .slice(&encrypted)?
            .with_verification_key(verification_key)?
            .with_typed_key::<TestKem, TestDek>(&enc_sk);
        assert!(res2.is_err(), "Decryption should fail with no AAD");

        Ok(())
    }

    #[test]
    fn test_kdf_roundtrip_all_modes() -> crate::Result<()> {
        // 1. Setup
        let (pk, sk) = TestKem::generate_keypair()?;
        let pk_wrapped = AsymmetricPublicKey::new(pk.to_bytes());
        let plaintext = get_test_data();
        let aad = b"test-aad-for-kdf-roundtrip";
        let kek_id = "test-kdf-kek-id".to_string();
        let salt = b"kdf-salt";
        let info = b"kdf-info";
        let seal = HybridSeal::new();
        type Kdf = HkdfSha256;

        // 2. Encryption with KDF
        // We also add AAD to ensure it works together with KDF.
        let encrypted = seal
            .encrypt::<TestDek>(pk_wrapped, kek_id.clone())
            .with_aad(aad)
            .with_kdf(
                Kdf::default(),
                Some(salt),
                Some(info),
                <TestDek as SymmetricCipher>::KEY_SIZE as u32,
            )
            .to_vec::<TestKem>(plaintext)?;

        // 3. Decryption tests for all sync modes

        // Mode 1: In-memory (`slice`)
        let decrypted1 = seal
            .decrypt()
            .slice(&encrypted)?
            .with_aad(aad)
            .with_typed_key::<TestKem, TestDek>(&sk)?;
        assert_eq!(
            plaintext,
            decrypted1.as_slice(),
            "In-memory KDF mode failed"
        );

        // Mode 2: In-memory parallel (`slice_parallel`)
        let decrypted2 = seal
            .decrypt()
            .slice_parallel(&encrypted)?
            .with_aad(aad)
            .with_typed_key::<TestKem, TestDek>(&sk)?;
        assert_eq!(
            plaintext,
            decrypted2.as_slice(),
            "In-memory parallel KDF mode failed"
        );

        // Mode 3: Streaming (`reader`)
        let pending3 = seal.decrypt().reader(Cursor::new(encrypted.clone()))?;
        let mut decryptor3 = pending3
            .with_aad(aad)
            .with_typed_key::<TestKem, TestDek>(&sk)?;
        let mut decrypted3 = Vec::new();
        decryptor3.read_to_end(&mut decrypted3)?;
        assert_eq!(plaintext, decrypted3.as_slice(), "Streaming KDF mode failed");

        // Mode 4: Parallel Streaming (`reader_parallel` to writer)
        let mut decrypted4 = Vec::new();
        seal.decrypt()
            .reader_parallel(Cursor::new(&encrypted))?
            .with_aad(aad)
            .with_typed_key_to_writer::<TestKem, TestDek, _>(&sk, &mut decrypted4)?;
        assert_eq!(
            plaintext,
            decrypted4.as_slice(),
            "Parallel streaming KDF mode failed"
        );

        Ok(())
    }

    #[test]
    fn test_xof_roundtrip_all_modes() -> crate::Result<()> {
        // 1. Setup
        let (pk, sk) = TestKem::generate_keypair()?;
        let pk_wrapped = AsymmetricPublicKey::new(pk.to_bytes());
        let plaintext = get_test_data();
        let aad = b"test-aad-for-xof-roundtrip";
        let kek_id = "test-xof-kek-id".to_string();
        let salt = b"xof-salt";
        let info = b"xof-info";
        let seal = HybridSeal::new();
        type Xof = Shake256;

        // 2. Encryption with XOF
        let encrypted = seal
            .encrypt::<TestDek>(pk_wrapped, kek_id.clone())
            .with_aad(aad)
            .with_xof(
                Xof::default(),
                Some(salt),
                Some(info),
                <TestDek as SymmetricCipher>::KEY_SIZE as u32,
            )
            .to_vec::<TestKem>(plaintext)?;

        // 3. Decryption tests for all sync modes

        // Mode 1: In-memory (`slice`)
        let decrypted1 = seal
            .decrypt()
            .slice(&encrypted)?
            .with_aad(aad)
            .with_typed_key::<TestKem, TestDek>(&sk)?;
        assert_eq!(
            plaintext,
            decrypted1.as_slice(),
            "In-memory XOF mode failed"
        );

        // Mode 2: In-memory parallel (`slice_parallel`)
        let decrypted2 = seal
            .decrypt()
            .slice_parallel(&encrypted)?
            .with_aad(aad)
            .with_typed_key::<TestKem, TestDek>(&sk)?;
        assert_eq!(
            plaintext,
            decrypted2.as_slice(),
            "In-memory parallel XOF mode failed"
        );

        // Mode 3: Streaming (`reader`)
        let pending3 = seal.decrypt().reader(Cursor::new(encrypted.clone()))?;
        let mut decryptor3 = pending3
            .with_aad(aad)
            .with_typed_key::<TestKem, TestDek>(&sk)?;
        let mut decrypted3 = Vec::new();
        decryptor3.read_to_end(&mut decrypted3)?;
        assert_eq!(plaintext, decrypted3.as_slice(), "Streaming XOF mode failed");

        // Mode 4: Parallel Streaming (`reader_parallel` to writer)
        let mut decrypted4 = Vec::new();
        seal.decrypt()
            .reader_parallel(Cursor::new(&encrypted))?
            .with_aad(aad)
            .with_typed_key_to_writer::<TestKem, TestDek, _>(&sk, &mut decrypted4)?;
        assert_eq!(
            plaintext,
            decrypted4.as_slice(),
            "Parallel streaming XOF mode failed"
        );

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
            let pk_wrapped = AsymmetricPublicKey::new(pk.to_bytes());
            key_store.insert(TEST_KEK_ID.to_string(), sk.clone());

            let plaintext = get_test_data();
            let seal = HybridSeal::new();

            // Encrypt
            let mut encrypted_data = Vec::new();
            let mut encryptor = seal
                .encrypt::<TestDek>(pk_wrapped, TEST_KEK_ID.to_string())
                .into_async_writer::<TestKem, _>(&mut encrypted_data)
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
                .with_typed_key::<TestKem, TestDek>((*decryption_key).clone())
                .await
                .unwrap();

            let mut decrypted_data = Vec::new();
            decryptor.read_to_end(&mut decrypted_data).await.unwrap();
            assert_eq!(plaintext.to_vec(), decrypted_data);
        }

        #[tokio::test]
        async fn test_kdf_async_roundtrip() -> crate::Result<()> {
            // 1. Setup
            let (pk, sk) = TestKem::generate_keypair()?;
            let pk_wrapped = AsymmetricPublicKey::new(pk.to_bytes());
            let plaintext = get_test_data();
            let aad = b"test-aad-for-kdf-async-roundtrip";
            let kek_id = "test-kdf-kek-id-async".to_string();
            let salt = b"kdf-salt-async";
            let info = b"kdf-info-async";
            let seal = HybridSeal::new();
            type Kdf = HkdfSha256;

            // 2. Encryption with KDF
            let encrypted = seal
                .encrypt::<TestDek>(pk_wrapped, kek_id.clone())
                .with_aad(aad)
                .with_kdf(
                    Kdf::default(),
                    Some(salt),
                    Some(info),
                    <TestDek as SymmetricCipher>::KEY_SIZE as u32,
                )
                .to_vec::<TestKem>(plaintext)?;

            // 3. Async Decryption
            let mut decryptor = seal
                .decrypt()
                .async_reader(Cursor::new(&encrypted))
                .await?
                .with_aad(aad)
                .with_typed_key::<TestKem, TestDek>(sk.clone())
                .await?;

            let mut decrypted = Vec::new();
            decryptor.read_to_end(&mut decrypted).await?;
            assert_eq!(
                plaintext,
                decrypted.as_slice(),
                "Async streaming KDF mode failed"
            );

            Ok(())
        }

        #[tokio::test]
        async fn test_xof_async_roundtrip() -> crate::Result<()> {
            // 1. Setup
            let (pk, sk) = TestKem::generate_keypair()?;
            let pk_wrapped = AsymmetricPublicKey::new(pk.to_bytes());
            let plaintext = get_test_data();
            let aad = b"test-aad-for-xof-async-roundtrip";
            let kek_id = "test-xof-kek-id-async".to_string();
            let salt = b"xof-salt-async";
            let info = b"xof-info-async";
            let seal = HybridSeal::new();
            type Xof = Shake256;

            // 2. Encryption with XOF
            let encrypted = seal
                .encrypt::<TestDek>(pk_wrapped, kek_id.clone())
                .with_aad(aad)
                .with_xof(
                    Xof::default(),
                    Some(salt),
                    Some(info),
                    <TestDek as SymmetricCipher>::KEY_SIZE as u32,
                )
                .to_vec::<TestKem>(plaintext)?;

            // 3. Async Decryption
            let mut decryptor = seal
                .decrypt()
                .async_reader(Cursor::new(&encrypted))
                .await?
                .with_aad(aad)
                .with_typed_key::<TestKem, TestDek>(sk.clone())
                .await?;

            let mut decrypted = Vec::new();
            decryptor.read_to_end(&mut decrypted).await?;
            assert_eq!(
                plaintext,
                decrypted.as_slice(),
                "Async streaming XOF mode failed"
            );

            Ok(())
        }

        #[tokio::test]
        async fn test_async_signed_aad_tampering_fails() -> crate::Result<()> {
            let (enc_pk, enc_sk) = TestKem::generate_keypair()?;
            let enc_pk_wrapped = AsymmetricPublicKey::new(enc_pk.to_bytes());
            let (sig_pk, sig_sk) = TestSigner::generate_keypair()?;
            let sig_sk_wrapped = AsymmetricPrivateKey::new(sig_sk.to_bytes());
            let sig_pk_bytes = sig_pk.to_bytes();
            let verification_key = SignaturePublicKey::new(sig_pk_bytes);

            let signer_key_id = "test-signer-key-async".to_string();
            let plaintext = get_test_data();
            let aad = b"test-signed-aad-async";
            let kek_id = "test-signed-aad-kek-async".to_string();
            let seal = HybridSeal::new();

            // Encrypt
            let mut encrypted = Vec::new();
            let mut encryptor = seal
                .encrypt::<TestDek>(enc_pk_wrapped, kek_id)
                .with_aad(aad)
                .with_signer::<TestSigner>(sig_sk_wrapped, signer_key_id)
                .into_async_writer::<TestKem, _>(&mut encrypted)
                .await?;
            encryptor.write_all(plaintext).await?;
            encryptor.shutdown().await?;

            // Successful roundtrip
            let mut decryptor = seal
                .decrypt()
                .async_reader(Cursor::new(&encrypted))
                .await?
                .with_aad(aad)
                .with_verification_key(verification_key.clone())
                .await?
                .with_typed_key::<TestKem, TestDek>(enc_sk.clone())
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
                .with_verification_key(verification_key)
                .await?
                .with_typed_key::<TestKem, TestDek>(enc_sk.clone())
                .await;
            assert!(res.is_err());

            Ok(())
        }
    }
}
