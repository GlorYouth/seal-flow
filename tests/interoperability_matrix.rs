use seal_flow::{
    base::keys::{TypedAsymmetricPrivateKey, TypedAsymmetricPublicKey, TypedSymmetricKey},
    error::Result,
    prelude::*,
    high_level::{HybridSeal, SymmetricSeal},
};
use std::io::{Cursor, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TEST_KEM: AsymmetricAlgorithmEnum = AsymmetricAlgorithmEnum::Rsa2048Sha256;
const TEST_DEK: SymmetricAlgorithmEnum = SymmetricAlgorithmEnum::Aes256Gcm;

// --- Symmetric Interoperability Tests ---

#[derive(Debug)]
enum SymmetricEncryptorMode {
    Ordinary,
    Parallel,
    Streaming,
    AsyncStreaming,
    ParallelStreaming,
}

#[derive(Debug)]
enum SymmetricDecryptorMode {
    Ordinary,
    Parallel,
    Streaming,
    AsyncStreaming,
    ParallelStreaming,
}

impl SymmetricEncryptorMode {
    async fn encrypt(&self, key: &TypedSymmetricKey, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key_id = "test_key_id".to_string();
        let seal = SymmetricSeal::default();

        match self {
            SymmetricEncryptorMode::Ordinary => seal.encrypt(key.clone(), key_id).to_vec(plaintext),
            SymmetricEncryptorMode::Parallel => {
                seal.encrypt(key.clone(), key_id)
                    .to_vec_parallel(plaintext)
            }
            SymmetricEncryptorMode::Streaming => {
                let mut encrypted_data = Vec::new();
                {
                    let mut encryptor = seal
                        .encrypt(key.clone(), key_id)
                        .into_writer(&mut encrypted_data)?;
                    encryptor.write_all(plaintext)?;
                    encryptor.finish()?;
                }
                Ok(encrypted_data)
            }
            SymmetricEncryptorMode::AsyncStreaming => {
                let mut encrypted_data = Vec::new();
                {
                    let mut encryptor = seal
                        .encrypt(key.clone(), key_id)
                        .into_async_writer(&mut encrypted_data)
                        .await?;
                    encryptor.write_all(plaintext).await?;
                    encryptor.shutdown().await?;
                }
                Ok(encrypted_data)
            }
            SymmetricEncryptorMode::ParallelStreaming => {
                let mut encrypted_data = Vec::new();
                seal.encrypt(key.clone(), key_id)
                    .pipe_parallel(Cursor::new(plaintext), &mut encrypted_data)?;
                Ok(encrypted_data)
            }
        }
    }
}

impl SymmetricDecryptorMode {
    async fn decrypt(&self, key: &TypedSymmetricKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let seal = SymmetricSeal::default();
        match self {
            SymmetricDecryptorMode::Ordinary => {
                seal.decrypt().slice(ciphertext)?.with_key_to_vec(key)
            }
            SymmetricDecryptorMode::Parallel => seal
                .decrypt()
                .slice_parallel(ciphertext)?
                .with_key_to_vec(key),
            SymmetricDecryptorMode::Streaming => {
                let pending = seal.decrypt().reader(Cursor::new(ciphertext))?;
                let mut decryptor = pending.with_key_to_reader(key)?;
                let mut decrypted_data = Vec::new();
                decryptor.read_to_end(&mut decrypted_data)?;
                Ok(decrypted_data)
            }
            SymmetricDecryptorMode::AsyncStreaming => {
                let pending = seal.decrypt().async_reader(Cursor::new(ciphertext)).await?;
                let mut decryptor = pending.with_key_to_async_reader(key).await?;
                let mut decrypted_data = Vec::new();
                decryptor.read_to_end(&mut decrypted_data).await?;
                Ok(decrypted_data)
            }
            SymmetricDecryptorMode::ParallelStreaming => {
                let mut decrypted_data = Vec::new();
                let pending = seal.decrypt().reader_parallel(Cursor::new(ciphertext))?;
                pending.with_key_to_writer(key, &mut decrypted_data)?;
                Ok(decrypted_data)
            }
        }
    }
}

#[tokio::test]
async fn symmetric_interoperability_matrix() {
    let encryptor_modes = [
        SymmetricEncryptorMode::Ordinary,
        SymmetricEncryptorMode::Parallel,
        SymmetricEncryptorMode::Streaming,
        SymmetricEncryptorMode::AsyncStreaming,
        SymmetricEncryptorMode::ParallelStreaming,
    ];

    let decryptor_modes = [
        SymmetricDecryptorMode::Ordinary,
        SymmetricDecryptorMode::Parallel,
        SymmetricDecryptorMode::Streaming,
        SymmetricDecryptorMode::AsyncStreaming,
        SymmetricDecryptorMode::ParallelStreaming,
    ];

    let key = TEST_DEK
        .into_symmetric_wrapper()
        .generate_typed_key()
        .unwrap();
    let plaintext = b"This is a test message for interoperability across different modes.";

    for enc_mode in &encryptor_modes {
        let ciphertext = enc_mode.encrypt(&key, plaintext).await.unwrap_or_else(|e| {
            panic!(
                "Encryption failed for mode: {:?} with error: {:?}",
                enc_mode, e
            )
        });

        for dec_mode in &decryptor_modes {
            let decrypted = dec_mode
                .decrypt(&key, &ciphertext)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "Decryption failed for enc_mode {:?} and dec_mode {:?} with error: {:?}",
                        enc_mode, dec_mode, e
                    )
                });
            assert_eq!(
                plaintext.to_vec(),
                decrypted,
                "Decryption content mismatch between enc_mode {:?} and dec_mode {:?}",
                enc_mode,
                dec_mode
            );
        }
    }
}

// --- Hybrid Interoperability Tests ---

#[derive(Debug)]
enum HybridEncryptorMode {
    Ordinary,
    Parallel,
    Streaming,
    AsyncStreaming,
    ParallelStreaming,
}

#[derive(Debug)]
enum HybridDecryptorMode {
    Ordinary,
    Parallel,
    Streaming,
    AsyncStreaming,
    ParallelStreaming,
}

impl HybridEncryptorMode {
    async fn encrypt(
        &self,
        pk: &TypedAsymmetricPublicKey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let kek_id = "test_kek_id".to_string();
        let seal = HybridSeal::default();

        match self {
            HybridEncryptorMode::Ordinary => seal
                .encrypt(pk.clone(), kek_id)
                .execute_with(TEST_DEK)
                .to_vec(plaintext),
            HybridEncryptorMode::Parallel => seal
                .encrypt(pk.clone(), kek_id)
                .execute_with(TEST_DEK)
                .to_vec_parallel(plaintext),
            HybridEncryptorMode::Streaming => {
                let mut encrypted_data = Vec::new();
                {
                    let mut encryptor = seal
                        .encrypt(pk.clone(), kek_id)
                        .execute_with(TEST_DEK)
                        .into_writer(&mut encrypted_data)?;
                    encryptor.write_all(plaintext)?;
                    encryptor.finish()?;
                }
                Ok(encrypted_data)
            }
            HybridEncryptorMode::AsyncStreaming => {
                let mut encrypted_data = Vec::new();
                {
                    let mut encryptor = seal
                        .encrypt(pk.clone(), kek_id)
                        .execute_with(TEST_DEK)
                        .into_async_writer(&mut encrypted_data)
                        .await?;
                    encryptor.write_all(plaintext).await?;
                    encryptor.shutdown().await?;
                }
                Ok(encrypted_data)
            }
            HybridEncryptorMode::ParallelStreaming => {
                let mut encrypted_data = Vec::new();
                seal.encrypt(pk.clone(), kek_id)
                    .execute_with(TEST_DEK)
                    .pipe_parallel(Cursor::new(plaintext), &mut encrypted_data)?;
                Ok(encrypted_data)
            }
        }
    }
}

impl HybridDecryptorMode {
    async fn decrypt(
        &self,
        sk: &TypedAsymmetricPrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let seal = HybridSeal::default();
        match self {
            HybridDecryptorMode::Ordinary => seal.decrypt().slice(ciphertext)?.with_key_to_vec(sk),
            HybridDecryptorMode::Parallel => seal
                .decrypt()
                .slice_parallel(ciphertext)?
                .with_key_to_vec(sk),
            HybridDecryptorMode::Streaming => {
                let pending = seal.decrypt().reader(Cursor::new(ciphertext.to_vec()))?;
                let mut decryptor = pending.with_key_to_reader(sk)?;
                let mut decrypted_data = Vec::new();
                decryptor.read_to_end(&mut decrypted_data)?;
                Ok(decrypted_data)
            }
            HybridDecryptorMode::AsyncStreaming => {
                let _ = seal.decrypt().async_reader(Cursor::new(ciphertext)).await?;
                let sk_clone = sk.clone();
                let ciphertext_clone = ciphertext.to_vec();
                tokio::task::spawn_blocking(move || {
                    let seal = HybridSeal::default();
                    let pending = seal.decrypt().reader(Cursor::new(ciphertext_clone))?;
                    let mut decryptor = pending.with_key_to_reader(&sk_clone)?;
                    let mut decrypted_data = Vec::new();
                    decryptor.read_to_end(&mut decrypted_data)?;
                    Ok(decrypted_data)
                })
                .await?
            }
            HybridDecryptorMode::ParallelStreaming => {
                let mut decrypted_data = Vec::new();
                let pending = seal.decrypt().reader_parallel(Cursor::new(ciphertext))?;
                pending.with_key_to_writer(sk, &mut decrypted_data)?;
                Ok(decrypted_data)
            }
        }
    }
}

#[tokio::test]
async fn hybrid_interoperability_matrix() {
    let encryptor_modes = [
        HybridEncryptorMode::Ordinary,
        HybridEncryptorMode::Parallel,
        HybridEncryptorMode::Streaming,
        HybridEncryptorMode::AsyncStreaming,
        HybridEncryptorMode::ParallelStreaming,
    ];

    let decryptor_modes = [
        HybridDecryptorMode::Ordinary,
        HybridDecryptorMode::Parallel,
        HybridDecryptorMode::Streaming,
        HybridDecryptorMode::AsyncStreaming,
        HybridDecryptorMode::ParallelStreaming,
    ];

    let (pk, sk) = TEST_KEM
        .into_asymmetric_wrapper()
        .generate_keypair()
        .unwrap()
        .into_keypair();
    let plaintext = b"This is a test message for hybrid interoperability across different modes.";

    for enc_mode in &encryptor_modes {
        let ciphertext = enc_mode
            .encrypt(&pk, plaintext)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "Encryption failed for hybrid mode: {:?} with error: {:?}",
                    enc_mode, e
                )
            });

        for dec_mode in &decryptor_modes {
            let decrypted = dec_mode
                .decrypt(&sk, &ciphertext)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "Decryption failed for hybrid enc_mode {:?} and dec_mode {:?} with error: {:?}",
                        enc_mode, dec_mode, e
                    )
                });
            assert_eq!(
                plaintext.to_vec(),
                decrypted,
                "Decryption content mismatch between hybrid enc_mode {:?} and dec_mode {:?}",
                enc_mode,
                dec_mode
            );
        }
    }
}
