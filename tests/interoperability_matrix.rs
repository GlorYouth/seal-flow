use seal_crypto::prelude::*;
use seal_crypto::schemes::asymmetric::traditional::rsa::Rsa2048;
use seal_crypto::schemes::hash::Sha256;
use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
use seal_flow::{
    error::Result,
    seal::{hybrid::HybridSeal, symmetric::SymmetricSeal},
};
use std::io::{Cursor, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type TestKem = Rsa2048<Sha256>;
type TestDek = Aes256Gcm;

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
    async fn encrypt(
        &self,
        key: &<TestDek as SymmetricKeySet>::Key,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let key_id = "test_key_id".to_string();
        let seal = SymmetricSeal::new();

        match self {
            SymmetricEncryptorMode::Ordinary => {
                seal.in_memory::<TestDek>()
                    .encrypt(key, plaintext, key_id)
            }
            SymmetricEncryptorMode::Parallel => seal
                .in_memory_parallel::<TestDek>()
                .encrypt(key, plaintext, key_id),
            SymmetricEncryptorMode::Streaming => {
                let mut encrypted_data = Vec::new();
                let mut encryptor =
                    seal.streaming_encryptor::<TestDek, _>(&mut encrypted_data, key, key_id)?;
                encryptor.write_all(plaintext)?;
                encryptor.finish()?;
                Ok(encrypted_data)
            }
            SymmetricEncryptorMode::AsyncStreaming => {
                let mut encrypted_data = Vec::new();
                let mut encryptor = seal
                    .asynchronous_encryptor::<TestDek, _>(&mut encrypted_data, key, key_id)
                    .await?;
                encryptor.write_all(plaintext).await?;
                encryptor.shutdown().await?;
                Ok(encrypted_data)
            }
            SymmetricEncryptorMode::ParallelStreaming => {
                let mut encrypted_data = Vec::new();
                seal.parallel_streaming::<TestDek>()
                    .encrypt(key, Cursor::new(plaintext), &mut encrypted_data, key_id)?;
                Ok(encrypted_data)
            }
        }
    }
}

impl SymmetricDecryptorMode {
    async fn decrypt(
        &self,
        key: &<TestDek as SymmetricKeySet>::Key,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let seal = SymmetricSeal::new();
        match self {
            SymmetricDecryptorMode::Ordinary => seal
                .in_memory::<TestDek>()
                .decrypt(ciphertext)?
                .with_key::<TestDek>(key),
            SymmetricDecryptorMode::Parallel => seal
                .in_memory_parallel::<TestDek>()
                .decrypt(ciphertext)?
                .with_key::<TestDek>(key),
            SymmetricDecryptorMode::Streaming => {
                let pending = seal.streaming_decryptor_from_reader(Cursor::new(ciphertext))?;
                let mut decryptor = pending.with_key::<TestDek>(key)?;
                let mut decrypted_data = Vec::new();
                decryptor.read_to_end(&mut decrypted_data)?;
                Ok(decrypted_data)
            }
            SymmetricDecryptorMode::AsyncStreaming => {
                let pending = seal
                    .asynchronous_decryptor_from_reader(Cursor::new(ciphertext))
                    .await?;
                let mut decryptor = pending.with_key::<TestDek>(key)?;
                let mut decrypted_data = Vec::new();
                decryptor.read_to_end(&mut decrypted_data).await?;
                Ok(decrypted_data)
            }
            SymmetricDecryptorMode::ParallelStreaming => {
                let mut decrypted_data = Vec::new();
                let pending = seal
                    .parallel_streaming::<TestDek>()
                    .decrypt(Cursor::new(ciphertext))?;
                pending.with_key_to_writer::<TestDek, _>(key, &mut decrypted_data)?;
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

    let key = TestDek::generate_key().unwrap();
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
        pk: &<TestKem as AsymmetricKeySet>::PublicKey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let kek_id = "test_kek_id".to_string();
        let seal = HybridSeal::new();

        match self {
            HybridEncryptorMode::Ordinary => seal.in_memory::<TestKem, TestDek>().encrypt(pk, plaintext, kek_id),
            HybridEncryptorMode::Parallel => seal
                .in_memory_parallel::<TestKem, TestDek>()
                .encrypt(pk, plaintext, kek_id),
            HybridEncryptorMode::Streaming => {
                let mut encrypted_data = Vec::new();
                let mut encryptor =
                    seal.streaming_encryptor::<TestKem, TestDek, _>(&mut encrypted_data, pk, kek_id)?;
                encryptor.write_all(plaintext)?;
                encryptor.finish()?;
                Ok(encrypted_data)
            }
            HybridEncryptorMode::AsyncStreaming => {
                let mut encrypted_data = Vec::new();
                let mut encryptor = seal
                    .asynchronous_encryptor::<TestKem, TestDek, _>(&mut encrypted_data, pk.clone(), kek_id)
                    .await?;
                encryptor.write_all(plaintext).await?;
                encryptor.shutdown().await?;
                Ok(encrypted_data)
            }
            HybridEncryptorMode::ParallelStreaming => {
                let mut encrypted_data = Vec::new();
                seal.parallel_streaming::<TestKem, TestDek>().encrypt(
                    pk,
                    Cursor::new(plaintext),
                    &mut encrypted_data,
                    kek_id,
                )?;
                Ok(encrypted_data)
            }
        }
    }
}

impl HybridDecryptorMode {
    async fn decrypt(
        &self,
        sk: &<TestKem as AsymmetricKeySet>::PrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let seal = HybridSeal::new();
        match self {
            HybridDecryptorMode::Ordinary => seal
                .in_memory::<TestKem, TestDek>()
                .decrypt(ciphertext)?
                .with_private_key::<TestKem, TestDek>(sk),
            HybridDecryptorMode::Parallel => seal
                .in_memory_parallel::<TestKem, TestDek>()
                .decrypt(ciphertext)?
                .with_private_key::<TestKem, TestDek>(sk),
            HybridDecryptorMode::Streaming => {
                let pending =
                    seal.streaming_decryptor_from_reader(Cursor::new(ciphertext))?;
                let mut decryptor = pending.with_private_key::<TestKem, TestDek>(sk)?;
                let mut decrypted_data = Vec::new();
                decryptor.read_to_end(&mut decrypted_data)?;
                Ok(decrypted_data)
            }
            HybridDecryptorMode::AsyncStreaming => {
                let pending = seal
                    .asynchronous_decryptor_from_reader(Cursor::new(ciphertext))
                    .await?;
                let mut decryptor = pending
                    .with_private_key::<TestKem, TestDek>(sk.clone())
                    .await?;
                let mut decrypted_data = Vec::new();
                decryptor.read_to_end(&mut decrypted_data).await?;
                Ok(decrypted_data)
            }
            HybridDecryptorMode::ParallelStreaming => {
                let mut decrypted_data = Vec::new();
                let pending = seal
                    .parallel_streaming::<TestKem, TestDek>()
                    .decrypt(Cursor::new(ciphertext))?;
                pending.with_private_key_to_writer::<TestKem, TestDek, _>(sk, &mut decrypted_data)?;
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

    let (pk, sk) = TestKem::generate_keypair().unwrap();
    let plaintext = b"This is a test message for hybrid interoperability across different modes.";

    for enc_mode in &encryptor_modes {
        let ciphertext = enc_mode.encrypt(&pk, plaintext).await.unwrap_or_else(|e| {
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
