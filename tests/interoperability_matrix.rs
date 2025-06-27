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
                seal.encrypt::<TestDek>(&key, key_id).to_vec(plaintext)
            }
            SymmetricEncryptorMode::Parallel => seal
                .encrypt::<TestDek>(&key, key_id)
                .to_vec_parallel(plaintext),
            SymmetricEncryptorMode::Streaming => {
                let mut encrypted_data = Vec::new();
                let mut encryptor = seal
                    .encrypt::<TestDek>(key, key_id)
                    .into_writer(&mut encrypted_data)?;
                encryptor.write_all(plaintext)?;
                encryptor.finish()?;
                Ok(encrypted_data)
            }
            SymmetricEncryptorMode::AsyncStreaming => {
                let mut encrypted_data = Vec::new();
                let mut encryptor = seal
                    .encrypt::<TestDek>(key, key_id)
                    .into_async_writer(&mut encrypted_data)
                    .await?;
                encryptor.write_all(plaintext).await?;
                encryptor.shutdown().await?;
                Ok(encrypted_data)
            }
            SymmetricEncryptorMode::ParallelStreaming => {
                let mut encrypted_data = Vec::new();
                seal.encrypt::<TestDek>(key, key_id)
                    .pipe_parallel(Cursor::new(plaintext), &mut encrypted_data)?;
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
                .decrypt()
                .from_slice(ciphertext)?
                .with_key::<TestDek>(key),
            SymmetricDecryptorMode::Parallel => seal
                .decrypt()
                .from_slice_parallel(ciphertext)?
                .with_key::<TestDek>(key),
            SymmetricDecryptorMode::Streaming => {
                let pending = seal.decrypt().from_reader(Cursor::new(ciphertext))?;
                let mut decryptor = pending.with_key::<TestDek>(key)?;
                let mut decrypted_data = Vec::new();
                decryptor.read_to_end(&mut decrypted_data)?;
                Ok(decrypted_data)
            }
            SymmetricDecryptorMode::AsyncStreaming => {
                let pending = seal
                    .decrypt()
                    .from_async_reader(Cursor::new(ciphertext))
                    .await?;
                let mut decryptor = pending.with_key::<TestDek>(key)?;
                let mut decrypted_data = Vec::new();
                decryptor.read_to_end(&mut decrypted_data).await?;
                Ok(decrypted_data)
            }
            SymmetricDecryptorMode::ParallelStreaming => {
                let mut decrypted_data = Vec::new();
                let pending = seal
                    .decrypt()
                    .from_reader_parallel(Cursor::new(ciphertext))?;
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
            HybridEncryptorMode::Ordinary => seal
                .encrypt::<TestKem, TestDek>(pk, kek_id)
                .to_vec(plaintext),
            HybridEncryptorMode::Parallel => seal
                .encrypt::<TestKem, TestDek>(pk, kek_id)
                .to_vec_parallel(plaintext),
            HybridEncryptorMode::Streaming => {
                let mut encrypted_data = Vec::new();
                let mut encryptor = seal
                    .encrypt::<TestKem, TestDek>(pk, kek_id)
                    .into_writer(&mut encrypted_data)?;
                encryptor.write_all(plaintext)?;
                encryptor.finish()?;
                Ok(encrypted_data)
            }
            HybridEncryptorMode::AsyncStreaming => {
                let mut encrypted_data = Vec::new();
                let mut encryptor = seal
                    .encrypt::<TestKem, TestDek>(pk, kek_id)
                    .into_async_writer(&mut encrypted_data)
                    .await?;
                encryptor.write_all(plaintext).await?;
                encryptor.shutdown().await?;
                Ok(encrypted_data)
            }
            HybridEncryptorMode::ParallelStreaming => {
                let mut encrypted_data = Vec::new();
                seal.encrypt::<TestKem, TestDek>(pk, kek_id)
                    .pipe_parallel(Cursor::new(plaintext), &mut encrypted_data)?;
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
                .decrypt()
                .from_slice(ciphertext)?
                .with_private_key::<TestKem, TestDek>(sk),
            HybridDecryptorMode::Parallel => seal
                .decrypt()
                .from_slice_parallel(ciphertext)?
                .with_private_key::<TestKem, TestDek>(sk),
            HybridDecryptorMode::Streaming => {
                let pending = seal.decrypt().from_reader(Cursor::new(ciphertext))?;
                let mut decryptor = pending.with_private_key::<TestKem, TestDek>(sk)?;
                let mut decrypted_data = Vec::new();
                decryptor.read_to_end(&mut decrypted_data)?;
                Ok(decrypted_data)
            }
            HybridDecryptorMode::AsyncStreaming => {
                let pending = seal
                    .decrypt()
                    .from_async_reader(Cursor::new(ciphertext))
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
                    .decrypt()
                    .from_reader_parallel(Cursor::new(ciphertext))?;
                pending
                    .with_private_key_to_writer::<TestKem, TestDek, _>(sk, &mut decrypted_data)?;
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
