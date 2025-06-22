use seal_crypto::prelude::*;
use seal_flow::{
    algorithms::definitions::{Aes256GcmScheme, Rsa2048},
    error::Result,
    hybrid, symmetric,
};
use std::io::{Cursor, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use seal_crypto::schemes::hash::Sha256;
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
        key: &<Aes256GcmScheme as SymmetricKeySet>::Key,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let key_id = "test_key_id".to_string();

        match self {
            SymmetricEncryptorMode::Ordinary => {
                symmetric::ordinary::encrypt::<Aes256GcmScheme>(key, plaintext, key_id)
            }
            SymmetricEncryptorMode::Parallel => {
                symmetric::parallel::encrypt::<Aes256GcmScheme>(key, plaintext, key_id)
            }
            SymmetricEncryptorMode::Streaming => {
                let mut encrypted_data = Vec::new();
                let mut encryptor = symmetric::streaming::Encryptor::<_, Aes256GcmScheme>::new(
                    &mut encrypted_data,
                    key.clone(),
                    key_id,
                )?;
                encryptor.write_all(plaintext)?;
                encryptor.flush()?;
                Ok(encrypted_data)
            }
            SymmetricEncryptorMode::AsyncStreaming => {
                let mut encrypted_data = Vec::new();
                let mut encryptor = symmetric::asynchronous::Encryptor::<_, Aes256GcmScheme>::new(
                    &mut encrypted_data,
                    key.clone(),
                    key_id,
                )
                .await?;
                encryptor.write_all(plaintext).await?;
                encryptor.shutdown().await?;
                Ok(encrypted_data)
            }
            SymmetricEncryptorMode::ParallelStreaming => {
                let mut encrypted_data = Vec::new();
                symmetric::parallel_streaming::encrypt::<Aes256GcmScheme, _, _>(
                    key,
                    Cursor::new(plaintext),
                    &mut encrypted_data,
                    key_id,
                )?;
                Ok(encrypted_data)
            }
        }
    }
}

impl SymmetricDecryptorMode {
    async fn decrypt(
        &self,
        key: &<Aes256GcmScheme as SymmetricKeySet>::Key,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        match self {
            SymmetricDecryptorMode::Ordinary => {
                symmetric::ordinary::decrypt::<Aes256GcmScheme>(key, ciphertext)
            }
            SymmetricDecryptorMode::Parallel => {
                symmetric::parallel::decrypt::<Aes256GcmScheme>(key, ciphertext)
            }
            SymmetricDecryptorMode::Streaming => {
                let mut decryptor = symmetric::streaming::Decryptor::<_, Aes256GcmScheme>::new(
                    Cursor::new(ciphertext),
                    &key,
                )?;
                let mut decrypted_data = Vec::new();
                decryptor.read_to_end(&mut decrypted_data)?;
                Ok(decrypted_data)
            }
            SymmetricDecryptorMode::AsyncStreaming => {
                let mut decryptor =
                    symmetric::asynchronous::Decryptor::<_, Aes256GcmScheme>::new(ciphertext, &key)
                        .await?;
                let mut decrypted_data = Vec::new();
                decryptor.read_to_end(&mut decrypted_data).await?;
                Ok(decrypted_data)
            }
            SymmetricDecryptorMode::ParallelStreaming => {
                let mut decrypted_data = Vec::new();
                symmetric::parallel_streaming::decrypt::<Aes256GcmScheme, _, _>(
                    key,
                    Cursor::new(ciphertext),
                    &mut decrypted_data,
                )?;
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

    let key = Aes256GcmScheme::generate_key().unwrap();
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
        pk: &<Rsa2048 as AsymmetricKeySet>::PublicKey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let kek_id = "test_kek_id".to_string();

        match self {
            HybridEncryptorMode::Ordinary => {
                hybrid::ordinary::encrypt::<Rsa2048, Aes256GcmScheme>(pk, plaintext, kek_id)
            }
            HybridEncryptorMode::Parallel => {
                hybrid::parallel::encrypt::<Rsa2048, Aes256GcmScheme>(pk, plaintext, kek_id)
            }
            HybridEncryptorMode::Streaming => {
                let mut encrypted_data = Vec::new();
                let mut encryptor = hybrid::streaming::Encryptor::<
                    _,
                    Rsa2048,
                    Aes256GcmScheme,
                >::new(&mut encrypted_data, pk, kek_id)?;
                encryptor.write_all(plaintext)?;
                encryptor.flush()?;
                Ok(encrypted_data)
            }
            HybridEncryptorMode::AsyncStreaming => {
                let mut encrypted_data = Vec::new();
                let mut encryptor = hybrid::asynchronous::Encryptor::<
                    _,
                    Rsa2048,
                    Aes256GcmScheme,
                >::new(&mut encrypted_data, pk.clone(), kek_id)
                .await?;
                encryptor.write_all(plaintext).await?;
                encryptor.shutdown().await?;
                Ok(encrypted_data)
            }
            HybridEncryptorMode::ParallelStreaming => {
                let mut encrypted_data = Vec::new();
                hybrid::parallel_streaming::encrypt::<Rsa2048, Aes256GcmScheme, _, _>(
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
        sk: &<Rsa2048 as AsymmetricKeySet>::PrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        match self {
            HybridDecryptorMode::Ordinary => {
                hybrid::ordinary::decrypt::<Rsa2048, Aes256GcmScheme>(sk, ciphertext)
            }
            HybridDecryptorMode::Parallel => {
                hybrid::parallel::decrypt::<Rsa2048, Aes256GcmScheme>(sk, ciphertext)
            }
            HybridDecryptorMode::Streaming => {
                let mut decryptor = hybrid::streaming::Decryptor::<
                    _,
                    Rsa2048,
                    Aes256GcmScheme,
                >::new(Cursor::new(ciphertext), sk)?;
                let mut decrypted_data = Vec::new();
                decryptor.read_to_end(&mut decrypted_data)?;
                Ok(decrypted_data)
            }
            HybridDecryptorMode::AsyncStreaming => {
                let mut decryptor = hybrid::asynchronous::Decryptor::<
                    _,
                    Rsa2048,
                    Aes256GcmScheme,
                >::new(ciphertext, sk.clone())
                .await?;
                let mut decrypted_data = Vec::new();
                decryptor.read_to_end(&mut decrypted_data).await?;
                Ok(decrypted_data)
            }
            HybridDecryptorMode::ParallelStreaming => {
                let mut decrypted_data = Vec::new();
                hybrid::parallel_streaming::decrypt::<Rsa2048, Aes256GcmScheme, _, _>(
                    sk,
                    Cursor::new(ciphertext),
                    &mut decrypted_data,
                )?;
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

    let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
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
