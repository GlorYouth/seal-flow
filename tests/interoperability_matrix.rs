use seal_flow::{
    common::{
        algorithms::SymmetricAlgorithm,
    },
    error::Result,
    symmetric::{
        asynchronous::{AsyncStreamingDecryptor, AsyncStreamingEncryptor},
        ordinary::{decrypt as symmetric_ordinary_decrypt, encrypt as symmetric_ordinary_encrypt},
        parallel::{symmetric_parallel_decrypt, symmetric_parallel_encrypt},
        parallel_streaming::{
            decrypt as symmetric_parallel_streaming_decrypt,
            encrypt as symmetric_parallel_streaming_encrypt,
        },
        streaming::{StreamingDecryptor, StreamingEncryptor},
    },
};
use seal_crypto::{
    systems::symmetric::aes_gcm::{Aes256, AesGcmScheme},
    traits::symmetric::SymmetricKeyGenerator,
    zeroize::Zeroizing,
};
use std::io::{Cursor, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        key: &Zeroizing<Vec<u8>>,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let key_id = "test_key_id".to_string();
        let algorithm = SymmetricAlgorithm::Aes256Gcm;

        match self {
            SymmetricEncryptorMode::Ordinary => {
                symmetric_ordinary_encrypt::<AesGcmScheme<Aes256>>(key, plaintext, key_id, algorithm)
            }
            SymmetricEncryptorMode::Parallel => {
                symmetric_parallel_encrypt::<AesGcmScheme<Aes256>>(key, plaintext, key_id, algorithm)
            }
            SymmetricEncryptorMode::Streaming => {
                let mut encrypted_data = Vec::new();
                let mut encryptor = StreamingEncryptor::<_, AesGcmScheme<Aes256>>::new(
                    &mut encrypted_data,
                    key.clone(),
                    key_id,
                    algorithm,
                )?;
                encryptor.write_all(plaintext)?;
                encryptor.flush()?;
                Ok(encrypted_data)
            }
            SymmetricEncryptorMode::AsyncStreaming => {
                let mut encrypted_data = Vec::new();
                let mut encryptor = AsyncStreamingEncryptor::<_, AesGcmScheme<Aes256>>::new(
                    &mut encrypted_data,
                    key.clone(),
                    key_id,
                    algorithm,
                )
                .await?;
                encryptor.write_all(plaintext).await?;
                encryptor.shutdown().await?;
                Ok(encrypted_data)
            }
            SymmetricEncryptorMode::ParallelStreaming => {
                let mut encrypted_data = Vec::new();
                symmetric_parallel_streaming_encrypt::<AesGcmScheme<Aes256>, _, _>(
                    key,
                    Cursor::new(plaintext),
                    &mut encrypted_data,
                    key_id,
                    algorithm,
                )?;
                Ok(encrypted_data)
            }
        }
    }
}

impl SymmetricDecryptorMode {
    async fn decrypt(
        &self,
        key: &Zeroizing<Vec<u8>>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        match self {
            SymmetricDecryptorMode::Ordinary => {
                symmetric_ordinary_decrypt::<AesGcmScheme<Aes256>>(key, ciphertext)
            }
            SymmetricDecryptorMode::Parallel => {
                symmetric_parallel_decrypt::<AesGcmScheme<Aes256>>(key, ciphertext)
            }
            SymmetricDecryptorMode::Streaming => {
                let mut decryptor =
                    StreamingDecryptor::<_, AesGcmScheme<Aes256>>::new(Cursor::new(ciphertext), key.clone())?;
                let mut decrypted_data = Vec::new();
                decryptor.read_to_end(&mut decrypted_data)?;
                Ok(decrypted_data)
            }
            SymmetricDecryptorMode::AsyncStreaming => {
                let mut decryptor = AsyncStreamingDecryptor::<_, AesGcmScheme<Aes256>>::new(
                    ciphertext,
                    key.clone(),
                )
                .await?;
                let mut decrypted_data = Vec::new();
                decryptor.read_to_end(&mut decrypted_data).await?;
                Ok(decrypted_data)
            }
            SymmetricDecryptorMode::ParallelStreaming => {
                let mut decrypted_data = Vec::new();
                symmetric_parallel_streaming_decrypt::<AesGcmScheme<Aes256>, _, _>(
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

    let key = AesGcmScheme::<Aes256>::generate_key().unwrap();
    let plaintext = b"This is a test message for interoperability across different modes.";

    for enc_mode in &encryptor_modes {
        let ciphertext = enc_mode
            .encrypt(&key, plaintext)
            .await
            .unwrap_or_else(|e| {
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

// --- Hybrid ---

use seal_flow::{
    common::algorithms::AsymmetricAlgorithm,
    hybrid::{
        asynchronous::AsyncHybridStreamingDecryptor,
        asynchronous::AsyncHybridStreamingEncryptor,
        ordinary::{hybrid_ordinary_decrypt, hybrid_ordinary_encrypt},
        parallel::{hybrid_parallel_decrypt, hybrid_parallel_encrypt},
        parallel_streaming::{
            decrypt as hybrid_parallel_streaming_decrypt,
            encrypt as hybrid_parallel_streaming_encrypt,
        },
        streaming::{HybridStreamingDecryptor, HybridStreamingEncryptor},
    },
};
use seal_crypto::systems::asymmetric::rsa::{Rsa2048, RsaScheme};
use seal_crypto::traits::kem::Kem;
use seal_crypto::traits::key::KeyGenerator;

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
        pk: &<RsaScheme<Rsa2048> as Kem>::PublicKey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let kek_id = "test_kek_id".to_string();
        let kek_algorithm = AsymmetricAlgorithm::Rsa2048;
        let dek_algorithm = SymmetricAlgorithm::Aes256Gcm;

        match self {
            HybridEncryptorMode::Ordinary => hybrid_ordinary_encrypt::<
                RsaScheme<Rsa2048>,
                AesGcmScheme<Aes256>,
            >(pk, plaintext, kek_id, kek_algorithm, dek_algorithm),
            HybridEncryptorMode::Parallel => hybrid_parallel_encrypt::<
                RsaScheme<Rsa2048>,
                AesGcmScheme<Aes256>,
            >(pk, plaintext, kek_id, kek_algorithm, dek_algorithm),
            HybridEncryptorMode::Streaming => {
                let mut encrypted_data = Vec::new();
                let mut encryptor = HybridStreamingEncryptor::<
                    _,
                    RsaScheme<Rsa2048>,
                    AesGcmScheme<Aes256>,
                >::new(
                    &mut encrypted_data,
                    pk,
                    kek_id,
                    kek_algorithm,
                    dek_algorithm,
                )?;
                encryptor.write_all(plaintext)?;
                encryptor.flush()?;
                Ok(encrypted_data)
            }
            HybridEncryptorMode::AsyncStreaming => {
                let mut encrypted_data = Vec::new();
                let mut encryptor = AsyncHybridStreamingEncryptor::<
                    _,
                    RsaScheme<Rsa2048>,
                    AesGcmScheme<Aes256>,
                >::new(
                    &mut encrypted_data,
                    pk.clone(),
                    kek_id,
                    kek_algorithm,
                    dek_algorithm,
                )
                .await?;
                encryptor.write_all(plaintext).await?;
                encryptor.shutdown().await?;
                Ok(encrypted_data)
            }
            HybridEncryptorMode::ParallelStreaming => {
                let mut encrypted_data = Vec::new();
                hybrid_parallel_streaming_encrypt::<
                    AesGcmScheme<Aes256>,
                    RsaScheme<Rsa2048>,
                    _,
                    _,
                >(
                    pk,
                    Cursor::new(plaintext),
                    &mut encrypted_data,
                    kek_id,
                    kek_algorithm,
                    dek_algorithm,
                )?;
                Ok(encrypted_data)
            }
        }
    }
}

impl HybridDecryptorMode {
    async fn decrypt(
        &self,
        sk: &<RsaScheme<Rsa2048> as Kem>::PrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        match self {
            HybridDecryptorMode::Ordinary => {
                hybrid_ordinary_decrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(sk, ciphertext)
            }
            HybridDecryptorMode::Parallel => {
                hybrid_parallel_decrypt::<RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>(sk, ciphertext)
            }
            HybridDecryptorMode::Streaming => {
                let mut decryptor =
                    HybridStreamingDecryptor::<_, RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>::new(
                        Cursor::new(ciphertext),
                        sk,
                    )?;
                let mut decrypted_data = Vec::new();
                decryptor.read_to_end(&mut decrypted_data)?;
                Ok(decrypted_data)
            }
            HybridDecryptorMode::AsyncStreaming => {
                let mut decryptor =
                    AsyncHybridStreamingDecryptor::<_, RsaScheme<Rsa2048>, AesGcmScheme<Aes256>>::new(
                        ciphertext,
                        sk.clone(),
                    )
                    .await?;
                let mut decrypted_data = Vec::new();
                decryptor.read_to_end(&mut decrypted_data).await?;
                Ok(decrypted_data)
            }
            HybridDecryptorMode::ParallelStreaming => {
                let mut decrypted_data = Vec::new();
                hybrid_parallel_streaming_decrypt::<
                    AesGcmScheme<Aes256>,
                    RsaScheme<Rsa2048>,
                    _,
                    _,
                >(
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

    let (pk, sk) = RsaScheme::<Rsa2048>::generate_keypair().unwrap();
    let plaintext = b"This is a test message for hybrid interoperability.";

    for enc_mode in &encryptor_modes {
        let ciphertext = enc_mode.encrypt(&pk, plaintext).await.unwrap_or_else(|e| {
            panic!(
                "Hybrid encryption failed for mode: {:?} with error: {:?}",
                enc_mode, e
            )
        });

        for dec_mode in &decryptor_modes {
            let decrypted = dec_mode
                .decrypt(&sk, &ciphertext)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "Hybrid decryption failed for enc_mode {:?} and dec_mode {:?} with error: {:?}",
                        enc_mode, dec_mode, e
                    )
                });
            assert_eq!(
                plaintext.to_vec(),
                decrypted,
                "Hybrid decryption content mismatch between enc_mode {:?} and dec_mode {:?}",
                enc_mode,
                dec_mode
            );
        }
    }
} 