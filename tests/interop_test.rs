use seal_crypto_wrapper::algorithms::aead::AeadAlgorithm;
use seal_crypto_wrapper::bincode;
use seal_flow::common::header::{AeadParams, AeadParamsBuilder, SealFlowHeader};
use seal_flow::crypto::prelude::*;
#[cfg(feature = "async")]
use seal_flow::processor::api::prepare_decryption_from_async_reader;
use seal_flow::processor::api::{
    EncryptionConfigurator, prepare_decryption_from_reader, prepare_decryption_from_slice,
};
use std::borrow::Cow;
use std::io::{Cursor, Read, Write};
use std::{future::Future, pin::Pin, sync::Arc};

const TEST_CHUNK_SIZE: u32 = 1024;
const TEST_AAD: &[u8] = b"test aad";
const TEST_DATA: &[u8] = b"some test data to be encrypted";

fn aead_params(aad: Option<&[u8]>) -> AeadParams {
    let algorithm = AeadAlgorithm::build().aes256_gcm();
    let mut builder = AeadParamsBuilder::new(algorithm, TEST_CHUNK_SIZE);
    if let Some(aad) = aad {
        builder = builder.aad_hash(aad, HashAlgorithm::Sha256.into_wrapper());
    }
    builder = builder
        .base_nonce(|nonce| {
            nonce.fill(1);
            Ok(())
        })
        .unwrap();
    builder.build()
}

#[derive(Clone, bincode::Encode, bincode::Decode, serde::Serialize, serde::Deserialize)]
#[bincode(crate = "seal_crypto_wrapper::bincode")]
struct TestHeader {
    params: AeadParams,
}

impl SealFlowHeader for TestHeader {
    fn aead_params(&self) -> &AeadParams {
        &self.params
    }
}

fn new_test_header(aad: Option<&[u8]>) -> TestHeader {
    TestHeader {
        params: aead_params(aad),
    }
}

// Encryption Helpers
fn encrypt_ordinary(
    key: &TypedAeadKey,
    aad: Option<Vec<u8>>,
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let header = new_test_header(aad.as_deref());
    let configurator = EncryptionConfigurator::new(header, Cow::Borrowed(key), aad);
    let flow = configurator.into_writer(Vec::new())?;
    flow.encrypt_ordinary(plaintext).map_err(|e| e.into())
}

fn encrypt_parallel(
    key: &TypedAeadKey,
    aad: Option<Vec<u8>>,
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let header = new_test_header(aad.as_deref());
    let configurator = EncryptionConfigurator::new(header, Cow::Borrowed(key), aad);
    let flow = configurator.into_writer(Vec::new())?;
    flow.encrypt_parallel(plaintext).map_err(|e| e.into())
}

fn encrypt_streaming(
    key: &TypedAeadKey,
    aad: Option<Vec<u8>>,
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let header = new_test_header(aad.as_deref());
    let configurator = EncryptionConfigurator::new(header, Cow::Borrowed(key), aad);
    let mut ciphertext = Vec::new();
    let flow = configurator.into_writer(&mut ciphertext)?;
    let mut encryptor = flow.start_streaming()?;
    encryptor.write_all(plaintext)?;
    encryptor.finish()?;
    Ok(ciphertext)
}

fn encrypt_parallel_streaming(
    key: &TypedAeadKey,
    aad: Option<Vec<u8>>,
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let header = new_test_header(aad.as_deref());
    let configurator = EncryptionConfigurator::new(header, Cow::Borrowed(key), aad);
    let mut ciphertext = Vec::new();
    let flow = configurator.into_parallel_streaming_flow(&mut ciphertext, 4)?;
    let reader = Cursor::new(plaintext);
    flow.start_parallel_streaming(reader)?;
    Ok(ciphertext)
}

#[cfg(feature = "async")]
async fn encrypt_asynchronous(
    key: &TypedAeadKey,
    aad: Option<Vec<u8>>,
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use tokio::io::AsyncWriteExt;

    let header = new_test_header(aad.as_deref());
    let configurator = EncryptionConfigurator::new(header, Cow::Borrowed(key), aad);
    let mut ciphertext = Vec::new();
    let flow = configurator.into_async_flow(&mut ciphertext, 4).await?;
    let mut encryptor = flow.start_asynchronous()?;
    encryptor.write_all(plaintext).await?;
    encryptor.shutdown().await?;
    Ok(ciphertext)
}

#[tokio::test]
async fn test_all_modes_interoperability() -> anyhow::Result<()> {
    let key = TypedAeadKey::generate(AeadAlgorithm::build().aes256_gcm())?;
    let plaintext = TEST_DATA;

    // --- Encryption Mode Definitions ---
    enum EncFn {
        Sync(
            Arc<
                dyn Fn(&TypedAeadKey, Option<Vec<u8>>, &[u8]) -> anyhow::Result<Vec<u8>>
                    + Send
                    + Sync,
            >,
        ),
        Async(
            Arc<
                dyn for<'a> Fn(
                        &'a TypedAeadKey,
                        Option<Vec<u8>>,
                        &'a [u8],
                    )
                        -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<u8>>> + Send + 'a>>
                    + Send
                    + Sync,
            >,
        ),
    }

    let encryption_modes = {
        let mut modes = vec![
            ("Ordinary", EncFn::Sync(Arc::new(encrypt_ordinary))),
            ("Parallel", EncFn::Sync(Arc::new(encrypt_parallel))),
            ("Streaming", EncFn::Sync(Arc::new(encrypt_streaming))),
            (
                "ParallelStreaming",
                EncFn::Sync(Arc::new(encrypt_parallel_streaming)),
            ),
        ];
        #[cfg(feature = "async")]
        modes.push((
            "Asynchronous",
            EncFn::Async(Arc::new(|key, aad, plaintext| {
                Box::pin(encrypt_asynchronous(key, aad, plaintext))
            })),
        ));
        modes
    };

    // --- Decryption Mode Definitions ---
    type DecryptResult<'a> = Pin<Box<dyn Future<Output = anyhow::Result<Vec<u8>>> + Send + 'a>>;
    type DecryptFn = Arc<
        dyn for<'a> Fn(&'a [u8], &'a TypedAeadKey, Option<Vec<u8>>) -> DecryptResult<'a>
            + Send
            + Sync,
    >;

    let decryption_modes: Vec<(&str, DecryptFn)> = {
        let mut modes: Vec<(&str, DecryptFn)> = vec![
            (
                "Ordinary",
                Arc::new(|ciphertext, key, aad| {
                    Box::pin(async move {
                        let pending =
                            prepare_decryption_from_slice::<TestHeader>(ciphertext, None)?;
                        pending
                            .decrypt_ordinary(Cow::Borrowed(key), aad)
                            .map_err(|e| e.into())
                    })
                }),
            ),
            (
                "Parallel",
                Arc::new(|ciphertext, key, aad| {
                    Box::pin(async move {
                        let pending =
                            prepare_decryption_from_slice::<TestHeader>(ciphertext, None)?;
                        pending
                            .decrypt_parallel(Cow::Borrowed(key), aad)
                            .map_err(|e| e.into())
                    })
                }),
            ),
            (
                "Streaming",
                Arc::new(|ciphertext, key, aad| {
                    Box::pin(async move {
                        let mut reader = Cursor::new(ciphertext);
                        let pending =
                            prepare_decryption_from_reader::<_, TestHeader>(&mut reader, None)?;
                        let mut decryptor = pending.decrypt_streaming(Cow::Borrowed(key), aad)?;
                        let mut decrypted = Vec::new();
                        decryptor.read_to_end(&mut decrypted)?;
                        Ok(decrypted)
                    })
                }),
            ),
            (
                "Parallel Streaming",
                Arc::new(|ciphertext, key, aad| {
                    Box::pin(async move {
                        let mut reader = Cursor::new(ciphertext);
                        let pending =
                            prepare_decryption_from_reader::<_, TestHeader>(&mut reader, None)?;
                        let mut writer = Vec::new();
                        pending.decrypt_parallel_streaming(
                            &mut writer,
                            Cow::Borrowed(key),
                            aad,
                            4,
                        )?;
                        Ok(writer)
                    })
                }),
            ),
        ];

        #[cfg(feature = "async")]
        modes.push((
            "Asynchronous",
            Arc::new(|ciphertext, key, aad| {
                Box::pin(async move {
                    use tokio::io::AsyncReadExt;
                    let mut reader = tokio::io::BufReader::new(ciphertext);
                    let pending =
                        prepare_decryption_from_async_reader::<_, TestHeader>(&mut reader, None)
                            .await?;
                    let mut decryptor = pending.decrypt_asynchronous(Cow::Borrowed(key), aad, 4);
                    let mut decrypted = Vec::new();
                    decryptor.read_to_end(&mut decrypted).await?;
                    Ok(decrypted)
                })
            }),
        ));
        modes
    };

    // --- Test Execution ---
    for (enc_name, enc_fn) in &encryption_modes {
        println!("\n=======================================================");
        println!("  ENCRYPTION MODE: {}", enc_name);
        println!("=======================================================");

        let ciphertext = match enc_fn {
            EncFn::Sync(f) => f(&key, Some(TEST_AAD.to_vec()), plaintext)?,
            EncFn::Async(f) => f(&key, Some(TEST_AAD.to_vec()), plaintext).await?,
        };

        for (dec_name, dec_fn) in &decryption_modes {
            print!("  -> Decrypting with {:<20}... ", dec_name);
            std::io::stdout().flush()?;

            let result = dec_fn(&ciphertext, &key, Some(TEST_AAD.to_vec())).await;

            match result {
                Ok(decrypted_data) => {
                    if decrypted_data == plaintext {
                        println!("✅ SUCCESS");
                    } else {
                        println!("❌ FAILED (data mismatch)");
                        assert_eq!(decrypted_data, plaintext, "Data mismatch during decryption");
                    }
                }
                Err(e) => {
                    println!("❌ FAILED (error: {})", e);
                    return Err(e.into());
                }
            }
        }
    }

    Ok(())
}
