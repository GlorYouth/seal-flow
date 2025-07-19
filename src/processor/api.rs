//! Provides a simplified, unified API for the different processing modes.
//! This acts as a facade over the `ordinary`, `streaming`, `parallel`, etc. modules.
//!
//! 为不同的处理模式提供了一个简化的、统一的 API。
//! 这个模块作为 `ordinary`, `streaming`, `parallel` 等模块的外观。

use crate::common::header::{
    SealFlowEnvelopeHeader, SealFlowHeader,
};
use crate::error::Result;
use seal_crypto_wrapper::prelude::TypedSymmetricKey;
use seal_crypto_wrapper::wrappers::symmetric::SymmetricAlgorithmWrapper;
use std::borrow::Cow;
use std::io::{Read, Write};
use crate::processor::traits::FinishingWrite;
#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(feature = "async")]
use crate::processor::body::asynchronous::{AsyncDecryptorImpl, AsyncEncryptorImpl};

// --- Ordinary ---

/// Encrypts data in-memory using a single thread.
/// Prepends a length-prefixed `SealFlowEnvelopeHeader` to the ciphertext.
pub fn encrypt_ordinary<'a>(
    plaintext: &[u8],
    key: Cow<'a, TypedSymmetricKey>,
    header: SealFlowEnvelopeHeader,
    aad: Option<Vec<u8>>,
) -> Result<Vec<u8>> {
    let symmetric_params = header.symmetric_params().clone();
    let encryptor = super::body::ordinary::OrdinaryEncryptor::new(symmetric_params, aad);
    let mut ciphertext = encryptor.encrypt(plaintext, key)?;

    let mut header_bytes = header.encode_to_prefixed_vec()?;
    header_bytes.append(&mut ciphertext);
    Ok(header_bytes)
}

/// Decrypts data in-memory using a single thread.
/// The ciphertext is expected to start with a length-prefixed `SealFlowEnvelopeHeader`.
/// Returns the parsed header and the decrypted plaintext.
pub fn decrypt_ordinary<'a>(
    ciphertext: &[u8],
    key: Cow<'a, TypedSymmetricKey>,
    aad: Option<Vec<u8>>,
) -> Result<(SealFlowEnvelopeHeader, Vec<u8>)> {
    let (header, ciphertext_body) = SealFlowEnvelopeHeader::decode_from_prefixed_slice(ciphertext)?;
    let params = header.symmetric_params();

    // TODO: Verify AAD hash if present in header

    let wrapper = SymmetricAlgorithmWrapper::from_enum(params.algorithm);
    let decryptor = super::body::ordinary::OrdinaryDecryptor::new(
        wrapper,
        params.base_nonce.clone(),
        params.chunk_size as usize,
        aad,
    );
    let plaintext = decryptor.decrypt(ciphertext_body, key)?;
    Ok((header, plaintext))
}

// --- Streaming ---

/// Returns a writer that encrypts data as it's written.
/// The writer will first write a length-prefixed `SealFlowEnvelopeHeader`.
pub fn encrypt_streaming<'a, W: Write + 'a>(
    mut writer: W,
    key: Cow<'a, TypedSymmetricKey>,
    header: SealFlowEnvelopeHeader,
    aad: Option<Vec<u8>>,
) -> Result<Box<dyn FinishingWrite + 'a>> {
    header.write_to_prefixed_writer(&mut writer)?;
    let symmetric_params = header.symmetric_params().clone();
    let setup = super::body::streaming::StreamingEncryptorSetup::new(symmetric_params, aad);
    let encryptor = setup.start(writer, key)?;
    Ok(Box::new(encryptor))
}

/// Returns a reader that decrypts data as it's read.
/// The reader is expected to start with a length-prefixed `SealFlowEnvelopeHeader`.
/// Returns the parsed header and a reader for the decrypted plaintext.
pub fn decrypt_streaming<'a, R: Read + 'a>(
    mut reader: R,
    key: Cow<'a, TypedSymmetricKey>,
    aad: Option<Vec<u8>>,
) -> Result<(SealFlowEnvelopeHeader, impl Read + 'a)> {
    let header = SealFlowEnvelopeHeader::decode_from_prefixed_reader(&mut reader)?;
    let params = header.symmetric_params();

    // TODO: Verify AAD hash if present in header

    let wrapper = SymmetricAlgorithmWrapper::from_enum(params.algorithm);
    let setup = super::body::streaming::StreamingDecryptorSetup::new(
        wrapper,
        params.base_nonce.clone(),
        params.chunk_size as usize,
        aad,
    );
    Ok((header, setup.start(reader, key)))
}

// --- Parallel ---

/// Encrypts data in-memory using multiple threads.
/// Prepends a length-prefixed `SealFlowEnvelopeHeader` to the ciphertext.
pub fn encrypt_parallel<'a>(
    plaintext: &[u8],
    key: Cow<'a, TypedSymmetricKey>,
    header: SealFlowEnvelopeHeader,
    aad: Option<Vec<u8>>,
) -> Result<Vec<u8>> {
    let symmetric_params = header.symmetric_params().clone();
    let encryptor = super::body::parallel::ParallelEncryptor::new(symmetric_params, aad);
    let mut ciphertext = encryptor.encrypt(plaintext, key)?;

    let mut header_bytes = header.encode_to_prefixed_vec()?;
    header_bytes.append(&mut ciphertext);
    Ok(header_bytes)
}

/// Decrypts data in-memory using multiple threads.
/// The ciphertext is expected to start with a length-prefixed `SealFlowEnvelopeHeader`.
/// Returns the parsed header and the decrypted plaintext.
pub fn decrypt_parallel<'a>(
    ciphertext: &[u8],
    key: Cow<'a, TypedSymmetricKey>,
    aad: Option<Vec<u8>>,
) -> Result<(SealFlowEnvelopeHeader, Vec<u8>)> {
    let (header, ciphertext_body) = SealFlowEnvelopeHeader::decode_from_prefixed_slice(ciphertext)?;
    let params = header.symmetric_params();

    // TODO: Verify AAD hash if present in header

    let wrapper = SymmetricAlgorithmWrapper::from_enum(params.algorithm);
    let decryptor = super::body::parallel::ParallelDecryptor::new(
        wrapper,
        params.base_nonce.clone(),
        params.chunk_size as usize,
        aad,
    );
    let plaintext = decryptor.decrypt(ciphertext_body, key)?;
    Ok((header, plaintext))
}

// --- Parallel Streaming ---

/// Encrypts a stream in parallel.
/// The output will start with a length-prefixed `SealFlowEnvelopeHeader`.
pub fn encrypt_parallel_streaming<'a, R, W>(
    reader: R,
    mut writer: W,
    key: Cow<'a, TypedSymmetricKey>,
    header: SealFlowEnvelopeHeader,
    aad: Option<Vec<u8>>,
    channel_bound: usize,
) -> Result<()>
    where
        R: Read + Send,
        W: Write + Send,
{
    header.write_to_prefixed_writer(&mut writer)?;
    let symmetric_params = header.symmetric_params().clone();
    let encryptor = super::body::parallel_streaming::ParallelStreamingEncryptor::new(
        symmetric_params,
        aad,
        channel_bound,
    );
    encryptor.run(reader, writer, key)
}

/// Decrypts a stream in parallel.
/// The reader is expected to start with a length-prefixed `SealFlowEnvelopeHeader`.
/// Returns the parsed header upon successful decryption.
pub fn decrypt_parallel_streaming<'a, R, W>(
    mut reader: R,
    writer: W,
    key: Cow<'a, TypedSymmetricKey>,
    aad: Option<Vec<u8>>,
    channel_bound: usize,
) -> Result<SealFlowEnvelopeHeader>
    where
        R: Read + Send,
        W: Write + Send,
{
    let header = SealFlowEnvelopeHeader::decode_from_prefixed_reader(&mut reader)?;
    let params = header.symmetric_params();

    // TODO: Verify AAD hash if present in header

    let wrapper = SymmetricAlgorithmWrapper::from_enum(params.algorithm);
    let decryptor = super::body::parallel_streaming::ParallelStreamingDecryptor::new(
        wrapper,
        params.base_nonce.clone(),
        aad,
        params.chunk_size as usize,
        channel_bound,
    );
    decryptor.run(reader, writer, key)?;
    Ok(header)
}


// --- Asynchronous ---

/// Returns a writer that asynchronously encrypts data as it's written.
/// The writer will first write a length-prefixed `SealFlowEnvelopeHeader`.
#[cfg(feature = "async")]
pub async fn encrypt_asynchronous<'a, W: AsyncWrite + Send + Unpin + 'a>(
    mut writer: W,
    key: Cow<'a, TypedSymmetricKey>,
    header: SealFlowEnvelopeHeader,
    aad: Option<Vec<u8>>,
    channel_bound: usize,
) -> Result<AsyncEncryptorImpl<'a, W>> {
    header.write_to_prefixed_async_writer(&mut writer).await?;
    let symmetric_params = header.symmetric_params().clone();
    let setup = super::body::asynchronous::AsyncEncryptorSetup::new(symmetric_params, aad, channel_bound);
    setup.start(writer, key)
}

/// Returns a reader that asynchronously decrypts data as it's read.
/// The reader is expected to start with a length-prefixed `SealFlowEnvelopeHeader`.
/// Returns the parsed header and a reader for the decrypted plaintext.
#[cfg(feature = "async")]
pub async fn decrypt_asynchronous<'a, R: AsyncRead + Send + Unpin + 'a>(
    mut reader: R,
    key: Cow<'a, TypedSymmetricKey>,
    aad: Option<Vec<u8>>,
    channel_bound: usize,
) -> Result<(SealFlowEnvelopeHeader, AsyncDecryptorImpl<'a, R>)> {
    let header = SealFlowEnvelopeHeader::decode_from_prefixed_async_reader(&mut reader).await?;
    let params = header.symmetric_params();

    // TODO: Verify AAD hash if present in header

    let wrapper = SymmetricAlgorithmWrapper::from_enum(params.algorithm);
    let setup = super::body::asynchronous::AsyncDecryptorSetup::new(
        wrapper,
        params.base_nonce.clone(),
        aad,
        params.chunk_size as usize,
        channel_bound,
    );
    Ok((header, setup.start(reader, key)))
} 