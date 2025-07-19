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

// --- Encryption Flow ---

/// The starting point for any encryption operation.
/// This struct configures the encryption behavior and initiates the process.
pub struct EncryptionConfigurator<'a> {
    header: SealFlowEnvelopeHeader,
    key: Cow<'a, TypedSymmetricKey>,
    aad: Option<Vec<u8>>,
}

impl<'a> EncryptionConfigurator<'a> {
    /// Creates a new encryption configurator.
    ///
    /// # Arguments
    /// * `header`: The `SealFlowEnvelopeHeader` containing all metadata for the encryption.
    /// * `key`: The symmetric key for encryption.
    /// * `aad`: Optional Additional Authenticated Data.
    pub fn new(
        header: SealFlowEnvelopeHeader,
        key: Cow<'a, TypedSymmetricKey>,
        aad: Option<Vec<u8>>,
    ) -> Self {
        Self { header, key, aad }
    }

    /// Encrypts data in-memory using a single thread.
    /// This method performs the entire "write header + encrypt body" process.
    pub fn encrypt_ordinary(self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let symmetric_params = self.header.symmetric_params().clone();
        let encryptor = super::body::ordinary::OrdinaryEncryptor::new(symmetric_params, self.aad);
        let mut ciphertext = encryptor.encrypt(plaintext, self.key)?;

        let mut header_bytes = self.header.encode_to_prefixed_vec()?;
        header_bytes.append(&mut ciphertext);
        Ok(header_bytes)
    }

    /// Encrypts data in-memory using multiple threads.
    /// This method performs the entire "write header + encrypt body" process.
    pub fn encrypt_parallel(self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let symmetric_params = self.header.symmetric_params().clone();
        let encryptor = super::body::parallel::ParallelEncryptor::new(symmetric_params, self.aad);
        let mut ciphertext = encryptor.encrypt(plaintext, self.key)?;

        let mut header_bytes = self.header.encode_to_prefixed_vec()?;
        header_bytes.append(&mut ciphertext);
        Ok(header_bytes)
    }

    /// Writes the header to a synchronous writer and transitions to a streaming encryption flow.
    pub fn into_streaming_flow<W: Write + 'a>(
        self,
        mut writer: W,
    ) -> Result<StreamingEncryptionFlow<'a, W>> {
        self.header.write_to_prefixed_writer(&mut writer)?;
        Ok(StreamingEncryptionFlow {
            writer,
            config: self,
        })
    }

    /// Writes the header to a synchronous writer and transitions to a parallel streaming encryption flow.
    pub fn into_parallel_streaming_flow<W: Write + Send + 'a>(
        self,
        mut writer: W,
        channel_bound: usize,
    ) -> Result<ParallelStreamingEncryptionFlow<'a, W>> {
        self.header.write_to_prefixed_writer(&mut writer)?;
        Ok(ParallelStreamingEncryptionFlow {
            writer,
            config: self,
            channel_bound,
        })
    }

    /// Asynchronously writes the header to a writer and transitions to an asynchronous encryption flow.
    #[cfg(feature = "async")]
    pub async fn into_async_flow<W: AsyncWrite + Send + Unpin + 'a>(
        self,
        mut writer: W,
        channel_bound: usize,
    ) -> Result<AsyncEncryptionFlow<'a, W>> {
        self.header
            .write_to_prefixed_async_writer(&mut writer)
            .await?;
        Ok(AsyncEncryptionFlow {
            writer,
            config: self,
            channel_bound,
        })
    }
}

/// Represents the state after the header has been written to a synchronous stream.
pub struct StreamingEncryptionFlow<'a, W: Write + 'a> {
    writer: W,
    config: EncryptionConfigurator<'a>,
}

impl<'a, W: Write + 'a> StreamingEncryptionFlow<'a, W> {
    /// Starts the encryption on the stream, returning a writer that encrypts data as it's written.
    pub fn start(self) -> Result<Box<dyn FinishingWrite + 'a>> {
        let symmetric_params = self.config.header.symmetric_params().clone();
        let setup =
            super::body::streaming::StreamingEncryptorSetup::new(symmetric_params, self.config.aad);
        let encryptor = setup.start(self.writer, self.config.key)?;
        Ok(Box::new(encryptor))
    }
}

/// Represents the state after the header has been written for a parallel streaming operation.
pub struct ParallelStreamingEncryptionFlow<'a, W: Write + Send + 'a> {
    writer: W,
    config: EncryptionConfigurator<'a>,
    channel_bound: usize,
}

impl<'a, W: Write + Send + 'a> ParallelStreamingEncryptionFlow<'a, W> {
    /// Starts the parallel encryption, consuming a reader and writing encrypted data to the writer.
    pub fn start<R: Read + Send>(self, reader: R) -> Result<()> {
        let symmetric_params = self.config.header.symmetric_params().clone();
        let encryptor = super::body::parallel_streaming::ParallelStreamingEncryptor::new(
            symmetric_params,
            self.config.aad,
            self.channel_bound,
        );
        encryptor.run(reader, self.writer, self.config.key)
    }
}

/// Represents the state after the header has been written to an asynchronous stream.
#[cfg(feature = "async")]
pub struct AsyncEncryptionFlow<'a, W: AsyncWrite + Send + Unpin + 'a> {
    writer: W,
    config: EncryptionConfigurator<'a>,
    channel_bound: usize,
}

#[cfg(feature = "async")]
impl<'a, W: AsyncWrite + Send + Unpin + 'a> AsyncEncryptionFlow<'a, W> {
    /// Starts the encryption on the async stream, returning a writer that encrypts data as it's written.
    pub fn start(self) -> Result<AsyncEncryptorImpl<'a, W>> {
        let symmetric_params = self.config.header.symmetric_params().clone();
        let setup = super::body::asynchronous::AsyncEncryptorSetup::new(
            symmetric_params,
            self.config.aad,
            self.channel_bound,
        );
        setup.start(self.writer, self.config.key)
    }
}


// --- Decryption Body ---

/// Decrypts data in-memory using a single thread.
/// The ciphertext is expected to start with a length-prefixed `SealFlowEnvelopeHeader`.
/// Returns the parsed header and the decrypted plaintext.
pub fn decrypt_ordinary_body<'a>(
    ciphertext_body: &[u8],
    key: Cow<'a, TypedSymmetricKey>,
    header: &SealFlowEnvelopeHeader,
    aad: Option<Vec<u8>>,
) -> Result<Vec<u8>> {
    let params = header.symmetric_params();

    // TODO: Verify AAD hash if present in header

    let wrapper = SymmetricAlgorithmWrapper::from_enum(params.algorithm);
    let decryptor = super::body::ordinary::OrdinaryDecryptor::new(
        wrapper,
        params.base_nonce.clone(),
        params.chunk_size as usize,
        aad,
    );
    decryptor.decrypt(ciphertext_body, key)
}

// --- Streaming ---

/// Returns a reader that decrypts data as it's read.
/// The reader is expected to start with a length-prefixed `SealFlowEnvelopeHeader`.
/// Returns the parsed header and a reader for the decrypted plaintext.
pub fn decrypt_streaming_body<'a, R: Read + 'a>(
    reader: R,
    key: Cow<'a, TypedSymmetricKey>,
    header: &SealFlowEnvelopeHeader,
    aad: Option<Vec<u8>>,
) -> Result<impl Read + 'a> {
    let params = header.symmetric_params();

    // TODO: Verify AAD hash if present in header

    let wrapper = SymmetricAlgorithmWrapper::from_enum(params.algorithm);
    let setup = super::body::streaming::StreamingDecryptorSetup::new(
        wrapper,
        params.base_nonce.clone(),
        params.chunk_size as usize,
        aad,
    );
    Ok(setup.start(reader, key))
}

// --- Parallel ---

/// Decrypts data in-memory using multiple threads.
/// The ciphertext is expected to start with a length-prefixed `SealFlowEnvelopeHeader`.
/// Returns the parsed header and the decrypted plaintext.
pub fn decrypt_parallel_body<'a>(
    ciphertext_body: &[u8],
    key: Cow<'a, TypedSymmetricKey>,
    header: &SealFlowEnvelopeHeader,
    aad: Option<Vec<u8>>,
) -> Result<Vec<u8>> {
    let params = header.symmetric_params();

    // TODO: Verify AAD hash if present in header

    let wrapper = SymmetricAlgorithmWrapper::from_enum(params.algorithm);
    let decryptor = super::body::parallel::ParallelDecryptor::new(
        wrapper,
        params.base_nonce.clone(),
        params.chunk_size as usize,
        aad,
    );
    decryptor.decrypt(ciphertext_body, key)
}

// --- Parallel Streaming ---

/// Decrypts a stream in parallel.
/// The reader is expected to contain only the ciphertext body, as the header should be pre-parsed.
pub fn decrypt_parallel_streaming_body<'a, R, W>(
    reader: R,
    writer: W,
    key: Cow<'a, TypedSymmetricKey>,
    header: &SealFlowEnvelopeHeader,
    aad: Option<Vec<u8>>,
    channel_bound: usize,
) -> Result<()>
    where
        R: Read + Send,
        W: Write + Send,
{
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
    decryptor.run(reader, writer, key)
}


// --- Asynchronous ---

/// Returns a reader that asynchronously decrypts data as it's read.
/// The reader is expected to contain only the ciphertext body, as the header should be pre-parsed.
#[cfg(feature = "async")]
pub fn decrypt_asynchronous_body<'a, R: AsyncRead + Send + Unpin + 'a>(
    reader: R,
    key: Cow<'a, TypedSymmetricKey>,
    header: &SealFlowEnvelopeHeader,
    aad: Option<Vec<u8>>,
    channel_bound: usize,
) -> AsyncDecryptorImpl<'a, R> {
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
    setup.start(reader, key)
}

// --- Header Parsing ---

/// Reads a header from a slice.
/// Returns the parsed header and the remaining ciphertext body.
pub fn read_header_from_slice(ciphertext: &[u8]) -> Result<(SealFlowEnvelopeHeader, &[u8])> {
    SealFlowEnvelopeHeader::decode_from_prefixed_slice(ciphertext)
}

/// Reads a header from a synchronous reader.
/// The reader will be consumed to the end of the header.
pub fn read_header_from_reader<R: Read>(reader: &mut R) -> Result<SealFlowEnvelopeHeader> {
    SealFlowEnvelopeHeader::decode_from_prefixed_reader(reader)
}

/// Reads a header from an asynchronous reader.
/// The reader will be consumed to the end of the header.
#[cfg(feature = "async")]
pub async fn read_header_from_async_reader<R: AsyncRead + Unpin + Send>(
    reader: &mut R,
) -> Result<SealFlowEnvelopeHeader> {
    SealFlowEnvelopeHeader::decode_from_prefixed_async_reader(reader).await
} 