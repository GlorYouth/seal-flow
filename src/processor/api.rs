//! Provides a simplified, unified API for the different processing modes.
//! This acts as a facade over the `ordinary`, `streaming`, `parallel`, etc. modules.
//!
//! 为不同的处理模式提供了一个简化的、统一的 API。
//! 这个模块作为 `ordinary`, `streaming`, `parallel` 等模块的外观。

use crate::common::header::SealFlowHeader;
use crate::error::Result;
#[cfg(feature = "async")]
use crate::processor::body::asynchronous::{AsyncDecryptorImpl, AsyncEncryptorImpl};
use crate::processor::traits::FinishingWrite;
use seal_crypto_wrapper::prelude::{TypedSignaturePublicKey, TypedSymmetricKey};
use seal_crypto_wrapper::wrappers::symmetric::SymmetricAlgorithmWrapper;
use std::borrow::Cow;
use std::io::{Read, Write};
use std::marker::PhantomData;
#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};

// --- Encryption Flow ---

/// The starting point for any encryption operation.
/// This struct configures the encryption behavior and initiates the process.
pub struct EncryptionConfigurator<'a, H> {
    header: H,
    key: Cow<'a, TypedSymmetricKey>,
    aad: Option<Vec<u8>>,
}

impl<'a, H: SealFlowHeader> EncryptionConfigurator<'a, H> {
    /// Creates a new encryption configurator.
    ///
    /// # Arguments
    /// * `header`: The `SealFlowEnvelopeHeader` containing all metadata for the encryption.
    /// * `key`: The symmetric key for encryption.
    /// * `aad`: Optional Additional Authenticated Data.
    pub fn new(header: H, key: Cow<'a, TypedSymmetricKey>, aad: Option<Vec<u8>>) -> Self {
        Self { header, key, aad }
    }

    /// Writes the header to a synchronous writer and transitions to a streaming encryption flow.
    pub fn into_writer<W: Write + 'a>(self, mut writer: W) -> Result<EncryptionFlow<'a, W, H>> {
        self.header.write_to_prefixed_writer(&mut writer)?;
        Ok(EncryptionFlow {
            writer,
            config: self,
        })
    }

    /// Writes the header to a synchronous writer and transitions to a parallel streaming encryption flow.
    pub fn into_parallel_streaming_flow<W: Write + Send + 'a>(
        self,
        mut writer: W,
        channel_bound: usize,
    ) -> Result<ParallelEncryptionStreamFlow<'a, W, H>> {
        self.header.write_to_prefixed_writer(&mut writer)?;
        Ok(ParallelEncryptionStreamFlow {
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
    ) -> Result<AsyncEncryptionStreamFlow<'a, W, H>> {
        self.header
            .write_to_prefixed_async_writer(&mut writer)
            .await?;
        Ok(AsyncEncryptionStreamFlow {
            writer,
            config: self,
            channel_bound,
        })
    }
}

/// Represents the state after the header has been written to a synchronous stream.
pub struct EncryptionFlow<'a, W: Write + 'a, H: SealFlowHeader> {
    writer: W,
    config: EncryptionConfigurator<'a, H>,
}

impl<'a, W: Write + 'a, H: SealFlowHeader> EncryptionFlow<'a, W, H> {
    pub fn encrypt_ordinary(self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let symmetric_params = self.config.header.symmetric_params().clone();
        let encryptor =
            super::body::ordinary::OrdinaryEncryptor::new(symmetric_params, self.config.aad);
        let mut ciphertext = encryptor.encrypt(plaintext, self.config.key)?;

        let mut header_bytes = self.config.header.encode_to_prefixed_vec()?;
        header_bytes.append(&mut ciphertext);
        Ok(header_bytes)
    }

    pub fn encrypt_parallel(self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let symmetric_params = self.config.header.symmetric_params().clone();
        let encryptor =
            super::body::parallel::ParallelEncryptor::new(symmetric_params, self.config.aad);
        let mut ciphertext = encryptor.encrypt(plaintext, self.config.key)?;

        let mut header_bytes = self.config.header.encode_to_prefixed_vec()?;
        header_bytes.append(&mut ciphertext);
        Ok(header_bytes)
    }

    /// Starts the encryption on the stream, returning a writer that encrypts data as it's written.
    pub fn start_streaming(self) -> Result<Box<dyn FinishingWrite + 'a>> {
        let symmetric_params = self.config.header.symmetric_params().clone();
        let setup =
            super::body::streaming::StreamingEncryptorSetup::new(symmetric_params, self.config.aad);
        let encryptor = setup.start(self.writer, self.config.key)?;
        Ok(Box::new(encryptor))
    }
}

impl<'a, H: SealFlowHeader> EncryptionFlow<'a, Vec<u8>, H> {
    pub fn encrypt_ordinary_to_vec(self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_ordinary(plaintext)
    }

    pub fn encrypt_parallel_to_vec(self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_parallel(plaintext)
    }
}

/// Represents the state after the header has been written for a parallel streaming operation.
pub struct ParallelEncryptionStreamFlow<'a, W: Write + Send + 'a, H: SealFlowHeader> {
    writer: W,
    config: EncryptionConfigurator<'a, H>,
    channel_bound: usize,
}

impl<'a, W: Write + Send + 'a, H: SealFlowHeader> ParallelEncryptionStreamFlow<'a, W, H> {
    /// Starts the parallel encryption, consuming a reader and writing encrypted data to the writer.
    pub fn start_parallel_streaming<R: Read + Send>(self, reader: R) -> Result<()> {
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
pub struct AsyncEncryptionStreamFlow<'a, W: AsyncWrite + Send + Unpin + 'a, H: SealFlowHeader> {
    writer: W,
    config: EncryptionConfigurator<'a, H>,
    channel_bound: usize,
}

#[cfg(feature = "async")]
impl<'a, W: AsyncWrite + Send + Unpin + 'a, H: SealFlowHeader> AsyncEncryptionStreamFlow<'a, W, H> {
    /// Starts the encryption on the async stream, returning a writer that encrypts data as it's written.
    pub fn start_asynchronous(self) -> Result<AsyncEncryptorImpl<'a, W>> {
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

/// Prepares for decryption by reading the header from a slice.
/// Returns a `PendingDecryption` instance and the remaining ciphertext body.
pub fn prepare_decryption_from_slice<'a, 'b, H: SealFlowHeader>(
    ciphertext: &'a [u8],
    verify_key: Option<&'b TypedSignaturePublicKey>,
) -> Result<PendingDecryption<&'a [u8], H>> {
    let (header, body) = H::decode_from_prefixed_slice(ciphertext, verify_key)?;
    let pending = PendingDecryption {
        header,
        source: body,
        _phantom: PhantomData,
    };
    Ok(pending)
}

/// Prepares for decryption by reading the header from a reader.
/// Returns a `PendingDecryption` instance, leaving the reader positioned at the start of the body.
pub fn prepare_decryption_from_reader<'a, R: Read, H: SealFlowHeader>(
    mut reader: R,
    verify_key: Option<&'a TypedSignaturePublicKey>,
) -> Result<PendingDecryption<R, H>> {
    let header = H::decode_from_prefixed_reader(&mut reader, verify_key)?;
    Ok(PendingDecryption {
        header,
        source: reader,
        _phantom: PhantomData,
    })
}

/// Prepares for decryption by reading the header from an asynchronous reader.
/// Returns a `PendingDecryption` instance, leaving the reader positioned at the start of the body.
#[cfg(feature = "async")]
pub async fn prepare_decryption_from_async_reader<'a,
    R: AsyncRead + Unpin + Send,
    H: SealFlowHeader,
>(
    mut reader: R,
    verify_key: Option<&'a TypedSignaturePublicKey>,
) -> Result<PendingDecryption<R, H>> {
    let header = H::decode_from_prefixed_async_reader(&mut reader, verify_key).await?;
    Ok(PendingDecryption {
        header,
        source: reader,
        _phantom: PhantomData,
    })
}

/// Represents a decryption operation that is ready to be executed.
/// The header has been parsed, and the ciphertext source is available.
pub struct PendingDecryption<S, H> {
    header: H,
    source: S,
    _phantom: PhantomData<H>,
}

impl<S, H: SealFlowHeader> PendingDecryption<S, H> {
    /// Returns a reference to the parsed header.
    pub fn header(&self) -> &H {
        &self.header
    }

    /// Returns a reference to the source of the ciphertext.
    pub fn source(&self) -> &S {
        &self.source
    }

    /// Consumes the `PendingDecryption` and returns the source.
    pub fn into_source(self) -> S {
        self.source
    }
}

impl<'a, H: SealFlowHeader> PendingDecryption<&'a [u8], H> {
    /// Decrypts data in-memory using a single thread.
    pub fn decrypt_ordinary(
        self,
        key: Cow<'a, TypedSymmetricKey>,
        aad: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let params = self.header.symmetric_params();
        let wrapper = SymmetricAlgorithmWrapper::from_enum(params.algorithm);
        let decryptor = super::body::ordinary::OrdinaryDecryptor::new(
            wrapper,
            params.base_nonce.clone(),
            params.chunk_size as usize,
            aad,
        );
        decryptor.decrypt(self.source, key)
    }

    /// Decrypts data in-memory using multiple threads.
    pub fn decrypt_parallel(
        self,
        key: Cow<'a, TypedSymmetricKey>,
        aad: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let params = self.header.symmetric_params();
        let wrapper = SymmetricAlgorithmWrapper::from_enum(params.algorithm);
        let decryptor = super::body::parallel::ParallelDecryptor::new(
            wrapper,
            params.base_nonce.clone(),
            params.chunk_size as usize,
            aad,
        );
        decryptor.decrypt(self.source, key)
    }
}

impl<'a, R: Read + 'a, H: SealFlowHeader> PendingDecryption<R, H> {
    /// Returns a reader that decrypts data as it's read.
    pub fn decrypt_streaming(
        self,
        key: Cow<'a, TypedSymmetricKey>,
        aad: Option<Vec<u8>>,
    ) -> Result<impl Read + 'a> {
        let params = self.header.symmetric_params();
        let wrapper = SymmetricAlgorithmWrapper::from_enum(params.algorithm);
        let setup = super::body::streaming::StreamingDecryptorSetup::new(
            wrapper,
            params.base_nonce.clone(),
            params.chunk_size as usize,
            aad,
        );
        Ok(setup.start(self.source, key))
    }
}

impl<'a, R: Read + Send + 'a, H: SealFlowHeader> PendingDecryption<R, H> {
    /// Decrypts a stream in parallel.
    pub fn decrypt_parallel_streaming<W>(
        self,
        writer: W,
        key: Cow<'a, TypedSymmetricKey>,
        aad: Option<Vec<u8>>,
        channel_bound: usize,
    ) -> Result<()>
    where
        W: Write + Send,
    {
        let params = self.header.symmetric_params();
        let wrapper = SymmetricAlgorithmWrapper::from_enum(params.algorithm);
        let decryptor = super::body::parallel_streaming::ParallelStreamingDecryptor::new(
            wrapper,
            params.base_nonce.clone(),
            aad,
            params.chunk_size as usize,
            channel_bound,
        );
        decryptor.run(self.source, writer, key)
    }
}

#[cfg(feature = "async")]
impl<'a, R: AsyncRead + Send + Unpin + 'a, H: SealFlowHeader> PendingDecryption<R, H> {
    /// Returns a reader that asynchronously decrypts data as it's read.
    pub fn decrypt_asynchronous(
        self,
        key: Cow<'a, TypedSymmetricKey>,
        aad: Option<Vec<u8>>,
        channel_bound: usize,
    ) -> AsyncDecryptorImpl<'a, R> {
        let params = self.header.symmetric_params();
        let wrapper = SymmetricAlgorithmWrapper::from_enum(params.algorithm);
        let setup = super::body::asynchronous::AsyncDecryptorSetup::new(
            wrapper,
            params.base_nonce.clone(),
            aad,
            params.chunk_size as usize,
            channel_bound,
        );
        setup.start(self.source, key)
    }
}

// --- Header Parsing ---

/// Reads a header from a slice.
/// Returns the parsed header and the remaining ciphertext body.
pub fn read_header_from_slice<'a, 'b, H: SealFlowHeader>(
    ciphertext: &'a [u8],
    verify_key: Option<&'b TypedSignaturePublicKey>,
) -> Result<(H, &'a [u8])> {
    H::decode_from_prefixed_slice(ciphertext, verify_key)
}

/// Reads a header from a synchronous reader.
/// The reader will be consumed to the end of the header.
pub fn read_header_from_reader<'a, R: Read, H: SealFlowHeader>(
    reader: &mut R,
    verify_key: Option<&'a TypedSignaturePublicKey>,
) -> Result<H> {
    H::decode_from_prefixed_reader(reader, verify_key)
}

/// Reads a header from an asynchronous reader.
/// The reader will be consumed to the end of the header.
#[cfg(feature = "async")]
pub async fn read_header_from_async_reader<'a, R: AsyncRead + Unpin + Send, H: SealFlowHeader>(
    reader: &mut R,
    verify_key: Option<&'a TypedSignaturePublicKey>,
) -> Result<H> {
    H::decode_from_prefixed_async_reader(reader, verify_key).await
}
