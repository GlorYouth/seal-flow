//! Implements the common logic for synchronous, streaming encryption and decryption.
//! This is the backend for both symmetric and hybrid streaming modes.
//!
//! 实现同步、流式加密和解密的通用逻辑。
//! 这是对称和混合流式模式的后端。

use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::{derive_nonce, DEFAULT_CHUNK_SIZE};
use crate::error::Result;
use crate::keys::TypedSymmetricKey;
use crate::algorithms::symmetric::SymmetricAlgorithmWrapper;
use std::io::{self, Read, Write};

use super::traits::StreamingBodyProcessor;

// --- Encryptor ---

/// The implementation of a synchronous, streaming encryptor.
///
/// 同步、流式加密器的实现。
pub struct EncryptorImpl<W: Write> {
    writer: W,
    algorithm: SymmetricAlgorithmWrapper,
    key: TypedSymmetricKey,
    base_nonce: [u8; 12],
    chunk_size: usize,
    buffer: Vec<u8>,
    chunk_counter: u64,
    encrypted_chunk_buffer: Vec<u8>,
    aad: Option<Vec<u8>>,
}

impl<W: Write> EncryptorImpl<W> {
    /// Creates a new `EncryptorImpl`.
    ///
    /// 创建一个新的 `EncryptorImpl`。
    pub fn new(
        writer: W,
        algorithm: SymmetricAlgorithmWrapper,
        key: TypedSymmetricKey,
        base_nonce: [u8; 12],
        aad: Option<&[u8]>,
    ) -> Result<Self> {
        let encrypted_chunk_buffer = vec![0u8; DEFAULT_CHUNK_SIZE as usize + algorithm.tag_size()];
        Ok(Self {
            writer,
            algorithm,
            key,
            base_nonce,
            chunk_size: DEFAULT_CHUNK_SIZE as usize,
            buffer: Vec::with_capacity(DEFAULT_CHUNK_SIZE as usize),
            chunk_counter: 0,
            encrypted_chunk_buffer,
            aad: aad.map(|d| d.to_vec()),
        })
    }

    /// Finalizes the encryption stream.
    /// This method must be called to ensure that the last partial chunk of data is
    /// encrypted and the authentication tag is written to the underlying writer.
    ///
    /// 完成加密流。
    /// 必须调用此方法以确保最后的数据块被加密，
    /// 并且认证标签被写入底层的 writer。
    pub fn finish(mut self) -> Result<()> {
        if !self.buffer.is_empty() {
            let nonce = derive_nonce(&self.base_nonce, self.chunk_counter);
            let bytes_written = self
                .algorithm
                .encrypt_to_buffer(
                    self.key.clone(),
                    &nonce,
                    &self.buffer,
                    &mut self.encrypted_chunk_buffer,
                    self.aad.as_deref(),
                )
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            self.writer
                .write_all(&self.encrypted_chunk_buffer[..bytes_written])?;
            self.chunk_counter += 1;
            self.buffer.clear();
        }
        self.writer.flush()?;
        Ok(())
    }
}

impl<W: Write> Write for EncryptorImpl<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut input = buf;

        if !self.buffer.is_empty() {
            let space_in_buffer = self.chunk_size - self.buffer.len();
            let fill_len = std::cmp::min(space_in_buffer, input.len());
            self.buffer.extend_from_slice(&input[..fill_len]);
            input = &input[fill_len..];

            if self.buffer.len() == self.chunk_size {
                let nonce = derive_nonce(&self.base_nonce, self.chunk_counter);

                let bytes_written = self
                    .algorithm
                    .encrypt_to_buffer(
                        self.key.clone(),
                        &nonce,
                        &self.buffer,
                        &mut self.encrypted_chunk_buffer,
                        self.aad.as_deref(),
                    )
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                self.writer
                    .write_all(&self.encrypted_chunk_buffer[..bytes_written])?;
                self.chunk_counter += 1;
                self.buffer.clear();
            }
        }

        while input.len() >= self.chunk_size {
            let chunk = &input[..self.chunk_size];
            let nonce = derive_nonce(&self.base_nonce, self.chunk_counter);

            let bytes_written = self
                .algorithm
                .encrypt_to_buffer(
                    self.key.clone(),
                    &nonce,
                    chunk,
                    &mut self.encrypted_chunk_buffer,
                    self.aad.as_deref(),
                )
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            self.writer
                .write_all(&self.encrypted_chunk_buffer[..bytes_written])?;

            self.chunk_counter += 1;
            input = &input[self.chunk_size..];
        }

        if !input.is_empty() {
            self.buffer.extend_from_slice(input);
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

// --- Decryptor ---

/// The implementation of a synchronous, streaming decryptor.
///
/// 同步、流式解密器的实现。
pub struct DecryptorImpl<R: Read> {
    reader: R,
    algorithm: SymmetricAlgorithmWrapper,
    key: TypedSymmetricKey,
    base_nonce: [u8; 12],
    encrypted_chunk_size: usize,
    buffer: io::Cursor<Vec<u8>>,
    encrypted_chunk_buffer: Vec<u8>,
    chunk_counter: u64,
    is_done: bool,
    aad: Option<Vec<u8>>,
}

impl<R: Read> DecryptorImpl<R> {
    /// Creates a new `DecryptorImpl`.
    ///
    /// 创建一个新的 `DecryptorImpl`。
    pub fn new(
        reader: R,
        algorithm: SymmetricAlgorithmWrapper,
        key: TypedSymmetricKey,
        base_nonce: [u8; 12],
        aad: Option<&[u8]>,
    ) -> Self {
        let encrypted_chunk_size = DEFAULT_CHUNK_SIZE as usize + algorithm.tag_size();
        Self {
            reader,
            algorithm,
            key,
            base_nonce,
            encrypted_chunk_size,
            buffer: io::Cursor::new(Vec::new()),
            encrypted_chunk_buffer: vec![0; encrypted_chunk_size],
            chunk_counter: 0,
            is_done: false,
            aad: aad.map(|d| d.to_vec()),
        }
    }
}

impl<R: Read> Read for DecryptorImpl<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes_read_from_buf = self.buffer.read(buf)?;
        if bytes_read_from_buf > 0 {
            return Ok(bytes_read_from_buf);
        }

        if self.is_done {
            return Ok(0);
        }

        let mut total_bytes_read = 0;
        while total_bytes_read < self.encrypted_chunk_size {
            match self
                .reader
                .read(&mut self.encrypted_chunk_buffer[total_bytes_read..])
            {
                Ok(0) => {
                    self.is_done = true;
                    break;
                }
                Ok(n) => total_bytes_read += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        if total_bytes_read == 0 {
            return Ok(0);
        }

        let nonce = derive_nonce(&self.base_nonce, self.chunk_counter);

        let decrypted_buf = self.buffer.get_mut();
        decrypted_buf.clear();
        decrypted_buf.resize(self.encrypted_chunk_size, 0);

        let bytes_written = self
            .algorithm
            .decrypt_to_buffer(
                self.key.clone(),
                &nonce,
                &self.encrypted_chunk_buffer[..total_bytes_read],
                decrypted_buf,
                self.aad.as_deref(),
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        decrypted_buf.truncate(bytes_written);
        self.buffer.set_position(0);
        self.chunk_counter += 1;

        self.buffer.read(buf)
    }
}

