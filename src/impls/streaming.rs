//! Implements the common logic for synchronous, streaming encryption and decryption.
use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::{derive_nonce, DEFAULT_CHUNK_SIZE};
use crate::error::Result;
use std::io::{self, Read, Write};

// --- Encryptor ---

pub struct EncryptorImpl<W: Write, S: SymmetricAlgorithm> {
    writer: W,
    symmetric_key: S::Key,
    base_nonce: [u8; 12],
    chunk_size: usize,
    buffer: Vec<u8>,
    chunk_counter: u64,
    encrypted_chunk_buffer: Vec<u8>,
    aad: Option<Vec<u8>>,
    _phantom: std::marker::PhantomData<S>,
}

impl<W: Write, S: SymmetricAlgorithm> EncryptorImpl<W, S> {
    pub fn new(
        writer: W,
        symmetric_key: S::Key,
        base_nonce: [u8; 12],
        aad: Option<&[u8]>,
    ) -> Result<Self> {
        Ok(Self {
            writer,
            symmetric_key,
            base_nonce,
            chunk_size: DEFAULT_CHUNK_SIZE as usize,
            buffer: Vec::with_capacity(DEFAULT_CHUNK_SIZE as usize),
            chunk_counter: 0,
            encrypted_chunk_buffer: vec![0u8; DEFAULT_CHUNK_SIZE as usize + S::TAG_SIZE],
            aad: aad.map(|d| d.to_vec()),
            _phantom: std::marker::PhantomData,
        })
    }

    pub fn finish(mut self) -> Result<()> {
        if !self.buffer.is_empty() {
            let nonce = derive_nonce(&self.base_nonce, self.chunk_counter);
            let bytes_written = S::encrypt_to_buffer(
                &self.symmetric_key,
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

impl<W: Write, S: SymmetricAlgorithm> Write for EncryptorImpl<W, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut input = buf;

        if !self.buffer.is_empty() {
            let space_in_buffer = self.chunk_size - self.buffer.len();
            let fill_len = std::cmp::min(space_in_buffer, input.len());
            self.buffer.extend_from_slice(&input[..fill_len]);
            input = &input[fill_len..];

            if self.buffer.len() == self.chunk_size {
                let nonce = derive_nonce(&self.base_nonce, self.chunk_counter);

                let bytes_written = S::encrypt_to_buffer(
                    &self.symmetric_key,
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

            let bytes_written = S::encrypt_to_buffer(
                &self.symmetric_key,
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

pub struct DecryptorImpl<R: Read, S: SymmetricAlgorithm> {
    reader: R,
    symmetric_key: S::Key,
    base_nonce: [u8; 12],
    encrypted_chunk_size: usize,
    buffer: io::Cursor<Vec<u8>>,
    encrypted_chunk_buffer: Vec<u8>,
    chunk_counter: u64,
    is_done: bool,
    aad: Option<Vec<u8>>,
    _phantom: std::marker::PhantomData<S>,
}

impl<R: Read, S: SymmetricAlgorithm> DecryptorImpl<R, S> {
    pub fn new(
        reader: R,
        key: S::Key,
        base_nonce: [u8; 12],
        encrypted_chunk_size: usize,
        aad: Option<&[u8]>,
    ) -> Self {
        Self {
            reader,
            symmetric_key: key,
            base_nonce,
            encrypted_chunk_size,
            buffer: io::Cursor::new(Vec::new()),
            encrypted_chunk_buffer: vec![0; encrypted_chunk_size],
            chunk_counter: 0,
            is_done: false,
            aad: aad.map(|d| d.to_vec()),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<R: Read, S: SymmetricAlgorithm> Read for DecryptorImpl<R, S> {
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

        let bytes_written = S::decrypt_to_buffer(
            &self.symmetric_key,
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