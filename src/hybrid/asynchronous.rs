//! Asynchronous, streaming hybrid encryption and decryption implementation.
#![cfg(feature = "async")]

use super::common::{
    create_header, derive_nonce, DEFAULT_CHUNK_SIZE,
};
use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, Result};
use futures::ready;
use pin_project_lite::pin_project;
use seal_crypto::zeroize::Zeroizing;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

// --- Encryptor ---

enum EncryptorState {
    Idle,
    Encrypting(JoinHandle<Result<Vec<u8>>>),
    Writing { chunk: Vec<u8>, pos: usize },
}

pin_project! {
    pub struct Encryptor<W: AsyncWrite, A, S> {
        #[pin]
        writer: W,
        symmetric_key: Zeroizing<Vec<u8>>,
        base_nonce: [u8; 12],
        chunk_size: usize,
        buffer: Vec<u8>,
        chunk_counter: u64,
        state: EncryptorState,
        _phantom: std::marker::PhantomData<(A, S)>,
    }
}

impl<W: AsyncWrite + Unpin, A, S> Encryptor<W, A, S>
where
    A: AsymmetricAlgorithm,
    A::EncapsulatedKey: Into<Vec<u8>> + Send,
    S: SymmetricAlgorithm,
{
    pub async fn new(mut writer: W, pk: A::PublicKey, kek_id: String) -> Result<Self> {
        let (header, base_nonce, shared_secret) =
            tokio::task::spawn_blocking(move || create_header::<A, S>(&pk.into(), kek_id))
                .await??;

        let header_bytes = header.encode_to_vec()?;
        use tokio::io::AsyncWriteExt;
        writer
            .write_all(&(header_bytes.len() as u32).to_le_bytes())
            .await?;
        writer.write_all(&header_bytes).await?;

        Ok(Self {
            writer,
            symmetric_key: shared_secret,
            base_nonce,
            chunk_size: DEFAULT_CHUNK_SIZE as usize,
            buffer: Vec::with_capacity(DEFAULT_CHUNK_SIZE as usize),
            chunk_counter: 0,
            state: EncryptorState::Idle,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<W: AsyncWrite + Unpin, A, S> AsyncWrite for Encryptor<W, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    S::Key: Clone + Send + Sync + From<Zeroizing<Vec<u8>>>,
{
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        this.buffer.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut this = self.as_mut().project();
            match this.state {
                EncryptorState::Idle => {
                    if this.buffer.is_empty() {
                        return this.writer.poll_flush(cx);
                    }
                    let chunk_len = std::cmp::min(this.buffer.len(), *this.chunk_size);
                    let chunk = this.buffer.drain(..chunk_len).collect::<Vec<u8>>();
                    let nonce = derive_nonce(this.base_nonce, *this.chunk_counter);
                    let key: S::Key = this.symmetric_key.clone().into();
                    let handle = tokio::task::spawn_blocking(move || {
                        S::encrypt(&key, &nonce, &chunk, None).map_err(Error::from)
                    });
                    *this.state = EncryptorState::Encrypting(handle);
                }
                EncryptorState::Encrypting(handle) => {
                    let encrypted_chunk = match ready!(Pin::new(handle).poll(cx)) {
                        Ok(Ok(chunk)) => chunk,
                        Ok(Err(e)) => {
                            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
                        }
                        Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
                    };
                    *this.state = EncryptorState::Writing {
                        chunk: encrypted_chunk,
                        pos: 0,
                    };
                }
                EncryptorState::Writing { chunk, pos } => {
                    while *pos < chunk.len() {
                        let bytes_written =
                            ready!(this.writer.as_mut().poll_write(cx, &chunk[*pos..]))?;
                        if bytes_written == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "failed to write whole chunk",
                            )));
                        }
                        *pos += bytes_written;
                    }
                    *this.chunk_counter += 1;
                    *this.state = EncryptorState::Idle;
                }
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        self.project().writer.poll_shutdown(cx)
    }
}

/// An asynchronous pending hybrid decryptor, waiting for the private key.
pub struct PendingDecryptor<R: AsyncRead + Unpin> {
    reader: R,
    header: Header,
}

impl<R: AsyncRead + Unpin> PendingDecryptor<R> {
    /// Creates a new `PendingDecryptor` by asynchronously reading the header.
    pub async fn from_reader(mut reader: R) -> Result<Self> {
        let header = Header::decode_from_prefixed_async_reader(&mut reader).await?;

        Ok(Self { reader, header })
    }

    /// Returns a reference to the header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Consumes the pending decryptor and returns a full `Decryptor`.
    pub async fn into_decryptor<A, S>(self, sk: A::PrivateKey) -> Result<Decryptor<R, A, S>>
    where
        A: AsymmetricAlgorithm,
        A::EncapsulatedKey: From<Vec<u8>> + Send,
        S: SymmetricAlgorithm,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        let (encapsulated_key, chunk_size, base_nonce) = match self.header.payload {
            HeaderPayload::Hybrid {
                encrypted_dek,
                stream_info: Some(info),
                ..
            } => (encrypted_dek.into(), info.chunk_size, info.base_nonce),
            _ => return Err(Error::InvalidHeader),
        };

        let shared_secret =
            tokio::task::spawn_blocking(move || A::decapsulate(&sk.into(), &encapsulated_key))
                .await??;

        let tag_len = S::TAG_SIZE;
        let encrypted_chunk_size = chunk_size as usize + tag_len;

        Ok(Decryptor::new(
            self.reader,
            shared_secret,
            base_nonce,
            encrypted_chunk_size,
        ))
    }
}

// --- Decryptor ---

enum DecryptorState {
    Idle,
    Decrypting(JoinHandle<Result<Vec<u8>>>),
}

pin_project! {
    pub struct Decryptor<R: AsyncRead, A, S> {
        #[pin]
        reader: R,
        symmetric_key: Zeroizing<Vec<u8>>,
        base_nonce: [u8; 12],
        encrypted_chunk_size: usize,
        buffer: io::Cursor<Vec<u8>>,
        chunk_counter: u64,
        is_done: bool,
        state: DecryptorState,
        _phantom: std::marker::PhantomData<(A, S)>,
    }
}

impl<R: AsyncRead + Unpin, A, S> Decryptor<R, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
{
    pub fn new(
        reader: R,
        symmetric_key: Zeroizing<Vec<u8>>,
        base_nonce: [u8; 12],
        encrypted_chunk_size: usize,
    ) -> Self {
        Self {
            reader,
            symmetric_key,
            base_nonce,
            encrypted_chunk_size,
            buffer: io::Cursor::new(Vec::new()),
            chunk_counter: 0,
            is_done: false,
            state: DecryptorState::Idle,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<R: AsyncRead + Unpin, A, S> AsyncRead for Decryptor<R, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    S::Key: Clone + Send + Sync + From<Zeroizing<Vec<u8>>>,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let this = self.as_mut().project();
            let bytes_in_internal_buffer =
                this.buffer.get_ref().len() - this.buffer.position() as usize;
            if bytes_in_internal_buffer > 0 {
                let to_copy = std::cmp::min(bytes_in_internal_buffer, buf.remaining());
                let current_pos = this.buffer.position() as usize;
                buf.put_slice(&this.buffer.get_ref()[current_pos..current_pos + to_copy]);
                this.buffer
                    .set_position(this.buffer.position() + to_copy as u64);
                return Poll::Ready(Ok(()));
            }

            if *this.is_done {
                return Poll::Ready(Ok(()));
            }

            let this = self.as_mut().project();
            match this.state {
                DecryptorState::Idle => {
                    let mut encrypted_chunk = vec![0u8; *this.encrypted_chunk_size];
                    let mut read_buf = ReadBuf::new(&mut encrypted_chunk);

                    ready!(this.reader.poll_read(cx, &mut read_buf))?;
                    let bytes_read = read_buf.filled().len();

                    if bytes_read == 0 {
                        *this.is_done = true;
                        return Poll::Ready(Ok(()));
                    }

                    let final_encrypted_chunk = &encrypted_chunk[..bytes_read];

                    let nonce = derive_nonce(this.base_nonce, *this.chunk_counter);

                    let key: S::Key = this.symmetric_key.clone().into();
                    let final_encrypted_chunk = final_encrypted_chunk.to_vec();
                    let handle = tokio::task::spawn_blocking(move || {
                        S::decrypt(&key, &nonce, &final_encrypted_chunk, None).map_err(Error::from)
                    });

                    *this.state = DecryptorState::Decrypting(handle);
                }
                DecryptorState::Decrypting(handle) => {
                    let plaintext_chunk = match ready!(Pin::new(handle).poll(cx)) {
                        Ok(Ok(data)) => data,
                        Ok(Err(e)) => {
                            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e)))
                        }
                        Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
                    };
                    *this.buffer = io::Cursor::new(plaintext_chunk);
                    *this.chunk_counter += 1;
                    *this.state = DecryptorState::Idle;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::prelude::KeyGenerator;
    use seal_crypto::schemes::asymmetric::traditional::rsa::Rsa2048;
    use seal_crypto::schemes::hash::Sha256;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use std::io::Cursor;

    async fn test_hybrid_async_streaming_roundtrip(plaintext: &[u8]) {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let kek_id = "test-rsa-key".to_string();

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor =
            Encryptor::<_, Rsa2048<Sha256>, Aes256Gcm>::new(&mut encrypted_data, pk, kek_id.clone())
                .await
                .unwrap();
        encryptor.write_all(plaintext).await.unwrap();
        encryptor.shutdown().await.unwrap();

        // Decrypt
        let pending =
            PendingDecryptor::from_reader(Cursor::new(&encrypted_data))
                .await
                .unwrap();
        assert_eq!(pending.header().payload.kek_id(), Some(kek_id.as_str()));

        let mut decryptor = pending
            .into_decryptor::<Rsa2048<Sha256>, Aes256Gcm>(sk)
            .await
            .unwrap();
        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).await.unwrap();
        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[tokio::test]
    async fn test_roundtrip_long_message_async() {
        let plaintext = b"This is a very long test message to test the async hybrid streaming encryption and decryption. It needs to be longer than a single chunk to ensure the chunking logic is working correctly.";
        test_hybrid_async_streaming_roundtrip(plaintext).await;
    }

    #[tokio::test]
    async fn test_roundtrip_empty_message_async() {
        test_hybrid_async_streaming_roundtrip(b"").await;
    }

    #[tokio::test]
    async fn test_roundtrip_exact_chunk_size_async() {
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];
        test_hybrid_async_streaming_roundtrip(&plaintext).await;
    }

    #[tokio::test]
    async fn test_tampered_ciphertext_fails_async() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"some important data";

        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, Rsa2048<Sha256>, Aes256Gcm>::new(
            &mut encrypted_data,
            pk,
            "test-kek-id".to_string(),
        )
        .await
        .unwrap();
        encryptor.write_all(plaintext).await.unwrap();
        encryptor.shutdown().await.unwrap();

        let header_len =
            4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        if encrypted_data.len() > header_len {
            encrypted_data[header_len] ^= 1;
        }

        let pending =
            PendingDecryptor::from_reader(Cursor::new(&encrypted_data))
                .await
                .unwrap();
        let mut decryptor = pending
            .into_decryptor::<Rsa2048<Sha256>, Aes256Gcm>(sk)
            .await
            .unwrap();
        let result = decryptor.read_to_end(&mut Vec::new()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_wrong_private_key_fails_async() {
        let (pk, _) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let (_, sk2) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"some data";

        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, Rsa2048<Sha256>, Aes256Gcm>::new(
            &mut encrypted_data,
            pk,
            "test_kek_id".to_string(),
        )
        .await
        .unwrap();
        encryptor.write_all(plaintext).await.unwrap();
        encryptor.shutdown().await.unwrap();

        let pending =
            PendingDecryptor::from_reader(Cursor::new(&encrypted_data))
                .await
                .unwrap();
        let result = pending
            .into_decryptor::<Rsa2048<Sha256>, Aes256Gcm>(sk2)
            .await;
        assert!(result.is_err());
    }
}
