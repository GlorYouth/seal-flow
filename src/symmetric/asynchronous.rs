#![cfg(feature = "async")]

use super::common::{create_header, derive_nonce, DEFAULT_CHUNK_SIZE};
use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, Result};
use futures::ready;
use pin_project_lite::pin_project;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

enum EncryptorState {
    Idle,
    Encrypting(JoinHandle<Result<Vec<u8>>>),
    Writing { chunk: Vec<u8>, pos: usize },
}

pin_project! {
    pub struct Encryptor<W: AsyncWrite, S: SymmetricAlgorithm> {
        #[pin]
        writer: W,
        symmetric_key: Arc<S::Key>,
        base_nonce: [u8; 12],
        chunk_size: usize,
        buffer: Vec<u8>,
        chunk_counter: u64,
        state: EncryptorState,
        _phantom: std::marker::PhantomData<S>,
    }
}

impl<W: AsyncWrite + Unpin, S: SymmetricAlgorithm> Encryptor<W, S>
where
    S: SymmetricAlgorithm,
    S::Key: Send + Sync,
{
    pub async fn new(mut writer: W, key: S::Key, key_id: String) -> Result<Self> {
        let (header, base_nonce) = create_header::<S>(key_id)?;

        let header_bytes = header.encode_to_vec()?;
        use tokio::io::AsyncWriteExt;
        writer
            .write_all(&(header_bytes.len() as u32).to_le_bytes())
            .await?;
        writer.write_all(&header_bytes).await?;

        Ok(Self {
            writer,
            symmetric_key: Arc::new(key),
            base_nonce,
            chunk_size: DEFAULT_CHUNK_SIZE as usize,
            buffer: Vec::with_capacity(DEFAULT_CHUNK_SIZE as usize),
            chunk_counter: 0,
            state: EncryptorState::Idle,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<W: AsyncWrite + Unpin, S: SymmetricAlgorithm> AsyncWrite for Encryptor<W, S>
where
    S: SymmetricAlgorithm,
    S::Key: Send + Sync,
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

                    let key = Arc::clone(this.symmetric_key);
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

/// An asynchronous decryptor that is pending the provision of a key.
///
/// This state is entered after the header has been successfully read from the
/// stream, allowing the user to inspect the header (e.g., to find the `key_id`)
/// before supplying the appropriate key to proceed with decryption.
pub struct PendingDecryptor<R: AsyncRead + Unpin> {
    reader: R,
    header: Header,
}

impl<R: AsyncRead + Unpin> PendingDecryptor<R> {
    /// Creates a new `PendingDecryptor` by asynchronously reading the header
    /// from the provided reader.
    pub async fn from_reader(mut reader: R) -> Result<Self> {
        let header = Header::decode_from_prefixed_async_reader(&mut reader).await?;
        Ok(Self { reader, header })
    }

    /// Returns a reference to the header that was read from the stream.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Consumes the `PendingDecryptor` and returns a full `Decryptor` instance,
    /// ready to decrypt the stream.
    pub fn into_decryptor<S: SymmetricAlgorithm>(self, key: S::Key) -> Result<Decryptor<R, S>>
    where
        S::Key: Send + Sync,
    {
        let (chunk_size, base_nonce) = match self.header.payload {
            HeaderPayload::Symmetric {
                stream_info: Some(info),
                ..
            } => (info.chunk_size, info.base_nonce),
            _ => return Err(Error::InvalidHeader),
        };

        let tag_len = S::TAG_SIZE;
        let encrypted_chunk_size = chunk_size as usize + tag_len;

        Ok(Decryptor::new(
            self.reader,
            key,
            base_nonce,
            encrypted_chunk_size,
        ))
    }
}

enum DecryptorState {
    Idle,
    Decrypting(JoinHandle<Result<Vec<u8>>>),
}

pin_project! {
    pub struct Decryptor<R: AsyncRead, S: SymmetricAlgorithm> {
        #[pin]
        reader: R,
        symmetric_key: Arc<S::Key>,
        base_nonce: [u8; 12],
        encrypted_chunk_size: usize,
        buffer: io::Cursor<Vec<u8>>,
        chunk_counter: u64,
        is_done: bool,
        state: DecryptorState,
        _phantom: std::marker::PhantomData<S>,
    }
}

impl<R: AsyncRead + Unpin, S> Decryptor<R, S>
where
    S: SymmetricAlgorithm,
    S::Key: Send + Sync,
{
    pub fn new(reader: R, key: S::Key, base_nonce: [u8; 12], encrypted_chunk_size: usize) -> Self {
        Self {
            reader,
            symmetric_key: Arc::new(key),
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

impl<R: AsyncRead + Unpin, S: SymmetricAlgorithm> AsyncRead for Decryptor<R, S>
where
    S: SymmetricAlgorithm,
    S::Key: Send + Sync,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let this = self.as_mut().project();
            if this.buffer.get_ref().len() > this.buffer.position() as usize {
                let to_copy = std::cmp::min(
                    this.buffer.get_ref().len() - this.buffer.position() as usize,
                    buf.remaining(),
                );
                buf.put_slice(
                    &this.buffer.get_ref()[this.buffer.position() as usize
                        ..this.buffer.position() as usize + to_copy],
                );
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
                    let n = read_buf.filled().len();

                    if n == 0 {
                        *this.is_done = true;
                        return Poll::Ready(Ok(()));
                    }

                    let nonce = derive_nonce(this.base_nonce, *this.chunk_counter);
                    let key = Arc::clone(this.symmetric_key);
                    let final_chunk = encrypted_chunk[..n].to_vec();
                    let handle = tokio::task::spawn_blocking(move || {
                        S::decrypt(&key, &nonce, &final_chunk, None).map_err(Error::from)
                    });

                    *this.state = DecryptorState::Decrypting(handle);
                }
                DecryptorState::Decrypting(handle) => {
                    let decrypted_chunk = match ready!(Pin::new(handle).poll(cx)) {
                        Ok(Ok(data)) => data,
                        Ok(Err(e)) => {
                            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e)))
                        }
                        Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
                    };
                    *this.buffer = io::Cursor::new(decrypted_chunk);
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
    use seal_crypto::prelude::SymmetricKeyGenerator;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
    use std::io::Cursor;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn test_async_streaming_roundtrip(plaintext: &[u8]) {
        let key = Aes256Gcm::generate_key().unwrap();
        let key_id = "test_key_id".to_string();

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor =
            Encryptor::<_, Aes256Gcm>::new(&mut encrypted_data, key.clone(), key_id.clone())
                .await
                .unwrap();
        encryptor.write_all(plaintext).await.unwrap();
        encryptor.shutdown().await.unwrap();

        // Decrypt using the new two-step process
        let pending_decryptor = PendingDecryptor::from_reader(Cursor::new(&encrypted_data))
            .await
            .unwrap();
        assert_eq!(
            pending_decryptor.header().payload.key_id(),
            Some(key_id.as_str())
        );

        let mut decryptor = pending_decryptor.into_decryptor::<Aes256Gcm>(key).unwrap();
        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).await.unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[tokio::test]
    async fn test_roundtrip_long_message_async() {
        let plaintext = b"This is a very long test message to test the async streaming encryption and decryption. It should be longer than a single chunk to ensure that the chunking logic is working correctly. Let's add more data to make sure it spans multiple chunks. Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        test_async_streaming_roundtrip(plaintext).await;
    }

    #[tokio::test]
    async fn test_roundtrip_empty_message_async() {
        test_async_streaming_roundtrip(b"").await;
    }

    #[tokio::test]
    async fn test_roundtrip_exact_chunk_size_async() {
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];
        test_async_streaming_roundtrip(&plaintext).await;
    }

    #[tokio::test]
    async fn test_tampered_ciphertext_fails_async() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some important data";

        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, Aes256Gcm>::new(
            &mut encrypted_data,
            key.clone(),
            "test_key_id".to_string(),
        )
        .await
        .unwrap();
        encryptor.write_all(plaintext).await.unwrap();
        encryptor.shutdown().await.unwrap();

        // Tamper with the ciphertext body, after the header
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        if encrypted_data.len() > header_len {
            encrypted_data[header_len] ^= 1;
        }

        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data))
            .await
            .unwrap();
        let mut decryptor = pending.into_decryptor::<Aes256Gcm>(key).unwrap();
        let result = decryptor.read_to_end(&mut Vec::new()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_wrong_key_fails_async() {
        let key1 = Aes256Gcm::generate_key().unwrap();
        let key2 = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some data";

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor =
            Encryptor::<_, Aes256Gcm>::new(&mut encrypted_data, key1, "key1".to_string())
                .await
                .unwrap();
        encryptor.write_all(plaintext).await.unwrap();
        encryptor.shutdown().await.unwrap();

        // Decrypt with the wrong key
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data))
            .await
            .unwrap();
        let mut decryptor = pending.into_decryptor::<Aes256Gcm>(key2).unwrap();
        let result = decryptor.read_to_end(&mut Vec::new()).await;

        assert!(result.is_err());
    }
}
