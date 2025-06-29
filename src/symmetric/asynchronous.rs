//! Implements an asynchronous streaming symmetric encryption/decryption scheme.
//! This mode is designed for high-performance processing of large files or data streams
//! by overlapping asynchronous I/O with parallel computation.

#![cfg(feature = "async")]

use super::common::{create_header, derive_nonce, DEFAULT_CHUNK_SIZE};
use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::buffer::BufferPool;
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, Result};
use bytes::BytesMut;
use futures::stream::{FuturesUnordered, StreamExt};
use pin_project_lite::pin_project;
use std::collections::BinaryHeap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

const CHANNEL_BOUND: usize = 16; // Concurrently processing chunks

/// A wrapper for chunks to allow ordering in a min-heap.
struct OrderedChunk {
    index: u64,
    data: Result<BytesMut>,
}

impl PartialEq for OrderedChunk {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
    }
}

impl Eq for OrderedChunk {}

impl PartialOrd for OrderedChunk {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrderedChunk {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Create a min-heap on the index by reversing the comparison
        other.index.cmp(&self.index)
    }
}

type EncryptTask = JoinHandle<Result<(u64, BytesMut)>>;

enum WritingState {
    Idle,
    Writing { chunk: BytesMut, pos: usize },
}

pin_project! {
    pub struct Encryptor<W: AsyncWrite, S: SymmetricAlgorithm> {
        #[pin]
        writer: W,
        symmetric_key: Arc<S::Key>,
        base_nonce: [u8; 12],
        chunk_size: usize,
        buffer: BytesMut,
        chunk_counter: u64,
        next_chunk_to_write: u64,
        is_shutdown: bool,

        // Concurrency and reordering
        encrypt_tasks: FuturesUnordered<EncryptTask>,
        pending_chunks: BinaryHeap<OrderedChunk>,
        writing_state: WritingState,

        // Buffer pools
        out_pool: Arc<BufferPool>,

        aad: Option<Arc<Vec<u8>>>,
        _phantom: std::marker::PhantomData<S>,
    }
}

impl<W: AsyncWrite + Unpin, S: SymmetricAlgorithm> Encryptor<W, S>
where
    S: SymmetricAlgorithm + 'static,
    S::Key: Send + Sync + 'static,
{
    pub async fn new(
        mut writer: W,
        key: S::Key,
        key_id: String,
        aad: Option<&[u8]>,
    ) -> Result<Self> {
        let (header, base_nonce) = create_header::<S>(key_id)?;

        let header_bytes = header.encode_to_vec()?;
        use tokio::io::AsyncWriteExt;
        writer
            .write_all(&(header_bytes.len() as u32).to_le_bytes())
            .await?;
        writer.write_all(&header_bytes).await?;

        let chunk_size = DEFAULT_CHUNK_SIZE as usize;
        let out_pool = Arc::new(BufferPool::new(chunk_size + S::TAG_SIZE));

        Ok(Self {
            writer,
            symmetric_key: Arc::new(key),
            base_nonce,
            chunk_size,
            buffer: BytesMut::with_capacity(chunk_size * 2),
            chunk_counter: 0,
            next_chunk_to_write: 0,
            is_shutdown: false,
            encrypt_tasks: FuturesUnordered::new(),
            pending_chunks: BinaryHeap::new(),
            writing_state: WritingState::Idle,
            out_pool,
            aad: aad.map(|d| Arc::new(d.to_vec())),
            _phantom: std::marker::PhantomData,
        })
    }

    fn poll_pipeline_progress(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let state_before = self.state_tuple();

        // --- Stage 1: Spawn encryption tasks from the input buffer ---
        while self.encrypt_tasks.len() < CHANNEL_BOUND {
            if self.buffer.len() < self.chunk_size && !self.is_shutdown {
                // Not enough data to form a full chunk, and we are not shutting down
                break;
            }

            if self.buffer.is_empty() {
                // No more data to encrypt
                break;
            }

            let chunk_len = std::cmp::min(self.buffer.len(), self.chunk_size);
            let in_buffer = self.buffer.split_to(chunk_len);

            let key = Arc::clone(&self.symmetric_key);
            let nonce = derive_nonce(&self.base_nonce, self.chunk_counter);
            let index = self.chunk_counter;
            let out_pool = Arc::clone(&self.out_pool);
            let aad_clone = self.aad.clone();

            let handle = tokio::task::spawn_blocking(move || {
                let mut out_buffer = out_pool.acquire();
                out_buffer.resize(out_buffer.capacity(), 0);

                let result = S::encrypt_to_buffer(
                    &key,
                    &nonce,
                    &in_buffer,
                    &mut out_buffer,
                    aad_clone.as_deref().map(|v| v.as_slice()),
                )
                .map(|bytes_written| {
                    out_buffer.truncate(bytes_written);
                    out_buffer
                })
                .map_err(Error::from);
                result.map(|buf| (index, buf))
            });

            self.encrypt_tasks.push(handle);
            self.chunk_counter += 1;
        }

        // --- Stage 2: Poll completed encryption tasks ---
        while let Poll::Ready(Some(result)) = self.encrypt_tasks.poll_next_unpin(cx) {
            match result {
                Ok(Ok((index, data))) => {
                    self.pending_chunks
                        .push(OrderedChunk { index, data: Ok(data) });
                }
                Ok(Err(e)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
                }
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
                }
            }
        }

        // --- Stage 3: Write completed chunks in order ---
        loop {
            // Check if we need to start writing a new chunk
            if let WritingState::Idle = self.writing_state {
                if let Some(chunk) = self.pending_chunks.peek() {
                    if chunk.index == self.next_chunk_to_write {
                        let chunk = self.pending_chunks.pop().unwrap();
                        match chunk.data {
                            Ok(data) => {
                                self.writing_state = WritingState::Writing { chunk: data, pos: 0 };
                            }
                            Err(e) => {
                                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
                            }
                        }
                    } else {
                        // The next chunk is not ready yet.
                        break;
                    }
                } else {
                    // No chunks are ready to be written.
                    break;
                }
            }

            // Try to write the current chunk
            if let WritingState::Writing { chunk, pos } = &mut self.writing_state {
                while *pos < chunk.len() {
                    let bytes_written =
                        match Pin::new(&mut self.writer).poll_write(cx, &chunk[*pos..]) {
                            Poll::Ready(Ok(n)) => n,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => {
                                let state_after = self.state_tuple();
                                return if state_before != state_after {
                                    Poll::Ready(Ok(true))
                                } else {
                                    Poll::Pending
                                };
                            }
                        };

                    if bytes_written == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "failed to write whole chunk",
                        )));
                    }
                    *pos += bytes_written;
                }

                // Finished writing this chunk
                if let WritingState::Writing { chunk, .. } =
                    std::mem::replace(&mut self.writing_state, WritingState::Idle)
                {
                    self.out_pool.release(chunk);
                }
                self.next_chunk_to_write += 1;
            } else {
                break;
            }
        }

        let state_after = self.state_tuple();
        Poll::Ready(Ok(state_before != state_after))
    }

    fn state_tuple(&self) -> (usize, usize, usize, bool, usize) {
        let (is_writing, pos) = match &self.writing_state {
            WritingState::Idle => (false, 0),
            WritingState::Writing { chunk: _, pos } => (true, *pos),
        };
        (
            self.buffer.len(),
            self.encrypt_tasks.len(),
            self.pending_chunks.len(),
            is_writing,
            pos,
        )
    }
}

impl<W: AsyncWrite + Unpin, S: SymmetricAlgorithm> AsyncWrite for Encryptor<W, S>
where
    S: SymmetricAlgorithm + 'static,
    S::Key: Send + Sync + 'static,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.as_mut().project().buffer.extend_from_slice(buf);
        // Try to push data through the pipeline, but don't wait for it to finish.
        let _ = self.as_mut().poll_pipeline_progress(cx);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let is_fully_drained = {
                let this = self.as_mut().project();
                this.buffer.is_empty()
                    && this.encrypt_tasks.is_empty()
                    && this.pending_chunks.is_empty()
                    && matches!(this.writing_state, WritingState::Idle)
            };

            if is_fully_drained {
                return self.project().writer.poll_flush(cx);
            }

            match self.as_mut().poll_pipeline_progress(cx) {
                Poll::Ready(Ok(true)) => continue,
                Poll::Ready(Ok(false)) => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !*self.as_mut().project().is_shutdown {
            *self.as_mut().project().is_shutdown = true;
        }

        loop {
            let is_fully_drained = {
                let this = self.as_mut().project();
                this.buffer.is_empty()
                    && this.encrypt_tasks.is_empty()
                    && this.pending_chunks.is_empty()
                    && matches!(this.writing_state, WritingState::Idle)
            };

            if is_fully_drained {
                return self.project().writer.poll_shutdown(cx);
            }

            match self.as_mut().poll_pipeline_progress(cx) {
                Poll::Ready(Ok(true)) => continue,
                Poll::Ready(Ok(false)) => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
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
    pub fn into_decryptor<S: SymmetricAlgorithm>(
        self,
        key: S::Key,
        aad: Option<&[u8]>,
    ) -> Result<Decryptor<R, S>>
    where
        S: SymmetricAlgorithm + 'static,
        S::Key: Send + Sync + 'static,
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
            chunk_size as usize,
            aad,
        ))
    }
}

type DecryptTask = JoinHandle<(u64, Result<BytesMut>)>;

pin_project! {
    pub struct Decryptor<R: AsyncRead, S: SymmetricAlgorithm> {
        #[pin]
        reader: R,
        symmetric_key: Arc<S::Key>,
        base_nonce: [u8; 12],
        encrypted_chunk_size: usize,
        decrypted_chunk_size: usize,

        read_buffer: BytesMut,
        out_cursor: io::Cursor<BytesMut>,

        chunk_counter: u64,
        next_chunk_to_read: u64,
        reader_done: bool,

        decrypt_tasks: FuturesUnordered<DecryptTask>,
        pending_chunks: std::collections::BTreeMap<u64, Result<BytesMut>>,

        out_pool: Arc<BufferPool>,

        aad: Option<Arc<Vec<u8>>>,
        _phantom: std::marker::PhantomData<S>,
    }
}

impl<R: AsyncRead + Unpin, S> Decryptor<R, S>
where
    S: SymmetricAlgorithm + 'static,
    S::Key: Send + Sync + 'static,
{
    pub fn new(
        reader: R,
        key: S::Key,
        base_nonce: [u8; 12],
        encrypted_chunk_size: usize,
        decrypted_chunk_size: usize,
        aad: Option<&[u8]>,
    ) -> Self {
        let out_pool = Arc::new(BufferPool::new(decrypted_chunk_size));
        Self {
            reader,
            symmetric_key: Arc::new(key),
            base_nonce,
            encrypted_chunk_size,
            decrypted_chunk_size,
            read_buffer: BytesMut::with_capacity(encrypted_chunk_size * 2),
            out_cursor: io::Cursor::new(BytesMut::new()),
            chunk_counter: 0,
            next_chunk_to_read: 0,
            reader_done: false,
            decrypt_tasks: FuturesUnordered::new(),
            pending_chunks: std::collections::BTreeMap::new(),
            out_pool,
            aad: aad.map(|d| Arc::new(d.to_vec())),
            _phantom: std::marker::PhantomData,
        }
    }

    fn poll_pipeline_progress(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let mut made_progress = false;
        // --- Stage 1: Read from source and spawn decrypt tasks ---
        if !self.reader_done {
            // Fill read buffer using a temporary stack buffer to avoid complex unsafe code.
            let mut temp_buf = [0u8; 8 * 1024];
            let mut read_buf = ReadBuf::new(&mut temp_buf);

            match Pin::new(&mut self.reader).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        self.reader_done = true;
                    } else {
                        self.read_buffer.extend_from_slice(read_buf.filled());
                    }
                    if n > 0 {
                        made_progress = true;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {} // Can continue, maybe there's data in buffer
            }

            // Spawn tasks
            let initial_tasks = self.decrypt_tasks.len();
            while self.decrypt_tasks.len() < CHANNEL_BOUND {
                if self.read_buffer.len() < self.encrypted_chunk_size && !self.reader_done {
                    break;
                }
                if self.read_buffer.is_empty() {
                    break;
                }

                let chunk_len = std::cmp::min(self.read_buffer.len(), self.encrypted_chunk_size);
                let in_buffer = self.read_buffer.split_to(chunk_len);

                let key = Arc::clone(&self.symmetric_key);
                let nonce = derive_nonce(&self.base_nonce, self.chunk_counter);
                let index = self.chunk_counter;
                let out_pool = Arc::clone(&self.out_pool);
                let aad_clone = self.aad.clone();

                let handle = tokio::task::spawn_blocking(move || {
                    let mut out_buffer = out_pool.acquire();
                    out_buffer.resize(out_buffer.capacity(), 0);

                    let result = S::decrypt_to_buffer(
                        &key,
                        &nonce,
                        &in_buffer,
                        &mut out_buffer,
                        aad_clone.as_deref().map(|v| v.as_slice()),
                    )
                    .map(|bytes_written| {
                        out_buffer.truncate(bytes_written);
                        out_buffer
                    })
                    .map_err(Error::from);
                    (index, result)
                });
                self.decrypt_tasks.push(handle);
                self.chunk_counter += 1;
            }
            if self.decrypt_tasks.len() > initial_tasks {
                made_progress = true;
            }
        }

        // --- Stage 2: Poll completed tasks ---
        let initial_pending = self.pending_chunks.len();
        while let Poll::Ready(Some(result)) = self.decrypt_tasks.poll_next_unpin(cx) {
            match result {
                Ok((index, dec_result)) => {
                    self.pending_chunks.insert(index, dec_result);
                }
                Err(e) => {
                    // Task panicked
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
                }
            }
        }
        if self.pending_chunks.len() > initial_pending {
            made_progress = true;
        }

        // --- Stage 3: Check for overall completion ---
        if self.reader_done
            && self.read_buffer.is_empty()
            && self.decrypt_tasks.is_empty()
            && self.out_cursor.position() as usize >= self.out_cursor.get_ref().len()
        {
            if let Some((_, result)) = self.pending_chunks.first_key_value() {
                if result.is_err() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Decryption failed",
                    )));
                }
            } else {
                return Poll::Ready(Ok(made_progress));
            }
        }

        Poll::Ready(Ok(made_progress))
    }

    fn state_tuple(&self) -> (usize, u64, u64, bool, usize, usize) {
        (
            self.read_buffer.len(),
            self.out_cursor.position(),
            self.next_chunk_to_read,
            self.reader_done,
            self.decrypt_tasks.len(),
            self.pending_chunks.len(),
        )
    }
}

impl<R: AsyncRead + Unpin, S: SymmetricAlgorithm> AsyncRead for Decryptor<R, S>
where
    S: SymmetricAlgorithm + 'static,
    S::Key: Send + Sync + 'static,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let pre_len = buf.filled().len();
            let state_before = self.as_ref().state_tuple();

            // --- First, try to satisfy read from the current output buffer ---
            {
                let this = self.as_mut().project();
                let pos = this.out_cursor.position() as usize;
                let out_buf = this.out_cursor.get_ref();
                let remaining_in_cursor = out_buf.len().saturating_sub(pos);

                if remaining_in_cursor > 0 {
                    let to_read = std::cmp::min(buf.remaining(), remaining_in_cursor);
                    buf.put_slice(&out_buf[pos..pos + to_read]);
                    this.out_cursor.set_position((pos + to_read) as u64);
                }
            }

            if buf.filled().len() > pre_len {
                return Poll::Ready(Ok(()));
            }

            // --- If buffer is empty, try to get the next decrypted chunk ---
            let next_chunk_opt = {
                let this = self.as_mut().project();
                this.pending_chunks.remove(this.next_chunk_to_read)
            };

            if let Some(result) = next_chunk_opt {
                match result {
                    Ok(data) => {
                        let this = self.as_mut().project();
                        let old_buf = std::mem::replace(this.out_cursor.get_mut(), data);
                        this.out_pool.release(old_buf);
                        this.out_cursor.set_position(0);
                        *this.next_chunk_to_read += 1;
                        continue;
                    }
                    Err(e) => {
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e)));
                    }
                }
            }

            // --- If no chunk is ready, poll the pipeline to make progress ---
            match self.as_mut().poll_pipeline_progress(cx) {
                Poll::Ready(Ok(true)) => {
                    // Progress was made, loop again to see if we can read now
                    continue;
                }
                Poll::Ready(Ok(false)) => {
                    // No progress, fall through to check for completion or pending
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }

            // --- Check for completion ---
            {
                let this = self.as_mut().project();
                let pos = this.out_cursor.position() as usize;
                let out_buf_len = this.out_cursor.get_ref().len();

                if *this.reader_done
                    && this.decrypt_tasks.is_empty()
                    && this.pending_chunks.is_empty()
                    && pos >= out_buf_len
                {
                    return Poll::Ready(Ok(()));
                }
            }

            // If we made no progress, we are pending
            let state_after = self.as_ref().state_tuple();
            if state_before == state_after {
                return Poll::Pending;
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

    async fn test_async_streaming_roundtrip(plaintext: &[u8], aad: Option<&[u8]>) {
        let key = Aes256Gcm::generate_key().unwrap();
        let key_id = "test_key_id".to_string();

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, Aes256Gcm>::new(
            &mut encrypted_data,
            key.clone(),
            key_id.clone(),
            aad,
        )
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

        let mut decryptor = pending_decryptor
            .into_decryptor::<Aes256Gcm>(key, aad)
            .unwrap();
        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).await.unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[tokio::test]
    async fn test_roundtrip_long_message_async() {
        let plaintext = b"This is a very long test message to test the async streaming encryption and decryption. It should be longer than a single chunk to ensure that the chunking logic is working correctly. Let's add more data to make sure it spans multiple chunks. Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        test_async_streaming_roundtrip(plaintext, None).await;
    }

    #[tokio::test]
    async fn test_roundtrip_empty_message_async() {
        test_async_streaming_roundtrip(b"", None).await;
    }

    #[tokio::test]
    async fn test_roundtrip_exact_chunk_size_async() {
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];
        test_async_streaming_roundtrip(&plaintext, None).await;
    }

    #[tokio::test]
    async fn test_aad_roundtrip_async() {
        let plaintext = b"secret async message";
        let aad = b"public async context";
        test_async_streaming_roundtrip(plaintext, Some(aad)).await;
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
            None,
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
        let mut decryptor = pending.into_decryptor::<Aes256Gcm>(key, None).unwrap();
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
            Encryptor::<_, Aes256Gcm>::new(&mut encrypted_data, key1, "key1".to_string(), None)
                .await
                .unwrap();
        encryptor.write_all(plaintext).await.unwrap();
        encryptor.shutdown().await.unwrap();

        // Decrypt with the wrong key
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data))
            .await
            .unwrap();
        let mut decryptor = pending.into_decryptor::<Aes256Gcm>(key2, None).unwrap();
        let result = decryptor.read_to_end(&mut Vec::new()).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_wrong_aad_fails_async() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some data";
        let aad1 = b"correct async aad";
        let aad2 = b"wrong async aad";

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, Aes256Gcm>::new(
            &mut encrypted_data,
            key.clone(),
            "key1".to_string(),
            Some(aad1),
        )
        .await
        .unwrap();
        encryptor.write_all(plaintext).await.unwrap();
        encryptor.shutdown().await.unwrap();

        // Decrypt with the wrong aad
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data))
            .await
            .unwrap();
        let mut decryptor = pending
            .into_decryptor::<Aes256Gcm>(key.clone(), Some(aad2))
            .unwrap();
        let result = decryptor.read_to_end(&mut Vec::new()).await;
        assert!(result.is_err());

        // Decrypt with no aad
        let pending2 = PendingDecryptor::from_reader(Cursor::new(encrypted_data))
            .await
            .unwrap();
        let mut decryptor2 = pending2.into_decryptor::<Aes256Gcm>(key, None).unwrap();
        let result2 = decryptor2.read_to_end(&mut Vec::new()).await;
        assert!(result2.is_err());
    }
}
