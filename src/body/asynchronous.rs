//! Contains the common implementation for asynchronous streaming encryption and decryption.
//! This module provides the core pipeline logic, which is then wrapped by the
//! symmetric and hybrid encryption modules to provide a complete solution.
//!
//! 包含异步流式加密和解密的通用实现。
//! 该模块提供了核心的管道逻辑，然后由对称和混合加密模块进行包装，
//! 以提供完整的解决方案。

#![cfg(feature = "async")]

use crate::algorithms::symmetric::SymmetricAlgorithmWrapper;
use crate::common::buffer::BufferPool;
use crate::common::{
    config::ArcConfig,
    derive_nonce, OrderedChunk,
};
use crate::error::{Error, Result};
use crate::keys::TypedSymmetricKey;
use bytes::BytesMut;
use futures::stream::{FuturesUnordered, StreamExt};
use pin_project_lite::pin_project;
use std::collections::{BTreeMap, BinaryHeap};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

// --- Helper Structs for Encryption ---

/// A handle to a spawned encryption task.
///
/// 生成的加密任务的句柄。
pub(crate) type EncryptTask = JoinHandle<Result<(u64, BytesMut)>>;

/// The state of the writer in the encryption pipeline.
///
/// 加密管道中写入器的状态。
pub(crate) enum WritingState {
    /// Idle, waiting for a chunk to write.
    ///
    /// 空闲，等待要写入的块。
    Idle,
    /// Currently writing a chunk.
    ///
    /// 正在写入一个块。
    Writing {
        /// The chunk being written.
        ///
        /// 正在写入的块。
        chunk: BytesMut,
        /// The current position within the chunk.
        ///
        /// 块内的当前位置。
        pos: usize,
    },
}

// --- Encryptor Implementation ---

pin_project! {
    /// The implementation of an asynchronous, streaming encryptor.
    ///
    /// 异步、流式加密器的实现。
    pub struct EncryptorImpl<W: AsyncWrite> {
        #[pin]
        pub(crate) writer: W,
        pub(crate) key: Arc<TypedSymmetricKey>,
        pub(crate) algorithm: SymmetricAlgorithmWrapper,
        pub(crate) base_nonce: [u8; 12],
        pub(crate) config: ArcConfig,
        pub(crate) buffer: BytesMut,
        pub(crate) chunk_counter: u64,
        pub(crate) next_chunk_to_write: u64,
        pub(crate) is_shutdown: bool,
        pub(crate) encrypt_tasks: FuturesUnordered<EncryptTask>,
        pub(crate) pending_chunks: BinaryHeap<OrderedChunk>,
        pub(crate) writing_state: WritingState,
        pub(crate) out_pool: Arc<BufferPool>,
        pub(crate) aad: Option<Arc<Vec<u8>>>,
    }
}

impl<W: AsyncWrite + Unpin> EncryptorImpl<W> {
    /// Creates a new `EncryptorImpl`.
    ///
    /// 创建一个新的 `EncryptorImpl`。
    pub(crate) fn new<'a>(
        writer: W,
        algorithm: SymmetricAlgorithmWrapper,
        config: BodyEncryptConfig<'a>,
    ) -> Self {
        let BodyEncryptConfig { key, nonce, aad, config, .. } = config;
        let chunk_size = config.chunk_size() as usize;
        let out_pool = Arc::new(BufferPool::new(chunk_size + algorithm.tag_size()));

        Self {
            writer,
            algorithm,
            key: Arc::new(key),
            base_nonce: *nonce,
            config,
            buffer: BytesMut::with_capacity(chunk_size * 2),
            chunk_counter: 0,
            next_chunk_to_write: 0,
            is_shutdown: false,
            encrypt_tasks: FuturesUnordered::new(),
            pending_chunks: BinaryHeap::new(),
            writing_state: WritingState::Idle,
            out_pool,
            aad: aad.map(|d| Arc::new(d.to_vec())),
        }
    }

    /// Polls the encryption pipeline to make progress.
    ///
    /// 轮询加密管道以推进进度。
    pub(crate) fn poll_pipeline_progress(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        let state_before = self.state_tuple();

        // Stage 1: Spawn encryption tasks
        // 阶段 1: 生成加密任务
        while self.encrypt_tasks.len() < self.config.channel_bound() {
            if self.buffer.len() < self.config.chunk_size() as usize && !self.is_shutdown {
                break;
            }
            if self.buffer.is_empty() {
                break;
            }

            let chunk_len = std::cmp::min(self.buffer.len(), self.config.chunk_size() as usize);
            let in_buffer = self.buffer.split_to(chunk_len);

            let algo = Arc::new(self.algorithm.clone());
            let nonce = derive_nonce(&self.base_nonce, self.chunk_counter);
            let index = self.chunk_counter;
            let out_pool = Arc::clone(&self.out_pool);
            let aad_clone = self.aad.clone();
            let key = self.key.clone();

            let handle = tokio::task::spawn_blocking(move || {
                let mut out_buffer = out_pool.acquire();
                out_buffer.resize(out_buffer.capacity(), 0);

                let result = algo
                    .encrypt_to_buffer(
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

        // Stage 2: Poll completed encryption tasks
        // 阶段 2: 轮询已完成的加密任务
        while let Poll::Ready(Some(result)) = self.encrypt_tasks.poll_next_unpin(cx) {
            match result {
                Ok(Ok((index, data))) => {
                    self.pending_chunks.push(OrderedChunk {
                        index,
                        data: Ok(data),
                    });
                }
                Ok(Err(e)) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
                Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            }
        }

        // Stage 3: Write completed chunks in order
        // 阶段 3: 按顺序写入已完成的块
        loop {
            if let WritingState::Idle = self.writing_state {
                if let Some(chunk) = self.pending_chunks.peek() {
                    if chunk.index == self.next_chunk_to_write {
                        let chunk = self.pending_chunks.pop().unwrap();
                        match chunk.data {
                            Ok(data) => {
                                self.writing_state = WritingState::Writing {
                                    chunk: data,
                                    pos: 0,
                                }
                            }
                            Err(e) => {
                                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
                            }
                        }
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }

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
            WritingState::Writing { pos, .. } => (true, *pos),
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

impl<W: AsyncWrite + Unpin> AsyncWrite for EncryptorImpl<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.as_mut().project().buffer.extend_from_slice(buf);
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

// --- Decryptor Implementation ---

/// A handle to a spawned decryption task.
///
/// 生成的解密任务的句柄。
pub(crate) type DecryptTask = JoinHandle<(u64, Result<BytesMut>)>;

pin_project! {
    /// The implementation of an asynchronous, streaming decryptor.
    ///
    /// 异步、流式解密器的实现。
    pub struct DecryptorImpl<R: AsyncRead> {
        #[pin]
        pub(crate) reader: R,
        pub(crate) algorithm: SymmetricAlgorithmWrapper,
        pub(crate) key: Arc<TypedSymmetricKey>,
        pub(crate) base_nonce: [u8; 12],
        pub(crate) channel_bound: usize,
        pub(crate) encrypted_chunk_size: usize,
        pub(crate) decrypted_chunk_size: usize,
        pub(crate) read_buffer: BytesMut,
        pub(crate) out_cursor: io::Cursor<BytesMut>,
        pub(crate) chunk_counter: u64,
        pub(crate) next_chunk_to_read: u64,
        pub(crate) reader_done: bool,
        pub(crate) decrypt_tasks: FuturesUnordered<DecryptTask>,
        pub(crate) pending_chunks: BTreeMap<u64, Result<BytesMut>>,
        pub(crate) out_pool: Arc<BufferPool>,
        pub(crate) aad: Option<Arc<Vec<u8>>>,
    }
}

impl<R: AsyncRead + Unpin> DecryptorImpl<R> {
    /// Creates a new `DecryptorImpl`.
    ///
    /// 创建一个新的 `DecryptorImpl`。
    pub(crate) fn new<'a>(
        reader: R,
        algorithm: SymmetricAlgorithmWrapper,
        config: BodyDecryptConfig<'a>,
    ) -> Self {
        let BodyDecryptConfig { key, nonce, aad, config, .. } = config;
        let decrypted_chunk_size = config.chunk_size() as usize;
        let encrypted_chunk_size = decrypted_chunk_size + algorithm.tag_size();
        let out_pool = Arc::new(BufferPool::new(decrypted_chunk_size));
        Self {
            reader,
            algorithm,
            key: Arc::new(key),
            base_nonce: *nonce,
            channel_bound: config.channel_bound(),
            encrypted_chunk_size,
            decrypted_chunk_size,
            read_buffer: BytesMut::with_capacity(encrypted_chunk_size * 2),
            out_cursor: io::Cursor::new(BytesMut::new()),
            chunk_counter: 0,
            next_chunk_to_read: 0,
            reader_done: false,
            decrypt_tasks: FuturesUnordered::new(),
            pending_chunks: BTreeMap::new(),
            out_pool,
            aad: aad.map(|d| Arc::new(d.to_vec())),
        }
    }

    /// Polls the decryption pipeline to make progress.
    ///
    /// 轮询解密管道以推进进度。
    pub(crate) fn poll_pipeline_progress(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        let mut made_progress = false;

        // Stage 1: Read from source and spawn decrypt tasks
        // 阶段 1: 从源读取并生成解密任务
        if !self.reader_done {
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
                Poll::Pending => {}
            }

            let initial_tasks = self.decrypt_tasks.len();
            while self.decrypt_tasks.len() < self.channel_bound {
                if self.read_buffer.len() < self.encrypted_chunk_size && !self.reader_done {
                    break;
                }
                if self.read_buffer.is_empty() {
                    break;
                }

                let chunk_len = std::cmp::min(self.read_buffer.len(), self.encrypted_chunk_size);
                let in_buffer = self.read_buffer.split_to(chunk_len);

                let algo = Arc::new(self.algorithm.clone());
                let nonce = derive_nonce(&self.base_nonce, self.chunk_counter);
                let index = self.chunk_counter;
                let out_pool = Arc::clone(&self.out_pool);
                let aad_clone = self.aad.clone();
                let key = self.key.clone();

                let handle = tokio::task::spawn_blocking(move || {
                    let mut out_buffer = out_pool.acquire();
                    out_buffer.resize(out_buffer.capacity(), 0);

                    let result = algo
                        .decrypt_to_buffer(
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

        // Stage 2: Poll completed tasks
        // 阶段 2: 轮询已完成的任务
        let initial_pending = self.pending_chunks.len();
        while let Poll::Ready(Some(result)) = self.decrypt_tasks.poll_next_unpin(cx) {
            match result {
                Ok((index, dec_result)) => {
                    self.pending_chunks.insert(index, dec_result);
                }
                Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            }
        }
        if self.pending_chunks.len() > initial_pending {
            made_progress = true;
        }

        // Stage 3: Check for overall completion
        // 阶段 3: 检查整体是否完成
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

impl<R: AsyncRead + Unpin> AsyncRead for DecryptorImpl<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let pre_len = buf.filled().len();
            let state_before = self.as_ref().state_tuple();

            // Try to satisfy read from the current output buffer
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

            // If buffer is empty, try to get the next decrypted chunk
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
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e)))
                    }
                }
            }

            // If no chunk is ready, poll the pipeline to make progress
            match self.as_mut().poll_pipeline_progress(cx) {
                Poll::Ready(Ok(true)) => continue,
                Poll::Ready(Ok(false)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }

            // Check for completion
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

            let state_after = self.as_ref().state_tuple();
            if state_before == state_after {
                return Poll::Pending;
            }
        }
    }
}

// --- AsynchronousBodyProcessor Implementation ---

use super::traits::AsynchronousBodyProcessor;
use crate::algorithms::traits::SymmetricAlgorithm;
use super::config::{BodyDecryptConfig, BodyEncryptConfig};

impl<S: SymmetricAlgorithm + ?Sized> AsynchronousBodyProcessor for S {
    fn encrypt_body_async<'a>(
        &self,
        writer: Box<dyn AsyncWrite + Send + Unpin + 'a>,
        config: BodyEncryptConfig<'a>,
    ) -> Result<Box<dyn AsyncWrite + Send + Unpin + 'a>> {
        let encryptor = EncryptorImpl::new(
            writer,
            self.algorithm().into_symmetric_wrapper(),
            config,
        );
        Ok(Box::new(encryptor))
    }

    fn decrypt_body_async<'a>(
        &self,
        reader: Box<dyn AsyncRead + Send + Unpin + 'a>,
        config: BodyDecryptConfig<'a>,
    ) -> Result<Box<dyn AsyncRead + Send + Unpin + 'a>> {
        let decryptor = DecryptorImpl::new(
            reader,
            self.algorithm().into_symmetric_wrapper(),
            config,
        );
        Ok(Box::new(decryptor))
    }
}
