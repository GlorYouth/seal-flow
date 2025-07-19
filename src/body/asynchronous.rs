//! Contains the common implementation for asynchronous streaming encryption and decryption.
//! This module provides the core pipeline logic, which is then wrapped by the
//! symmetric and hybrid encryption modules to provide a complete solution.
//!
//! 包含异步流式加密和解密的通用实现。
//! 该模块提供了核心的管道逻辑，然后由对称和混合加密模块进行包装，
//! 以提供完整的解决方案。

#![cfg(feature = "async")]

use super::config::{BodyDecryptConfig, BodyEncryptConfig};
use super::traits::AsynchronousBodyProcessor;
use crate::common::buffer::BufferPool;
use crate::common::header::SymmetricParams;
use crate::common::{derive_nonce, OrderedChunk};
use crate::error::{Error, Result};
use bytes::BytesMut;
use futures::stream::{FuturesUnordered, StreamExt};
use pin_project_lite::pin_project;
use seal_crypto_wrapper::prelude::TypedSymmetricKey;
use seal_crypto_wrapper::traits::SymmetricAlgorithmTrait;
use seal_crypto_wrapper::wrappers::symmetric::SymmetricAlgorithmWrapper;
use std::borrow::Cow;
use std::collections::{BTreeMap, BinaryHeap};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

// --- Encryptor ---

pub struct AsyncEncryptorSetup<'a> {
    pub symmetric_params: SymmetricParams,
    algorithm: SymmetricAlgorithmWrapper,
    key: Cow<'a, TypedSymmetricKey>,
    aad: Option<Vec<u8>>,
    channel_bound: usize,
}

impl<'a> AsyncEncryptorSetup<'a> {
    pub fn start<W: AsyncWrite + Send + Unpin + 'a>(
        self,
        writer: W,
    ) -> AsyncEncryptorImpl<'a, W> {
        let chunk_size = self.symmetric_params.chunk_size as usize;
        let out_pool = Arc::new(BufferPool::new(chunk_size + self.algorithm.tag_size()));

        AsyncEncryptorImpl {
            writer,
            algorithm: self.algorithm,
            key: Arc::new(self.key.into_owned()),
            base_nonce: self.symmetric_params.base_nonce,
            channel_bound: self.channel_bound,
            buffer: BytesMut::with_capacity(chunk_size * 2),
            chunk_counter: 0,
            next_chunk_to_write: 0,
            is_shutdown: false,
            encrypt_tasks: FuturesUnordered::new(),
            pending_chunks: BinaryHeap::new(),
            writing_state: WritingState::Idle,
            out_pool,
            aad: self.aad.map(Arc::new),
            _lifetime: std::marker::PhantomData,
        }
    }
}

type EncryptTask = JoinHandle<Result<(u64, BytesMut)>>;

enum WritingState {
    Idle,
    Writing {
        chunk: BytesMut,
        pos: usize,
    },
}

pin_project! {
    pub struct AsyncEncryptorImpl<'a, W: AsyncWrite> {
        #[pin]
        writer: W,
        key: Arc<TypedSymmetricKey>,
        algorithm: SymmetricAlgorithmWrapper,
        base_nonce: Box<[u8]>,
        channel_bound: usize,
        buffer: BytesMut,
        chunk_counter: u64,
        next_chunk_to_write: u64,
        is_shutdown: bool,
        encrypt_tasks: FuturesUnordered<EncryptTask>,
        pending_chunks: BinaryHeap<OrderedChunk>,
        writing_state: WritingState,
        out_pool: Arc<BufferPool>,
        aad: Option<Arc<Vec<u8>>>,
        _lifetime: std::marker::PhantomData<&'a ()>,
    }
}

impl<'a, W: AsyncWrite + Unpin> AsyncEncryptorImpl<'a, W> {
    fn poll_pipeline_progress(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        let state_before = self.state_tuple();
        let chunk_size = self.buffer.capacity() / 2; 

        while self.encrypt_tasks.len() < self.channel_bound {
            if self.buffer.len() < chunk_size && !self.is_shutdown {
                break;
            }
            if self.buffer.is_empty() {
                break;
            }

            let chunk_len = std::cmp::min(self.buffer.len(), chunk_size);
            let in_buffer = self.buffer.split_to(chunk_len);

            let algo = self.algorithm.clone();
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
                        &in_buffer,
                        &mut out_buffer,
                        &key,
                        &nonce,
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

impl<'a, W: AsyncWrite + Unpin> AsyncWrite for AsyncEncryptorImpl<'a, W> {
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

// --- Decryptor ---

pub struct AsyncDecryptorSetup<'a> {
    algorithm: SymmetricAlgorithmWrapper,
    key: Cow<'a, TypedSymmetricKey>,
    nonce: Box<[u8]>,
    aad: Option<Vec<u8>>,
    chunk_size: usize,
    channel_bound: usize,
}

impl<'a> AsyncDecryptorSetup<'a> {
    pub fn start<R: AsyncRead + Send + Unpin + 'a>(self, reader: R) -> AsyncDecryptorImpl<'a, R> {
        let decrypted_chunk_size = self.chunk_size;
        let encrypted_chunk_size = decrypted_chunk_size + self.algorithm.tag_size();
        let out_pool = Arc::new(BufferPool::new(decrypted_chunk_size));
        AsyncDecryptorImpl {
            reader,
            algorithm: self.algorithm,
            key: Arc::new(self.key.into_owned()),
            base_nonce: self.nonce,
            channel_bound: self.channel_bound,
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
            aad: self.aad.map(Arc::new),
            _lifetime: std::marker::PhantomData,
        }
    }
}

type DecryptTask = JoinHandle<(u64, Result<BytesMut>)>;

pin_project! {
    pub struct AsyncDecryptorImpl<'a, R: AsyncRead> {
        #[pin]
        reader: R,
        algorithm: SymmetricAlgorithmWrapper,
        key: Arc<TypedSymmetricKey>,
        base_nonce: Box<[u8]>,
        channel_bound: usize,
        encrypted_chunk_size: usize,
        decrypted_chunk_size: usize,
        read_buffer: BytesMut,
        out_cursor: io::Cursor<BytesMut>,
        chunk_counter: u64,
        next_chunk_to_read: u64,
        reader_done: bool,
        decrypt_tasks: FuturesUnordered<DecryptTask>,
        pending_chunks: BTreeMap<u64, Result<BytesMut>>,
        out_pool: Arc<BufferPool>,
        aad: Option<Arc<Vec<u8>>>,
        _lifetime: std::marker::PhantomData<&'a ()>,
    }
}

impl<'a, R: AsyncRead + Unpin> AsyncDecryptorImpl<'a, R> {
    fn poll_pipeline_progress(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        let mut made_progress = false;

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

                let algo = self.algorithm.clone();
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
                            &in_buffer,
                            &mut out_buffer,
                            &key,
                            &nonce,
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

impl<'a, R: AsyncRead + Unpin> AsyncRead for AsyncDecryptorImpl<'a, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let pre_len = buf.filled().len();
            let state_before = self.as_ref().state_tuple();

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

            match self.as_mut().poll_pipeline_progress(cx) {
                Poll::Ready(Ok(true)) => continue,
                Poll::Ready(Ok(false)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }

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

impl<S: SymmetricAlgorithmTrait + ?Sized> AsynchronousBodyProcessor for S {
    fn setup_encryptor<'a>(
        &self,
        config: BodyEncryptConfig<'a>,
    ) -> Result<AsyncEncryptorSetup<'a>> {
        let BodyEncryptConfig {
            key,
            nonce,
            aad,
            config,
        } = config;
        let symmetric_params = SymmetricParams::new(
            config.chunk_size(),
            nonce,
            aad.as_deref(),
        );
        Ok(AsyncEncryptorSetup {
            symmetric_params,
            algorithm: self.algorithm().into_symmetric_wrapper(),
            key,
            aad,
            channel_bound: config.channel_bound(),
        })
    }

    fn setup_decryptor<'a>(
        &self,
        config: BodyDecryptConfig<'a>,
    ) -> Result<AsyncDecryptorSetup<'a>> {
        let chunk_size = config.chunk_size();
        let channel_bound = config.channel_bound();
        Ok(AsyncDecryptorSetup {
            algorithm: self.algorithm().into_symmetric_wrapper(),
            key: config.key,
            nonce: config.nonce,
            aad: config.aad,
            chunk_size,
            channel_bound,
        })
    }
}
