use bytes::BytesMut;
use crossbeam_channel::{bounded, Receiver, Sender};
const POOL_SIZE: usize = 16;

/// A simple, thread-safe memory pool for `BytesMut` buffers.
///
/// 用于 `BytesMut` 缓冲区的简单、线程安全的内存池。
pub struct BufferPool {
    pool: Receiver<BytesMut>,
    returner: Sender<BytesMut>,
    buffer_size: usize,
}

impl BufferPool {
    /// Creates a new pool with a specific buffer size.
    ///
    /// 使用指定的缓冲区大小创建一个新的池。
    pub fn new(buffer_size: usize) -> Self {
        let (returner, pool) = bounded(POOL_SIZE);
        for _ in 0..POOL_SIZE {
            returner.send(BytesMut::with_capacity(buffer_size)).unwrap();
        }
        Self {
            pool,
            returner,
            buffer_size,
        }
    }


    /// Acquires a buffer from the pool.
    ///
    /// 从池中获取一个缓冲区。
    pub fn acquire(&self) -> BytesMut {
        self.pool
            .recv()
            .unwrap_or_else(|_| BytesMut::with_capacity(self.buffer_size))
    }

    /// Releases a buffer back to the pool.
    ///
    /// 将缓冲区释放回池中。
    pub fn release(&self, mut buf: BytesMut) {
        buf.clear();
        // Ignore error in case the pool has been dropped
        // 忽略错误，以防池已被丢弃
        let _ = self.returner.send(buf);
    }
}
