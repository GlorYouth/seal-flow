use bytes::BytesMut;
use crossbeam_channel::{bounded, Receiver, Sender};
const POOL_SIZE: usize = 16;

/// A simple, thread-safe memory pool for `BytesMut` buffers.
pub struct BufferPool {
    pool: Receiver<BytesMut>,
    returner: Sender<BytesMut>,
    buffer_size: usize,
}

impl BufferPool {
    /// Creates a new pool with a specific buffer size.
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
    pub fn acquire(&self) -> BytesMut {
        self.pool
            .recv()
            .unwrap_or_else(|_| BytesMut::with_capacity(self.buffer_size))
    }

    /// Releases a buffer back to the pool.
    pub fn release(&self, mut buf: BytesMut) {
        buf.clear();
        // Ignore error in case the pool has been dropped
        let _ = self.returner.send(buf);
    }
}
