//! Defines the processing modes for encryption and decryption operations.
//!
//! 定义了加密和解密操作的处理模式。

use serde::{Deserialize, Serialize};
use crate::bincode;

/// Specifies the execution strategy for an encryption or decryption operation.
/// This allows choosing between different trade-offs of memory usage,
/// latency, and throughput.
///
/// 指定加密或解密操作的执行策略。
/// 这允许在内存使用、延迟和吞吐量之间进行不同的权衡。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
#[bincode(crate = "crate::bincode")]
pub enum ProcessingMode {
    /// In-memory, single-threaded processing. Best for small-to-medium sized data.
    ///
    /// 内存中、单线程处理。最适合中小型数据。
    Ordinary,

    /// Streaming, single-threaded processing. Best for large data when memory
    /// usage is a concern and parallelism is not required.
    ///
    /// 流式、单线程处理。当内存使用是主要考虑因素且不需要并行性时，最适合处理大数据。
    Streaming,

    /// In-memory, parallel processing using Rayon. Best for medium-to-large sized
    /// data on multi-core machines to maximize throughput.
    ///
    /// 使用 Rayon 进行内存中并行处理。最适合在多核机器上处理中到大型数据以最大化吞吐量。
    Parallel,

    /// Streaming, parallel processing using crossbeam threads. A good balance for
    /// very large data on multi-core machines, keeping memory usage low while
    /// leveraging multiple cores.
    ///
    /// 使用 crossbeam 线程进行流式并行处理。在多核机器上是处理非常大数据的一个很好平衡点，
    /// 既能保持较低的内存使用，又能利用多个核心。
    ParallelStreaming,

    /// Asynchronous streaming processing using Tokio. Best for integration into
    /// async applications, allowing non-blocking I/O.
    ///
    /// 使用 Tokio 的异步流式处理。最适合集成到异步应用程序中，允许非阻塞 I/O。
    #[cfg(feature = "async")]
    Asynchronous,
} 