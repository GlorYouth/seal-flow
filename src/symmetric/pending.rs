//! Defines the generic PendingDecryptor used across different symmetric encryption modes.
//!
//! 定义用于不同对称加密模式的通用 PendingDecryptor。

use crate::common::header::Header;

/// A generic decryptor that is pending the provision of a key.
///
/// It holds the data source (e.g., a byte slice or a reader), the parsed header,
/// and the algorithm instance needed for decryption.
pub(crate) struct PendingDecryptor<Source, Algo> {
    pub(super) source: Source,
    pub(super) header: Header,
    pub(super) algorithm: Algo,
}

impl<Source, Algo> PendingDecryptor<Source, Algo> {
    pub(crate) fn new(source: Source, header: Header, algorithm: Algo) -> Self {
        Self {
            source,
            header,
            algorithm,
        }
    }
} 