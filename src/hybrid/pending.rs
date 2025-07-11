//! Defines the generic PendingDecryptor used across different hybrid encryption modes.
//!
//! 定义用于不同混合加密模式的通用 PendingDecryptor。

use crate::algorithms::definitions::hybrid::HybridAlgorithmWrapper;
use crate::common::config::ArcConfig;
use crate::common::header::Header;

/// A generic decryptor that is pending the provision of a key.
///
/// It holds the data source (e.g., a byte slice or a reader), the parsed header,
/// and the algorithm instance needed for decryption.
pub struct PendingDecryptor<Source> {
    pub(super) source: Source,
    pub(super) header: Header,
    pub(super) algorithm: HybridAlgorithmWrapper,
    pub(super) config: ArcConfig,
}
