//! Common utilities for symmetric encryption modes.
//!
//! 对称加密模式的通用工具。

use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::{Header, HeaderPayload, SealMode, StreamInfo};
use crate::common::DEFAULT_CHUNK_SIZE;
use crate::error::Result;
use rand::{rngs::OsRng, TryRngCore};

/// Creates a complete header and a new base_nonce for a symmetric encryption stream.
///
/// 为对称加密流创建一个完整的标头和一个新的 base_nonce。
pub fn create_header<S: SymmetricAlgorithm>(key_id: String) -> Result<(Header, [u8; 12])> {
    let mut base_nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut base_nonce)?;

    let header = Header {
        version: 1,
        mode: SealMode::Symmetric,
        payload: HeaderPayload::Symmetric {
            key_id,
            algorithm: S::ALGORITHM,
            stream_info: Some(StreamInfo {
                chunk_size: DEFAULT_CHUNK_SIZE,
                base_nonce,
            }),
        },
    };
    Ok((header, base_nonce))
}
