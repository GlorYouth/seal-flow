use crate::{common::algorithms::SignatureAlgorithm, keys::TypedSymmetricKey};
use bytes::BytesMut;
use std::borrow::Borrow;

/// This module re-exports common functionalities from the `common` directory.
///
/// 这个模块从 `common` 目录中重新导出公共功能。
pub mod algorithms;
pub(crate) mod buffer;
pub mod config;
pub mod header;

pub const DEFAULT_CHUNK_SIZE: u32 = 65536;

/// Derives a nonce for a specific chunk index from a base nonce.
pub fn derive_nonce(base_nonce: &[u8; 12], chunk_index: u64) -> [u8; 12] {
    let mut nonce_bytes = *base_nonce;
    let i_bytes = chunk_index.to_le_bytes(); // u64 -> 8 bytes, little-endian

    // XOR the chunk index into the last 8 bytes of the nonce
    for j in 0..8 {
        nonce_bytes[4 + j] ^= i_bytes[j];
    }

    nonce_bytes
}

pub const CHANNEL_BOUND: usize = 16;

/// A wrapper for chunks to allow ordering in a min-heap.
pub(crate) struct OrderedChunk {
    pub(crate) index: u64,
    pub(crate) data: crate::Result<BytesMut>,
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

pub struct SignerSet {
    pub(crate) signer_key_id: String,
    pub(crate) signer_algorithm: SignatureAlgorithm,
    pub(crate) signer: Box<dyn Fn(&[u8], Option<&[u8]>) -> crate::Result<Vec<u8>> + Send + Sync>,
}

pub struct DerivationSet {
    pub(crate) derivation_info: header::DerivationInfo,
    pub(crate) deriver_fn:
        Box<dyn Fn(&TypedSymmetricKey) -> crate::Result<TypedSymmetricKey> + Send + Sync>,
}
