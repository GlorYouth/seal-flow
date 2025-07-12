use crate::{
    algorithms::signature::SignatureAlgorithmWrapper,
    keys::{TypedSignaturePrivateKey, TypedSymmetricKey},
};
use bytes::BytesMut;

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
    pub(crate) signer: SignatureAlgorithmWrapper,
    pub(crate) signing_key: TypedSignaturePrivateKey,
}

use crate::algorithms::kdf::key::KdfKeyWrapper;
use crate::algorithms::xof::XofWrapper;

pub(crate) enum DerivationWrapper {
    Kdf(KdfKeyWrapper),
    Xof(XofWrapper),
}

impl DerivationWrapper {
    pub fn derive(
        &self,
        ikm: &TypedSymmetricKey,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
    ) -> crate::Result<TypedSymmetricKey> {
        use crate::algorithms::traits::KdfKeyAlgorithm;
        use crate::algorithms::traits::XofAlgorithm;
        match self {
            DerivationWrapper::Kdf(kdf_wrapper) => kdf_wrapper.derive(ikm, salt, info),
            DerivationWrapper::Xof(xof_wrapper) => xof_wrapper.derive(ikm, salt, info),
        }
    }
}

pub struct DerivationSet {
    pub(crate) derivation_info: header::DerivationInfo,
    pub(crate) wrapper: DerivationWrapper,
}

impl DerivationSet {
    pub fn salt(&self) -> Option<&[u8]> {
        match &self.derivation_info {
            header::DerivationInfo::Kdf(kdf_info) => kdf_info.salt.as_deref(),
            header::DerivationInfo::Xof(xof_info) => xof_info.salt.as_deref(),
        }
    }

    pub fn info(&self) -> Option<&[u8]> {
        match &self.derivation_info {
            header::DerivationInfo::Kdf(kdf_info) => kdf_info.info.as_deref(),
            header::DerivationInfo::Xof(xof_info) => xof_info.info.as_deref(),
        }
    }
}
