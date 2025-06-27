use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::{Header, HeaderPayload, SealMode, StreamInfo};
use crate::error::Result;
use rand::{rngs::OsRng, TryRngCore};

pub const DEFAULT_CHUNK_SIZE: u32 = 65536; // 64 KiB

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

/// Creates a complete header and a new base_nonce for a symmetric encryption stream.
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
