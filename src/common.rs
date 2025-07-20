
use bytes::BytesMut;

pub(crate) mod buffer;
pub mod header;



/// Derives a nonce for a specific chunk index from a base nonce.
pub(crate) fn derive_nonce(base_nonce: &[u8], chunk_index: u64) -> Box<[u8]> {
    let mut nonce_bytes = base_nonce.to_vec();
    let i_bytes = chunk_index.to_le_bytes(); // u64 -> 8 bytes, little-endian

    let nonce_len = nonce_bytes.len();
    if nonce_len < 8 {
        // If nonce is too short, XOR over the whole nonce, truncating the chunk index.
        for i in 0..nonce_len {
            nonce_bytes[i] ^= i_bytes[i];
        }
    } else {
        // XOR the chunk index into the last 8 bytes of the nonce.
        let offset = nonce_len - 8;
        for i in 0..8 {
            nonce_bytes[offset + i] ^= i_bytes[i];
        }
    }

    nonce_bytes.into_boxed_slice()
}



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
