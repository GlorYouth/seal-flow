
use bytes::BytesMut;
use seal_crypto_wrapper::prelude::{TypedSignaturePrivateKey, Zeroizing};
use seal_crypto_wrapper::wrappers::asymmetric::signature::SignatureAlgorithmWrapper;
use seal_crypto_wrapper::wrappers::kdf::key::KdfKeyWrapper;
use seal_crypto_wrapper::wrappers::xof::XofWrapper;

pub(crate) mod buffer;
pub mod config;
pub mod header;
pub mod mode;

pub const DEFAULT_CHUNK_SIZE: u32 = 65536;

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
    pub signer_key_id: String,
    pub signer: SignatureAlgorithmWrapper,
    pub signing_key: TypedSignaturePrivateKey,
}

pub enum DerivationWrapper {
    Kdf(KdfKeyWrapper),
    Xof(XofWrapper),
}

impl DerivationWrapper {
    pub fn derive(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> crate::Result<Zeroizing<Vec<u8>>> {
        use seal_crypto_wrapper::prelude::XofAlgorithmTrait;
        use crate::error::Error;
        match self {
            DerivationWrapper::Kdf(kdf_wrapper) => kdf_wrapper.derive(ikm, salt, info, output_len).map_err(Error::from),
            DerivationWrapper::Xof(xof_wrapper) => {
                let mut xof_reader = xof_wrapper.reader(ikm, salt, info)?;
                let dek = xof_reader.read_boxed(output_len);
                Ok(Zeroizing::new(dek.to_vec()))
            }
        }
    }
}

pub struct DerivationSet {
    pub derivation_info: header::DerivationBlock,
    pub wrapper: DerivationWrapper,
}

impl DerivationSet {
    pub fn salt(&self) -> Option<&[u8]> {
        match &self.derivation_info {
            header::DerivationBlock::Kdf(kdf_info) => kdf_info.salt.as_deref(),
            header::DerivationBlock::Xof(xof_info) => xof_info.salt.as_deref(),
        }
    }

    pub fn info(&self) -> Option<&[u8]> {
        match &self.derivation_info {
            header::DerivationBlock::Kdf(kdf_info) => kdf_info.info.as_deref(),
            header::DerivationBlock::Xof(xof_info) => xof_info.info.as_deref(),
        }
    }
}
