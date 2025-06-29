use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::header::{Header, HeaderPayload, SealMode, StreamInfo};
use crate::common::DEFAULT_CHUNK_SIZE;
use crate::error::Result;
use rand::{rngs::OsRng, TryRngCore};
use seal_crypto::zeroize::Zeroizing;

/// Creates a complete header, a new base_nonce, and the shared secret (DEK)
/// for a hybrid encryption stream.
pub fn create_header<A, S>(
    pk: &A::PublicKey,
    kek_id: String,
) -> Result<(Header, [u8; 12], Zeroizing<Vec<u8>>)>
where
    A: AsymmetricAlgorithm,
    A::EncapsulatedKey: Into<Vec<u8>>,
    S: SymmetricAlgorithm,
{
    // 1. KEM Encapsulate
    let (shared_secret, encapsulated_key) = A::encapsulate(pk)?;

    // 2. Generate base_nonce
    let mut base_nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut base_nonce)?;

    // 3. Construct Header
    let header = Header {
        version: 1,
        mode: SealMode::Hybrid,
        payload: HeaderPayload::Hybrid {
            kek_id,
            kek_algorithm: A::ALGORITHM,
            dek_algorithm: S::ALGORITHM,
            encrypted_dek: encapsulated_key.into(),
            stream_info: Some(StreamInfo {
                chunk_size: DEFAULT_CHUNK_SIZE,
                base_nonce,
            }),
        },
    };

    Ok((header, base_nonce, shared_secret))
}
