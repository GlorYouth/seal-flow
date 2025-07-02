use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::header::{Header, HeaderPayload, KdfInfo, SealMode, SingerInfo, StreamInfo};
use crate::common::SignerSet;
use crate::common::DEFAULT_CHUNK_SIZE;
use crate::error::Result;
use rand::{rngs::OsRng, TryRngCore};
use seal_crypto::zeroize::Zeroizing;

/// Creates a complete header, a new base_nonce, and the shared secret (DEK)
/// for a hybrid encryption stream.
pub fn create_header<A, S>(
    pk: &A::PublicKey,
    kek_id: String,
    signer: Option<SignerSet>,
    aad: Option<&[u8]>,
    kdf_info: Option<KdfInfo>,
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

    // 3. Construct Header payload, starting without a signature
    let mut payload = HeaderPayload::Hybrid {
        kek_id,
        kek_algorithm: A::ALGORITHM,
        dek_algorithm: S::ALGORITHM,
        encrypted_dek: encapsulated_key.into(),
        stream_info: Some(StreamInfo {
            chunk_size: DEFAULT_CHUNK_SIZE,
            base_nonce,
        }),
        signature: None,
        kdf_info,
    };

    // 4. Sign the payload and mutate it if a signer is provided
    if let Some(s) = signer {
        // The payload already has signature: None, so we can serialize it directly.
        let payload_bytes = bincode::encode_to_vec(&payload, bincode::config::standard())?;
        let signature_bytes = (s.signer)(&payload_bytes, aad)?;

        // Now, set the signature on the actual payload by mutating it.
        if let HeaderPayload::Hybrid {
            ref mut signature, ..
        } = payload
        {
            *signature = Some(SingerInfo {
                signer_key_id: s.signer_key_id,
                signer_algorithm: s.signer_algorithm,
                signature: signature_bytes,
            });
        }
    }

    let header = Header {
        version: 1,
        mode: SealMode::Hybrid,
        payload,
    };

    Ok((header, base_nonce, shared_secret))
}
