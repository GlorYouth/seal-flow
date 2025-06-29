use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::SignerSet;
use crate::common::header::{Header, HeaderPayload, SealMode, SingerInfo, StreamInfo};
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
    let mut payload = HeaderPayload::Hybrid {
        kek_id,
        kek_algorithm: A::ALGORITHM,
        dek_algorithm: S::ALGORITHM,
        encrypted_dek: encapsulated_key.into(),
        stream_info: Some(StreamInfo {
            chunk_size: DEFAULT_CHUNK_SIZE,
            base_nonce,
        }),
        signature: signer.as_ref().map(|s| SingerInfo {
            signer_key_id: s.signer_key_id.clone(),
            signer_algorithm: s.signer_algorithm,
            signature: Vec::new(),
        }),
    };

    // 4. Sign the payload if a signer is provided
    if let Some(signer) = signer.as_ref() {
        // Create a temporary payload without the signature for signing
        let mut temp_payload = payload.clone();
        if let HeaderPayload::Hybrid {
            ref mut signature, ..
        } = temp_payload
        {
            *signature = None;
        }

        let payload_bytes =
            bincode::encode_to_vec(&temp_payload, bincode::config::standard())?;
        let signature_bytes = (signer.signer)(&payload_bytes)?;

        // Now, set the signature on the actual payload
        if let HeaderPayload::Hybrid {
            ref mut signature, ..
        } = payload
        {
            *signature = Some(SingerInfo {
                signer_key_id: signer.signer_key_id.clone(),
                signer_algorithm: signer.signer_algorithm,
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
