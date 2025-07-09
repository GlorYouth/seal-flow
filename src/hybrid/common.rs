//! Common utilities for hybrid encryption modes.
//!
//! 混合加密模式的通用工具。

use crate::algorithms::traits::HybridAlgorithm;
use crate::common::header::{
    DerivationInfo, Header, HeaderPayload, SealMode, SignerInfo, StreamInfo,
};
use crate::common::SignerSet;
use crate::common::DEFAULT_CHUNK_SIZE;
use crate::error::Result;
use crate::keys::TypedAsymmetricPublicKey;
use crate::keys::TypedSymmetricKey;
use rand::{rngs::OsRng, TryRngCore};
use seal_crypto::prelude::Key;

/// Creates a complete header, a new base_nonce, and the shared secret (DEK)
/// for a hybrid encryption stream.
///
/// 为混合加密流创建一个完整的标头、一个新的 base_nonce 和共享密钥 (DEK)。
pub fn create_header<H: HybridAlgorithm + ?Sized>(
    algorithm: &H,
    public_key: &TypedAsymmetricPublicKey,
    kek_id: String,
    signer: Option<SignerSet>,
    aad: Option<&[u8]>,
    derivation_info: Option<DerivationInfo>,
) -> Result<(Header, [u8; 12], TypedSymmetricKey)> {
    // 1. KEM Encapsulate
    // 1. KEM 封装
    let (shared_secret, encapsulated_key) = algorithm.encapsulate_key(public_key)?;

    // 2. Generate base_nonce
    // 2. 生成 base_nonce
    let mut base_nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut base_nonce)?;

    // 3. Construct Header payload, starting without a signature
    // 3. 构造标头有效载荷，初始不带签名
    let mut payload = HeaderPayload::Hybrid {
        kek_id,
        kek_algorithm: algorithm.asymmetric_algorithm().algorithm(),
        dek_algorithm: algorithm.symmetric_algorithm().algorithm(),
        encrypted_dek: encapsulated_key.to_bytes(),
        stream_info: Some(StreamInfo {
            chunk_size: DEFAULT_CHUNK_SIZE,
            base_nonce,
        }),
        signature: None,
        derivation_info,
    };

    // 4. Sign the payload and mutate it if a signer is provided
    // 4. 如果提供了签名者，则对有效载荷进行签名并修改
    if let Some(s) = signer {
        // The payload already has signature: None, so we can serialize it directly.
        // 有效载荷的签名字段为 None，所以我们可以直接序列化它。
        let payload_bytes = bincode::encode_to_vec(&payload, bincode::config::standard())?;
        let signature_bytes = (s.signer)(&payload_bytes, aad)?;

        // Now, set the signature on the actual payload by mutating it.
        // 现在，通过修改可变载荷来设置签名。
        if let HeaderPayload::Hybrid {
            ref mut signature, ..
        } = payload
        {
            *signature = Some(SignerInfo {
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

    let shared_secret = TypedSymmetricKey::from_bytes(&shared_secret, algorithm.symmetric_algorithm().algorithm())?;

    Ok((header, base_nonce, shared_secret))
}
