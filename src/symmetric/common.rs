//! Common utilities for symmetric encryption modes.
//!
//! 对称加密模式的通用工具。

use crate::algorithms::traits::SymmetricAlgorithm;
use crate::body::config::BodyDecryptConfig;
use crate::common::config::{ArcConfig, DecryptorConfig};
use crate::common::header::{Header, HeaderPayload, SpecificHeaderPayload};
use crate::keys::TypedSymmetricKey;
use rand::{rngs::OsRng, TryRngCore};
use std::borrow::Cow;

/// Creates a complete header and a new base_nonce for a symmetric encryption stream.
///
/// 为对称加密流创建一个完整的标头和一个新的 base_nonce。
pub fn create_header<S: SymmetricAlgorithm>(
    algorithm: &S,
    key_id: String,
    chunk_size: u32,
) -> crate::Result<(Header, [u8; 12])> {
    let mut base_nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut base_nonce)?;

    let header = Header {
        version: 1,
        payload: HeaderPayload {
            chunk_size,
            base_nonce,
            specific_payload: SpecificHeaderPayload::Symmetric {
                key_id,
                algorithm: algorithm.algorithm(),
            },
        },
    };
    Ok((header, base_nonce))
}

pub(super) fn prepare_body_decrypt_config(
    header: &Header,
    key: &TypedSymmetricKey,
    aad: Option<Vec<u8>>,
    arc_config: ArcConfig,
) -> crate::Result<BodyDecryptConfig<'static>> {
    let HeaderPayload {
        base_nonce,
        chunk_size,
        ..
    } = header.payload;

    let config = BodyDecryptConfig {
        key: Cow::Owned(key.clone()),
        nonce: base_nonce,
        aad,
        config: DecryptorConfig {
            chunk_size,
            arc_config,
        },
    };

    Ok(config)
}
