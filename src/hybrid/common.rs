//! Common utilities for hybrid encryption modes.
//!
//! 混合加密模式的通用工具。

use crate::algorithms::traits::HybridAlgorithm;
use crate::common::header::{
    DerivationInfo, Header, HeaderPayload, SpecificHeaderPayload,
};
use crate::common::SignerSet;
use crate::error::Result;
use crate::keys::TypedAsymmetricPublicKey;
use rand::{rngs::OsRng, TryRngCore};
use seal_crypto::prelude::Key;

use crate::body::config::BodyDecryptConfig;
use crate::common::config::{ArcConfig, DecryptorConfig};
use crate::error::{Error, FormatError};
use crate::keys::TypedAsymmetricPrivateKey;
use crate::keys::TypedSymmetricKey;
use seal_crypto::zeroize::Zeroizing;
use std::borrow::Cow;

/// Creates a complete header, a new base_nonce, and the shared secret (DEK)
/// for a hybrid encryption stream.
///
/// 为混合加密流创建一个完整的标头、一个新的 base_nonce 和共享密钥 (DEK)。
pub(super) fn create_header<H: HybridAlgorithm + ?Sized>(
    algorithm: &H,
    public_key: &TypedAsymmetricPublicKey,
    kek_id: String,
    signer: Option<SignerSet>,
    derivation_info: Option<DerivationInfo>,
    chunk_size: u32,
    aad: Option<&[u8]>,
    extra_data: Option<Vec<u8>>,
) -> Result<(Header, [u8; 12], Zeroizing<Vec<u8>>)> {
    // 1. KEM Encapsulate
    // 1. KEM 封装
    let (shared_secret, encapsulated_key) = algorithm.encapsulate_key(public_key)?;

    // 2. Generate base_nonce
    // 2. 生成 base_nonce
    let mut base_nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut base_nonce)?;

    // 3. Construct Header payload, starting without a signature
    // 3. 构造标头有效载荷，初始不带签名
    let mut payload = HeaderPayload {
        chunk_size,
        base_nonce,
        specific_payload: SpecificHeaderPayload::Hybrid {
            kek_id,
            kek_algorithm: algorithm.asymmetric_algorithm().algorithm(),
            dek_algorithm: algorithm.symmetric_algorithm().algorithm(),
            encrypted_dek: encapsulated_key.to_bytes(),
            signature: None,
            derivation_info,
        },
        extra_data,
    };

    // 4. 如果提供了签名者，则对有效载荷进行签名并修改
    if let Some(s) = signer {
        // The payload already has signature: None, so we can serialize it directly.
        // 有效载荷的签名字段为 None，所以我们可以直接序列化它。
        payload.sign_and_embed(&s, aad)?;
    }

    let header = Header {
        version: 1,
        payload,
    };

    Ok((header, base_nonce, shared_secret))
}

pub(super) fn prepare_body_decrypt_config(
    header: Header,
    algorithm: &impl HybridAlgorithm,
    private_key: &TypedAsymmetricPrivateKey,
    aad: Option<Vec<u8>>,
    arc_config: ArcConfig,
) -> Result<BodyDecryptConfig<'static>> {
    let (encapsulated_key, base_nonce, derivation_info, chunk_size) = if let HeaderPayload {
        base_nonce,
        chunk_size,
        specific_payload:
            SpecificHeaderPayload::Hybrid {
                encrypted_dek,
                derivation_info,
                dek_algorithm,
                kek_algorithm,
                ..
            },
        ..
    } = header.payload
    {
        if dek_algorithm != algorithm.symmetric_algorithm().algorithm()
            || kek_algorithm != algorithm.asymmetric_algorithm().algorithm()
        {
            return Err(Error::Format(FormatError::InvalidKeyType));
        }

        (
            Zeroizing::new(encrypted_dek.clone()),
            base_nonce,
            derivation_info.clone(),
            chunk_size,
        )
    } else {
        return Err(Error::Format(FormatError::InvalidHeader));
    };

    let shared_secret = algorithm
        .asymmetric_algorithm()
        .decapsulate_key(private_key, &encapsulated_key)?;

    let dek = if let Some(info) = derivation_info {
        use crate::algorithms::traits::KdfKeyAlgorithm;
        use crate::algorithms::traits::XofAlgorithm;
        use crate::common::header::DerivationInfo::{Kdf, Xof};
        match info {
            Kdf(kdf_info) => kdf_info.kdf_algorithm.into_kdf_key_wrapper().derive(
                shared_secret.as_ref(),
                kdf_info.salt.as_deref(),
                kdf_info.info.as_deref(),
                algorithm.symmetric_algorithm().key_size(),
            )?,
            Xof(xof_info) => {
                let mut xof_reader = xof_info.xof_algorithm.into_xof_wrapper().reader(
                    shared_secret.as_ref(),
                    xof_info.salt.as_deref(),
                    xof_info.info.as_deref(),
                )?;
                let dek = xof_reader.read_boxed(algorithm.symmetric_algorithm().key_size());
                Zeroizing::new(dek.to_vec())
            },
        }
    } else {
        shared_secret
    };

    let dek = TypedSymmetricKey::from_bytes(dek.as_ref(), algorithm.symmetric_algorithm().algorithm())?;

    let body_config = BodyDecryptConfig {
        key: Cow::Owned(dek),
        nonce: base_nonce,
        aad,
        config: DecryptorConfig {
            chunk_size,
            arc_config,
        },
    };

    Ok(body_config)
}
