use crate::algorithms::hybrid::HybridAlgorithmWrapper;
use crate::body::config::BodyEncryptConfig;
use crate::common::config::ArcConfig;
use crate::common::{DerivationSet, SignerSet};
use crate::hybrid::common::create_header;
use crate::keys::TypedAsymmetricPublicKey;
use std::borrow::Cow;

pub struct HybridConfig<'a> {
    pub algorithm: Cow<'a, HybridAlgorithmWrapper>,
    pub public_key: Cow<'a, TypedAsymmetricPublicKey>,
    pub kek_id: String,
    pub signer: Option<SignerSet>,
    pub aad: Option<Vec<u8>>,
    pub derivation_config: Option<DerivationSet>,
    pub config: ArcConfig,
}

impl<'a> HybridConfig<'a> {
    pub fn into_body_config_and_header(self) -> crate::Result<(BodyEncryptConfig<'a>, Vec<u8>)> {
        let (derivation_info, deriver_fn) = self
            .derivation_config
            .map(|d| (d.derivation_info, d.deriver_fn))
            .unzip();

        let (header, base_nonce, shared_secret) = create_header(
            self.algorithm.as_ref(),
            self.public_key.as_ref(),
            self.kek_id,
            self.signer,
            self.aad.as_deref(),
            derivation_info,
            self.config.chunk_size(),
        )?;

        let dek = if let Some(f) = deriver_fn {
            f(&shared_secret)?
        } else {
            shared_secret
        };

        let header_bytes = header.encode_to_vec()?;

        let body_config = BodyEncryptConfig {
            key: Cow::Owned(dek),
            nonce: base_nonce,
            aad: self.aad,
            config: self.config,
        };

        Ok((body_config, header_bytes))
    }
}
