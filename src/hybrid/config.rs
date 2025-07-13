use crate::algorithms::hybrid::HybridAlgorithmWrapper;
use crate::algorithms::traits::HybridAlgorithm;
use crate::body::config::BodyEncryptConfig;
use crate::common::config::ArcConfig;
use crate::common::{DerivationSet, SignerSet};
use crate::hybrid::common::create_header;
use crate::keys::TypedAsymmetricPublicKey;
use crate::keys::TypedSymmetricKey;
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
        let (header, base_nonce, shared_secret) = create_header(
            self.algorithm.as_ref(),
            self.public_key.as_ref(),
            self.kek_id,
            self.signer,
            self.derivation_config
                .as_ref()
                .map(|d| d.derivation_info.clone()),
            self.config.chunk_size(),
            self.aad.as_deref(),
        )?;

        let dek = if let Some(derivation_set) = self.derivation_config {
            derivation_set.wrapper.derive(
                shared_secret.as_ref(),
                derivation_set.salt(),
                derivation_set.info(),
                self.algorithm.as_ref().symmetric_algorithm().key_size(),
            )?
        } else {
            shared_secret
        };

        let header_bytes = header.encode_to_vec()?;

        let dek = TypedSymmetricKey::from_bytes(dek.as_ref(), self.algorithm.as_ref().symmetric_algorithm().algorithm())?;

        let body_config = BodyEncryptConfig {
            key: Cow::Owned(dek),
            nonce: base_nonce,
            aad: self.aad,
            config: self.config,
        };

        Ok((body_config, header_bytes))
    }
}
