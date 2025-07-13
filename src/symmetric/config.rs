use crate::algorithms::symmetric::SymmetricAlgorithmWrapper;
use crate::body::config::BodyEncryptConfig;
use crate::common::config::ArcConfig;
use crate::keys::TypedSymmetricKey;
use crate::symmetric::common::create_header;
use std::borrow::Cow;

pub struct SymmetricConfig<'a> {
    pub algorithm: Cow<'a, SymmetricAlgorithmWrapper>,
    pub key: Cow<'a, TypedSymmetricKey>,
    pub key_id: String,
    pub aad: Option<Vec<u8>>,
    pub extra_data: Option<Vec<u8>>,
    pub config: ArcConfig,
}

impl<'a> SymmetricConfig<'a> {
    pub fn into_body_config_and_header(self) -> crate::Result<(BodyEncryptConfig<'a>, Vec<u8>)> {
        let (header, base_nonce) = create_header(
            self.algorithm.as_ref(),
            self.key_id,
            self.config.chunk_size(),
            self.extra_data,
        )?;
        let header_bytes = header.encode_to_vec()?;

        let body_config = BodyEncryptConfig {
            key: self.key,
            nonce: base_nonce,
            aad: self.aad,
            config: self.config,
        };

        Ok((body_config, header_bytes))
    }
}
