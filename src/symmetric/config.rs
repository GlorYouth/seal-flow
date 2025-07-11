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
    pub config: ArcConfig,
}

impl<'a> SymmetricConfig<'a> {
    pub fn into_encrypt_config(self) -> crate::Result<BodyEncryptConfig<'a>> {
        let (header, base_nonce) = create_header(
            self.algorithm.as_ref(),
            self.key_id,
            self.config.chunk_size(),
        )?;
        let header_bytes = header.encode_to_vec()?;

        Ok(BodyEncryptConfig {
            key: self.key,
            nonce: base_nonce,
            header_bytes,
            aad: self.aad,
            config: self.config,
        })
    }
}
