use std::borrow::Cow;

use crate::{
    common::config::{ArcConfig, DecryptorConfig},
    keys::TypedSymmetricKey,
};

pub struct BodyEncryptConfig<'a> {
    pub key: Cow<'a, TypedSymmetricKey>,
    pub nonce: [u8; 12],
    pub aad: Option<Vec<u8>>,
    pub config: ArcConfig,
}

impl<'a> BodyEncryptConfig<'a> {
    pub fn key(&self) -> &TypedSymmetricKey {
        self.key.as_ref()
    }

    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    pub fn aad(&self) -> Option<&[u8]> {
        self.aad.as_deref()
    }

    pub fn chunk_size(&self) -> usize {
        self.config.chunk_size() as usize
    }

    pub fn channel_bound(&self) -> usize {
        self.config.channel_bound()
    }
}

pub struct BodyDecryptConfig<'a> {
    pub key: Cow<'a, TypedSymmetricKey>,
    pub nonce: [u8; 12],
    pub aad: Option<Vec<u8>>,
    pub config: DecryptorConfig,
}

impl<'a> BodyDecryptConfig<'a> {
    pub fn key(&self) -> &TypedSymmetricKey {
        self.key.as_ref()
    }

    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    pub fn aad(&self) -> Option<&[u8]> {
        self.aad.as_deref()
    }

    pub fn chunk_size(&self) -> usize {
        self.config.chunk_size() as usize
    }

    pub fn channel_bound(&self) -> usize {
        self.config.channel_bound()
    }
}
