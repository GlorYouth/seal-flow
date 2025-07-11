use crate::{
    common::config::{ArcConfig, DecryptorConfig},
    keys::TypedSymmetricKey,
};

pub struct BodyEncryptConfig<'a> {
    pub key: TypedSymmetricKey,
    pub nonce: &'a [u8; 12],
    pub header_bytes: Vec<u8>,
    pub aad: Option<Vec<u8>>,
    pub config: ArcConfig,
}

impl<'a> BodyEncryptConfig<'a> {
    pub(crate) fn key(&self) -> &TypedSymmetricKey {
        &self.key
    }

    pub(crate) fn nonce(&self) -> &[u8; 12] {
        self.nonce
    }

    pub(crate) fn header_bytes(&self) -> &Vec<u8> {
        &self.header_bytes
    }

    pub(crate) fn aad(&self) -> Option<&[u8]> {
        self.aad.as_deref()
    }

    pub(crate) fn chunk_size(&self) -> usize {
        self.config.chunk_size() as usize
    }
    
    pub(crate) fn channel_bound(&self) -> usize {
        self.config.channel_bound()
    }
}

pub struct BodyDecryptConfig<'a> {
    pub key: TypedSymmetricKey,
    pub nonce: &'a [u8; 12],
    pub ciphertext: &'a [u8],
    pub aad: Option<Vec<u8>>,
    pub config: DecryptorConfig,
}

impl<'a> BodyDecryptConfig<'a> {
    pub(crate) fn key(&self) -> &TypedSymmetricKey {
        &self.key
    }

    pub(crate) fn nonce(&self) -> &[u8; 12] {
        self.nonce
    }

    pub(crate) fn ciphertext(&self) -> &[u8] {
        self.ciphertext
    }

    pub(crate) fn aad(&self) -> Option<&[u8]> {
        self.aad.as_deref()
    }

    pub(crate) fn chunk_size(&self) -> usize {
        self.config.chunk_size() as usize
    }
    
    pub(crate) fn channel_bound(&self) -> usize {
        self.config.channel_bound()
    }
}