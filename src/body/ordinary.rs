//! Implements the common logic for ordinary (single-threaded, in-memory) encryption and decryption.
//! This is the backend for both symmetric and hybrid ordinary modes.
//!
//! 实现普通（单线程、内存中）加密和解密的通用逻辑。
//! 这是对称和混合普通模式的后端。

use super::config::{BodyDecryptConfig, BodyEncryptConfig};
use super::traits::OrdinaryBodyProcessor;
use crate::common::derive_nonce;
use crate::common::header::SymmetricParams;
use crate::error::Result;
use seal_crypto_wrapper::prelude::{TypedSymmetricKey};
use seal_crypto_wrapper::traits::SymmetricAlgorithmTrait;
use seal_crypto_wrapper::wrappers::symmetric::SymmetricAlgorithmWrapper;
use std::borrow::Cow;

pub struct OrdinaryEncryptor<'a> {
    pub symmetric_params: SymmetricParams,
    algorithm: SymmetricAlgorithmWrapper,
    key: Cow<'a, TypedSymmetricKey>,
    aad: Option<Vec<u8>>,
}

impl<'a> OrdinaryEncryptor<'a> {
    pub fn encrypt(self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let chunk_size = self.symmetric_params.chunk_size as usize;
        let mut encrypted_body = Vec::with_capacity(
            plaintext.len() + (plaintext.len() / chunk_size + 1) * self.algorithm.tag_size(),
        );

        let mut temp_chunk_buffer = vec![0u8; chunk_size + self.algorithm.tag_size()];

        for (i, chunk) in plaintext.chunks(chunk_size).enumerate() {
            let nonce = derive_nonce(&self.symmetric_params.base_nonce, i as u64);
            let bytes_written = self.algorithm.encrypt_to_buffer(
                chunk,
                &mut temp_chunk_buffer,
                &self.key,
                &nonce,
                self.aad.as_deref(),
            )?;
            encrypted_body.extend_from_slice(&temp_chunk_buffer[..bytes_written]);
        }

        Ok(encrypted_body)
    }
}

pub struct OrdinaryDecryptor<'a> {
    algorithm: SymmetricAlgorithmWrapper,
    key: Cow<'a, TypedSymmetricKey>,
    nonce: Box<[u8]>,
    chunk_size: usize,
    aad: Option<Vec<u8>>,
}

impl<'a> OrdinaryDecryptor<'a> {
    pub fn decrypt(self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let chunk_size_with_tag = self.chunk_size + self.algorithm.tag_size();

        let mut decrypted_chunk_buffer = vec![0u8; chunk_size_with_tag];

        let mut cursor = 0;
        let mut chunk_index = 0;
        while cursor < ciphertext.len() {
            let remaining_len = ciphertext.len() - cursor;
            let current_chunk_len = std::cmp::min(remaining_len, chunk_size_with_tag);

            if current_chunk_len == 0 {
                break;
            }

            let encrypted_chunk = &ciphertext[cursor..cursor + current_chunk_len];

            let current_nonce = derive_nonce(&self.nonce, chunk_index as u64);
            let bytes_written = self.algorithm.decrypt_to_buffer(
                encrypted_chunk,
                &mut decrypted_chunk_buffer,
                &self.key,
                &current_nonce,
                self.aad.as_deref(),
            )?;

            plaintext.extend_from_slice(&decrypted_chunk_buffer[..bytes_written]);

            cursor += current_chunk_len;
            chunk_index += 1;
        }

        Ok(plaintext)
    }
}

impl<S: SymmetricAlgorithmTrait + ?Sized> OrdinaryBodyProcessor for S {
    fn setup_encryptor<'a>(
        &self,
        config: BodyEncryptConfig<'a>,
    ) -> Result<OrdinaryEncryptor<'a>> {
        let BodyEncryptConfig {
            key,
            nonce,
            aad,
            config,
        } = config;
        let symmetric_params = SymmetricParams::new(
            config.chunk_size(),
            nonce,
            aad.as_deref(),
        );
        Ok(OrdinaryEncryptor {
            symmetric_params,
            algorithm: self.algorithm().into_symmetric_wrapper(),
            key,
            aad,
        })
    }
    
    fn setup_decryptor<'a>(
        &self,
        config: BodyDecryptConfig<'a>,
    ) -> Result<OrdinaryDecryptor<'a>> {
        let chunk_size = config.chunk_size();
        Ok(OrdinaryDecryptor {
            algorithm: self.algorithm().into_symmetric_wrapper(),
            key: config.key,
            nonce: config.nonce,
            chunk_size,
            aad: config.aad,
        })
    }
}
