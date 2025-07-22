//! Implements the common logic for ordinary (single-threaded, in-memory) encryption and decryption.
//! This is the backend for both symmetric and hybrid ordinary modes.
//!
//! 实现普通（单线程、内存中）加密和解密的通用逻辑。
//! 这是对称和混合普通模式的后端。

use crate::common::derive_nonce;
use crate::common::header::AeadParams;
use crate::error::{Error, FormatError, Result};
use seal_crypto_wrapper::prelude::TypedAeadKey;
use seal_crypto_wrapper::traits::AeadAlgorithmTrait;
use seal_crypto_wrapper::wrappers::aead::AeadAlgorithmWrapper;
use std::borrow::Cow;

pub struct OrdinaryEncryptor<'a> {
    pub aead_params: AeadParams,
    pub(crate) aad: Option<Vec<u8>>,
    _lifetime: std::marker::PhantomData<&'a ()>,
}

impl<'a> OrdinaryEncryptor<'a> {
    pub(crate) fn new(aead_params: AeadParams, aad: Option<Vec<u8>>) -> Self {
        Self {
            aead_params,
            aad,
            _lifetime: std::marker::PhantomData,
        }
    }

    pub fn encrypt(self, plaintext: &[u8], key: Cow<'a, TypedAeadKey>) -> Result<Vec<u8>> {
        if self.aead_params.algorithm != key.algorithm() {
            return Err(Error::Format(FormatError::InvalidKeyType.into()));
        }

        let algorithm = AeadAlgorithmWrapper::from_enum(self.aead_params.algorithm);

        let mut ciphertext = Vec::with_capacity(
            plaintext.len()
                + algorithm.tag_size()
                    * (plaintext.len() / self.aead_params.chunk_size as usize + 1),
        );
        let chunk_size = self.aead_params.chunk_size as usize;

        let mut encrypted_chunk_buffer = vec![0u8; chunk_size + algorithm.tag_size()];

        let mut cursor = 0;
        let mut chunk_index = 0;
        while cursor < plaintext.len() {
            let remaining_len = plaintext.len() - cursor;
            let current_chunk_len = std::cmp::min(remaining_len, chunk_size);

            let plain_chunk = &plaintext[cursor..cursor + current_chunk_len];

            let current_nonce = derive_nonce(&self.aead_params.base_nonce, chunk_index as u64);

            let bytes_written = algorithm.encrypt_to_buffer(
                plain_chunk,
                &mut encrypted_chunk_buffer,
                &key,
                &current_nonce,
                self.aad.as_deref(),
            )?;

            ciphertext.extend_from_slice(&encrypted_chunk_buffer[..bytes_written]);

            cursor += current_chunk_len;
            chunk_index += 1;
        }

        Ok(ciphertext)
    }
}

pub struct OrdinaryDecryptor<'a> {
    pub(crate) algorithm: AeadAlgorithmWrapper,
    pub(crate) nonce: Box<[u8]>,
    pub(crate) chunk_size: usize,
    pub(crate) aad: Option<Vec<u8>>,
    _lifetime: std::marker::PhantomData<&'a ()>,
}

impl<'a> OrdinaryDecryptor<'a> {
    pub(crate) fn new(
        algorithm: AeadAlgorithmWrapper,
        nonce: Box<[u8]>,
        chunk_size: usize,
        aad: Option<Vec<u8>>,
    ) -> Self {
        Self {
            algorithm,
            nonce,
            chunk_size,
            aad,
            _lifetime: std::marker::PhantomData,
        }
    }

    pub fn decrypt(self, ciphertext: &[u8], key: Cow<'a, TypedAeadKey>) -> Result<Vec<u8>> {
        if self.algorithm.algorithm() != key.algorithm() {
            return Err(Error::Format(FormatError::InvalidKeyType.into()));
        }

        let algorithm = AeadAlgorithmWrapper::from_enum(self.algorithm.algorithm());

        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let chunk_size_with_tag = self.chunk_size + algorithm.tag_size();

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
            let bytes_written = algorithm.decrypt_to_buffer(
                encrypted_chunk,
                &mut decrypted_chunk_buffer,
                &key,
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
