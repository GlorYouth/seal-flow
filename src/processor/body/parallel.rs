//! Implements the common logic for parallel, in-memory encryption and decryption.
//! This is the backend for both symmetric and hybrid parallel modes.
//!
//! 实现并行、内存中加密和解密的通用逻辑。
//! 这是对称和混合并行模式的后端。

use crate::common::derive_nonce;
use crate::common::header::AeadParams;
use crate::error::{Error, FormatError, Result};
use rayon::prelude::*;
use seal_crypto_wrapper::prelude::TypedAeadKey;
use seal_crypto_wrapper::traits::AeadAlgorithmTrait;
use seal_crypto_wrapper::wrappers::aead::AeadAlgorithmWrapper;
use std::borrow::Cow;
use std::marker::PhantomData;

pub struct ParallelEncryptor<'a> {
    pub aead_params: AeadParams,
    pub(crate) aad: Option<Vec<u8>>,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> ParallelEncryptor<'a> {
    pub(crate) fn new(aead_params: AeadParams, aad: Option<Vec<u8>>) -> Self {
        Self {
            aead_params,
            aad,
            _lifetime: PhantomData,
        }
    }

    pub fn encrypt(self, plaintext: &[u8], key: Cow<'a, TypedAeadKey>) -> Result<Vec<u8>> {
        if self.aead_params.algorithm != key.algorithm() {
            return Err(Error::Format(FormatError::InvalidKeyType.into()));
        }

        let algorithm = AeadAlgorithmWrapper::from_enum(self.aead_params.algorithm);

        let chunk_size = self.aead_params.chunk_size as usize;
        let aad = self.aad.as_deref();
        let base_nonce = &self.aead_params.base_nonce;

        let chunks: Vec<_> = plaintext.chunks(chunk_size).enumerate().collect();

        let encrypted_chunks: Result<Vec<Vec<u8>>> = chunks
            .into_par_iter()
            .map(|(i, chunk)| {
                let nonce = derive_nonce(base_nonce, i as u64);
                let mut encrypted_chunk = vec![0; chunk.len() + algorithm.tag_size()];
                let bytes_written =
                    algorithm.encrypt_to_buffer(chunk, &mut encrypted_chunk, &key, &nonce, aad)?;
                encrypted_chunk.truncate(bytes_written);
                Ok(encrypted_chunk)
            })
            .collect();

        Ok(encrypted_chunks?.into_iter().flatten().collect())
    }
}

pub struct ParallelDecryptor<'a> {
    pub(crate) algorithm: AeadAlgorithmWrapper,
    pub(crate) nonce: Box<[u8]>,
    pub(crate) chunk_size: usize,
    pub(crate) aad: Option<Vec<u8>>,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> ParallelDecryptor<'a> {
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
            _lifetime: PhantomData,
        }
    }

    pub fn decrypt(
        self,
        ciphertext_body: &[u8],
        key: Cow<'a, TypedAeadKey>,
    ) -> Result<Vec<u8>> {
        let chunk_size_with_tag = self.chunk_size + self.algorithm.tag_size();
        let aad = self.aad.as_deref();
        let base_nonce = &self.nonce;

        let chunks: Vec<_> = ciphertext_body
            .chunks(chunk_size_with_tag)
            .enumerate()
            .collect();

        let decrypted_chunks: Result<Vec<Vec<u8>>> = chunks
            .into_par_iter()
            .map(|(i, chunk)| {
                let nonce = derive_nonce(base_nonce, i as u64);
                let mut decrypted_chunk = vec![0; chunk.len()];
                let bytes_written = self.algorithm.decrypt_to_buffer(
                    chunk,
                    &mut decrypted_chunk,
                    &key,
                    &nonce,
                    aad,
                )?;
                decrypted_chunk.truncate(bytes_written);
                Ok(decrypted_chunk)
            })
            .collect();

        let mut plaintext = Vec::with_capacity(ciphertext_body.len());
        for chunk in decrypted_chunks? {
            plaintext.extend_from_slice(&chunk);
        }

        Ok(plaintext)
    }
}
