//! Implements the common logic for parallel, in-memory encryption and decryption.
//! This is the backend for both symmetric and hybrid parallel modes.
//!
//! 实现并行、内存中加密和解密的通用逻辑。
//! 这是对称和混合并行模式的后端。

use crate::common::derive_nonce;
use crate::common::header::SymmetricParams;
use crate::error::Result;
use seal_crypto_wrapper::prelude::TypedSymmetricKey;
use seal_crypto_wrapper::traits::SymmetricAlgorithmTrait;
use seal_crypto_wrapper::wrappers::symmetric::SymmetricAlgorithmWrapper;
use rayon::prelude::*;
use std::borrow::Cow;
use std::marker::PhantomData;

pub struct ParallelEncryptor<'a> {
    pub symmetric_params: SymmetricParams,
    pub(crate) algorithm: SymmetricAlgorithmWrapper,
    pub(crate) aad: Option<Vec<u8>>,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> ParallelEncryptor<'a> {
    pub(crate) fn new(
        symmetric_params: SymmetricParams,
        algorithm: SymmetricAlgorithmWrapper,
        aad: Option<Vec<u8>>,
    ) -> Self {
        Self {
            symmetric_params,
            algorithm,
            aad,
            _lifetime: PhantomData,
        }
    }

    pub fn encrypt(self, plaintext: &[u8], key: Cow<'a, TypedSymmetricKey>) -> Result<Vec<u8>> {
        let chunk_size = self.symmetric_params.chunk_size as usize;
        let aad = self.aad.as_deref();
        let base_nonce = &self.symmetric_params.base_nonce;

        let chunks: Vec<_> = plaintext.chunks(chunk_size).enumerate().collect();

        let encrypted_chunks: Result<Vec<Vec<u8>>> = chunks
            .into_par_iter()
            .map(|(i, chunk)| {
                let nonce = derive_nonce(base_nonce, i as u64);
                let mut encrypted_chunk = vec![0; chunk.len() + self.algorithm.tag_size()];
                let bytes_written = self.algorithm.encrypt_to_buffer(
                    chunk,
                    &mut encrypted_chunk,
                    &key,
                    &nonce,
                    aad,
                )?;
                encrypted_chunk.truncate(bytes_written);
                Ok(encrypted_chunk)
            })
            .collect();

        Ok(encrypted_chunks?.into_iter().flatten().collect())
    }
}

pub struct ParallelDecryptor<'a> {
    pub(crate) algorithm: SymmetricAlgorithmWrapper,
    pub(crate) nonce: Box<[u8]>,
    pub(crate) chunk_size: usize,
    pub(crate) aad: Option<Vec<u8>>,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> ParallelDecryptor<'a> {
    pub(crate) fn new(
        algorithm: SymmetricAlgorithmWrapper,
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

    pub fn decrypt(self, ciphertext_body: &[u8], key: Cow<'a, TypedSymmetricKey>) -> Result<Vec<u8>> {
        let chunk_size_with_tag = self.chunk_size + self.algorithm.tag_size();
        let aad = self.aad.as_deref();
        let base_nonce = &self.nonce;

        let chunks: Vec<_> = ciphertext_body.chunks(chunk_size_with_tag).enumerate().collect();

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
