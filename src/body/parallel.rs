//! Implements the common logic for parallel, in-memory encryption and decryption.
//! This is the backend for both symmetric and hybrid parallel modes.
//!
//! 实现并行、内存中加密和解密的通用逻辑。
//! 这是对称和混合并行模式的后端。

use super::config::{BodyDecryptConfig, BodyEncryptConfig};
use super::traits::ParallelBodyProcessor;
use crate::common::derive_nonce;
use crate::common::header::SymmetricParams;
use crate::error::{Error, FormatError, Result};
use seal_crypto_wrapper::prelude::TypedSymmetricKey;
use seal_crypto_wrapper::traits::SymmetricAlgorithmTrait;
use seal_crypto_wrapper::wrappers::symmetric::SymmetricAlgorithmWrapper;
use rayon::prelude::*;
use std::borrow::Cow;

pub struct ParallelEncryptor<'a> {
    pub symmetric_params: SymmetricParams,
    algorithm: SymmetricAlgorithmWrapper,
    key: Cow<'a, TypedSymmetricKey>,
    aad: Option<Vec<u8>>,
}

impl<'a> ParallelEncryptor<'a> {
    pub fn encrypt(self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let chunk_size = self.symmetric_params.chunk_size as usize;
        let tag_size = self.algorithm.tag_size();
        let num_chunks = (plaintext.len() + chunk_size - 1) / chunk_size;
        let last_chunk_len = if plaintext.len() % chunk_size == 0 {
            if plaintext.is_empty() { 0 } else { chunk_size }
        } else {
            plaintext.len() % chunk_size
        };

        let total_body_size = if plaintext.is_empty() {
            0
        } else {
            (num_chunks.saturating_sub(1)) * (chunk_size + tag_size) + (last_chunk_len + tag_size)
        };
        let mut encrypted_body = vec![0u8; total_body_size];

        if !plaintext.is_empty() {
            encrypted_body
                .par_chunks_mut(chunk_size + tag_size)
                .zip(plaintext.par_chunks(chunk_size))
                .enumerate()
                .try_for_each(|(i, (output_chunk, input_chunk))| -> Result<()> {
                    let nonce = derive_nonce(&self.symmetric_params.base_nonce, i as u64);
                    let expected_output_len = input_chunk.len() + tag_size;
                    let buffer_slice = &mut output_chunk[..expected_output_len];

                    self.algorithm.encrypt_to_buffer(
                        input_chunk,
                        buffer_slice,
                        self.key.as_ref(),
                        &nonce,
                        self.aad.as_deref(),
                    )
                    .map(|_| ())
                    .map_err(Error::from)
                })?;
        }

        Ok(encrypted_body)
    }
}

pub struct ParallelDecryptor<'a> {
    algorithm: SymmetricAlgorithmWrapper,
    key: Cow<'a, TypedSymmetricKey>,
    nonce: Box<[u8]>,
    chunk_size: usize,
    aad: Option<Vec<u8>>,
}

impl<'a> ParallelDecryptor<'a> {
    pub fn decrypt(self, ciphertext_body: &[u8]) -> Result<Vec<u8>> {
        let tag_len = self.algorithm.tag_size();
        let encrypted_chunk_size = self.chunk_size + tag_len;

        let num_chunks = (ciphertext_body.len() + encrypted_chunk_size - 1) / encrypted_chunk_size;
        let last_chunk_len = if ciphertext_body.len() % encrypted_chunk_size == 0 {
            if ciphertext_body.is_empty() { 0 } else { encrypted_chunk_size }
        } else {
            ciphertext_body.len() % encrypted_chunk_size
        };

        if last_chunk_len > 0 && last_chunk_len <= tag_len {
            return Err(Error::Format(FormatError::InvalidCiphertext));
        }

        let total_size = (num_chunks.saturating_sub(1)) * self.chunk_size
            + (if last_chunk_len > tag_len { last_chunk_len - tag_len } else { 0 });
        let mut plaintext = vec![0u8; total_size];

        let decrypted_chunk_lengths: Vec<usize> = plaintext
            .par_chunks_mut(self.chunk_size)
            .zip(ciphertext_body.par_chunks(encrypted_chunk_size))
            .enumerate()
            .map(|(i, (plaintext_chunk, encrypted_chunk))| -> Result<usize> {
                let nonce = derive_nonce(&self.nonce, i as u64);
                self.algorithm.decrypt_to_buffer(
                    encrypted_chunk,
                    plaintext_chunk,
                    self.key.as_ref(),
                    &nonce,
                    self.aad.as_deref(),
                )
                .map_err(Error::from)
            })
            .collect::<Result<Vec<usize>>>()?;

        let actual_size = decrypted_chunk_lengths.iter().sum();
        plaintext.truncate(actual_size);

        Ok(plaintext)
    }
}

impl<S: SymmetricAlgorithmTrait + ?Sized> ParallelBodyProcessor for S {
    fn setup_encryptor<'a>(
        &self,
        config: BodyEncryptConfig<'a>,
    ) -> Result<ParallelEncryptor<'a>> {
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
        Ok(ParallelEncryptor {
            symmetric_params,
            algorithm: self.algorithm().into_symmetric_wrapper(),
            key,
            aad,
        })
    }

    fn setup_decryptor<'a>(
        &self,
        config: BodyDecryptConfig<'a>,
    ) -> Result<ParallelDecryptor<'a>> {
        let chunk_size = config.chunk_size();
        Ok(ParallelDecryptor {
            algorithm: self.algorithm().into_symmetric_wrapper(),
            key: config.key,
            nonce: config.nonce,
            chunk_size,
            aad: config.aad,
        })
    }
}
