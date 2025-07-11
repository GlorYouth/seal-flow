//! Implements the common logic for parallel, in-memory encryption and decryption.
//! This is the backend for both symmetric and hybrid parallel modes.
//!
//! 实现并行、内存中加密和解密的通用逻辑。
//! 这是对称和混合并行模式的后端。

use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::{derive_nonce, DEFAULT_CHUNK_SIZE};
use crate::error::{Error, FormatError, Result};
use rayon::prelude::*;

use super::traits::ParallelBodyProcessor;
use crate::keys::TypedSymmetricKey;

impl<S: SymmetricAlgorithm + ?Sized> ParallelBodyProcessor for S {
    /// Encrypts in-memory data in parallel.
    ///
    /// 并行加密内存中的数据。
    fn encrypt_body_parallel(
        &self,
        key: TypedSymmetricKey,
        base_nonce: &[u8; 12],
        header_bytes: Vec<u8>,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let chunk_size = DEFAULT_CHUNK_SIZE as usize;
        let tag_size = self.tag_size();

        // Pre-allocate output buffer
        // 预分配输出缓冲区
        let num_chunks = (plaintext.len() + chunk_size - 1) / chunk_size;
        let last_chunk_len = if plaintext.len() % chunk_size == 0 {
            if plaintext.is_empty() {
                0
            } else {
                chunk_size
            }
        } else {
            plaintext.len() % chunk_size
        };

        let total_body_size = if plaintext.is_empty() {
            0
        } else {
            (num_chunks.saturating_sub(1)) * (chunk_size + tag_size) + (last_chunk_len + tag_size)
        };
        let mut final_output = Vec::with_capacity(4 + header_bytes.len() + total_body_size);
        final_output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        final_output.extend_from_slice(&header_bytes);
        // The rest of the buffer is for the body, which we will fill in parallel
        // 缓冲区的其余部分用于存放将要并行填充的主体
        let body_len = total_body_size;
        final_output.resize(4 + header_bytes.len() + body_len, 0);

        let (_header_part, body_part) = final_output.split_at_mut(4 + header_bytes.len());

        // Process chunks in parallel using Rayon, writing directly to the output buffer
        // 使用 Rayon 并行处理数据块，直接写入输出缓冲区
        if !plaintext.is_empty() {
            body_part
                .par_chunks_mut(chunk_size + tag_size)
                .zip(plaintext.par_chunks(chunk_size))
                .enumerate()
                .try_for_each(|(i, (output_chunk, input_chunk))| -> Result<()> {
                    let nonce = derive_nonce(base_nonce, i as u64);
                    let expected_output_len = input_chunk.len() + tag_size;
                    let buffer_slice = &mut output_chunk[..expected_output_len];

                    self.encrypt_to_buffer(key.clone(), &nonce, input_chunk, buffer_slice, aad)
                        .map(|_| ())
                        .map_err(Error::from)
                })?;
        }

        Ok(final_output)
    }

    /// Decrypts a ciphertext body in parallel.
    ///
    /// 并行解密密文体。
    fn decrypt_body_parallel(
        &self,
        key: TypedSymmetricKey,
        base_nonce: &[u8; 12],
        ciphertext_body: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let chunk_size = DEFAULT_CHUNK_SIZE as usize;
        let tag_len = self.tag_size();
        let encrypted_chunk_size = chunk_size + tag_len;

        // Pre-allocate plaintext buffer
        // 预分配明文缓冲区
        let num_chunks = (ciphertext_body.len() + encrypted_chunk_size - 1) / encrypted_chunk_size;
        let last_chunk_len = if ciphertext_body.len() % encrypted_chunk_size == 0 {
            if ciphertext_body.is_empty() {
                0
            } else {
                encrypted_chunk_size
            }
        } else {
            ciphertext_body.len() % encrypted_chunk_size
        };

        if last_chunk_len > 0 && last_chunk_len <= tag_len {
            return Err(Error::Format(FormatError::InvalidCiphertext));
        }

        let total_size = (num_chunks.saturating_sub(1)) * chunk_size
            + (if last_chunk_len > tag_len {
                last_chunk_len - tag_len
            } else {
                0
            });
        let mut plaintext = vec![0u8; total_size];

        // Decrypt in parallel, writing directly to the plaintext buffer
        // 并行解密，直接写入明文缓冲区
        let decrypted_chunk_lengths: Vec<usize> = plaintext
            .par_chunks_mut(chunk_size)
            .zip(ciphertext_body.par_chunks(encrypted_chunk_size))
            .enumerate()
            .map(|(i, (plaintext_chunk, encrypted_chunk))| -> Result<usize> {
                let nonce = derive_nonce(base_nonce, i as u64);

                // Decrypt the chunk
                // 解密数据块
                self.decrypt_to_buffer(key.clone(), &nonce, encrypted_chunk, plaintext_chunk, aad)
                    .map_err(Error::from)
            })
            .collect::<Result<Vec<usize>>>()?;

        // Truncate the plaintext to the actual decrypted size
        // 将明文截断为实际解密后的大小
        let actual_size = decrypted_chunk_lengths.iter().sum();
        plaintext.truncate(actual_size);

        Ok(plaintext)
    }
}
