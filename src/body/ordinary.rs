//! Implements the common logic for ordinary (single-threaded, in-memory) encryption and decryption.
//! This is the backend for both symmetric and hybrid ordinary modes.
//!
//! 实现普通（单线程、内存中）加密和解密的通用逻辑。
//! 这是对称和混合普通模式的后端。

use super::traits::OrdinaryBodyProcessor;
use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::{derive_nonce, DEFAULT_CHUNK_SIZE};
use crate::error::Result;
use crate::keys::TypedSymmetricKey;

impl<S: SymmetricAlgorithm + ?Sized> OrdinaryBodyProcessor for S {
    /// Encrypts in-memory data sequentially.
    ///
    /// 顺序加密内存中的数据。
    fn encrypt_in_memory(
        &self,
        key: TypedSymmetricKey,
        nonce: &[u8; 12],
        header_bytes: Vec<u8>,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let mut encrypted_body = Vec::with_capacity(
            plaintext.len() + (plaintext.len() / DEFAULT_CHUNK_SIZE as usize + 1) * self.tag_size(),
        );

        let mut temp_chunk_buffer = vec![0u8; DEFAULT_CHUNK_SIZE as usize + self.tag_size()];

        for (i, chunk) in plaintext.chunks(DEFAULT_CHUNK_SIZE as usize).enumerate() {
            let nonce = derive_nonce(nonce, i as u64);
            let bytes_written =
                self.encrypt_to_buffer(key.clone(), &nonce, chunk, &mut temp_chunk_buffer, aad)?;
            encrypted_body.extend_from_slice(&temp_chunk_buffer[..bytes_written]);
        }

        let mut final_output = Vec::with_capacity(4 + header_bytes.len() + encrypted_body.len());
        final_output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        final_output.extend_from_slice(&header_bytes);
        final_output.extend_from_slice(&encrypted_body);

        Ok(final_output)
    }
    /// Decrypts a ciphertext body sequentially.
    ///
    /// 顺序解密密文体。
    fn decrypt_in_memory(
        &self,
        key: TypedSymmetricKey,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let chunk_size_with_tag = DEFAULT_CHUNK_SIZE as usize + self.tag_size();

        // Reusable buffer for decrypted chunks, sized for the largest possible chunk.
        let mut decrypted_chunk_buffer = vec![0u8; DEFAULT_CHUNK_SIZE as usize + self.tag_size()];

        let mut cursor = 0;
        let mut chunk_index = 0;
        while cursor < ciphertext.len() {
            let remaining_len = ciphertext.len() - cursor;
            let current_chunk_len = std::cmp::min(remaining_len, chunk_size_with_tag);

            if current_chunk_len == 0 {
                break;
            }

            let encrypted_chunk = &ciphertext[cursor..cursor + current_chunk_len];

            let nonce = derive_nonce(nonce, chunk_index as u64);
            let bytes_written = self.decrypt_to_buffer(
                key.clone(),
                &nonce,
                encrypted_chunk,
                &mut decrypted_chunk_buffer,
                aad,
            )?;

            plaintext.extend_from_slice(&decrypted_chunk_buffer[..bytes_written]);

            cursor += current_chunk_len;
            chunk_index += 1;
        }

        Ok(plaintext)
    }
}
