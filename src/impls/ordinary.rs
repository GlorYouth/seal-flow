//! Implements the common logic for ordinary (single-threaded, in-memory) encryption and decryption.
use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::{derive_nonce, DEFAULT_CHUNK_SIZE};
use crate::error::Result;

/// Encrypts in-memory data sequentially.
pub fn encrypt_in_memory<S: SymmetricAlgorithm>(
    key: S::Key,
    base_nonce: [u8; 12],
    header_bytes: Vec<u8>,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let key_material = key.into();

    let mut encrypted_body = Vec::with_capacity(
        plaintext.len() + (plaintext.len() / DEFAULT_CHUNK_SIZE as usize + 1) * S::TAG_SIZE,
    );

    let mut temp_chunk_buffer = vec![0u8; DEFAULT_CHUNK_SIZE as usize + S::TAG_SIZE];

    for (i, chunk) in plaintext.chunks(DEFAULT_CHUNK_SIZE as usize).enumerate() {
        let nonce = derive_nonce(&base_nonce, i as u64);
        let bytes_written =
            S::encrypt_to_buffer(&key_material, &nonce, chunk, &mut temp_chunk_buffer, aad)?;
        encrypted_body.extend_from_slice(&temp_chunk_buffer[..bytes_written]);
    }

    let mut final_output = Vec::with_capacity(4 + header_bytes.len() + encrypted_body.len());
    final_output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    final_output.extend_from_slice(&header_bytes);
    final_output.extend_from_slice(&encrypted_body);

    Ok(final_output)
}

/// Decrypts a ciphertext body sequentially.
pub fn decrypt_in_memory<S: SymmetricAlgorithm>(
    key: S::Key,
    base_nonce: [u8; 12],
    chunk_size_u32: u32,
    ciphertext_body: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let key_material = key.into();
    let mut plaintext = Vec::with_capacity(ciphertext_body.len());
    let chunk_size_with_tag = chunk_size_u32 as usize + S::TAG_SIZE;

    // Reusable buffer for decrypted chunks, sized for the largest possible chunk.
    let mut decrypted_chunk_buffer = vec![0u8; chunk_size_u32 as usize];

    let mut cursor = 0;
    let mut chunk_index = 0;
    while cursor < ciphertext_body.len() {
        let remaining_len = ciphertext_body.len() - cursor;
        let current_chunk_len = std::cmp::min(remaining_len, chunk_size_with_tag);

        if current_chunk_len == 0 {
            break;
        }

        let encrypted_chunk = &ciphertext_body[cursor..cursor + current_chunk_len];

        let nonce = derive_nonce(&base_nonce, chunk_index as u64);
        let bytes_written = S::decrypt_to_buffer(
            &key_material,
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
