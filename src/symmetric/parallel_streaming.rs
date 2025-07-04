//! Implements a parallel streaming symmetric encryption/decryption scheme.
//! This mode is designed for high-performance processing of large files or data streams
//! by overlapping I/O with parallel computation.
//!
//! 实现并行流式对称加解密方案。
//! 此模式通过将 I/O 与并行计算重叠，专为高性能处理大文件或数据流而设计。

use super::common::create_header;
use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::{Header, HeaderPayload};
use crate::common::PendingImpl;
use crate::error::{Error, FormatError, Result};
use crate::impls::parallel_streaming::{decrypt_pipeline, encrypt_pipeline};
use std::io::{Read, Write};

/// Encrypts data from a reader and writes to a writer using a parallel streaming approach.
///
/// 使用并行流式方法从 reader 加密数据并写入 writer。
pub fn encrypt<S, R, W>(
    key: S::Key,
    reader: R,
    mut writer: W,
    key_id: String,
    aad: Option<&[u8]>,
) -> Result<()>
where
    S: SymmetricAlgorithm,
    S::Key: Sync + Send,
    R: Read + Send,
    W: Write,
{
    // 1. Setup Header and write it
    let (header, base_nonce) = create_header::<S>(key_id)?;

    let header_bytes = header.encode_to_vec()?;
    writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
    writer.write_all(&header_bytes)?;

    encrypt_pipeline::<S, R, W>(key, base_nonce, reader, writer, aad)
}

/// Decrypts a stream and writes the output to another stream.
///
/// 解密一个流并将输出写入另一个流。
pub fn decrypt_body_stream<S, R, W>(
    key: S::Key,
    header: &Header,
    reader: R,
    writer: W,
    aad: Option<&[u8]>,
) -> Result<()>
where
    S: SymmetricAlgorithm,
    S::Key: Sync + Send,
    R: Read + Send,
    W: Write,
{
    let (chunk_size, base_nonce) = match &header.payload {
        HeaderPayload::Symmetric {
            stream_info: Some(info),
            ..
        } => (info.chunk_size, info.base_nonce),
        _ => return Err(Error::Format(FormatError::InvalidHeader)),
    };

    decrypt_pipeline::<S, R, W>(key, base_nonce, chunk_size, reader, writer, aad)
}

/// A pending decryptor for a parallel stream, waiting for a key.
///
/// This state is entered after the header has been successfully read from the
/// stream, allowing the user to inspect the header (e.g., to find the `key_id`)
/// before supplying the appropriate key to proceed with decryption.
///
/// 一个用于并行流的待处理解密器，等待密钥。
///
/// 当从流中成功读取标头后，进入此状态，允许用户在提供适当的密钥以继续解密之前检查标头（例如，查找 `key_id`）。
pub struct PendingDecryptor<R: Read + Send> {
    reader: R,
    header: Header,
}

impl<R: Read + Send> PendingDecryptor<R> {
    /// Creates a new `PendingDecryptor` by reading the header from the stream.
    ///
    /// 通过从流中读取标头来创建一个新的 `PendingDecryptor`。
    pub fn from_reader(mut reader: R) -> Result<Self> {
        let header = Header::decode_from_prefixed_reader(&mut reader)?;
        Ok(Self { reader, header })
    }

    /// Consumes the `PendingDecryptor` and decrypts the rest of the stream,
    /// writing the plaintext to the provided writer.
    ///
    /// 消费 `PendingDecryptor` 并解密流的其余部分，
    /// 将明文写入提供的 writer。
    pub fn decrypt_to_writer<S: SymmetricAlgorithm, W: Write>(
        self,
        key: S::Key,
        writer: W,
        aad: Option<&[u8]>,
    ) -> Result<()>
    where
        S::Key: Sync + Send,
    {
        decrypt_body_stream::<S, R, W>(key, &self.header, self.reader, writer, aad)
    }
}

impl<R: Read + Send> PendingImpl for PendingDecryptor<R> {
    fn header(&self) -> &Header {
        &self.header
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::DEFAULT_CHUNK_SIZE;
    use seal_crypto::prelude::SymmetricKeyGenerator;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
    use std::io::Cursor;

    fn get_test_data(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 256) as u8).collect()
    }

    #[test]
    fn test_parallel_streaming_roundtrip() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = get_test_data(1024 * 1024); // 1 MiB

        let mut encrypted_data = Vec::new();
        encrypt::<Aes256Gcm, _, _>(
            key.clone(),
            Cursor::new(&plaintext),
            &mut encrypted_data,
            "test_key".to_string(),
            None,
        )
        .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        assert_eq!(pending.header().payload.key_id(), Some("test_key"));
        pending
            .decrypt_to_writer::<Aes256Gcm, _>(key, &mut decrypted_data, None)
            .unwrap();

        assert_eq!(plaintext, decrypted_data);
    }

    #[test]
    fn test_empty_input() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"";

        let mut encrypted_data = Vec::new();
        encrypt::<Aes256Gcm, _, _>(
            key.clone(),
            Cursor::new(&plaintext),
            &mut encrypted_data,
            "test_key".to_string(),
            None,
        )
        .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        pending
            .decrypt_to_writer::<Aes256Gcm, _>(key, &mut decrypted_data, None)
            .unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[test]
    fn test_exact_chunk_multiple() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = get_test_data((DEFAULT_CHUNK_SIZE * 3) as usize);

        let mut encrypted_data = Vec::new();
        encrypt::<Aes256Gcm, _, _>(
            key.clone(),
            Cursor::new(&plaintext),
            &mut encrypted_data,
            "test_key".to_string(),
            None,
        )
        .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        pending
            .decrypt_to_writer::<Aes256Gcm, _>(key, &mut decrypted_data, None)
            .unwrap();

        assert_eq!(plaintext, decrypted_data);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = get_test_data(1024);

        let mut encrypted_data = Vec::new();
        encrypt::<Aes256Gcm, _, _>(
            key.clone(),
            Cursor::new(&plaintext),
            &mut encrypted_data,
            "test_key".to_string(),
            None,
        )
        .unwrap();

        // Tamper
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        encrypted_data[header_len + 10] ^= 1;

        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let result = pending.decrypt_to_writer::<Aes256Gcm, _>(key, &mut decrypted_data, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = Aes256Gcm::generate_key().unwrap();
        let key2 = Aes256Gcm::generate_key().unwrap();
        let plaintext = get_test_data(1024);

        let mut encrypted_data = Vec::new();
        encrypt::<Aes256Gcm, _, _>(
            key1,
            Cursor::new(&plaintext),
            &mut encrypted_data,
            "key1".to_string(),
            None,
        )
        .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let result = pending.decrypt_to_writer::<Aes256Gcm, _>(key2, &mut decrypted_data, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_aad_roundtrip() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = get_test_data(1024 * 256); // 256 KiB
        let aad = b"parallel streaming aad";

        let mut encrypted_data = Vec::new();
        encrypt::<Aes256Gcm, _, _>(
            key.clone(),
            Cursor::new(&plaintext),
            &mut encrypted_data,
            "test_key_aad".to_string(),
            Some(aad),
        )
        .unwrap();

        // Decrypt with correct AAD
        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        assert_eq!(pending.header().payload.key_id(), Some("test_key_aad"));
        pending
            .decrypt_to_writer::<Aes256Gcm, _>(key.clone(), &mut decrypted_data, Some(aad))
            .unwrap();
        assert_eq!(plaintext, decrypted_data);

        // Decrypt with wrong AAD fails
        let mut decrypted_data_fail = Vec::new();
        let pending_fail = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let result = pending_fail.decrypt_to_writer::<Aes256Gcm, _>(
            key.clone(),
            &mut decrypted_data_fail,
            Some(b"wrong aad"),
        );
        assert!(result.is_err());

        // Decrypt with no AAD fails
        let mut decrypted_data_fail2 = Vec::new();
        let pending_fail2 = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let result2 =
            pending_fail2.decrypt_to_writer::<Aes256Gcm, _>(key, &mut decrypted_data_fail2, None);
        assert!(result2.is_err());
    }
}
