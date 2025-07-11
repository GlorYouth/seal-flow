//! Implements `std::io` traits for synchronous, streaming symmetric encryption.
//!
//! 为同步、流式对称加密实现 `std::io` trait。

use super::common::create_header;
use crate::algorithms::traits::SymmetricAlgorithm;
use crate::common::header::{Header, HeaderPayload};
use crate::common::PendingImpl;
use crate::error::{Error, FormatError, Result};
use crate::impls::streaming::{DecryptorImpl, EncryptorImpl};
use std::io::{self, Read, Write};

/// Implements `std::io::Write` for synchronous, streaming symmetric encryption.
///
/// 为同步、流式对称加密实现 `std::io::Write`。
pub struct Encryptor<W: Write, S: SymmetricAlgorithm> {
    inner: EncryptorImpl<W, S>,
}

impl<W: Write, S: SymmetricAlgorithm> Encryptor<W, S> {
    /// Creates a new `Encryptor`.
    ///
    /// The header is immediately written to the underlying writer.
    ///
    /// # Arguments
    ///
    /// * `writer`: The writer to which encrypted data will be written.
    /// * `key`: The symmetric key for encryption.
    /// * `key_id`: An identifier for the key, stored in the header.
    /// * `aad`: Optional additional authenticated data.
    ///
    /// # Returns
    ///
    /// A new `Encryptor` instance.
    ///
    /// 创建一个新的 `Encryptor`。
    ///
    /// 标头会立即写入底层的 writer。
    ///
    /// # 参数
    ///
    /// * `writer`: 将写入加密数据的 writer。
    /// * `key`: 用于加密的对称密钥。
    /// * `key_id`: 密钥的标识符，存储在标头中。
    /// * `aad`: 可选的附加认证数据。
    ///
    /// # 返回
    ///
    ///一个新的 `Encryptor` 实例。
    pub fn new(mut writer: W, key: S::Key, key_id: String, aad: Option<&[u8]>) -> Result<Self> {
        let (header, base_nonce) = create_header::<S>(key_id)?;

        let header_bytes = header.encode_to_vec()?;
        writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&header_bytes)?;

        let inner = EncryptorImpl::new(writer, key, base_nonce, aad)?;

        Ok(Self { inner })
    }

    /// Finalizes the encryption stream.
    ///
    /// This method must be called to ensure that the last partial chunk of data is
    /// encrypted and the authentication tag is written to the underlying writer.
    ///
    /// 必须调用此方法以确保最后的数据块被加密，
    /// 并且认证标签被写入底层的 writer。
    pub fn finish(self) -> Result<()> {
        self.inner.finish()
    }
}

impl<W: Write, S: SymmetricAlgorithm> Write for Encryptor<W, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A decryptor that is pending the provision of a key.
///
/// This state is entered after the header has been successfully read from the
/// stream, allowing the user to inspect the header (e.g., to find the `key_id`)
/// before supplying the appropriate key to proceed with decryption.
///
/// 一个待处理的解密器，等待提供密钥。
///
/// 当从流中成功读取标头后，进入此状态，允许用户在提供适当的密钥以继续解密之前检查标头（例如，查找 `key_id`）。
pub struct PendingDecryptor<R: Read> {
    reader: R,
    header: Header,
}

impl<R: Read> PendingDecryptor<R> {
    /// Creates a new `PendingDecryptor` by reading the header from the provided reader.
    ///
    /// 通过从提供的 reader 中读取标头来创建一个新的 `PendingDecryptor`。
    pub fn from_reader(mut reader: R) -> Result<Self> {
        let header = Header::decode_from_prefixed_reader(&mut reader)?;
        Ok(Self { reader, header })
    }

    /// Consumes the `PendingDecryptor` and returns a full `Decryptor` instance,
    /// ready to decrypt the stream.
    ///
    /// 消费 `PendingDecryptor` 并返回一个完整的 `Decryptor` 实例，准备解密流。
    pub fn into_decryptor<S: SymmetricAlgorithm>(
        self,
        key: S::Key,
        aad: Option<&[u8]>,
    ) -> Result<Decryptor<R, S>> {
        let (chunk_size, base_nonce) = match &self.header.payload {
            HeaderPayload::Symmetric {
                stream_info: Some(info),
                ..
            } => (info.chunk_size, info.base_nonce),
            _ => return Err(Error::Format(FormatError::InvalidHeader)),
        };

        let tag_len = S::TAG_SIZE;
        let encrypted_chunk_size = chunk_size as usize + tag_len;

        let inner = DecryptorImpl::new(self.reader, key, base_nonce, encrypted_chunk_size, aad);
        Ok(Decryptor { inner })
    }
}

/// Implements `std::io::Read` for synchronous, streaming symmetric decryption.
///
/// 为同步、流式对称解密实现 `std::io::Read`。
pub struct Decryptor<R: Read, S: SymmetricAlgorithm> {
    inner: DecryptorImpl<R, S>,
}

impl<R: Read, S: SymmetricAlgorithm> Read for Decryptor<R, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Read> PendingImpl for PendingDecryptor<R> {
    fn header(&self) -> &Header {
        &self.header
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::prelude::SymmetricKeyGenerator;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
    use std::io::{Cursor, Read, Write};

    fn test_streaming_roundtrip(plaintext: &[u8], aad: Option<&[u8]>) {
        let key = Aes256Gcm::generate_key().unwrap();
        let key_id = "test_key_id".to_string();

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor =
            Encryptor::<_, Aes256Gcm>::new(&mut encrypted_data, key.clone(), key_id.clone(), aad)
                .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt using the new two-step process
        let pending_decryptor =
            PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        assert_eq!(
            pending_decryptor.header().payload.key_id(),
            Some(key_id.as_str())
        );

        let mut decryptor = pending_decryptor
            .into_decryptor::<Aes256Gcm>(key, aad)
            .unwrap();
        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[test]
    fn test_roundtrip_long_message() {
        let plaintext = b"This is a very long test message to test the streaming encryption and decryption. It should be longer than a single chunk to ensure that the chunking logic is working correctly. Let's add more data to make sure it spans multiple chunks. Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        test_streaming_roundtrip(plaintext, None);
    }

    #[test]
    fn test_roundtrip_empty_message() {
        test_streaming_roundtrip(b"", None);
    }

    #[test]
    fn test_roundtrip_exact_chunk_size() {
        let plaintext = vec![42u8; crate::common::DEFAULT_CHUNK_SIZE as usize];
        test_streaming_roundtrip(&plaintext, None);
    }

    #[test]
    fn test_aad_roundtrip() {
        let plaintext = b"streaming data with aad";
        let aad = b"streaming context";
        test_streaming_roundtrip(plaintext, Some(aad));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some important data";

        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, Aes256Gcm>::new(
            &mut encrypted_data,
            key.clone(),
            "test_key_id".to_string(),
            None,
        )
        .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Tamper with the ciphertext body, after the header
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        if encrypted_data.len() > header_len {
            encrypted_data[header_len] ^= 1;
        }

        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let mut decryptor = pending.into_decryptor::<Aes256Gcm>(key, None).unwrap();
        let result = decryptor.read_to_end(&mut Vec::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = Aes256Gcm::generate_key().unwrap();
        let key2 = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some data";

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor =
            Encryptor::<_, Aes256Gcm>::new(&mut encrypted_data, key1, "key1".to_string(), None)
                .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt with the wrong key
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let mut decryptor = pending.into_decryptor::<Aes256Gcm>(key2, None).unwrap();
        let result = decryptor.read_to_end(&mut Vec::new());

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = Aes256Gcm::generate_key().unwrap();
        let plaintext = b"some important data";
        let aad1 = b"correct aad";
        let aad2 = b"wrong aad";

        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, Aes256Gcm>::new(
            &mut encrypted_data,
            key.clone(),
            "test_key_id".to_string(),
            Some(aad1),
        )
        .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt with wrong AAD
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let mut decryptor = pending
            .into_decryptor::<Aes256Gcm>(key.clone(), Some(aad2))
            .unwrap();
        let result = decryptor.read_to_end(&mut Vec::new());
        assert!(result.is_err());

        // Decrypt with no AAD
        let pending2 = PendingDecryptor::from_reader(Cursor::new(encrypted_data)).unwrap();
        let mut decryptor2 = pending2.into_decryptor::<Aes256Gcm>(key, None).unwrap();
        let result2 = decryptor2.read_to_end(&mut Vec::new());
        assert!(result2.is_err());
    }
}
