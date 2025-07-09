//! Implements a parallel streaming symmetric encryption/decryption scheme.
//! This mode is designed for high-performance processing of large files or data streams
//! by overlapping I/O with parallel computation.
//!
//! 实现并行流式对称加解密方案。
//! 此模式通过将 I/O 与并行计算重叠，专为高性能处理大文件或数据流而设计。

use crate::algorithms::traits::SymmetricAlgorithm;
use crate::body::traits::ParallelStreamingBodyProcessor;
use crate::common::header::{Header, HeaderPayload};
use crate::common::PendingImpl;
use crate::error::{Error, FormatError, Result};
use crate::keys::TypedSymmetricKey;
use crate::symmetric::common::create_header;
use crate::symmetric::traits::SymmetricParallelStreamingProcessor;
use std::io::{Read, Write};
use std::sync::Arc;

/// A pending decryptor for a parallel stream, waiting for a key.
pub struct PendingDecryptor<R: Read + Send> {
    reader: R,
    header: Header,
}

impl<'a, R: Read + Send + 'a> PendingDecryptor<R> {
    pub fn from_reader(mut reader: R) -> Result<Self> {
        let header = Header::decode_from_prefixed_reader(&mut reader)?;
        Ok(Self { reader, header })
    }

    pub fn decrypt_to_writer<S, W>(
        self,
        algorithm: Arc<S>,
        key: TypedSymmetricKey,
        writer: W,
        aad: Option<&'a [u8]>,
    ) -> Result<()>
    where
        S: SymmetricAlgorithm + Send + Sync + 'a,
        W: Write + Send + 'a,
    {
        let base_nonce = match &self.header.payload {
            HeaderPayload::Symmetric {
                stream_info: Some(info),
                ..
            } => info.base_nonce,
            _ => return Err(Error::Format(FormatError::InvalidHeader)),
        };
        let processor = algorithm.clone_box();
        processor.decrypt_pipeline(
            key,
            base_nonce,
            Box::new(self.reader),
            Box::new(writer),
            aad,
        )
    }
}

impl<R: Read + Send> PendingImpl for PendingDecryptor<R> {
    fn header(&self) -> &Header {
        &self.header
    }
}

pub struct ParallelStreaming<'a, S: SymmetricAlgorithm> {
    algorithm: Arc<S>,
    _marker: std::marker::PhantomData<&'a S>,
}

impl<'a, S: SymmetricAlgorithm> ParallelStreaming<'a, S> {
    pub fn new(algorithm: Arc<S>) -> Self {
        Self {
            algorithm,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<'a, S: SymmetricAlgorithm + Send + Sync + 'a> SymmetricParallelStreamingProcessor
    for ParallelStreaming<'a, S>
{
    fn encrypt_pipeline<'b>(
        &self,
        key: TypedSymmetricKey,
        key_id: String,
        reader: Box<dyn Read + Send + 'b>,
        mut writer: Box<dyn Write + Send + 'b>,
        aad: Option<&'b [u8]>,
    ) -> Result<()> {
        let (header, base_nonce) = create_header(&*self.algorithm, key_id)?;
        let header_bytes = header.encode_to_vec()?;
        writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&header_bytes)?;
        let processor = self.algorithm.clone_box();
        processor.encrypt_pipeline(key, base_nonce, reader, writer, aad)
    }

    fn decrypt_pipeline<'b>(
        &self,
        key: TypedSymmetricKey,
        reader: Box<dyn Read + Send + 'b>,
        writer: Box<dyn Write + Send + 'b>,
        aad: Option<&'b [u8]>,
    ) -> Result<()> {
        let pending = PendingDecryptor::from_reader(reader)?;
        pending.decrypt_to_writer(self.algorithm.clone(), key, writer, aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::definitions::symmetric::Aes256GcmWrapper;
    use crate::common::DEFAULT_CHUNK_SIZE;
    use crate::keys::TypedSymmetricKey;
    use seal_crypto::prelude::SymmetricKeyGenerator;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
    use std::io::Cursor;

    fn get_wrapper() -> Arc<Aes256GcmWrapper> {
        Arc::new(Aes256GcmWrapper::new())
    }

    fn get_test_data(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 256) as u8).collect()
    }

    #[test]
    fn test_parallel_streaming_roundtrip() {
        let wrapper = get_wrapper();
        let processor = ParallelStreaming::new(wrapper.clone());
        let plaintext = get_test_data(1024 * 1024); // 1 MiB
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let mut encrypted_data = Vec::new();
        processor
            .encrypt_pipeline(
                key.clone(),
                "test_key".to_string(),
                Box::new(Cursor::new(&plaintext)),
                Box::new(&mut encrypted_data),
                None,
            )
            .unwrap();

        let mut decrypted_data = Vec::new();
        processor
            .decrypt_pipeline(
                key.clone(),
                Box::new(Cursor::new(&encrypted_data)),
                Box::new(&mut decrypted_data),
                None,
            )
            .unwrap();

        assert_eq!(plaintext, decrypted_data);
    }

    #[test]
    fn test_processor_roundtrip() {
        let wrapper = get_wrapper();
        let processor = ParallelStreaming::new(wrapper.clone());
        let plaintext = get_test_data(1024 * 512); // 512 KiB
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let aad = Some(b"parallel streaming processor aad" as &[u8]);

        // Encrypt
        let mut encrypted_data = Vec::new();
        processor
            .encrypt_pipeline(
                key.clone(),
                "proc_key".to_string(),
                Box::new(Cursor::new(&plaintext)),
                Box::new(&mut encrypted_data),
                aad,
            )
            .unwrap();

        // Decrypt
        let mut decrypted_data = Vec::new();
        processor
            .decrypt_pipeline(
                key.clone(),
                Box::new(Cursor::new(&encrypted_data)),
                Box::new(&mut decrypted_data),
                aad,
            )
            .unwrap();

        assert_eq!(plaintext, decrypted_data);
    }

    #[test]
    fn test_empty_input() {
        let wrapper = get_wrapper();
        let processor = ParallelStreaming::new(wrapper.clone());
        let plaintext = b"";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let mut encrypted_data = Vec::new();
        processor
            .encrypt_pipeline(
                key.clone(),
                "test_key".to_string(),
                Box::new(Cursor::new(&plaintext)),
                Box::new(&mut encrypted_data),
                None,
            )
            .unwrap();

        let mut decrypted_data = Vec::new();
        processor
            .decrypt_pipeline(
                key.clone(),
                Box::new(Cursor::new(&encrypted_data)),
                Box::new(&mut decrypted_data),
                None,
            )
            .unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[test]
    fn test_exact_chunk_multiple() {
        let wrapper = get_wrapper();
        let processor = ParallelStreaming::new(wrapper.clone());
        let plaintext = get_test_data((DEFAULT_CHUNK_SIZE * 3) as usize);
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let mut encrypted_data = Vec::new();
        processor
            .encrypt_pipeline(
                key.clone(),
                "test_key".to_string(),
                Box::new(Cursor::new(&plaintext)),
                Box::new(&mut encrypted_data),
                None,
            )
            .unwrap();

        let mut decrypted_data = Vec::new();
        processor
            .decrypt_pipeline(
                key.clone(),
                Box::new(Cursor::new(&encrypted_data)),
                Box::new(&mut decrypted_data),
                None,
            )
            .unwrap();

        assert_eq!(plaintext, decrypted_data);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let wrapper = get_wrapper();
        let processor = ParallelStreaming::new(wrapper.clone());
        let plaintext = get_test_data(1024);
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let mut encrypted_data = Vec::new();
        processor
            .encrypt_pipeline(
                key.clone(),
                "test_key".to_string(),
                Box::new(Cursor::new(&plaintext)),
                Box::new(&mut encrypted_data),
                None,
            )
            .unwrap();

        // Tamper
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        encrypted_data[header_len + 10] ^= 1;

        let mut decrypted_data = Vec::new();
        let result = processor.decrypt_pipeline(
            key.clone(),
            Box::new(Cursor::new(&encrypted_data)),
            Box::new(&mut decrypted_data),
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let wrapper = get_wrapper();
        let processor = ParallelStreaming::new(wrapper.clone());
        let plaintext = get_test_data(1024);
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let mut encrypted_data = Vec::new();
        processor
            .encrypt_pipeline(
                key.clone(),
                "key1".to_string(),
                Box::new(Cursor::new(&plaintext)),
                Box::new(&mut encrypted_data),
                None,
            )
            .unwrap();

        let mut decrypted_data = Vec::new();
        let result = processor.decrypt_pipeline(
            key.clone(),
            Box::new(Cursor::new(&encrypted_data)),
            Box::new(&mut decrypted_data),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_aad_roundtrip() {
        let wrapper = get_wrapper();
        let processor = ParallelStreaming::new(wrapper.clone());
        let plaintext = get_test_data(1024 * 256); // 256 KiB
        let aad = b"parallel streaming aad";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let mut encrypted_data = Vec::new();
        processor
            .encrypt_pipeline(
                key.clone(),
                "test_key_aad".to_string(),
                Box::new(Cursor::new(&plaintext)),
                Box::new(&mut encrypted_data),
                Some(aad),
            )
            .unwrap();

        // Decrypt with correct AAD
        let mut decrypted_data = Vec::new();
        processor
            .decrypt_pipeline(
                key.clone(),
                Box::new(Cursor::new(&encrypted_data)),
                Box::new(&mut decrypted_data),
                Some(aad),
            )
            .unwrap();
        assert_eq!(plaintext, decrypted_data);

        // Decrypt with wrong AAD fails
        let mut decrypted_data_fail = Vec::new();
        let result = processor.decrypt_pipeline(
            key.clone(),
            Box::new(Cursor::new(&encrypted_data)),
            Box::new(&mut decrypted_data_fail),
            Some(b"wrong aad"),
        );
        assert!(result.is_err());

        // Decrypt with no AAD fails
        let mut decrypted_data_fail2 = Vec::new();
        let result2 = processor.decrypt_pipeline(
            key.clone(),
            Box::new(Cursor::new(&encrypted_data)),
            Box::new(&mut decrypted_data_fail2),
            None,
        );
        assert!(result2.is_err());
    }
}
