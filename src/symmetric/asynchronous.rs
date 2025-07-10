//! Implements an asynchronous streaming symmetric encryption/decryption scheme.
//! This mode is designed for high-performance processing of large files or data streams
//! by overlapping asynchronous I/O with parallel computation.
//!
//! 实现异步流式对称加解密方案。
//! 此模式通过将异步 I/O 与并行计算重叠，专为高性能处理大文件或数据流而设计。

#![cfg(feature = "async")]

use crate::algorithms::traits::SymmetricAlgorithm;
use crate::body::asynchronous::{DecryptorImpl, EncryptorImpl};
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, FormatError, Result};
use crate::keys::TypedSymmetricKey;
use crate::symmetric::common::create_header;
use crate::symmetric::pending::PendingDecryptor;
use crate::symmetric::traits::{
    SymmetricAsynchronousPendingDecryptor, SymmetricAsynchronousProcessor,
};
use async_trait::async_trait;
use pin_project_lite::pin_project;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// --- Encryptor ---

pin_project! {
    /// An asynchronous, streaming symmetric encryptor.
    pub struct Encryptor<W: AsyncWrite> {
        #[pin]
        inner: EncryptorImpl<W>,
    }
}

impl<W: AsyncWrite + Unpin> Encryptor<W> {
    /// Creates a new `Encryptor`.
    pub async fn new<S: SymmetricAlgorithm>(
        mut writer: W,
        algorithm: &S,
        key: TypedSymmetricKey,
        key_id: String,
        aad: Option<&[u8]>,
    ) -> Result<Self> {
        let (header, base_nonce) = create_header(algorithm, key_id)?;

        let header_bytes = header.encode_to_vec()?;
        use tokio::io::AsyncWriteExt;
        writer
            .write_all(&(header_bytes.len() as u32).to_le_bytes())
            .await?;
        writer.write_all(&header_bytes).await?;

        let inner = EncryptorImpl::new(
            writer,
            key.into(),
            algorithm.clone_box_symmetric().into(),
            base_nonce,
            aad,
        );

        Ok(Self { inner })
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Encryptor<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

#[async_trait]
impl<'decr, S> SymmetricAsynchronousPendingDecryptor<'decr>
    for PendingDecryptor<Box<dyn AsyncRead + Unpin + Send + 'decr>, &'decr S>
where
    S: SymmetricAlgorithm + Send + Sync + 'decr,
{
    async fn into_decryptor<'a>(
        self: Box<Self>,
        key: TypedSymmetricKey,
        aad: Option<&'a [u8]>,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin + 'decr>> {
        let base_nonce = match self.header.payload {
            HeaderPayload::Symmetric {
                stream_info: Some(info),
                ..
            } => info.base_nonce,
            _ => return Err(Error::Format(FormatError::InvalidHeader)),
        };

        let inner = DecryptorImpl::new(
            self.source,
            key.into(),
            self.algorithm.clone_box_symmetric().into(),
            base_nonce,
            aad,
        );
        Ok(Box::new(Decryptor { inner }))
    }

    fn header(&self) -> &Header {
        &self.header
    }
}

pin_project! {
    /// An asynchronous, streaming symmetric decryptor.
    pub struct Decryptor<R: AsyncRead> {
        #[pin]
        inner: DecryptorImpl<R>,
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Decryptor<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

pub struct Asynchronous<'s, S: SymmetricAlgorithm> {
    algorithm: &'s S,
}

impl<'s, S: SymmetricAlgorithm> Asynchronous<'s, S> {
    pub fn new(algorithm: &'s S) -> Self {
        Self { algorithm }
    }
}

#[async_trait]
impl<'s, S: SymmetricAlgorithm + Send + Sync> SymmetricAsynchronousProcessor
    for Asynchronous<'s, S>
{
    async fn encrypt_symmetric_async<'b>(
        &self,
        key: TypedSymmetricKey,
        key_id: String,
        writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'b>,
        aad: Option<&'b [u8]>,
    ) -> Result<Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'b>> {
        let encryptor = Encryptor::new(writer, self.algorithm, key, key_id, aad).await?;
        Ok(Box::new(encryptor))
    }

    async fn begin_decrypt_symmetric_async<'a, 'p>(
        &'p self,
        mut reader: Box<dyn tokio::io::AsyncRead + Send + Unpin + 'a>,
    ) -> Result<Box<dyn SymmetricAsynchronousPendingDecryptor<'a> + Send + 'a>>
    where
        's: 'p,
        'p: 'a,
    {
        let header = Header::decode_from_prefixed_async_reader(&mut reader).await?;
        let pending = PendingDecryptor {
            source: reader,
            header,
            algorithm: self.algorithm,
        };
        Ok(Box::new(pending))
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn get_wrapper() -> Aes256GcmWrapper {
        Aes256GcmWrapper::new()
    }

    async fn test_roundtrip(plaintext: &[u8], aad: Option<&[u8]>) {
        let wrapper = get_wrapper();
        let processor = Asynchronous::new(&wrapper);
        let key_id = "test_key_id".to_string();
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        // Encrypt
        let mut encrypted_data = Vec::new();
        {
            let mut encryptor = processor
                .encrypt_symmetric_async(
                    key.clone(),
                    key_id.clone(),
                    Box::new(&mut encrypted_data),
                    aad,
                )
                .await
                .unwrap();
            encryptor.write_all(plaintext).await.unwrap();
            encryptor.shutdown().await.unwrap();
        }

        // Decrypt
        let mut decryptor = processor
            .begin_decrypt_symmetric_async(Box::new(Cursor::new(encrypted_data)))
            .await
            .unwrap()
            .into_decryptor(key.clone(), aad)
            .await
            .unwrap();
        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).await.unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[tokio::test]
    async fn test_processor_roundtrip_async() {
        let wrapper = get_wrapper();
        let processor = Asynchronous::new(&wrapper);
        let plaintext = b"This is an async processor test.";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let aad = Some(b"async processor aad" as &[u8]);

        // Encrypt
        let mut encrypted_data = Vec::new();
        {
            let mut encrypt_stream = processor
                .encrypt_symmetric_async(
                    key.clone(),
                    "proc_key".to_string(),
                    Box::new(&mut encrypted_data),
                    aad,
                )
                .await
                .unwrap();
            encrypt_stream.write_all(plaintext).await.unwrap();
            encrypt_stream.shutdown().await.unwrap();
        }

        // Decrypt
        let mut decrypt_stream = processor
            .begin_decrypt_symmetric_async(Box::new(Cursor::new(&encrypted_data)))
            .await
            .unwrap()
            .into_decryptor(key.clone(), aad)
            .await
            .unwrap();
        let mut decrypted_data = Vec::new();
        decrypt_stream
            .read_to_end(&mut decrypted_data)
            .await
            .unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[tokio::test]
    async fn test_roundtrip_long_message_async() {
        let plaintext = b"This is a very long test message to test the async streaming encryption and decryption. It should be longer than a single chunk to ensure that the chunking logic is working correctly. Let's add more data to make sure it spans multiple chunks. Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        test_roundtrip(plaintext, None).await;
    }

    #[tokio::test]
    async fn test_roundtrip_empty_message_async() {
        test_roundtrip(b"", None).await;
    }

    #[tokio::test]
    async fn test_roundtrip_exact_chunk_size_async() {
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];
        test_roundtrip(&plaintext, None).await;
    }

    #[tokio::test]
    async fn test_aad_roundtrip_async() {
        let plaintext = b"secret async message";
        let aad = b"public async context";
        test_roundtrip(plaintext, Some(aad)).await;
    }

    #[tokio::test]
    async fn test_tampered_ciphertext_fails_async() {
        let wrapper = get_wrapper();
        let processor = Asynchronous::new(&wrapper);
        let plaintext = b"some important data";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let mut encrypted_data = Vec::new();
        {
            let mut encryptor = processor
                .encrypt_symmetric_async(
                    key.clone(),
                    "test_key_id".to_string(),
                    Box::new(&mut encrypted_data),
                    None,
                )
                .await
                .unwrap();
            encryptor.write_all(plaintext).await.unwrap();
            encryptor.shutdown().await.unwrap();
        }

        // Tamper with the ciphertext body, after the header
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        if encrypted_data.len() > header_len {
            encrypted_data[header_len] ^= 1;
        }

        let mut decryptor = processor
            .begin_decrypt_symmetric_async(Box::new(Cursor::new(&encrypted_data)))
            .await
            .unwrap()
            .into_decryptor(key.clone(), None)
            .await
            .unwrap();
        let result = decryptor.read_to_end(&mut Vec::new()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_wrong_key_fails_async() {
        let wrapper = get_wrapper();
        let processor = Asynchronous::new(&wrapper);
        let plaintext = b"some data";
        let key1 = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        let key2 = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());

        // Encrypt
        let mut encrypted_data = Vec::new();
        {
            let mut encryptor = processor
                .encrypt_symmetric_async(
                    key1,
                    "key1".to_string(),
                    Box::new(&mut encrypted_data),
                    None,
                )
                .await
                .unwrap();
            encryptor.write_all(plaintext).await.unwrap();
            encryptor.shutdown().await.unwrap();
        }

        // Decrypt with the wrong key
        let mut decryptor = processor
            .begin_decrypt_symmetric_async(Box::new(Cursor::new(&encrypted_data)))
            .await
            .unwrap()
            .into_decryptor(key2, None)
            .await
            .unwrap();
        let result = decryptor.read_to_end(&mut Vec::new()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_wrong_aad_fails_async() {
        let wrapper = get_wrapper();
        let processor = Asynchronous::new(&wrapper);
        let plaintext = b"some data";
        let aad1 = b"correct async aad";
        let aad2 = b"wrong async aad";
        let key = TypedSymmetricKey::Aes256Gcm(Aes256Gcm::generate_key().unwrap());
        // Encrypt
        let mut encrypted_data = Vec::new();
        {
            let mut encryptor = processor
                .encrypt_symmetric_async(
                    key.clone(),
                    "key1".to_string(),
                    Box::new(&mut encrypted_data),
                    Some(aad1),
                )
                .await
                .unwrap();
            encryptor.write_all(plaintext).await.unwrap();
            encryptor.shutdown().await.unwrap();
        }

        // Decrypt with the wrong aad
        {
            let mut decryptor = processor
                .begin_decrypt_symmetric_async(Box::new(Cursor::new(&encrypted_data)))
                .await
                .unwrap()
                .into_decryptor(key.clone(), Some(aad2))
                .await
                .unwrap();
            let result = decryptor.read_to_end(&mut Vec::new()).await;
            assert!(result.is_err());
        }

        // Decrypt with no aad
        {
            let mut decryptor = processor
                .begin_decrypt_symmetric_async(Box::new(Cursor::new(&encrypted_data)))
                .await
                .unwrap()
                .into_decryptor(key, None)
                .await
                .unwrap();
            let result = decryptor.read_to_end(&mut Vec::new()).await;
            assert!(result.is_err());
        }
    }
}
