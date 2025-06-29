//! Asynchronous, streaming hybrid encryption and decryption implementation.
#![cfg(feature = "async")]

use super::common::create_header;
use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::SignerSet;
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, Result};
use crate::impls::asynchronous::{DecryptorImpl, EncryptorImpl};
use pin_project_lite::pin_project;
use seal_crypto::zeroize::Zeroizing;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

// --- Encryptor ---

pin_project! {
    /// An asynchronous, streaming hybrid encryptor.
    pub struct Encryptor<W: AsyncWrite, A, S: SymmetricAlgorithm> {
        #[pin]
        inner: EncryptorImpl<W, S>,
        _phantom: std::marker::PhantomData<A>,
    }
}

impl<W: AsyncWrite + Unpin, A, S> Encryptor<W, A, S>
where
    A: AsymmetricAlgorithm + 'static,
    A::PublicKey: Send,
    A::EncapsulatedKey: Into<Vec<u8>> + Send,
    S: SymmetricAlgorithm + 'static,
    S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync + 'static,
{
    /// Creates a new `Encryptor`.
    pub async fn new(
        mut writer: W,
        pk: A::PublicKey,
        kek_id: String,
        signer: Option<SignerSet>,
        aad: Option<&[u8]>,
    ) -> Result<Self> {
        let (header, base_nonce, shared_secret) =
            tokio::task::spawn_blocking(move || create_header::<A, S>(&pk.into(), kek_id, signer))
                .await??;

        let header_bytes = header.encode_to_vec()?;
        use tokio::io::AsyncWriteExt;
        writer
            .write_all(&(header_bytes.len() as u32).to_le_bytes())
            .await?;
        writer.write_all(&header_bytes).await?;

        let inner = EncryptorImpl::new(writer, shared_secret.into(), base_nonce, aad);

        Ok(Self {
            inner,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<W: AsyncWrite + Unpin, A, S> AsyncWrite for Encryptor<W, A, S>
where
    A: AsymmetricAlgorithm + 'static,
    A::PublicKey: Send,
    A::EncapsulatedKey: Into<Vec<u8>> + Send,
    S: SymmetricAlgorithm + 'static,
    S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync + 'static,
{
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

// --- Decryptor ---

/// An asynchronous pending hybrid decryptor, waiting for the private key.
pub struct PendingDecryptor<R: AsyncRead + Unpin> {
    reader: R,
    header: Header,
}

impl<R: AsyncRead + Unpin> PendingDecryptor<R> {
    /// Creates a new `PendingDecryptor` by asynchronously reading the header.
    pub async fn from_reader(mut reader: R) -> Result<Self> {
        let header = Header::decode_from_prefixed_async_reader(&mut reader).await?;
        Ok(Self { reader, header })
    }

    /// Returns a reference to the header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Consumes the `PendingDecryptor` and returns a full `Decryptor`.
    pub async fn into_decryptor<A, S>(
        self,
        sk: A::PrivateKey,
        aad: Option<&[u8]>,
    ) -> Result<Decryptor<R, A, S>>
    where
        A: AsymmetricAlgorithm + 'static,
        A::PrivateKey: Send,
        A::EncapsulatedKey: From<Vec<u8>> + Send,
        S: SymmetricAlgorithm + 'static,
        S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync + 'static,
    {
        let (encapsulated_key, chunk_size, base_nonce) = match self.header.payload {
            HeaderPayload::Hybrid {
                encrypted_dek,
                stream_info: Some(info),
                ..
            } => (encrypted_dek.into(), info.chunk_size, info.base_nonce),
            _ => return Err(Error::InvalidHeader),
        };

        let shared_secret =
            tokio::task::spawn_blocking(move || A::decapsulate(&sk.into(), &encapsulated_key))
                .await??;

        let tag_len = S::TAG_SIZE;
        let encrypted_chunk_size = chunk_size as usize + tag_len;
        let decrypted_chunk_size = chunk_size as usize;

        let inner = DecryptorImpl::new(
            self.reader,
            shared_secret.into(),
            base_nonce,
            encrypted_chunk_size,
            decrypted_chunk_size,
            aad,
        );

        Ok(Decryptor {
            inner,
            _phantom: std::marker::PhantomData,
        })
    }
}

pin_project! {
    /// An asynchronous, streaming hybrid decryptor.
    pub struct Decryptor<R: AsyncRead, A, S: SymmetricAlgorithm> {
        #[pin]
        inner: DecryptorImpl<R, S>,
        _phantom: std::marker::PhantomData<(A, S)>,
    }
}

impl<R: AsyncRead + Unpin, A, S> AsyncRead for Decryptor<R, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm + 'static,
    S::Key: Send + Sync + 'static,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::DEFAULT_CHUNK_SIZE;
    use seal_crypto::prelude::KeyGenerator;
    use seal_crypto::schemes::asymmetric::traditional::rsa::Rsa2048;
    use seal_crypto::schemes::hash::Sha256;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
    use std::io::Cursor;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn test_hybrid_async_streaming_roundtrip(plaintext: &[u8], aad: Option<&[u8]>) {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let kek_id = "test-rsa-key".to_string();

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, Rsa2048<Sha256>, Aes256Gcm>::new(
            &mut encrypted_data,
            pk,
            kek_id.clone(),
            None,
            aad,
        )
        .await
        .unwrap();
        encryptor.write_all(plaintext).await.unwrap();
        encryptor.shutdown().await.unwrap();

        // Decrypt
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data))
            .await
            .unwrap();
        assert_eq!(pending.header().payload.kek_id(), Some(kek_id.as_str()));

        let mut decryptor = pending
            .into_decryptor::<Rsa2048<Sha256>, Aes256Gcm>(sk, aad)
            .await
            .unwrap();
        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).await.unwrap();
        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[tokio::test]
    async fn test_roundtrip_long_message_async() {
        let plaintext = b"This is a very long test message to test the async hybrid streaming encryption and decryption. It needs to be longer than a single chunk to ensure the chunking logic is working correctly.";
        test_hybrid_async_streaming_roundtrip(plaintext, None).await;
    }

    #[tokio::test]
    async fn test_roundtrip_empty_message_async() {
        test_hybrid_async_streaming_roundtrip(b"", None).await;
    }

    #[tokio::test]
    async fn test_roundtrip_exact_chunk_size_async() {
        let plaintext = vec![42u8; DEFAULT_CHUNK_SIZE as usize];
        test_hybrid_async_streaming_roundtrip(&plaintext, None).await;
    }

    #[tokio::test]
    async fn test_aad_roundtrip_async() {
        let plaintext = b"secret async hybrid message";
        let aad = b"public async hybrid context";
        test_hybrid_async_streaming_roundtrip(plaintext, Some(aad)).await;
    }

    #[tokio::test]
    async fn test_tampered_ciphertext_fails_async() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"some important data";

        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, Rsa2048<Sha256>, Aes256Gcm>::new(
            &mut encrypted_data,
            pk,
            "test-kek-id".to_string(),
            None,
            None,
        )
        .await
        .unwrap();
        encryptor.write_all(plaintext).await.unwrap();
        encryptor.shutdown().await.unwrap();

        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        if encrypted_data.len() > header_len {
            encrypted_data[header_len] ^= 1;
        }

        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data))
            .await
            .unwrap();
        let mut decryptor = pending
            .into_decryptor::<Rsa2048<Sha256>, Aes256Gcm>(sk, None)
            .await
            .unwrap();
        let result = decryptor.read_to_end(&mut Vec::new()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_wrong_private_key_fails_async() {
        let (pk, _) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let (_, sk2) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"some data";

        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, Rsa2048<Sha256>, Aes256Gcm>::new(
            &mut encrypted_data,
            pk,
            "test_kek_id".to_string(),
            None,
            None,
        )
        .await
        .unwrap();
        encryptor.write_all(plaintext).await.unwrap();
        encryptor.shutdown().await.unwrap();

        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data))
            .await
            .unwrap();

        let decryptor_result = pending
            .into_decryptor::<Rsa2048<Sha256>, Aes256Gcm>(sk2, None)
            .await;

        if let Ok(mut decryptor) = decryptor_result {
            let read_result = decryptor.read_to_end(&mut Vec::new()).await;
            assert!(
                read_result.is_err(),
                "Decryption should fail with wrong private key"
            );
        } else {
            assert!(
                decryptor_result.is_err(),
                "Decapsulation should fail with wrong private key"
            );
        }
    }

    #[tokio::test]
    async fn test_wrong_aad_fails_async() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"some data";
        let aad1 = b"correct async aad";
        let aad2 = b"wrong async aad";

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, Rsa2048<Sha256>, Aes256Gcm>::new(
            &mut encrypted_data,
            pk,
            "key1".to_string(),
            None,
            Some(aad1),
        )
        .await
        .unwrap();
        encryptor.write_all(plaintext).await.unwrap();
        encryptor.shutdown().await.unwrap();

        // Decrypt with the wrong aad
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data))
            .await
            .unwrap();
        let mut decryptor = pending
            .into_decryptor::<Rsa2048<Sha256>, Aes256Gcm>(sk.clone(), Some(aad2))
            .await
            .unwrap();
        let result = decryptor.read_to_end(&mut Vec::new()).await;
        assert!(result.is_err());

        // Decrypt with no aad
        let pending2 = PendingDecryptor::from_reader(Cursor::new(encrypted_data))
            .await
            .unwrap();
        let mut decryptor2 = pending2
            .into_decryptor::<Rsa2048<Sha256>, Aes256Gcm>(sk, None)
            .await
            .unwrap();
        let result2 = decryptor2.read_to_end(&mut Vec::new()).await;
        assert!(result2.is_err());
    }
}
