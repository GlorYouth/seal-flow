//! Synchronous, streaming hybrid encryption and decryption implementation.
use super::common::create_header;
use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, Result};
use crate::impls::streaming::{DecryptorImpl, EncryptorImpl};
use seal_crypto::prelude::*;
use seal_crypto::zeroize::Zeroizing;
use std::io::{self, Read, Write};

/// An `std::io::Write` adapter for streaming hybrid encryption.
pub struct Encryptor<W: Write, A, S: SymmetricAlgorithm> {
    inner: EncryptorImpl<W, S>,
    _phantom: std::marker::PhantomData<A>,
}

impl<W, A, S> Encryptor<W, A, S>
where
    W: Write,
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    Vec<u8>: From<<A as Kem>::EncapsulatedKey>,
    <S as SymmetricKeySet>::Key: From<Zeroizing<Vec<u8>>>,
    A::EncapsulatedKey: Into<Vec<u8>>,
{
    /// Creates a new streaming encryptor.
    ///
    /// This will perform the KEM encapsulate operation immediately to generate the DEK,
    /// and write the complete header to the underlying writer.
    pub fn new(
        mut writer: W,
        pk: &A::PublicKey,
        kek_id: String,
        aad: Option<&[u8]>,
    ) -> Result<Self> {
        // 1. Create header, nonce, and DEK
        let (header, base_nonce, symmetric_key) = create_header::<A, S>(pk, kek_id)?;

        // 2. Write header length and header to the writer
        let header_bytes = header.encode_to_vec()?;
        writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&header_bytes)?;

        let inner = EncryptorImpl::new(writer, symmetric_key.into(), base_nonce, aad)?;

        Ok(Self {
            inner,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Finalizes the encryption stream.
    ///
    /// This method must be called to ensure that the last partial chunk of data is
    /// encrypted and the authentication tag is written to the underlying writer.
    pub fn finish(self) -> Result<()> {
        self.inner.finish()
    }
}

impl<W: Write, A, S: SymmetricAlgorithm> Write for Encryptor<W, A, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A pending hybrid decryptor that has read the header and is waiting for the private key.
pub struct PendingDecryptor<R: Read> {
    reader: R,
    header: Header,
}

impl<R: Read> PendingDecryptor<R> {
    /// Creates a new `PendingDecryptor` by reading the header from the stream.
    pub fn from_reader(mut reader: R) -> Result<Self> {
        let header = Header::decode_from_prefixed_reader(&mut reader)?;

        Ok(Self { reader, header })
    }

    /// Returns a reference to the header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Consumes the pending decryptor and returns a full `Decryptor` by providing the private key.
    pub fn into_decryptor<A, S>(
        self,
        sk: &A::PrivateKey,
        aad: Option<&[u8]>,
    ) -> Result<Decryptor<R, A, S>>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
        A::PrivateKey: Clone,
        A::EncapsulatedKey: From<Vec<u8>> + Send,
        S::Key: From<Zeroizing<Vec<u8>>>,
    {
        let (encapsulated_key, chunk_size, base_nonce) = match self.header.payload {
            HeaderPayload::Hybrid {
                encrypted_dek,
                stream_info: Some(info),
                ..
            } => (encrypted_dek.into(), info.chunk_size, info.base_nonce),
            _ => return Err(Error::InvalidHeader),
        };

        let shared_secret = A::decapsulate(&sk.clone().into(), &encapsulated_key)?;
        let key_material: S::Key = shared_secret.into();
        let tag_len = S::TAG_SIZE;
        let encrypted_chunk_size = chunk_size as usize + tag_len;

        let inner = DecryptorImpl::new(
            self.reader,
            key_material,
            base_nonce,
            encrypted_chunk_size,
            aad,
        );

        Ok(Decryptor {
            inner,
            _phantom: std::marker::PhantomData,
        })
    }
}

/// Implements `std::io::Read` for synchronous, streaming hybrid decryption.
pub struct Decryptor<R: Read, A: AsymmetricAlgorithm, S: SymmetricAlgorithm> {
    inner: DecryptorImpl<R, S>,
    _phantom: std::marker::PhantomData<(A, S)>,
}

impl<R: Read, A, S> Read for Decryptor<R, A, S>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>>,
    A::PrivateKey: Clone,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::prelude::KeyGenerator;
    use seal_crypto::schemes::asymmetric::traditional::rsa::Rsa2048;
    use seal_crypto::schemes::hash::Sha256;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
    use std::io::Cursor;

    fn test_hybrid_streaming_roundtrip(plaintext: &[u8], aad: Option<&[u8]>) {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let kek_id = "test_kek_id".to_string();

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor =
            Encryptor::<_, Rsa2048, Aes256Gcm>::new(&mut encrypted_data, &pk, kek_id.clone(), aad)
                .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt
        let pending_decryptor =
            PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        assert_eq!(
            pending_decryptor.header().payload.kek_id(),
            Some(kek_id.as_str())
        );

        let mut decryptor = pending_decryptor
            .into_decryptor::<Rsa2048, Aes256Gcm>(&sk, aad)
            .unwrap();
        let mut decrypted_data = Vec::new();
        decryptor.read_to_end(&mut decrypted_data).unwrap();

        assert_eq!(plaintext, decrypted_data.as_slice());
    }

    #[test]
    fn test_roundtrip_long_message() {
        let plaintext = b"This is a very long test message to test the streaming encryption and decryption. It should be longer than a single chunk to ensure that the chunking logic is working correctly. Let's add more data to make sure it spans multiple chunks. Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        test_hybrid_streaming_roundtrip(plaintext, None);
    }

    #[test]
    fn test_roundtrip_empty_message() {
        test_hybrid_streaming_roundtrip(b"", None);
    }

    #[test]
    fn test_roundtrip_exact_chunk_size() {
        let plaintext = vec![42u8; crate::common::header::DEFAULT_CHUNK_SIZE as usize];
        test_hybrid_streaming_roundtrip(&plaintext, None);
    }

    #[test]
    fn test_aad_roundtrip() {
        let plaintext = b"streaming hybrid data with aad";
        let aad = b"streaming hybrid context";
        test_hybrid_streaming_roundtrip(plaintext, Some(aad));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"some important data";

        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, Rsa2048, Aes256Gcm>::new(
            &mut encrypted_data,
            &pk,
            "test_kek_id".to_string(),
            None,
        )
        .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Tamper with the ciphertext body
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        if encrypted_data.len() > header_len {
            encrypted_data[header_len] ^= 1;
        }

        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let mut decryptor = pending
            .into_decryptor::<Rsa2048, Aes256Gcm>(&sk, None)
            .unwrap();

        let result = decryptor.read_to_end(&mut Vec::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let (pk, _) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let (_, sk2) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"some data";

        // Encrypt
        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, Rsa2048, Aes256Gcm>::new(
            &mut encrypted_data,
            &pk,
            "test_kek_id".to_string(),
            None,
        )
        .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt with the wrong key
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let result = pending.into_decryptor::<Rsa2048, Aes256Gcm>(&sk2, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = b"some important data";
        let aad1 = b"correct aad";
        let aad2 = b"wrong aad";

        let mut encrypted_data = Vec::new();
        let mut encryptor = Encryptor::<_, Rsa2048, Aes256Gcm>::new(
            &mut encrypted_data,
            &pk,
            "test_kek_id".to_string(),
            Some(aad1),
        )
        .unwrap();
        encryptor.write_all(plaintext).unwrap();
        encryptor.finish().unwrap();

        // Decrypt with wrong AAD
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();

        let mut decryptor = pending
            .into_decryptor::<Rsa2048, Aes256Gcm>(&sk, Some(aad2))
            .unwrap();
        let result = decryptor.read_to_end(&mut Vec::new());
        assert!(result.is_err());

        // Decrypt with no AAD
        let pending2 = PendingDecryptor::from_reader(Cursor::new(encrypted_data)).unwrap();
        let mut decryptor2 = pending2
            .into_decryptor::<Rsa2048, Aes256Gcm>(&sk, None)
            .unwrap();
        let result2 = decryptor2.read_to_end(&mut Vec::new());
        assert!(result2.is_err());
    }
}
