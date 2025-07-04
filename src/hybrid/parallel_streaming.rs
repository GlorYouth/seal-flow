//! Implements a parallel streaming hybrid encryption/decryption scheme.

use super::common::create_header;
use crate::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::common::header::{Header, HeaderPayload};
use crate::common::{DerivationSet, PendingImpl, SignerSet};
use crate::error::{Error, FormatError, Result};
use crate::impls::parallel_streaming::{decrypt_pipeline, encrypt_pipeline};
use seal_crypto::zeroize::Zeroizing;
use std::io::{Read, Write};

/// Encrypts data from a reader and writes to a writer using a parallel streaming approach.
pub fn encrypt<'a, A, S, R, W>(
    pk: &'a A::PublicKey,
    reader: R,
    mut writer: W,
    kek_id: String,
    signer: Option<SignerSet>,
    aad: Option<&'a [u8]>,
    derivation_config: Option<DerivationSet>,
) -> Result<()>
where
    A: AsymmetricAlgorithm,
    A::EncapsulatedKey: Into<Vec<u8>> + Send,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync,
    R: Read + Send,
    W: Write,
{
    let (info, deriver_fn) = derivation_config
        .map(|d| (d.derivation_info, d.deriver_fn))
        .unzip();

    let (header, base_nonce, shared_secret) = create_header::<A, S>(pk, kek_id, signer, aad, info)?;

    let dek = if let Some(f) = deriver_fn {
        f(&shared_secret)?
    } else {
        shared_secret
    };

    let header_bytes = header.encode_to_vec()?;
    writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
    writer.write_all(&header_bytes)?;

    let key: S::Key = dek.into();
    encrypt_pipeline::<S, R, W>(key, base_nonce, reader, writer, aad)
}

/// A pending decryptor for a parallel hybrid stream, waiting for the private key.
///
/// This state is entered after the header has been successfully read from the
/// stream, allowing the user to inspect the header (e.g., to find the `kek_id`)
/// before supplying the appropriate private key to proceed with decryption.
pub struct PendingDecryptor<R>
where
    R: Read + Send,
{
    reader: R,
    header: Header,
}

impl<R> PendingDecryptor<R>
where
    R: Read + Send,
{
    /// Creates a new `PendingDecryptor` by reading the header from the stream.
    pub fn from_reader(mut reader: R) -> Result<Self> {
        let header = Header::decode_from_prefixed_reader(&mut reader)?;
        Ok(Self { reader, header })
    }

    /// Consumes the pending decryptor, decrypts the stream with the provided private key,
    /// and writes the plaintext to the writer.
    pub fn decrypt_to_writer<A, S, W>(
        self,
        sk: &A::PrivateKey,
        writer: W,
        aad: Option<&[u8]>,
    ) -> Result<()>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
        S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync,
        A::PrivateKey: Clone,
        A::EncapsulatedKey: From<Vec<u8>> + Send,
        W: Write,
    {
        decrypt_body_stream::<A, S, _, W>(sk, &self.header, self.reader, writer, aad)
    }
}

impl<R> PendingImpl for PendingDecryptor<R>
where
    R: Read + Send,
{
    fn header(&self) -> &Header {
        &self.header
    }
}

/// Decrypts a data stream body and writes to a writer using a parallel streaming approach.
pub fn decrypt_body_stream<A, S, R, W>(
    sk: &A::PrivateKey,
    header: &Header,
    reader: R,
    writer: W,
    aad: Option<&[u8]>,
) -> Result<()>
where
    A: AsymmetricAlgorithm,
    S: SymmetricAlgorithm,
    S::Key: From<Zeroizing<Vec<u8>>> + Send + Sync,
    A::PrivateKey: Clone,
    A::EncapsulatedKey: From<Vec<u8>>,
    R: Read + Send,
    W: Write,
{
    let (chunk_size, base_nonce, encapsulated_key, derivation_info) = match &header.payload {
        HeaderPayload::Hybrid {
            stream_info: Some(info),
            encrypted_dek,
            derivation_info,
            ..
        } => (
            info.chunk_size,
            info.base_nonce,
            encrypted_dek.clone().into(),
            derivation_info.clone(),
        ),
        _ => return Err(Error::Format(FormatError::InvalidHeader)),
    };

    let shared_secret = A::decapsulate(&sk.clone().into(), &encapsulated_key)?;

    // Derive key if a deriver function is specified
    let dek = if let Some(info) = derivation_info {
        info.derive_key(&shared_secret)?
    } else {
        shared_secret
    };

    let key_material: S::Key = dek.into();

    decrypt_pipeline::<S, R, W>(key_material, base_nonce, chunk_size, reader, writer, aad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::header::{DerivationInfo, KdfInfo};
    use crate::common::DerivationSet;
    use seal_crypto::prelude::{KeyBasedDerivation, KeyGenerator};
    use seal_crypto::schemes::asymmetric::traditional::rsa::Rsa2048;
    use seal_crypto::schemes::hash::Sha256;
    use seal_crypto::schemes::kdf::hkdf::HkdfSha256;
    use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
    use std::io::Cursor;

    fn get_test_data(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 256) as u8).collect()
    }

    #[test]
    fn test_hybrid_parallel_streaming_roundtrip() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let kek_id = "test-kek-id".to_string();
        let plaintext = get_test_data(1024 * 1024); // 1 MiB

        let mut encrypted_data = Vec::new();
        encrypt::<Rsa2048<Sha256>, Aes256Gcm, _, _>(
            &pk,
            Cursor::new(&plaintext),
            &mut encrypted_data,
            kek_id.clone(),
            None,
            None,
            None,
        )
        .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        assert_eq!(pending.header().payload.kek_id(), Some(kek_id.as_str()));
        pending
            .decrypt_to_writer::<Rsa2048<Sha256>, Aes256Gcm, _>(&sk, &mut decrypted_data, None)
            .unwrap();

        assert_eq!(plaintext, decrypted_data);
    }

    #[test]
    fn test_empty_input() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let kek_id = "test-kek-id".to_string();
        let plaintext = get_test_data(0);

        let mut encrypted_data = Vec::new();
        encrypt::<Rsa2048<Sha256>, Aes256Gcm, _, _>(
            &pk,
            Cursor::new(&plaintext),
            &mut encrypted_data,
            kek_id.clone(),
            None,
            None,
            None,
        )
        .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        assert_eq!(pending.header().payload.kek_id(), Some(kek_id.as_str()));
        pending
            .decrypt_to_writer::<Rsa2048<Sha256>, Aes256Gcm, _>(&sk, &mut decrypted_data, None)
            .unwrap();

        assert_eq!(plaintext, decrypted_data);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let kek_id = "test-kek-id".to_string();
        let plaintext = get_test_data(1024);

        let mut encrypted_data = Vec::new();
        encrypt::<Rsa2048<Sha256>, Aes256Gcm, _, _>(
            &pk,
            Cursor::new(&plaintext),
            &mut encrypted_data,
            kek_id.clone(),
            None,
            None,
            None,
        )
        .unwrap();

        // Tamper
        let header_len = 4 + u32::from_le_bytes(encrypted_data[0..4].try_into().unwrap()) as usize;
        encrypted_data[header_len + 10] ^= 1;

        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let result = pending.decrypt_to_writer::<Rsa2048<Sha256>, Aes256Gcm, _>(
            &sk,
            &mut decrypted_data,
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_private_key_fails() {
        let (pk, _) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let (_, sk2) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let kek_id = "test-kek-id".to_string();
        let plaintext = get_test_data(1024);

        let mut encrypted_data = Vec::new();
        encrypt::<Rsa2048<Sha256>, Aes256Gcm, _, _>(
            &pk,
            Cursor::new(&plaintext),
            &mut encrypted_data,
            kek_id.clone(),
            None,
            None,
            None,
        )
        .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let result = pending.decrypt_to_writer::<Rsa2048<Sha256>, Aes256Gcm, _>(
            &sk2,
            &mut decrypted_data,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_aad_roundtrip() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let plaintext = get_test_data(1024 * 256); // 256 KiB
        let aad = b"parallel streaming aad";

        let mut encrypted_data = Vec::new();
        encrypt::<Rsa2048<Sha256>, Aes256Gcm, _, _>(
            &pk,
            Cursor::new(&plaintext),
            &mut encrypted_data,
            "test_kek_id_aad".to_string(),
            None,
            Some(aad),
            None,
        )
        .unwrap();

        // Decrypt with correct AAD
        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        assert_eq!(pending.header().payload.kek_id(), Some("test_kek_id_aad"));
        pending
            .decrypt_to_writer::<Rsa2048<Sha256>, Aes256Gcm, _>(&sk, &mut decrypted_data, Some(aad))
            .unwrap();
        assert_eq!(plaintext, decrypted_data);

        // Decrypt with wrong AAD fails
        let mut decrypted_data_fail = Vec::new();
        let pending_fail = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let result = pending_fail.decrypt_to_writer::<Rsa2048<Sha256>, Aes256Gcm, _>(
            &sk,
            &mut decrypted_data_fail,
            Some(b"wrong aad"),
        );
        assert!(result.is_err());

        // Decrypt with no AAD fails
        let mut decrypted_data_fail2 = Vec::new();
        let pending_fail2 = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        let result2 = pending_fail2.decrypt_to_writer::<Rsa2048<Sha256>, Aes256Gcm, _>(
            &sk,
            &mut decrypted_data_fail2,
            None,
        );
        assert!(result2.is_err());
    }

    #[test]
    fn test_hybrid_parallel_streaming_roundtrip_with_kdf() {
        let (pk, sk) = Rsa2048::<Sha256>::generate_keypair().unwrap();
        let kek_id = "test-kek-id-kdf".to_string();
        let plaintext = get_test_data(1024 * 1024); // 1 MiB

        let salt = b"salt-parallel-streaming";
        let info = b"info-parallel-streaming";
        let output_len = 32;

        let kdf_info = KdfInfo {
            kdf_algorithm: crate::common::algorithms::KdfAlgorithm::HkdfSha256,
            salt: Some(salt.to_vec()),
            info: Some(info.to_vec()),
            output_len,
        };

        let deriver = HkdfSha256::default();
        let kdf_fn = Box::new(move |ikm: &[u8]| {
            deriver
                .derive(ikm, Some(salt), Some(info), output_len as usize)
                .map(|dk| Zeroizing::new(dk.as_bytes().to_vec()))
                .map_err(|e| e.into())
        });

        let mut encrypted_data = Vec::new();
        encrypt::<Rsa2048<Sha256>, Aes256Gcm, _, _>(
            &pk,
            Cursor::new(&plaintext),
            &mut encrypted_data,
            kek_id.clone(),
            None,
            None,
            Some(DerivationSet {
                derivation_info: DerivationInfo::Kdf(kdf_info),
                deriver_fn: kdf_fn,
            }),
        )
        .unwrap();

        let mut decrypted_data = Vec::new();
        let pending = PendingDecryptor::from_reader(Cursor::new(&encrypted_data)).unwrap();
        assert_eq!(pending.header().payload.kek_id(), Some(kek_id.as_str()));
        pending
            .decrypt_to_writer::<Rsa2048<Sha256>, Aes256Gcm, _>(&sk, &mut decrypted_data, None)
            .unwrap();

        assert_eq!(plaintext, decrypted_data);
    }
}
