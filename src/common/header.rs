use bincode::{Decode, Encode};
// 这两个枚举也可以考虑放到 seal-crypto 中，以便共享
use crate::common::algorithms::{AsymmetricAlgorithm, SignatureAlgorithm, SymmetricAlgorithm};
use crate::error::{Error, Result};
use std::io::Read;

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncReadExt};

/// 定义加密操作的模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode)]
pub enum SealMode {
    Symmetric,
    Hybrid,
}

/// 流式处理的元数据
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
pub struct StreamInfo {
    pub chunk_size: u32,
    pub base_nonce: [u8; 12],
}

#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
pub struct SingerInfo {
    pub signer_key_id: String,
    pub signer_algorithm: SignatureAlgorithm,
    pub signature: Vec<u8>,
}

/// HeaderPayload 包含了特定于加密模式的元数据
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
pub enum HeaderPayload {
    Symmetric {
        key_id: String, // 用于密钥管理的标识符
        algorithm: SymmetricAlgorithm,
        stream_info: Option<StreamInfo>,
    },
    Hybrid {
        kek_id: String, // 密钥加密密钥的标识符
        kek_algorithm: AsymmetricAlgorithm,
        dek_algorithm: SymmetricAlgorithm,
        encrypted_dek: Vec<u8>,
        stream_info: Option<StreamInfo>, // 混合模式理论上也可以流式处理
        signature: Option<SingerInfo>,
    },
}

impl HeaderPayload {
    /// Returns the key ID if the payload is for symmetric encryption.
    pub fn key_id(&self) -> Option<&str> {
        match self {
            HeaderPayload::Symmetric { key_id, .. } => Some(key_id),
            _ => None,
        }
    }

    /// Returns the Key-Encrypting-Key (KEK) ID if the payload is for hybrid encryption.
    pub fn kek_id(&self) -> Option<&str> {
        match self {
            HeaderPayload::Hybrid { kek_id, .. } => Some(kek_id),
            _ => None,
        }
    }

    /// Returns the signer key ID if the payload is for hybrid encryption.
    pub fn signer_key_id(&self) -> Option<&str> {
        match self {
            HeaderPayload::Hybrid { signature, .. } => {
                signature.as_ref().map(|s| s.signer_key_id.as_str())
            }
            _ => None,
        }
    }

    /// Returns the symmetric algorithm used for data encryption.
    /// In Hybrid mode, this is the Data-Encrypting-Key (DEK) algorithm.
    pub fn symmetric_algorithm(&self) -> SymmetricAlgorithm {
        match self {
            HeaderPayload::Symmetric { algorithm, .. } => *algorithm,
            HeaderPayload::Hybrid { dek_algorithm, .. } => *dek_algorithm,
        }
    }

    /// Returns the asymmetric algorithm used for key encapsulation, if applicable.
    /// This is only present in Hybrid mode.
    pub fn asymmetric_algorithm(&self) -> Option<AsymmetricAlgorithm> {
        match self {
            HeaderPayload::Hybrid { kek_algorithm, .. } => Some(*kek_algorithm),
            _ => None,
        }
    }

    /// Returns the signature algorithm, if applicable.
    pub fn signer_algorithm(&self) -> Option<SignatureAlgorithm> {
        match self {
            HeaderPayload::Hybrid { signature, .. } => {
                signature.as_ref().map(|s| s.signer_algorithm)
            }
            _ => None,
        }
    }

    /// Returns the signature, if applicable.
    pub fn signature(&self) -> Option<&[u8]> {
        match self {
            HeaderPayload::Hybrid { signature, .. } => {
                signature.as_ref().map(|s| s.signature.as_slice())
            }
            _ => None,
        }
    }

    pub(crate) fn get_signed_payload_and_sig(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        if let HeaderPayload::Hybrid { .. } = self {
            let signature = self.signature().ok_or(Error::SignatureMissing)?.to_vec();

            let mut temp_payload = self.clone();
            if let HeaderPayload::Hybrid {
                ref mut signature, ..
            } = temp_payload
            {
                *signature = None;
            }

            let payload_bytes = bincode::encode_to_vec(&temp_payload, bincode::config::standard())?;
            Ok((payload_bytes, signature))
        } else {
            Err(Error::UnsupportedOperation)
        }
    }
}

/// 所有加密数据流的元数据信封
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
pub struct Header {
    pub version: u16,
    pub mode: SealMode,
    pub payload: HeaderPayload,
}

impl Header {
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        static CONFIG: bincode::config::Configuration = bincode::config::standard();
        bincode::encode_to_vec(self, CONFIG).map_err(Error::from)
    }

    pub fn decode_from_slice(data: &[u8]) -> Result<(Self, usize)> {
        static CONFIG: bincode::config::Configuration = bincode::config::standard();
        bincode::decode_from_slice(data, CONFIG).map_err(Error::from)
    }

    /// Decodes a length-prefixed header from a byte slice.
    ///
    /// The format is expected to be `[4-byte length (u32 LE)][bincode-encoded Header]`.
    ///
    /// # Returns
    ///
    /// A tuple containing the parsed `Header` and a slice pointing to the remaining data.
    pub fn decode_from_prefixed_slice(ciphertext: &[u8]) -> Result<(Self, &[u8])> {
        if ciphertext.len() < 4 {
            return Err(Error::InvalidCiphertextFormat);
        }
        let header_len = u32::from_le_bytes(ciphertext[0..4].try_into().unwrap()) as usize;
        if ciphertext.len() < 4 + header_len {
            return Err(Error::InvalidCiphertextFormat);
        }
        let header_bytes = &ciphertext[4..4 + header_len];
        let ciphertext_body = &ciphertext[4 + header_len..];

        let (header, _) = Self::decode_from_slice(header_bytes)?;
        Ok((header, ciphertext_body))
    }

    /// Reads and decodes a length-prefixed header from a synchronous reader.
    pub fn decode_from_prefixed_reader<R: Read>(reader: &mut R) -> Result<Self> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let header_len = u32::from_le_bytes(len_buf) as usize;

        let mut header_bytes = vec![0u8; header_len];
        reader.read_exact(&mut header_bytes)?;
        let (header, _) = Self::decode_from_slice(&header_bytes)?;

        Ok(header)
    }

    /// Reads and decodes a length-prefixed header from an asynchronous reader.
    #[cfg(feature = "async")]
    pub async fn decode_from_prefixed_async_reader<R: AsyncRead + Unpin>(
        reader: &mut R,
    ) -> Result<Self> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let header_len = u32::from_le_bytes(len_buf) as usize;

        let mut header_bytes = vec![0u8; header_len];
        reader.read_exact(&mut header_bytes).await?;
        let (header, _) = Self::decode_from_slice(&header_bytes)?;

        Ok(header)
    }

    /// Verifies the header signature if a verification key is provided.
    pub fn verify(
        &self,
        verification_key: Option<crate::keys::SignaturePublicKey>,
        aad: Option<&[u8]>,
    ) -> Result<()> {
        // 如果没有提供验证密钥，跳过验证
        let verification_key = match verification_key {
            Some(key) => key,
            None => return Ok(()),
        };

        // 如果头部有签名，则进行验证
        if let Some(algo) = self.payload.signer_algorithm() {
            // 获取签名载荷和签名本身
            let (mut payload_bytes, signature) = self.payload.get_signed_payload_and_sig()?;

            // 将 AAD（如果存在）附加到要验证的负载中
            if let Some(aad_data) = aad {
                payload_bytes.extend_from_slice(aad_data);
            }

            use seal_crypto::prelude::*;
            use seal_crypto::schemes::asymmetric::post_quantum::dilithium::{
                Dilithium2, Dilithium3, Dilithium5,
            };
            use seal_crypto::schemes::asymmetric::traditional::ecc::{Ed25519, EcdsaP256};

            // 根据签名算法选择正确的验证方法
            match algo {
                SignatureAlgorithm::Dilithium2 => match verification_key {
                    crate::keys::SignaturePublicKey::Dilithium2(key) => {
                        Dilithium2::verify(&key, &payload_bytes, &Signature(signature))?;
                    }
                    _ => return Err(Error::UnsupportedOperation),
                },
                SignatureAlgorithm::Dilithium3 => match verification_key {
                    crate::keys::SignaturePublicKey::Dilithium3(key) => {
                        Dilithium3::verify(&key, &payload_bytes, &Signature(signature))?;
                    }
                    _ => return Err(Error::UnsupportedOperation),
                },
                SignatureAlgorithm::Dilithium5 => match verification_key {
                    crate::keys::SignaturePublicKey::Dilithium5(key) => {
                        Dilithium5::verify(&key, &payload_bytes, &Signature(signature))?;
                    }
                    _ => return Err(Error::UnsupportedOperation),
                },
                SignatureAlgorithm::Ed25519 => match verification_key {
                    crate::keys::SignaturePublicKey::Ed25519(key) => {
                        Ed25519::verify(&key, &payload_bytes, &Signature(signature))?;
                    }
                    _ => return Err(Error::UnsupportedOperation),
                },
                SignatureAlgorithm::EcdsaP256 => match verification_key {
                    crate::keys::SignaturePublicKey::EcdsaP256(key) => {
                        EcdsaP256::verify(&key, &payload_bytes, &Signature(signature))?;
                    }
                    _ => return Err(Error::UnsupportedOperation),
                },
            }
            Ok(())
        } else {
            // 没有签名，但提供了验证密钥
            Err(Error::SignatureMissing)
        }
    }
}
