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
            HeaderPayload::Hybrid { signature, .. } => signature.as_ref().map(|s| s.signer_key_id.as_str()),
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
            HeaderPayload::Hybrid {
                signature, ..
            } => signature.as_ref().map(|s| s.signer_algorithm),
            _ => None,
        }
    }

    /// Returns the signature, if applicable.
    pub fn signature(&self) -> Option<&[u8]> {
        match self {
            HeaderPayload::Hybrid { signature, .. } => signature.as_ref().map(|s| s.signature.as_slice()),
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

            let payload_bytes =
                bincode::encode_to_vec(&temp_payload, bincode::config::standard())?;
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
}
