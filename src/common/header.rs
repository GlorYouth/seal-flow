use bincode::{Decode, Encode};

// These enums could also be considered for placement in seal-crypto for sharing.
// 这两个枚举也可以考虑放到 seal-crypto 中，以便共享。
use crate::common::algorithms::{
    AsymmetricAlgorithm, KdfKeyAlgorithm, SignatureAlgorithm, SymmetricAlgorithm, XofAlgorithm,
};
use crate::error::{CryptoError, Error, FormatError, Result};
use crate::keys::TypedSignaturePublicKey;
use std::io::Read;

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncReadExt};

/// Information about the signer.
///
/// 签名者信息。
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
pub struct SignerInfo {
    /// The ID of the signer's key.
    ///
    /// 签名者密钥的 ID。
    pub signer_key_id: String,
    /// The signature algorithm used.
    ///
    /// 使用的签名算法。
    pub signer_algorithm: SignatureAlgorithm,
    /// The digital signature.
    ///
    /// 数字签名。
    pub signature: Vec<u8>,
}

/// KDF (Key-based Derivation Function) configuration information.
///
/// KDF (基于密钥的派生函数) 配置信息。
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
pub struct KdfInfo {
    /// The KDF algorithm.
    ///
    /// KDF 算法。
    pub kdf_algorithm: KdfKeyAlgorithm,
    /// The salt for the KDF.
    ///
    /// 用于 KDF 的盐。
    pub salt: Option<Vec<u8>>,
    /// Context and application-specific information for the KDF.
    ///
    /// 用于 KDF 的上下文和特定于应用程序的信息。
    pub info: Option<Vec<u8>>,
}

/// XOF (Extendable-Output Function) configuration information.
///
/// XOF (可扩展输出函数) 配置信息。
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
pub struct XofInfo {
    /// The XOF algorithm.
    ///
    /// XOF 算法。
    pub xof_algorithm: XofAlgorithm,
    /// The salt for the XOF.
    ///
    /// 用于 XOF 的盐。
    pub salt: Option<Vec<u8>>,
    /// Context and application-specific information for the XOF.
    ///
    /// 用于 XOF 的上下文和特定于应用程序的信息。
    pub info: Option<Vec<u8>>,
}

/// Information about the key derivation method used.
///
/// 有关所用密钥派生方法的信息。
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
pub enum DerivationInfo {
    /// Uses a standard Key-based Derivation Function (KDF).
    ///
    /// 使用标准的基于密钥的派生函数 (KDF)。
    Kdf(KdfInfo),
    /// Uses an Extendable-Output Function (XOF).
    ///
    /// 使用可扩展输出函数 (XOF)。
    Xof(XofInfo),
}

/// Specific header payload for different encryption modes.
///
/// 不同加密模式的具体头部有效载荷。
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
pub enum SpecificHeaderPayload {
    /// Payload for symmetric encryption.
    ///
    /// 对称加密的有效载荷。
    Symmetric {
        /// Identifier for key management.
        ///
        /// 用于密钥管理的标识符。
        key_id: String,
        /// The symmetric algorithm used.
        ///
        /// 使用的对称算法。
        algorithm: SymmetricAlgorithm,
    },
    /// Payload for hybrid encryption.
    ///
    /// 混合加密的有效载荷。
    Hybrid {
        /// Identifier for the Key-Encrypting-Key (KEK).
        ///
        /// 密钥加密密钥 (KEK) 的标识符。
        kek_id: String,
        /// The asymmetric algorithm for the KEK.
        ///
        /// 用于 KEK 的非对称算法。
        kek_algorithm: AsymmetricAlgorithm,
        /// The symmetric algorithm for the Data-Encrypting-Key (DEK).
        ///
        /// 用于数据加密密钥 (DEK) 的对称算法。
        dek_algorithm: SymmetricAlgorithm,
        /// The encrypted Data-Encrypting-Key (DEK).
        ///
        /// 加密的数据加密密钥 (DEK)。
        encrypted_dek: Vec<u8>,
        /// Signature information, if the header is signed.
        ///
        /// 签名信息，如果头部已签名。
        signature: Option<SignerInfo>,
        /// Key derivation information, if used.
        ///
        /// 密钥派生信息（如果使用）。
        derivation_info: Option<DerivationInfo>,
    },
}

/// Header payload for different encryption modes.
///
/// 不同加密模式的头有效载荷。
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
pub struct HeaderPayload {
    /// The chunk size for the symmetric algorithm.
    ///
    /// 对称算法的分块大小。
    pub chunk_size: u32,
    /// The base nonce for stream encryption.
    ///
    /// 流加密的基础 nonce。
    pub base_nonce: [u8; 12],
    /// The specific payload for the encryption mode.
    ///
    /// 特定于加密模式的有效载荷。
    pub specific_payload: SpecificHeaderPayload,
}

impl HeaderPayload {
    /// Returns the key ID if the payload is for symmetric encryption.
    ///
    /// 如果有效载荷用于对称加密，则返回密钥 ID。
    pub fn key_id(&self) -> Option<&str> {
        match &self.specific_payload {
            SpecificHeaderPayload::Symmetric { key_id, .. } => Some(key_id),
            _ => None,
        }
    }

    /// Returns the Key-Encrypting-Key (KEK) ID if the payload is for hybrid encryption.
    ///
    /// 如果有效载荷用于混合加密，则返回密钥加密密钥 (KEK) 的 ID。
    pub fn kek_id(&self) -> Option<&str> {
        match &self.specific_payload {
            SpecificHeaderPayload::Hybrid { kek_id, .. } => Some(kek_id),
            _ => None,
        }
    }

    /// Returns the signer key ID if the payload is for hybrid encryption.
    ///
    /// 如果有效载荷用于混合加密，则返回签名者密钥 ID。
    pub fn signer_key_id(&self) -> Option<&str> {
        match &self.specific_payload {
            SpecificHeaderPayload::Hybrid { signature, .. } => {
                signature.as_ref().map(|s| s.signer_key_id.as_str())
            }
            _ => None,
        }
    }

    /// Returns the symmetric algorithm used for data encryption.
    /// In Hybrid mode, this is the Data-Encrypting-Key (DEK) algorithm.
    ///
    /// 返回用于数据加密的对称算法。
    /// 在混合模式下，这是数据加密密钥 (DEK) 的算法。
    pub fn symmetric_algorithm(&self) -> SymmetricAlgorithm {
        match &self.specific_payload {
            SpecificHeaderPayload::Symmetric { algorithm, .. } => *algorithm,
            SpecificHeaderPayload::Hybrid { dek_algorithm, .. } => *dek_algorithm,
        }
    }

    /// Returns the asymmetric algorithm used for key encapsulation, if applicable.
    /// This is only present in Hybrid mode.
    ///
    /// 如果适用，返回用于密钥封装的非对称算法。
    /// 这仅存在于混合模式中。
    pub fn asymmetric_algorithm(&self) -> Option<AsymmetricAlgorithm> {
        match &self.specific_payload {
            SpecificHeaderPayload::Hybrid { kek_algorithm, .. } => Some(*kek_algorithm),
            _ => None,
        }
    }

    /// Returns the signature algorithm, if applicable.
    ///
    /// 如果适用，返回签名算法。
    pub fn signer_algorithm(&self) -> Option<SignatureAlgorithm> {
        match &self.specific_payload {
            SpecificHeaderPayload::Hybrid { signature, .. } => {
                signature.as_ref().map(|s| s.signer_algorithm)
            }
            _ => None,
        }
    }

    /// Returns the signature, if applicable.
    ///
    /// 如果适用，返回签名。
    pub fn signature(&self) -> Option<&[u8]> {
        match &self.specific_payload {
            SpecificHeaderPayload::Hybrid { signature, .. } => {
                signature.as_ref().map(|s| s.signature.as_slice())
            }
            _ => None,
        }
    }

    /// Gets the payload to be signed and the signature itself.
    ///
    /// 获取要签名的有效载荷和签名本身。
    pub(crate) fn get_signed_payload_and_sig(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        if let SpecificHeaderPayload::Hybrid { .. } = &self.specific_payload {
            let signature = self
                .signature()
                .ok_or(CryptoError::MissingSignature)?
                .to_vec();

            let mut temp_payload = self.clone();
            if let SpecificHeaderPayload::Hybrid {
                ref mut signature, ..
            } = &mut temp_payload.specific_payload
            {
                *signature = None;
            }

            let payload_bytes = bincode::encode_to_vec(&temp_payload, bincode::config::standard())?;
            Ok((payload_bytes, signature))
        } else {
            Err(CryptoError::UnsupportedOperation.into())
        }
    }
}

/// The metadata envelope for all encrypted data streams.
///
/// 所有加密数据流的元数据信封。
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
pub struct Header {
    /// The version of the header format.
    ///
    /// 标头格式的版本。
    pub version: u16,
    /// The payload containing mode-specific metadata.
    ///
    /// 包含特定于模式的元数据的有效载荷。
    pub payload: HeaderPayload,
}

impl Header {
    /// Encodes the header into a byte vector.
    ///
    /// 将标头编码为字节向量。
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        static CONFIG: bincode::config::Configuration = bincode::config::standard();
        bincode::encode_to_vec(self, CONFIG).map_err(Error::from)
    }

    /// Decodes a header from a byte slice.
    ///
    /// 从字节切片解码标头。
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
    ///
    /// 从带有长度前缀的字节切片解码标头。
    ///
    /// 预期的格式是 `[4字节长度(u32 LE)][bincode编码的Header]`。
    ///
    /// # 返回
    ///
    /// 一个元组，包含解析后的 `Header` 和指向剩余数据的切片。
    pub fn decode_from_prefixed_slice(ciphertext: &[u8]) -> Result<(Self, &[u8])> {
        if ciphertext.len() < 4 {
            return Err(FormatError::InvalidCiphertext.into());
        }
        let header_len = u32::from_le_bytes(ciphertext[0..4].try_into().unwrap()) as usize;
        if ciphertext.len() < 4 + header_len {
            return Err(FormatError::InvalidCiphertext.into());
        }
        let header_bytes = &ciphertext[4..4 + header_len];
        let ciphertext_body = &ciphertext[4 + header_len..];

        let (header, _) = Self::decode_from_slice(header_bytes)?;
        Ok((header, ciphertext_body))
    }

    /// Reads and decodes a length-prefixed header from a synchronous reader.
    ///
    /// 从同步读取器中读取并解码带有长度前缀的标头。
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
    ///
    /// 从异步读取器中读取并解码带有长度前缀的标头。
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
    ///
    /// 如果提供了验证密钥，则验证标头签名。
    pub fn verify(
        &self,
        verification_key: Option<&TypedSignaturePublicKey>,
        aad: Option<&[u8]>,
    ) -> Result<()> {
        // If no verification key is provided, skip verification.
        // 如果没有提供验证密钥，跳过验证。
        let verification_key = match verification_key {
            Some(key) => key,
            None => return Ok(()),
        };

        // If the header has a signature, verify it.
        // 如果头部有签名，则进行验证。
        if let Some(algo) = self.payload.signer_algorithm() {
            // Get the payload to be signed and the signature itself.
            // 获取签名载荷和签名本身。
            let (mut payload_bytes, signature) = self.payload.get_signed_payload_and_sig()?;

            // Append AAD (if it exists) to the payload to be verified.
            // 将 AAD（如果存在）附加到要验证的负载中。
            if let Some(aad_data) = aad {
                payload_bytes.extend_from_slice(aad_data);
            }

            let key_algo = verification_key.algorithm();
            if algo == key_algo {
                use crate::algorithms::traits::SignatureAlgorithm;

                key_algo.into_signature_wrapper().verify(&payload_bytes, verification_key, signature)?;
            } else {
                return Err(Error::Format(FormatError::InvalidKeyType));
            }
            
            Ok(())
        } else {
            // No signature, but a verification key was provided.
            // 没有签名，但提供了验证密钥。
            Err(CryptoError::MissingSignature.into())
        }
    }
}
