use bincode::{Decode, Encode};
use seal_crypto::zeroize::Zeroizing;
// These enums could also be considered for placement in seal-crypto for sharing.
// 这两个枚举也可以考虑放到 seal-crypto 中，以便共享。
use crate::common::algorithms::{
    AsymmetricAlgorithm, KdfAlgorithm, SignatureAlgorithm, SymmetricAlgorithm, XofAlgorithm,
};
use crate::error::{CryptoError, Error, FormatError, Result};
use std::io::Read;

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncReadExt};

/// Defines the mode of the encryption operation.
///
/// 定义加密操作的模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode)]
pub enum SealMode {
    /// Symmetric encryption mode.
    ///
    /// 对称加密模式。
    Symmetric,
    /// Hybrid encryption mode.
    ///
    /// 混合加密模式。
    Hybrid,
}

/// Metadata for streaming processing.
///
/// 流式处理的元数据。
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
pub struct StreamInfo {
    /// The size of each chunk.
    ///
    /// 每个数据块的大小。
    pub chunk_size: u32,
    /// The base nonce for stream encryption.
    ///
    /// 流加密的基础 nonce。
    pub base_nonce: [u8; 12],
}

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
    pub kdf_algorithm: KdfAlgorithm,
    /// The salt for the KDF.
    ///
    /// 用于 KDF 的盐。
    pub salt: Option<Vec<u8>>,
    /// Context and application-specific information for the KDF.
    ///
    /// 用于 KDF 的上下文和特定于应用程序的信息。
    pub info: Option<Vec<u8>>,
    /// The desired length of the derived key.
    ///
    /// 派生密钥的期望长度。
    pub output_len: u32,
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
    /// The desired length of the derived output.
    ///
    /// 派生输出的期望长度。
    pub output_len: u32,
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

impl DerivationInfo {
    /// Derives a key from the shared secret using the specified method.
    ///
    /// 使用指定的方法从共享秘密派生密钥。
    pub fn derive_key(
        &self,
        shared_secret: &[u8],
    ) -> Result<seal_crypto::zeroize::Zeroizing<Vec<u8>>> {
        use seal_crypto::prelude::{DigestXofReader, KeyBasedDerivation, XofDerivation};
        use seal_crypto::schemes::{
            kdf::hkdf::{HkdfSha256, HkdfSha384, HkdfSha512},
            xof::shake::{Shake128, Shake256},
        };
        use seal_crypto::zeroize::Zeroizing;

        match self {
            DerivationInfo::Kdf(kdf_info) => {
                let derived = match kdf_info.kdf_algorithm {
                    crate::common::algorithms::KdfAlgorithm::HkdfSha256 => HkdfSha256::default()
                        .derive(
                            shared_secret,
                            kdf_info.salt.as_deref(),
                            kdf_info.info.as_deref(),
                            kdf_info.output_len as usize,
                        )?,
                    crate::common::algorithms::KdfAlgorithm::HkdfSha384 => HkdfSha384::default()
                        .derive(
                            shared_secret,
                            kdf_info.salt.as_deref(),
                            kdf_info.info.as_deref(),
                            kdf_info.output_len as usize,
                        )?,
                    crate::common::algorithms::KdfAlgorithm::HkdfSha512 => HkdfSha512::default()
                        .derive(
                            shared_secret,
                            kdf_info.salt.as_deref(),
                            kdf_info.info.as_deref(),
                            kdf_info.output_len as usize,
                        )?,
                };
                Ok(Zeroizing::new(derived.as_bytes().to_vec()))
            }
            DerivationInfo::Xof(xof_info) => {
                let mut reader = match xof_info.xof_algorithm {
                    crate::common::algorithms::XofAlgorithm::Shake256 => Shake256::default()
                        .reader(
                            shared_secret,
                            xof_info.salt.as_deref(),
                            xof_info.info.as_deref(),
                        )?,
                    crate::common::algorithms::XofAlgorithm::Shake128 => Shake128::default()
                        .reader(
                            shared_secret,
                            xof_info.salt.as_deref(),
                            xof_info.info.as_deref(),
                        )?,
                };
                let mut dek_bytes = vec![0u8; xof_info.output_len as usize];
                reader.read(&mut dek_bytes);
                Ok(Zeroizing::new(dek_bytes))
            }
        }
    }
}

/// `HeaderPayload` contains metadata specific to the encryption mode.
///
/// `HeaderPayload` 包含特定于加密模式的元数据。
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
pub enum HeaderPayload {
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
        /// Streaming metadata, if applicable.
        ///
        /// 流式处理元数据（如果适用）。
        stream_info: Option<StreamInfo>,
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
        /// Streaming metadata, theoretically applicable to hybrid mode as well.
        ///
        /// 流式处理元数据，理论上也适用于混合模式。
        stream_info: Option<StreamInfo>,
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

impl HeaderPayload {
    /// Returns the key ID if the payload is for symmetric encryption.
    ///
    /// 如果有效载荷用于对称加密，则返回密钥 ID。
    pub fn key_id(&self) -> Option<&str> {
        match self {
            HeaderPayload::Symmetric { key_id, .. } => Some(key_id),
            _ => None,
        }
    }

    /// Returns the Key-Encrypting-Key (KEK) ID if the payload is for hybrid encryption.
    ///
    /// 如果有效载荷用于混合加密，则返回密钥加密密钥 (KEK) 的 ID。
    pub fn kek_id(&self) -> Option<&str> {
        match self {
            HeaderPayload::Hybrid { kek_id, .. } => Some(kek_id),
            _ => None,
        }
    }

    /// Returns the signer key ID if the payload is for hybrid encryption.
    ///
    /// 如果有效载荷用于混合加密，则返回签名者密钥 ID。
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
    ///
    /// 返回用于数据加密的对称算法。
    /// 在混合模式下，这是数据加密密钥 (DEK) 的算法。
    pub fn symmetric_algorithm(&self) -> SymmetricAlgorithm {
        match self {
            HeaderPayload::Symmetric { algorithm, .. } => *algorithm,
            HeaderPayload::Hybrid { dek_algorithm, .. } => *dek_algorithm,
        }
    }

    /// Returns the asymmetric algorithm used for key encapsulation, if applicable.
    /// This is only present in Hybrid mode.
    ///
    /// 如果适用，返回用于密钥封装的非对称算法。
    /// 这仅存在于混合模式中。
    pub fn asymmetric_algorithm(&self) -> Option<AsymmetricAlgorithm> {
        match self {
            HeaderPayload::Hybrid { kek_algorithm, .. } => Some(*kek_algorithm),
            _ => None,
        }
    }

    /// Returns the signature algorithm, if applicable.
    ///
    /// 如果适用，返回签名算法。
    pub fn signer_algorithm(&self) -> Option<SignatureAlgorithm> {
        match self {
            HeaderPayload::Hybrid { signature, .. } => {
                signature.as_ref().map(|s| s.signer_algorithm)
            }
            _ => None,
        }
    }

    /// Returns the signature, if applicable.
    ///
    /// 如果适用，返回签名。
    pub fn signature(&self) -> Option<&[u8]> {
        match self {
            HeaderPayload::Hybrid { signature, .. } => {
                signature.as_ref().map(|s| s.signature.as_slice())
            }
            _ => None,
        }
    }

    /// Gets the payload to be signed and the signature itself.
    ///
    /// 获取要签名的有效载荷和签名本身。
    pub(crate) fn get_signed_payload_and_sig(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        if let HeaderPayload::Hybrid { .. } = self {
            let signature = self
                .signature()
                .ok_or(CryptoError::MissingSignature)?
                .to_vec();

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
    /// The encryption mode used.
    ///
    /// 使用的加密模式。
    pub mode: SealMode,
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
        verification_key: Option<crate::keys::SignaturePublicKey>,
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

            use seal_crypto::prelude::*;
            use seal_crypto::schemes::asymmetric::post_quantum::dilithium::{
                Dilithium2, Dilithium3, Dilithium5,
            };
            use seal_crypto::schemes::asymmetric::traditional::ecc::{EcdsaP256, Ed25519};

            // Select the correct verification method based on the signature algorithm and recover the key directly from raw bytes.
            // 根据签名算法选择正确的验证方法并直接从原始字节恢复密钥。
            match algo {
                SignatureAlgorithm::Dilithium2 => {
                    let pk = <Dilithium2 as AsymmetricKeySet>::PublicKey::from_bytes(
                        verification_key.as_bytes(),
                    )?;
                    Dilithium2::verify(&pk, &payload_bytes, &Signature(signature))?;
                }
                SignatureAlgorithm::Dilithium3 => {
                    let pk = <Dilithium3 as AsymmetricKeySet>::PublicKey::from_bytes(
                        verification_key.as_bytes(),
                    )?;
                    Dilithium3::verify(&pk, &payload_bytes, &Signature(signature))?;
                }
                SignatureAlgorithm::Dilithium5 => {
                    let pk = <Dilithium5 as AsymmetricKeySet>::PublicKey::from_bytes(
                        verification_key.as_bytes(),
                    )?;
                    Dilithium5::verify(&pk, &payload_bytes, &Signature(signature))?;
                }
                SignatureAlgorithm::Ed25519 => {
                    let pk = <Ed25519 as AsymmetricKeySet>::PublicKey::from_bytes(
                        verification_key.as_bytes(),
                    )?;
                    Ed25519::verify(&pk, &payload_bytes, &Signature(signature))?;
                }
                SignatureAlgorithm::EcdsaP256 => {
                    let pk = <EcdsaP256 as AsymmetricKeySet>::PublicKey::from_bytes(
                        verification_key.as_bytes(),
                    )?;
                    EcdsaP256::verify(&pk, &payload_bytes, &Signature(signature))?;
                }
            }
            Ok(())
        } else {
            // No signature, but a verification key was provided.
            // 没有签名，但提供了验证密钥。
            Err(CryptoError::MissingSignature.into())
        }
    }
}
