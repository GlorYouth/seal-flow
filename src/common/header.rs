

// These enums could also be considered for placement in seal-crypto for sharing.
// 这两个枚举也可以考虑放到 seal-crypto 中，以便共享。
use crate::error::{Error, FormatError, Result};
use seal_crypto_wrapper::algorithms::kdf::key::KdfKeyAlgorithm;
use crate::bincode;
use seal_crypto_wrapper::prelude::{EncapsulatedKey, TypedKemPublicKey, TypedSignaturePublicKey, XofAlgorithm};
use std::io::Read;
use serde::{Deserialize, Serialize};

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncReadExt};

/// KDF (Key-based Derivation Function) configuration information.
///
/// KDF (基于密钥的派生函数) 配置信息。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
#[bincode(crate = "crate::bincode")]
pub struct KdfBlock {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
#[bincode(crate = "crate::bincode")]
pub struct XofBlock {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
#[bincode(crate = "crate::bincode")]
pub enum DerivationBlock {
    /// Uses a standard Key-based Derivation Function (KDF).
    ///
    /// 使用标准的基于密钥的派生函数 (KDF)。
    Kdf(KdfBlock),
    /// Uses an Extendable-Output Function (XOF).
    ///
    /// 使用可扩展输出函数 (XOF)。
    Xof(XofBlock),
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
#[bincode(crate = "crate::bincode")]
pub struct KemBlock {
    ephemeral_key: TypedKemPublicKey, // KEM 生成的临时公钥
    encapsulated_key: EncapsulatedKey, // 封装（加密）后的对称密钥
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
#[bincode(crate = "crate::bincode")]
pub struct SignatureBlock {
    // 公钥标识符，用于接收方查找验证密钥
    public_key_id: String,
    signature: Vec<u8>,
    signature_key: TypedSignaturePublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
#[bincode(crate = "crate::bincode")]
pub struct SymmetricParams {
    pub chunk_size: u32,
    pub base_nonce: Box<[u8]>, // 用于派生每个 chunk nonce 的基础 nonce
    pub aad_hash: Option<[u8; 32]>,
}

impl SymmetricParams {
    pub fn new(chunk_size: u32, base_nonce: Box<[u8]>, aad: Option<&[u8]>) -> Self {
        let aad_hash = aad.map(|data| {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().into()
        });
        Self {
            chunk_size,
            base_nonce,
            aad_hash,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
#[bincode(crate = "crate::bincode")]
pub struct SealFlowSymmetricHeader {
    // 头部格式版本，用于未来扩展
    version: u16, 
    symmetric_params: SymmetricParams,
    extra_data: Option<Vec<u8>>,
}


#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
#[bincode(crate = "crate::bincode")]
pub struct SealFlowHybridHeader {
    // 头部格式版本，用于未来扩展
    version: u16, 
    // 非对称加密参数
    kem_block: KemBlock,
    signature_block: Option<SignatureBlock>,
    // 对称加密参数
    symmetric_params: SymmetricParams,
    derivation_block: DerivationBlock,
    extra_data: Option<Vec<u8>>,
}


impl SealFlowHybridHeader {
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

    /// Returns the extra data attached to the header.
    ///
    /// 返回附加到头部的额外数据。
    pub fn extra_data(&self) -> Option<&[u8]> {
        self.extra_data.as_deref()
    }
}
