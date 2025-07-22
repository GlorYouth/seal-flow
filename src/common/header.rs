//! 这个模块包含所有 SealFlow 标头相关的定义。
//!
//! 这些标头定义了 SealFlow 加密和解密过程中使用的各种参数和元数据。
//! 它们是加密和解密过程中的关键组成部分，用于确保数据的安全性和完整性。
//!
//! 这个模块还提供了一些辅助函数，用于处理标头的编码和解码，以及验证标头的签名。
//!
//! 这些标头定义了 SealFlow 加密和解密过程中使用的各种参数和元数据。

// These enums could also be considered for placement in seal-crypto for sharing.
// 这两个枚举也可以考虑放到 seal-crypto 中，以便共享。
use crate::error::{Error, FormatError, Result};
use async_trait::async_trait;
use seal_crypto_wrapper::algorithms::symmetric::SymmetricAlgorithm;
use seal_crypto_wrapper::bincode;
use seal_crypto_wrapper::prelude::TypedSignaturePublicKey;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::io::{Read, Write};
#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
#[bincode(crate = "seal_crypto_wrapper::bincode")]
pub struct SymmetricParams {
    pub(crate) algorithm: SymmetricAlgorithm,
    pub(crate) chunk_size: u32,
    pub(crate) base_nonce: Box<[u8]>, // 用于派生每个 chunk nonce 的基础 nonce
    pub(crate) aad_hash: Option<Box<[u8]>>,
}

impl SymmetricParams {
    pub fn algorithm(&self) -> SymmetricAlgorithm {
        self.algorithm
    }

    pub fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    pub fn base_nonce(&self) -> &[u8] {
        &self.base_nonce
    }

    pub fn aad_hash(&self) -> Option<&[u8]> {
        self.aad_hash.as_deref()
    }
}

pub struct SymmetricParamsBuilder {
    algorithm: SymmetricAlgorithm,
    chunk_size: u32,
    base_nonce: Option<Box<[u8]>>,
    aad_hash: Option<Box<[u8]>>,
}

impl SymmetricParamsBuilder {
    pub fn new(algorithm: SymmetricAlgorithm, chunk_size: u32) -> Self {
        Self {
            algorithm,
            chunk_size,
            base_nonce: None,
            aad_hash: None,
        }
    }

    pub fn base_nonce(mut self, f: impl FnOnce(&mut [u8]) -> Result<()>) -> Result<Self> {
        let mut nonce = vec![0u8; self.algorithm.into_symmetric_wrapper().nonce_size()];
        f(&mut nonce)?;
        self.base_nonce = Some(nonce.into());
        Ok(self)
    }

    pub fn aad_hash(mut self, aad: &[u8], mut hasher: impl Digest) -> Self {
        hasher.update(aad);
        let hash = hasher.finalize();
        self.aad_hash = Some(hash.to_vec().into());
        self
    }

    pub fn build(self) -> SymmetricParams {
        SymmetricParams {
            algorithm: self.algorithm,
            chunk_size: self.chunk_size,
            base_nonce: self.base_nonce.unwrap_or_default(),
            aad_hash: self.aad_hash,
        }
    }
}

/// A trait representing the common interface for all SealFlow headers.
///
/// 代表所有 SealFlow 标头通用接口的 trait。
#[async_trait]
pub trait SealFlowHeader:
    Sized
    + Serialize
    + for<'de> Deserialize<'de>
    + bincode::Encode
    + bincode::Decode<()>
    + Clone
    + Send
    + Sync
    + 'static
{
    /// Encodes the header into a raw byte vector.
    ///
    /// 将标头编码为原始字节向量。
    fn encode_to_vec(&self) -> Result<Vec<u8>> {
        static CONFIG: bincode::config::Configuration = bincode::config::standard();
        bincode::encode_to_vec(self, CONFIG).map_err(Error::from)
    }

    /// Decodes a header from a raw byte slice.
    ///
    /// 从原始字节切片解码标头。
    fn decode_from_slice(data: &[u8]) -> Result<(Self, usize)> {
        static CONFIG: bincode::config::Configuration = bincode::config::standard();
        bincode::decode_from_slice(data, CONFIG).map_err(Error::from)
    }

    /// Verifies the signature within the header, if one exists.
    /// The default implementation does nothing.
    ///
    /// 验证标头中的签名（如果存在）。
    /// 默认实现不执行任何操作。
    fn verify_signature<'a>(&self, verify_key: Option<&'a TypedSignaturePublicKey>) -> Result<()> {
        let _ = verify_key;
        Ok(())
    }

    fn symmetric_params(&self) -> &SymmetricParams;
    fn extra_data(&self) -> Option<&[u8]>;

    fn encode_to_prefixed_vec(&self) -> Result<Vec<u8>> {
        let header_bytes = self.encode_to_vec()?;
        let header_len = header_bytes.len() as u32;
        let mut prefixed_header = Vec::with_capacity(4 + header_bytes.len());
        prefixed_header.extend_from_slice(&header_len.to_le_bytes());
        prefixed_header.extend_from_slice(&header_bytes);
        Ok(prefixed_header)
    }

    fn write_to_prefixed_writer<W: Write>(&self, writer: &mut W) -> Result<()> {
        let prefixed_bytes = self.encode_to_prefixed_vec()?;
        writer.write_all(&prefixed_bytes)?;
        Ok(())
    }

    #[cfg(feature = "async")]
    async fn write_to_prefixed_async_writer<W: AsyncWrite + Unpin + Send>(
        &self,
        writer: &mut W,
    ) -> Result<()> {
        let prefixed_bytes = self.encode_to_prefixed_vec()?;
        writer.write_all(&prefixed_bytes).await?;
        Ok(())
    }

    fn decode_from_prefixed_slice<'a, 'b>(
        ciphertext: &'a [u8],
        verify_key: Option<&'b TypedSignaturePublicKey>,
    ) -> Result<(Self, &'a [u8])> {
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
        header.verify_signature(verify_key)?;
        Ok((header, ciphertext_body))
    }

    fn decode_from_prefixed_reader<'a, R: Read>(
        reader: &mut R,
        verify_key: Option<&'a TypedSignaturePublicKey>,
    ) -> Result<Self> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let header_len = u32::from_le_bytes(len_buf) as usize;

        let mut header_bytes = vec![0u8; header_len];
        reader.read_exact(&mut header_bytes)?;
        let (header, _) = Self::decode_from_slice(&header_bytes)?;
        header.verify_signature(verify_key)?;

        Ok(header)
    }

    #[cfg(feature = "async")]
    async fn decode_from_prefixed_async_reader<'a, R: AsyncRead + Unpin + Send>(
        reader: &mut R,
        verify_key: Option<&'a TypedSignaturePublicKey>,
    ) -> Result<Self> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let header_len = u32::from_le_bytes(len_buf) as usize;

        let mut header_bytes = vec![0u8; header_len];
        reader.read_exact(&mut header_bytes).await?;
        let (header, _) = Self::decode_from_slice(&header_bytes)?;
        header.verify_signature(verify_key)?;

        Ok(header)
    }
}
