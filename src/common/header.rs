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
use crate::seal_crypto_wrapper::bincode;
use std::io::{Read, Write};
use serde::{Deserialize, Serialize};
use async_trait::async_trait;
use seal_crypto_wrapper::algorithms::symmetric::SymmetricAlgorithm;
#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
#[bincode(crate = "seal_crypto_wrapper::bincode")]
pub struct SymmetricParams {
    pub(crate) algorithm: SymmetricAlgorithm,
    pub(crate) chunk_size: u32,
    pub(crate) base_nonce: Box<[u8]>, // 用于派生每个 chunk nonce 的基础 nonce
    pub(crate) aad_hash: Option<[u8; 32]>,
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
    fn verify_signature(&self) -> Result<()> {
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

    fn decode_from_prefixed_slice(ciphertext: &[u8]) -> Result<(Self, &[u8])> {
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
        header.verify_signature()?;
        Ok((header, ciphertext_body))
    }

    fn decode_from_prefixed_reader<R: Read>(reader: &mut R) -> Result<Self> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let header_len = u32::from_le_bytes(len_buf) as usize;

        let mut header_bytes = vec![0u8; header_len];
        reader.read_exact(&mut header_bytes)?;
        let (header, _) = Self::decode_from_slice(&header_bytes)?;
        header.verify_signature()?;

        Ok(header)
    }

    #[cfg(feature = "async")]
    async fn decode_from_prefixed_async_reader<R: AsyncRead + Unpin + Send>(
        reader: &mut R,
    ) -> Result<Self> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let header_len = u32::from_le_bytes(len_buf) as usize;

        let mut header_bytes = vec![0u8; header_len];
        reader.read_exact(&mut header_bytes).await?;
        let (header, _) = Self::decode_from_slice(&header_bytes)?;
        header.verify_signature()?;

        Ok(header)
    }
}
