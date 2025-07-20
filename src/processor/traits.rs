//! Defines the traits for different body processing modes.
//!
//! 定义不同消息体处理模式的 trait。

use crate::error::Result;
use std::io::{Read, Write};
use crate::common::header::SymmetricParams;
#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};


pub trait FinishingWrite: Write {
    fn finish(self: Box<Self>) -> Result<()>;
}

/// An extension trait for SealFlow headers, providing functionality required by the processor.
///
/// SealFlow 头部的扩展 trait，提供处理器所需的功能。
#[async_trait::async_trait]
pub trait SealFlowHeaderExt: Sized + Send + Sync + 'static {
    /// Encodes the header into a byte vector, prefixed with its length.
    ///
    /// 将标头编码为带有长度前缀的字节向量。
    fn ext_encode_to_prefixed_vec(&self) -> Result<Vec<u8>>;

    /// Writes a length-prefixed header to a synchronous writer.
    ///
    /// 将带有长度前缀的标头写入同步写入器。
    fn ext_write_to_prefixed_writer<W: Write>(&self, writer: &mut W) -> Result<()>;

    /// Writes a length-prefixed header to an asynchronous writer.
    ///
    /// 将带有长度前缀的标头写入异步写入器。
    #[cfg(feature = "async")]
    async fn ext_write_to_prefixed_async_writer<W: AsyncWrite + Unpin + Send>(&self, writer: &mut W) -> Result<()>;

    /// Decodes a length-prefixed header from a byte slice.
    ///
    /// 从带有长度前缀的字节切片解码标头。
    fn ext_decode_from_prefixed_slice(ciphertext: &[u8]) -> Result<(Self, &[u8])>;

    /// Reads and decodes a length-prefixed header from a synchronous reader.
    ///
    /// 从同步读取器中读取并解码带有长度前缀的标头。
    fn ext_decode_from_prefixed_reader<R: Read>(reader: &mut R) -> Result<Self>;

    /// Reads and decodes a length-prefixed header from an asynchronous reader.
    ///
    /// 从异步读取器中读取并解码带有长度前缀的标头。
    #[cfg(feature = "async")]
    async fn ext_decode_from_prefixed_async_reader<R: AsyncRead + Unpin + Send>(
        reader: &mut R,
    ) -> Result<Self>;

    /// Returns the symmetric parameters for this header.
    ///
    
    /// 返回此标头的对称参数。
    fn ext_symmetric_params(&self) -> &SymmetricParams;

    /// Returns the extra data attached to the header.
    ///
    /// 返回附加到头部的额外数据。
    fn ext_extra_data(&self) -> Option<&[u8]>;
}
