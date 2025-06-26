//! Provides a unified, high-level API for SealFlow operations.
//!
//! This module introduces a builder pattern to configure and execute encryption
//! and decryption tasks, abstracting away the underlying implementation details
//! (like ordinary, parallel, or streaming modes).
//!
//! The main entry points are:
//! - [`symmetric::SymmetricSeal`]: For symmetric encryption operations.
//! - [`hybrid::HybridSeal`]: For hybrid (asymmetric + symmetric) encryption operations.
//!
//! # Example: Decryption Workflow with Peeking
//!
//! ```ignore
//! use seal_flow::seal::{peek_symmetric_key_id, symmetric::SymmetricSeal};
//! use std::io::Cursor;
//!
//! // Assume `get_key_from_store` and `encrypted_data` exist.
//! let key_id = peek_symmetric_key_id(Cursor::new(&encrypted_data)).unwrap();
//! let key = get_key_from_store(&key_id).unwrap();
//!
//! let decrypted = SymmetricSeal::new(&key)
//!     .in_memory::<Aes256Gcm>()
//!     .decrypt(&encrypted_data)
//!     .unwrap();
//! ```
pub mod hybrid;
pub mod symmetric;

pub use hybrid::HybridSeal;
pub use symmetric::SymmetricSeal;

use crate::common::header::{Header, HeaderPayload};
use crate::error::{Error, Result};
use std::io::Read;
#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncReadExt};

/// Peeks at the stream's header to read the Key-Encrypting-Key (KEK) ID.
///
/// This function reads only the necessary bytes from the start of the reader
/// to parse the header and extract the KEK ID used for hybrid encryption.
/// The reader's position will be advanced. Note that this function consumes the reader
/// and it's the caller's responsibility to handle the stream correctly,
/// perhaps by using a `BufReader` to avoid losing data.
pub fn peek_hybrid_kek_id<R: Read>(mut reader: R) -> Result<String> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let header_len = u32::from_le_bytes(len_buf) as usize;

    let mut header_bytes = vec![0u8; header_len];
    reader.read_exact(&mut header_bytes)?;
    let (header, _) = Header::decode_from_slice(&header_bytes)?;

    if let HeaderPayload::Hybrid { kek_id, .. } = header.payload {
        Ok(kek_id)
    } else {
        Err(Error::InvalidHeader)
    }
}

/// Peeks at the stream's header to read the symmetric key ID.
///
/// This function reads only the necessary bytes from the start of the reader
/// to parse the header and extract the key ID used for symmetric encryption.
/// The reader's position will be advanced.
pub fn peek_symmetric_key_id<R: Read>(mut reader: R) -> Result<String> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let header_len = u32::from_le_bytes(len_buf) as usize;

    let mut header_bytes = vec![0u8; header_len];
    reader.read_exact(&mut header_bytes)?;
    let (header, _) = Header::decode_from_slice(&header_bytes)?;

    if let HeaderPayload::Symmetric { key_id, .. } = header.payload {
        Ok(key_id)
    } else {
        Err(Error::InvalidHeader)
    }
}

/// Asynchronously peeks at the stream's header to read the Key-Encrypting-Key (KEK) ID.
#[cfg(feature = "async")]
pub async fn peek_hybrid_kek_id_async<R: AsyncRead + Unpin>(mut reader: R) -> Result<String> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let header_len = u32::from_le_bytes(len_buf) as usize;

    let mut header_bytes = vec![0u8; header_len];
    reader.read_exact(&mut header_bytes).await?;
    let (header, _) = Header::decode_from_slice(&header_bytes)?;

    if let HeaderPayload::Hybrid { kek_id, .. } = header.payload {
        Ok(kek_id)
    } else {
        Err(Error::InvalidHeader)
    }
}

/// Asynchronously peeks at the stream's header to read the symmetric key ID.
#[cfg(feature = "async")]
pub async fn peek_symmetric_key_id_async<R: AsyncRead + Unpin>(mut reader: R) -> Result<String> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let header_len = u32::from_le_bytes(len_buf) as usize;

    let mut header_bytes = vec![0u8; header_len];
    reader.read_exact(&mut header_bytes).await?;
    let (header, _) = Header::decode_from_slice(&header_bytes)?;

    if let HeaderPayload::Symmetric { key_id, .. } = header.payload {
        Ok(key_id)
    } else {
        Err(Error::InvalidHeader)
    }
}
