#![doc = include_str!("../README.md")]
//!
//! `seal-flow` 是一个旨在统一和简化加密操作的 Rust 库。它为对称和非对称（混合）加密提供了一个高级、流畅的接口，支持多种执行模式，包括内存、流式和异步操作。
//!
//! 主要目标是提供一个对开发者友好且难以误用的 API，同时允许通过模块化设计实现高级配置。
//!
//! ## 主要特点
//!
//! - **高级 API**：抽象出复杂的加密概念，提供简单的工作流。
//! - **混合加密**：结合了非对称（KEM）和对称（DEM）加密，实现了安全高效的数据加密。
//! - **对称加密**：为使用预共享密钥的场景提供直接的 AEAD 加密。
//! - **多种执行模式**：
//!   - **内存**：用于小型数据。
//!   - **并行内存**：利用多核 CPU 加速内存操作。
//!   - **流式**：适用于大文件或网络流，具有恒定的内存使用量。
//!   - **异步**：与 `tokio` 集成，用于非阻塞 I/O。
//! - **安全的密钥管理**：通过 `KeyProvider` trait 和安全的解密工作流，防止密钥误用。
//! - **模块化和可扩展**：允许轻松集成新的加密算法或自定义行为。
//!
//! ## 快速上手
//!
//! 将 `seal-flow` 添加到你的 `Cargo.toml` 中：
//!
//! ```toml
//! [dependencies]
//! seal-flow = "0.1.0"
//! ```
//!
//! 然后，你可以开始使用 `prelude` 来导入最常用的组件。
//!
//! ```ignore
//! use seal_flow::prelude::*;
//! ```

pub mod common;
pub mod error;
pub mod processor;
pub use error::{Error, Result};
#[cfg(feature = "async")]
pub use {::futures, ::tokio};

pub use ::seal_crypto_wrapper as crypto;
pub mod prelude {
    pub use crate::common::header::*;
    pub use crate::processor::api::*;
}
pub use ::sha2;
