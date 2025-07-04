//! Defines the core traits for type-safe algorithm specification.
//!
//! 定义用于类型安全算法规范的核心 trait。

use crate::common;
use seal_crypto::prelude::*;

/// Trait to provide the details for a specific symmetric algorithm.
/// The implementor of this trait is the scheme itself.
///
/// 用于提供特定对称算法详细信息的 trait。
/// 该 trait 的实现者是算法方案本身。
pub trait SymmetricAlgorithmDetails: AeadScheme + 'static {
    /// The corresponding algorithm enum.
    ///
    /// 对应的算法枚举。
    const ALGORITHM: common::algorithms::SymmetricAlgorithm;
}

/// Represents a concrete symmetric encryption algorithm.
/// This is a marker trait that bundles `SymmetricAlgorithmDetails` with key bounds.
///
/// 表示一个具体的对称加密算法。
/// 这是一个标记 trait，它将 `SymmetricAlgorithmDetails` 与密钥边界捆绑在一起。
pub trait SymmetricAlgorithm: SymmetricAlgorithmDetails {}

impl<T: SymmetricAlgorithmDetails> SymmetricAlgorithm for T {}

/// Trait to provide the details for a specific key-based key derivation function (KDF).
/// The implementor of this trait is the scheme itself.
///
/// 用于提供特定基于密钥的密钥派生函数 (KDF) 详细信息的 trait。
/// 该 trait 的实现者是算法方案本身。
pub trait KdfAlgorithmDetails: KeyBasedDerivation + 'static {
    /// The corresponding algorithm enum.
    ///
    /// 对应的算法枚举。
    const ALGORITHM: common::algorithms::KdfAlgorithm;
}

/// Represents a concrete key-based key derivation function (KDF).
/// This is a marker trait that bundles `KdfAlgorithmDetails`.
///
/// 表示一个具体的基于密钥的密钥派生函数 (KDF)。
/// 这是一个标记 trait，它将 `KdfAlgorithmDetails` 捆绑在一起。
pub trait KdfAlgorithm: KdfAlgorithmDetails {}

impl<T: KdfAlgorithmDetails> KdfAlgorithm for T {}

/// Trait to provide the details for a specific asymmetric algorithm.
/// The implementor of this trait is the scheme itself.
///
/// 用于提供特定非对称算法详细信息的 trait。
/// 该 trait 的实现者是算法方案本身。
pub trait AsymmetricAlgorithmDetails: Kem + KeyGenerator + 'static {
    /// The corresponding algorithm enum.
    ///
    /// 对应的算法枚举。
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm;
}

/// Represents a concrete asymmetric key encapsulation mechanism (KEM).
/// This is a marker trait that bundles `AsymmetricAlgorithmDetails` with key bounds.
///
/// 表示一个具体的非对称密钥封装机制 (KEM)。
/// 这是一个标记 trait，它将 `AsymmetricAlgorithmDetails` 与密钥边界捆绑在一起。
pub trait AsymmetricAlgorithm: AsymmetricAlgorithmDetails {}

impl<T: AsymmetricAlgorithmDetails> AsymmetricAlgorithm for T {}

/// Trait to provide the details for a specific digital signature algorithm.
/// The implementor of this trait is the scheme itself.
///
/// 用于提供特定数字签名算法详细信息的 trait。
/// 该 trait 的实现者是算法方案本身。
pub trait SignatureAlgorithmDetails: SignatureScheme + 'static {
    /// The corresponding algorithm enum.
    ///
    /// 对应的算法枚举。
    const ALGORITHM: common::algorithms::SignatureAlgorithm;
}

/// Represents a concrete digital signature scheme.
/// This is a marker trait that bundles `SignatureAlgorithmDetails`.
///
/// 表示一个具体的数字签名方案。
/// 这是一个标记 trait，它将 `SignatureAlgorithmDetails` 捆绑在一起。
pub trait SignatureAlgorithm: SignatureAlgorithmDetails {}

impl<T: SignatureAlgorithmDetails> SignatureAlgorithm for T {}

/// Trait to provide the details for a specific extendable-output function (XOF).
/// The implementor of this trait is the scheme itself.
///
/// 用于提供特定可扩展输出函数 (XOF) 详细信息的 trait。
/// 该 trait 的实现者是算法方案本身。
pub trait XofAlgorithmDetails: XofDerivation + 'static {
    /// The corresponding algorithm enum.
    ///
    /// 对应的算法枚举。
    const ALGORITHM: common::algorithms::XofAlgorithm;
}

/// Represents a concrete extendable-output function (XOF).
/// This is a marker trait that bundles `XofAlgorithmDetails`.
///
/// 表示一个具体的可扩展输出函数 (XOF)。
/// 这是一个标记 trait，它将 `XofAlgorithmDetails` 捆绑在一起。
pub trait XofAlgorithm: XofAlgorithmDetails {}

impl<T: XofAlgorithmDetails> XofAlgorithm for T {}
