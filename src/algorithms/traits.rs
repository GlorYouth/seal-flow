//! Defines the core traits for type-safe algorithm specification.

use crate::common;
use seal_crypto::prelude::*;

/// 代表一个具体的对称加密算法。
pub trait SymmetricAlgorithm: 'static + Send + Sync {
    /// 关联的 `seal-crypto` 方案，实现了所有核心加密操作。
    type Scheme: AeadScheme;

    /// 对应的算法枚举，用于序列化等目的。
    const ALGORITHM: common::algorithms::SymmetricAlgorithm;
}

/// 代表一个具体的非对称密钥封装机制 (KEM)。
pub trait AsymmetricAlgorithm: 'static + Send + Sync {
    /// 关联的 `seal-crypto` 方案，实现了 KEM 和密钥生成。
    type Scheme: Kem + KeyGenerator;

    /// 对应的算法枚举。
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm;
}