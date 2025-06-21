
use bincode::{Encode, Decode};
// 这两个枚举也可以考虑放到 seal-crypto 中，以便共享
use crate::common::algorithms::{AsymmetricAlgorithm, SymmetricAlgorithm};

/// 定义加密操作的模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode)]
pub enum SealMode {
    Symmetric,
    Hybrid,
}

/// 流式处理的元数据
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
pub struct StreamInfo {
    pub chunk_size: u32,
    pub base_nonce: [u8; 12],
}

/// HeaderPayload 包含了特定于加密模式的元数据
#[derive(Debug, Clone, PartialEq, Eq,  Decode, Encode)]
pub enum HeaderPayload {
    Symmetric {
        key_id: String, // 用于密钥管理的标识符
        algorithm: SymmetricAlgorithm,
        stream_info: Option<StreamInfo>,
    },
    Hybrid {
        kek_id: String, // 密钥加密密钥的标识符
        kek_algorithm: AsymmetricAlgorithm,
        dek_algorithm: SymmetricAlgorithm,
        encrypted_dek: Vec<u8>,
        stream_info: Option<StreamInfo>, // 混合模式理论上也可以流式处理
    },
}

/// 所有加密数据流的元数据信封
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode)]
pub struct Header {
    pub version: u16,
    pub mode: SealMode,
    pub payload: HeaderPayload,
}

impl Header {
    pub fn encode_to_vec(&self) -> Result<Vec<u8>, bincode::error::EncodeError> {
        static CONFIG: bincode::config::Configuration = bincode::config::standard();
        bincode::encode_to_vec(self, CONFIG)
    }

    pub fn decode_from_slice(data: &[u8]) -> Result<(Self, usize), bincode::error::DecodeError> {
        static CONFIG: bincode::config::Configuration = bincode::config::standard();
        bincode::decode_from_slice(data, CONFIG)
    }
}
