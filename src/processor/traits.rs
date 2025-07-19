//! Defines the traits for different body processing modes.
//!
//! 定义不同消息体处理模式的 trait。

use crate::error::Result;
use std::io::Write;


pub trait FinishingWrite: Write {
    fn finish(self: Box<Self>) -> Result<()>;
}
