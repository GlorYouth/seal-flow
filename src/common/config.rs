use crate::common::{CHANNEL_BOUND, DEFAULT_CHUNK_SIZE};
use std::sync::Arc;

pub(crate) struct ConfigIndex {
    pub chunk_size: u32,
    pub channel_bound: usize,
}

impl Default for ConfigIndex {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            channel_bound: CHANNEL_BOUND,
        }
    }
}

#[derive(Clone, Default)]
pub struct ArcConfig {
    index: Arc<ConfigIndex>,
}

impl ArcConfig {
    pub fn chunk_size(&self) -> u32 {
        self.index.chunk_size
    }

    pub fn channel_bound(&self) -> usize {
        self.index.channel_bound
    }
}

pub(crate) struct DecryptorConfig {
    pub chunk_size: u32,
    pub arc_config: ArcConfig,
}

impl DecryptorConfig {
    pub fn new(chunk_size: u32, arc_config: ArcConfig) -> Self {
        Self {
            chunk_size,
            arc_config,
        }
    }

    pub fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    pub fn arc_config(&self) -> &ArcConfig {
        &self.arc_config
    }

    pub fn channel_bound(&self) -> usize {
        self.arc_config.channel_bound()
    }
}

pub struct ConfigBuilder {
    pub chunk_size: u32,
    pub channel_bound: usize,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigBuilder {
    pub fn new() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            channel_bound: CHANNEL_BOUND,
        }
    }

    pub fn set_chunk_size(mut self, chunk_size: u32) -> Self {
        self.chunk_size = chunk_size;
        self
    }

    pub fn set_channel_bound(mut self, channel_bound: usize) -> Self {
        self.channel_bound = channel_bound;
        self
    }

    pub fn build(self) -> ArcConfig {
        ArcConfig {
            index: Arc::new(ConfigIndex {
                chunk_size: self.chunk_size,
                channel_bound: self.channel_bound,
            }),
        }
    }
}
