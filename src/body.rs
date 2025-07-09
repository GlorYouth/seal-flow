#[cfg(feature = "async")]
pub(crate) mod asynchronous;
pub(crate) mod ordinary;
pub(crate) mod parallel;
pub(crate) mod parallel_streaming;
pub(crate) mod streaming;
pub(crate) mod traits;
