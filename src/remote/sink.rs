//! Publisher-side remote sink.
//!
//! The read path (`RemoteSource`) deliberately has no write methods. The
//! publisher gets this separate trait so a reader cannot accidentally write.

use anyhow::Result;

use super::Upload;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Precondition {
    /// No conditional header; only the human-readable publisher report.
    None,
    /// Create only if the object does not exist.
    IfAbsent,
    /// Replace only if the current ETag matches.
    IfMatch(String),
}

#[derive(Debug, Clone, Default)]
pub struct ObjectMeta {
    pub size: u64,
    pub etag: Option<String>,
    pub checksum_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutStatus {
    Created,
    AlreadyExists,
    Replaced,
}

#[derive(Debug, Clone)]
pub struct PutOutcome {
    pub status: PutStatus,
    pub etag: Option<String>,
    pub size: u64,
}

pub trait RemoteSink: Send + Sync {
    fn head(&self, key: &str) -> Result<Option<ObjectMeta>>;
    fn get(&self, key: &str, max_bytes: u64) -> Result<Vec<u8>>;
    fn put(&self, upload: &Upload, precondition: Precondition) -> Result<PutOutcome>;
}
