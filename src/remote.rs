//! Remote artifact distribution: signed index, immutable CAS, replay state and
//! compatibility gates.
//!
//! The bucket is untrusted storage. Trust comes from the pinned Ed25519
//! publisher key and SHA-256 object names; the layout is deliberately boring:
//!
//! ```text
//! index.json                 small signed pointer (replaced atomically)
//! indexes/<sha256>.json      immutable canonical index body
//! publisher.json             human-readable copy of the signed metadata
//! blobs/<sha256>             immutable stored bytes (gzip or raw)
//! ```
//!
//! The pointer commits to the body hash and size and carries the sequence,
//! creation/expiry and signature. A body that does not hash to the committed
//! value is never parsed. Readers persist the highest accepted sequence per
//! endpoint/key and refuse rollbacks, equivocation and expired indexes.
//!
//! The CI-only publisher turns one vault generation into that tree under a
//! private staging root; transport uploads are a separate layer.

mod cas;
mod compat;
mod index;
mod publish;
mod state;
pub(crate) mod validate;

#[cfg(test)]
mod tests;

pub use cas::{
    BlobRef, Compression, MAX_IN_MEMORY_BLOB_BYTES, Upload, UploadMode, decode_blob, read_blob,
    upload_plan, verify_blob, write_blob,
};
pub use compat::{
    Compatibility, LocalEnvironment, Mismatch, RegistryIdentity, RustcIdentity, UnitCompatibility,
    compare_compatibility, source_path_hash,
};
pub use index::{
    FileRole, IndexBody, IndexPointer, PublisherMetadata, PublisherReport, RemoteFile, RemoteUnit,
    RemoteUnitKind, SourceKind, UnitSource, VerifiedIndex, make_index, publisher_report,
    read_index_tree, verify_body, verify_index, write_index_tree,
};
pub use publish::{PublishOutcome, PublishRequest, publish};
pub use state::{
    IndexStatus, RemoteState, clear_state, load_state, record_state, state_path, status,
};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Version of the pointer/body schema. A reader refuses anything else.
pub const SCHEMA_VERSION: u32 = 1;

pub const INDEX_FILE: &str = "index.json";
pub const PUBLISHER_FILE: &str = "publisher.json";
pub const BLOBS_DIR: &str = "blobs";
pub const INDEXES_DIR: &str = "indexes";
pub const STATE_DIR: &str = "remote";

/// The signed pointer is tiny by design.
pub const MAX_INDEX_POINTER_BYTES: u64 = 16 * 1024;
/// The canonical body is a metadata document, never artifact bytes.
pub const MAX_INDEX_BODY_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_INDEX_UNITS: usize = 100_000;
pub const MAX_INDEX_FILES: usize = 1_000_000;
pub const MAX_BLOB_BYTES: u64 = crate::util::MAX_FILE_BYTES;
pub const MAX_INDEX_VALIDITY_SECS: u64 = 90 * 24 * 60 * 60;
pub const MAX_CLOCK_SKEW_SECS: u64 = 5 * 60;

/// Unix seconds, saturating at zero for clocks before the epoch.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    crate::vault::hex_encode(&Sha256::digest(bytes))
}

/// True for exactly 64 lowercase hex characters. Lowercase-only keeps one
/// canonical spelling on case-insensitive filesystems.
pub fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(is_lower_hex)
}

pub(crate) fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

pub fn ensure_sha256(text: &str, what: &str) -> Result<()> {
    if !is_sha256(text) {
        anyhow::bail!("{what} must be 64 lowercase hex characters");
    }
    Ok(())
}

/// Object key for an immutable blob.
pub fn blob_key(sha256: &str) -> Result<String> {
    ensure_sha256(sha256, "blob SHA-256")?;
    Ok(format!("{BLOBS_DIR}/{sha256}"))
}

/// Object key for an immutable canonical index body.
pub fn body_key(sha256: &str) -> Result<String> {
    ensure_sha256(sha256, "index body SHA-256")?;
    Ok(format!("{INDEXES_DIR}/{sha256}.json"))
}

pub fn blob_path(root: &Path, sha256: &str) -> Result<PathBuf> {
    ensure_sha256(sha256, "blob SHA-256")?;
    Ok(root.join(BLOBS_DIR).join(sha256))
}

pub fn body_path(root: &Path, sha256: &str) -> Result<PathBuf> {
    ensure_sha256(sha256, "index body SHA-256")?;
    Ok(root.join(INDEXES_DIR).join(format!("{sha256}.json")))
}

/// Read a local regular file with a hard cap and no symlink following.
pub(crate) fn read_capped(path: &Path, max_bytes: u64, what: &str) -> Result<Vec<u8>> {
    let text = crate::util::read_small_text(path, max_bytes)
        .with_context(|| format!("reading {what} {}", path.display()))?;
    Ok(text.into_bytes())
}
