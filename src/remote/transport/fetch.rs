//! Read-only remote object source.
//!
//! Keeping the trait read-only makes "a reader never writes the bucket"
//! structural: there is no method that can put or delete an object.

use anyhow::Result;
use std::io::Write;

use super::is_miss;

/// The small signed pointer plus the cache validator for the publisher.
pub struct FetchedPointer {
    pub bytes: Vec<u8>,
    pub etag: Option<String>,
}

/// A read-only view of one remote bucket prefix.
pub trait RemoteSource: Send + Sync {
    /// Fetch the small signed pointer.
    fn fetch_pointer(&self) -> Result<Vec<u8>>;

    /// Fetch the pointer, preserving `None` for a clean 404. The publisher uses
    /// this to distinguish a first publish from an authorization failure.
    fn fetch_pointer_optional(&self) -> Result<Option<FetchedPointer>> {
        match self.fetch_pointer() {
            Ok(bytes) => Ok(Some(FetchedPointer { bytes, etag: None })),
            Err(err) if is_miss(&err) => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Fetch one canonical index body. The cap is enforced before parsing.
    fn fetch_body(&self, sha256: &str, max_bytes: u64) -> Result<Vec<u8>>;

    /// Stream one stored CAS object into `out`. Implementations must stop at
    /// `max_bytes`; the cache verifies the stored hash/size afterwards.
    fn fetch_blob(&self, sha256: &str, max_bytes: u64, out: &mut dyn Write) -> Result<()>;
}
