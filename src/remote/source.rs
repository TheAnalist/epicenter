//! Read-only local directory source.
//!
//! HTTPS/S3 implementations live alongside the [`RemoteSource`] trait in
//! `transport::fetch`; this module only adapts a local directory tree.

use anyhow::{Context, Result, bail};
use std::io::Write;
use std::path::{Path, PathBuf};

use super::transport::RemoteSource;
use super::{MAX_INDEX_BODY_BYTES, MAX_INDEX_POINTER_BYTES, blob_path, body_path, read_capped};
use crate::util;

/// Local directory source used by the reader tests and local diagnostics.
///
/// It is deliberately not reachable from a policy URL: exposing a local file
/// transport through `[remote]` would bypass the TLS requirement.
pub struct DirSource {
    root: PathBuf,
}

impl DirSource {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl RemoteSource for DirSource {
    fn fetch_pointer(&self) -> Result<Vec<u8>> {
        read_capped(
            &self.root.join(super::INDEX_FILE),
            MAX_INDEX_POINTER_BYTES,
            "index pointer",
        )
    }

    fn fetch_body(&self, sha256: &str, max_bytes: u64) -> Result<Vec<u8>> {
        let max = max_bytes.min(MAX_INDEX_BODY_BYTES);
        read_capped(&body_path(&self.root, sha256)?, max, "index body")
    }

    fn fetch_blob(&self, sha256: &str, max_bytes: u64, out: &mut dyn Write) -> Result<()> {
        let path = blob_path(&self.root, sha256)?;
        let mut input = util::open_regular(&path, false)
            .with_context(|| format!("opening {}", path.display()))?;
        let meta = input
            .metadata()
            .with_context(|| format!("inspecting {}", path.display()))?;
        if !meta.is_file() {
            bail!("{} is not a regular file", path.display());
        }
        if meta.len() > max_bytes {
            bail!(
                "remote blob {} is {} bytes (cap {max_bytes})",
                path.display(),
                meta.len()
            );
        }
        util::copy_capped(&mut input, out, max_bytes, &path)?;
        Ok(())
    }
}

/// Source factory for configured endpoints.
pub fn source_for(remote: &crate::settings::RemotePolicy) -> Result<Box<dyn RemoteSource>> {
    let config = super::transport::TransportConfig::from_policy(remote)?;
    match &config.endpoint {
        super::transport::Endpoint::Https(_) => {
            Ok(Box::new(super::transport::HttpsSource::new(&config)?))
        }
        super::transport::Endpoint::S3(_) => {
            Ok(Box::new(super::transport::S3Source::new(&config)?))
        }
    }
}
