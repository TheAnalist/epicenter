//! Verified local mirror of one remote endpoint.
//!
//! The cache has exactly the bucket shape, so the existing reader verifiers
//! can be reused without a second parser:
//!
//! ```text
//! <cache>/<endpoint+key>/
//!   index.json
//!   indexes/<sha256>.json
//!   blobs/<sha256>
//!   store/                 # imported units when the main store is read-only
//! ```
//!
//! Bodies and blobs are immutable and put-if-absent. The signed pointer is
//! replaced last. A corrupt cached object is removed and refetched; it is
//! never trusted because of its name or mtime.

use anyhow::{Context, Result, bail, ensure};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::{
    BlobRef, INDEX_FILE, MAX_INDEX_BODY_BYTES, MAX_INDEX_POINTER_BYTES, RemoteSource, body_path,
    cas::install_put_if_absent, read_capped, state,
};
use crate::settings::RemotePolicy;
use crate::util::{self, FileLock};
use walkdir::WalkDir;

/// Per-endpoint cache directory (also the import-cache store parent).
pub(crate) fn endpoint_root(remote: &RemotePolicy) -> Result<PathBuf> {
    Ok(remote.cache.join(state::endpoint_id(remote)?))
}

/// The cache store used when the configured vault is read-only.
pub(crate) fn store_root(remote: &RemotePolicy) -> Result<PathBuf> {
    Ok(endpoint_root(remote)?.join("store"))
}

/// Reject a symlink/reparse cache root, endpoint or cache store before any
/// reader consults or writes through it. The final `import_units`/manifest
/// paths repeat the check, so a swap after this point still fails closed.
pub(crate) fn validate_layout(remote: &RemotePolicy) -> Result<()> {
    if let Some(meta) = util::probe(&remote.cache, "remote cache root")?
        && !meta.is_dir()
    {
        bail!(
            "remote cache root {} is not a directory",
            remote.cache.display()
        );
    }
    let endpoint = endpoint_root(remote)?;
    if let Some(meta) = util::probe(&endpoint, "remote cache endpoint")?
        && !meta.is_dir()
    {
        bail!(
            "remote cache endpoint {} is not a directory",
            endpoint.display()
        );
    }
    let store = endpoint.join("store");
    if let Some(meta) = util::probe(&store, "remote cache store")?
        && !meta.is_dir()
    {
        bail!("remote cache store {} is not a directory", store.display());
    }
    Ok(())
}

pub(crate) struct Cache {
    root: PathBuf,
}

impl Cache {
    pub(crate) fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Create the private endpoint cache and take its writer lock.
    pub(crate) fn open_writer(remote: &RemotePolicy) -> Result<(Self, FileLock)> {
        validate_layout(remote)?;
        let root = endpoint_root(remote)?;
        util::create_private_dir_all(&root)?;
        util::check_private_dir(&root, util::Privacy::Enforce)?;
        let lock = FileLock::acquire(&root.join(".cache.lock"))?;
        Ok((Self::new(root), lock))
    }

    /// Read-only handle; missing files are reported as `None`.
    pub(crate) fn open_reader(remote: &RemotePolicy) -> Result<Self> {
        validate_layout(remote)?;
        Ok(Self::new(endpoint_root(remote)?))
    }

    pub(crate) fn read_pointer(&self) -> Result<Option<Vec<u8>>> {
        read_optional(
            &self.root.join(INDEX_FILE),
            MAX_INDEX_POINTER_BYTES,
            "index pointer",
        )
    }

    pub(crate) fn read_body(&self, sha256: &str) -> Result<Option<Vec<u8>>> {
        read_optional(
            &body_path(&self.root, sha256)?,
            MAX_INDEX_BODY_BYTES,
            "index body",
        )
    }

    pub(crate) fn remove_pointer(&self) -> Result<()> {
        remove_cached(&self.root.join(INDEX_FILE), "index pointer")
    }

    pub(crate) fn remove_body(&self, sha256: &str) -> Result<()> {
        remove_cached(&body_path(&self.root, sha256)?, "index body")
    }

    /// Install the pointer last, after its body has been verified.
    pub(crate) fn install_pointer(&self, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() as u64 <= MAX_INDEX_POINTER_BYTES,
            "remote index pointer is too large"
        );
        util::write_atomic_private(&self.root.join(INDEX_FILE), bytes)
    }

    /// Bodies are immutable and addressed by hash.
    pub(crate) fn install_body(&self, sha256: &str, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() as u64 <= MAX_INDEX_BODY_BYTES,
            "remote index body is too large"
        );
        let path = body_path(&self.root, sha256)?;
        match read_optional(&path, MAX_INDEX_BODY_BYTES, "index body")? {
            Some(existing) => {
                ensure!(
                    existing == bytes,
                    "cached index body {} does not match the signed hash",
                    path.display()
                );
                Ok(())
            }
            None => {
                if let Some(parent) = path.parent() {
                    util::create_private_dir_all(parent)?;
                }
                util::write_atomic_private(&path, bytes)
            }
        }
    }

    pub(crate) fn blob_path(&self, sha256: &str) -> Result<PathBuf> {
        super::blob_path(&self.root, sha256)
    }

    pub(crate) fn verify_blob(&self, blob: &BlobRef) -> Result<()> {
        super::verify_blob(&self.root, blob)
    }

    /// Fetch and install one immutable CAS object. A corrupt cached object is
    /// removed and refetched; a failed fetch leaves no partial file.
    pub(crate) fn install_blob(&self, source: &dyn RemoteSource, blob: &BlobRef) -> Result<()> {
        let final_path = self.blob_path(&blob.blob)?;
        if final_path.exists() {
            match self.verify_blob(blob) {
                Ok(()) => return Ok(()),
                Err(_) => {
                    // The cache is a local convenience, never the trust anchor.
                    util::remove_file(&self.root, &final_path)?;
                }
            }
        }
        let parent = final_path
            .parent()
            .context("remote blob path has no parent")?;
        util::create_private_dir_all(parent)?;
        util::check_private_dir(parent, util::Privacy::Enforce)?;
        let (tmp, mut file) = util::create_temp(parent, "cache-blob", "", 0o600)?;
        let result = (|| -> Result<()> {
            source.fetch_blob(&blob.blob, blob.blob_size, &mut file)?;
            file.flush()?;
            file.sync_all()?;
            Ok(())
        })();
        drop(file);
        if let Err(err) = result {
            let _ = fs::remove_file(&tmp);
            return Err(err).with_context(|| format!("fetching blob {}", blob.blob));
        }
        let meta = util::metadata_nofollow(&tmp)?;
        ensure!(
            meta.is_file() && meta.len() == blob.blob_size,
            "remote blob {} has the wrong stored size (expected {}, found {})",
            blob.blob,
            blob.blob_size,
            meta.len()
        );
        ensure!(
            util::sha256_file(&tmp)? == blob.blob,
            "remote blob {} failed its stored SHA-256 check",
            blob.blob
        );
        install_put_if_absent(&tmp, &final_path, &blob.blob, blob.blob_size)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file = util::open_regular(&final_path, false)?;
            file.set_permissions(fs::Permissions::from_mode(0o444))?;
        }
        Ok(())
    }

    /// Remove bodies and blobs no longer referenced by the accepted index.
    pub(crate) fn sweep(&self, index: &super::SignedIndex) -> Result<()> {
        use std::collections::HashSet;

        let body = index.pointer().body_sha256.as_str();
        let blobs: HashSet<&str> = index
            .body()
            .units
            .iter()
            .flat_map(|unit| unit.files.iter())
            .map(|file| file.blob.as_str())
            .collect();
        let indexes = self.root.join(super::INDEXES_DIR);
        let blob_dir = self.root.join(super::BLOBS_DIR);
        let mut budget = util::ScanBudget::new("remote cache sweep");
        for (dir, keep_body) in [(indexes, true), (blob_dir, false)] {
            if !dir.is_dir() {
                continue;
            }
            let walker = WalkDir::new(&dir)
                .min_depth(1)
                .max_depth(util::MAX_SCAN_DEPTH)
                .follow_links(false)
                .follow_root_links(false)
                .into_iter()
                .filter_entry(|entry| util::walk_entry_is_safe(&dir, entry));
            for entry in walker {
                if !budget.take() {
                    break;
                }
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => continue,
                };
                if !entry.file_type().is_file() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy();
                let keep = if keep_body {
                    name.strip_suffix(".json") == Some(body)
                } else {
                    blobs.contains(name.as_ref())
                };
                if !keep {
                    let _ = util::remove_file(&self.root, entry.path());
                }
            }
        }
        Ok(())
    }
}

fn read_optional(path: &Path, max_bytes: u64, what: &str) -> Result<Option<Vec<u8>>> {
    match util::probe(path, what)? {
        Some(meta) if meta.is_file() => Ok(Some(read_capped(path, max_bytes, what)?)),
        Some(_) => bail!("{what} {} is not a regular file", path.display()),
        None => Ok(None),
    }
}

fn remove_cached(path: &Path, what: &str) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("removing corrupt {what} {}", path.display())),
    }
}
