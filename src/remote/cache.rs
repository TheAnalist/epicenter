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

use anyhow::{Context, Result, ensure};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::{
    BLOBS_DIR, BlobRef, INDEX_FILE, INDEXES_DIR, MAX_INDEX_BODY_BYTES, MAX_INDEX_POINTER_BYTES,
    RemoteSource, body_path, cas::install_put_if_absent, read_capped, state,
};
use crate::settings::RemotePolicy;
use crate::util::{self, FileLock};

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
    let endpoint = endpoint_root(remote)?;
    util::probe_dir(&remote.cache, "remote cache root")?;
    util::probe_dir(&endpoint, "remote cache endpoint")?;
    util::probe_dir(&endpoint.join("store"), "remote cache store")?;
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
        remove_cached(&self.root, &self.root.join(INDEX_FILE), "index pointer")
    }

    pub(crate) fn remove_body(&self, sha256: &str) -> Result<()> {
        remove_cached(&self.root, &body_path(&self.root, sha256)?, "index body")
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
        if let Some(parent) = path.parent() {
            util::probe_dir(parent, "remote cache indexes directory")?;
        }
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
        let parent = final_path
            .parent()
            .context("remote blob path has no parent")?;
        util::probe_dir(parent, "remote cache blobs directory")?;
        if final_path.exists() {
            match self.verify_blob(blob) {
                Ok(()) => return Ok(()),
                Err(_) => {
                    // The cache is a local convenience, never the trust anchor.
                    util::remove_file(&self.root, &final_path)?;
                }
            }
        }
        util::create_private_dir_all(parent)?;
        util::check_private_dir(parent, util::Privacy::Enforce)?;
        let (tmp, ()) = util::with_temp_file(parent, "cache-blob", "", 0o600, |file| {
            source.fetch_blob(&blob.blob, blob.blob_size, file)?;
            file.flush()?;
            file.sync_all()?;
            Ok(())
        })
        .with_context(|| format!("fetching blob {}", blob.blob))?;
        util::verify_file_hash(&tmp, blob.blob_size, &blob.blob, "remote blob").inspect_err(
            |_| {
                let _ = fs::remove_file(&tmp);
            },
        )?;
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
        self.sweep_dir(INDEXES_DIR, |name| name.strip_suffix(".json") == Some(body))?;
        self.sweep_dir(BLOBS_DIR, |name| blobs.contains(name))?;
        Ok(())
    }

    /// Sweep one cache directory. The directory is resolved without following
    /// a symlink/reparse point, and deletions go through the no-follow helper.
    fn sweep_dir(&self, name: &str, keep: impl Fn(&str) -> bool) -> Result<()> {
        let Some(dir) = cache_dir(&self.root, name, "remote cache sweep directory")? else {
            return Ok(());
        };
        let mut budget = util::ScanBudget::new("remote cache sweep");
        let mut walk = util::SafeWalk::new(&dir).walk_with(&mut budget);
        for entry in walk.by_ref() {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            if !entry.file_type().is_file() {
                continue;
            }
            let owned = entry.file_name().to_string_lossy();
            if !keep(owned.as_ref()) {
                let _ = util::remove_file(&self.root, entry.path());
            }
        }
        Ok(())
    }
}

fn cache_dir(root: &Path, name: &str, what: &str) -> Result<Option<PathBuf>> {
    let dir = root.join(name);
    match util::probe_dir(&dir, what)? {
        Some(_) => Ok(Some(dir)),
        None => Ok(None),
    }
}

fn read_optional(path: &Path, max_bytes: u64, what: &str) -> Result<Option<Vec<u8>>> {
    if util::probe_file(path, what)?.is_none() {
        return Ok(None);
    }
    #[cfg(test)]
    BEFORE_READ.with(|hook| {
        if let Some(hook) = hook.borrow().as_ref() {
            hook(path);
        }
    });
    match read_capped(path, max_bytes, what) {
        Ok(bytes) => Ok(Some(bytes)),
        // A concurrent sweep may remove the file between the probe and the
        // open; that is a cache miss, not a failed read.
        Err(err) if util::is_not_found(&err) => Ok(None),
        Err(err) => Err(err),
    }
}

fn remove_cached(root: &Path, path: &Path, what: &str) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if util::probe_dir(parent, "remote cache directory")?.is_none() {
        return Ok(());
    }
    util::remove_file(root, path)
        .with_context(|| format!("removing corrupt {what} {}", path.display()))
}

#[cfg(test)]
type ReadHook = Box<dyn Fn(&Path)>;

#[cfg(test)]
thread_local! {
    static BEFORE_READ: std::cell::RefCell<Option<ReadHook>> = std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_before_read(hook: impl Fn(&Path) + 'static) {
    BEFORE_READ.with(|cell| *cell.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn clear_before_read() {
    BEFORE_READ.with(|cell| *cell.borrow_mut() = None);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::{BLOBS_DIR, INDEXES_DIR};
    use std::fs;

    #[test]
    fn a_file_removed_between_probe_and_open_is_a_miss() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("index.json");
        fs::write(&path, b"pointer")?;

        set_before_read(|path| {
            fs::remove_file(path).expect("remove the probed file before the open");
        });
        let result = read_optional(&path, 1024, "index pointer");
        clear_before_read();

        assert!(
            result?.is_none(),
            "a vanished file is a cache miss, not an error"
        );
        Ok(())
    }

    #[test]
    fn sweep_dir_removes_only_unreferenced_files() -> Result<()> {
        let root = tempfile::tempdir()?;
        let blobs = root.path().join(BLOBS_DIR);
        fs::create_dir(&blobs)?;
        fs::write(blobs.join("keep"), b"keep")?;
        fs::write(blobs.join("drop"), b"drop")?;

        let cache = Cache::new(root.path().to_path_buf());
        cache.sweep_dir(BLOBS_DIR, |name| name == "keep")?;

        assert!(blobs.join("keep").exists());
        assert!(!blobs.join("drop").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn remove_body_refuses_a_symlinked_indexes_directory() -> Result<()> {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let sha = "ab".repeat(32);
        let victim = outside.path().join(format!("{sha}.json"));
        fs::write(&victim, b"secret")?;
        symlink(outside.path(), root.path().join(INDEXES_DIR))?;

        let cache = Cache::new(root.path().to_path_buf());
        let err = cache
            .remove_body(&sha)
            .expect_err("a symlinked indexes directory must be refused");
        assert!(format!("{err:#}").contains("symlink/reparse"), "{err:#}");
        assert!(victim.exists(), "the redirected file must not be deleted");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn remove_pointer_refuses_a_symlinked_cache_root() -> Result<()> {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let victim = outside.path().join(super::INDEX_FILE);
        fs::write(&victim, b"secret")?;
        let root = parent.path().join("cache");
        symlink(outside.path(), &root)?;

        let cache = Cache::new(root);
        let err = cache
            .remove_pointer()
            .expect_err("a symlinked cache root must be refused");
        assert!(format!("{err:#}").contains("symlink/reparse"), "{err:#}");
        assert!(victim.exists(), "the redirected file must not be deleted");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn sweep_refuses_a_symlinked_blobs_directory() -> Result<()> {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let victim = outside.path().join("stale");
        fs::write(&victim, b"secret")?;
        symlink(outside.path(), root.path().join(BLOBS_DIR))?;

        let cache = Cache::new(root.path().to_path_buf());
        let err = cache
            .sweep_dir(BLOBS_DIR, |_| false)
            .expect_err("a symlinked blobs directory must be refused");
        assert!(format!("{err:#}").contains("symlink/reparse"), "{err:#}");
        assert!(victim.exists(), "the redirected file must not be deleted");
        Ok(())
    }
}
