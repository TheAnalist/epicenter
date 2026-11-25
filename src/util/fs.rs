// ── fs: path privacy, atomic installs, hashing, copying and removal ──

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

#[cfg(unix)]
use super::nofollow::open_file_nofollow;
use super::nofollow::open_regular;
#[cfg(unix)]
use super::platform::euid;
#[cfg(windows)]
use super::platform::windows_acl_is_private;
use super::platform::{
    Probed, ensure_windows_user_path, metadata_nofollow, owned_by_us, probe, probe_dir, probe_file,
    probe_kind,
};
use super::scan::MAX_FILE_BYTES;

/// Remove a tree robustly: read-only files (a wrapper's store, copies that
/// inherited the read-only attribute) block `remove_dir_all` on Windows, so
/// clear the flag and retry once; report the original error if it still fails.
pub fn force_remove_dir(path: &Path) -> std::io::Result<()> {
    let first = match std::fs::remove_dir_all(path) {
        Ok(()) => return Ok(()),
        Err(err) => err,
    };
    for entry in WalkDir::new(path)
        .follow_links(false)
        .follow_root_links(false)
    {
        let Ok(entry) = entry else { continue };
        // Never follow a symlink here: `set_permissions` on a symlink path
        // changes the *target* (possibly outside this tree).
        if entry.file_type().is_symlink() {
            continue;
        }
        let Ok(meta) = metadata_nofollow(entry.path()) else {
            continue;
        };
        let mut perms = meta.permissions();
        if perms.readonly() {
            // Add only the owner's write bit. `set_readonly(false)` on Unix
            // grants group/world write, which would briefly widen access in a
            // shared parent directory.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                perms = fs::Permissions::from_mode(perms.mode() | 0o200);
            }
            #[cfg(not(unix))]
            perms.set_readonly(false);
            let _ = fs::set_permissions(entry.path(), perms);
        }
    }
    fs::remove_dir_all(path).map_err(|_| first)
}

/// Expand a leading `~` with the user's home; other values pass through.
pub fn expand_tilde(raw: &str) -> Result<PathBuf> {
    let raw = raw.trim();
    if raw == "~" || raw.starts_with("~/") || raw.starts_with("~\\") {
        let rest = raw[1..].trim_start_matches(['/', '\\']);
        return Ok(crate::env::home()?.join(rest));
    }
    Ok(PathBuf::from(raw))
}

/// Expand `~` and resolve a relative path against `base`.
pub fn resolve_from(raw: &str, base: &Path) -> Result<PathBuf> {
    let path = expand_tilde(raw)?;
    Ok(if path.is_absolute() {
        path
    } else {
        base.join(path)
    })
}

/// Reject paths that must never become a deletion/chmod root: the filesystem
/// root, the user's home (or an ancestor), and the system temp directory (or
/// an ancestor).
pub fn reject_protected_path(path: &Path, what: &str) -> Result<()> {
    if path.parent().is_none() || path == Path::new("/") {
        anyhow::bail!("{what} {} must not be a filesystem root", path.display());
    }
    if let Ok(home) = crate::env::home()
        && (path == home || home.starts_with(path))
    {
        anyhow::bail!(
            "{what} {} must not be the home directory or its ancestor",
            path.display()
        );
    }
    let temp = std::env::temp_dir();
    if path == temp || temp.starts_with(path) {
        anyhow::bail!(
            "{what} {} must not be the temporary directory or its ancestor",
            path.display()
        );
    }
    Ok(())
}

fn refuse_destructive_chmod(path: &Path) -> Result<()> {
    reject_protected_path(path, "directory")
        .with_context(|| format!("refusing to make {} private", path.display()))
}

/// Create a directory tree with mode 0700 (Unix), refusing a symlinked or
/// foreign-owned final directory. Existing directories are tightened to 0700.
pub fn create_private_dir_all(path: &Path) -> Result<()> {
    refuse_destructive_chmod(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .with_context(|| format!("creating private directory {}", path.display()))?;
        let Some(meta) = probe_dir(path, "private directory")? else {
            anyhow::bail!("{} is not a real directory", path.display());
        };
        if !owned_by_us(path, &meta) {
            anyhow::bail!(
                "{} is owned by uid {} — refusing to use a cache directory not owned by uid {}",
                path.display(),
                std::os::unix::fs::MetadataExt::uid(&meta),
                euid()
            );
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("securing {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
            .with_context(|| format!("creating private directory {}", path.display()))?;
    }
    Ok(())
}

/// How to handle a directory that is group/world-accessible.
#[derive(Clone, Copy)]
pub enum Privacy {
    /// Tighten the mode to 0700. Windows has no repair path, so a permissive
    /// DACL is always rejected.
    Repair,
    /// Reject instead of tightening.
    Enforce,
}

/// Verify an existing directory is owned by us and owner-only, applying the
/// requested [`Privacy`] policy to a permissive mode.
///
/// `Repair` is for paths where tightening a legacy `0755` directory is safe
/// (store/build/work roots). `Enforce` is for paths where a permissive mode is
/// a security signal: a reused job dir may already have been written by
/// another principal before a chmod could run, so tightening it would hide
/// the exposure.
pub fn check_private_dir(path: &Path, privacy: Privacy) -> Result<()> {
    // Windows has no repair path: a permissive DACL is always rejected.
    #[cfg(not(unix))]
    let _ = privacy;
    refuse_destructive_chmod(path)?;
    let Some(meta) = probe_dir(path, "private directory")? else {
        anyhow::bail!("{} is not a real directory", path.display());
    };
    if !owned_by_us(path, &meta) {
        anyhow::bail!(
            "{} is owned by an untrusted principal — refusing a shared/untrusted directory",
            path.display()
        );
    }
    // set permissions only on unix systems
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.mode() & 0o077 != 0 {
            match privacy {
                Privacy::Repair => {
                    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                        .with_context(|| format!("securing {}", path.display()))?;
                }
                Privacy::Enforce => anyhow::bail!(
                    "{} grants group/world access (mode {:o}) — refusing a shared/untrusted directory",
                    path.display(),
                    meta.mode() & 0o777
                ),
            }
        }
    }
    // only checks is permitted to write
    // does not set permissions.
    #[cfg(windows)]
    if windows_acl_is_private(path) != Some(true) {
        anyhow::bail!(
            "{} DACL grants write access to an untrusted principal",
            path.display()
        );
    }
    Ok(())
}

/// Validate an existing private directory without changing its permissions.
/// Used for a user-supplied Cargo home: it must be a real directory, owned by
/// the current user, writable, and not group/world-writable (owner-only DACL
/// on Windows).
pub fn validate_private_dir(path: &Path, what: &str) -> Result<()> {
    let Some(meta) = probe_dir(path, what)? else {
        anyhow::bail!("{} {} does not exist", what, path.display());
    };
    if !owned_by_us(path, &meta) {
        anyhow::bail!("{} {} is owned by another user", what, path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode() & 0o777;
        if mode & 0o022 != 0 {
            anyhow::bail!(
                "{} {} is group/world-writable (mode {:o})",
                what,
                path.display(),
                mode
            );
        }
        if mode & 0o300 != 0o300 {
            anyhow::bail!(
                "{} {} is not writable by its owner (mode {:o})",
                what,
                path.display(),
                mode
            );
        }
    }
    #[cfg(windows)]
    match windows_acl_is_private(path) {
        Some(true) => {}
        Some(false) => anyhow::bail!(
            "{} {} grants write access outside the owner/SYSTEM/Administrators",
            what,
            path.display()
        ),
        None => anyhow::bail!(
            "{} {} DACL could not be inspected; refusing an unverified directory",
            what,
            path.display()
        ),
    }
    Ok(())
}

/// Check that `base/rel` is a chain of real directories ending in a regular
/// file, with no symlink at any component. Read-only; used before hashing or
/// restoring a store file.
pub fn check_regular_chain(base: &Path, rel: &Path) -> Result<()> {
    let base_meta = match metadata_nofollow(base) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            anyhow::bail!("{} is not a real directory", base.display());
        }
        Err(err) => {
            return Err(err).with_context(|| format!("inspecting {}", base.display()));
        }
    };
    if !base_meta.is_dir() {
        anyhow::bail!("{} is not a real directory", base.display());
    }
    let mut current = base.to_path_buf();
    let components: Vec<_> = rel.components().collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(part) = component else {
            anyhow::bail!("refusing non-normal path component in {}", rel.display());
        };
        current.push(part);
        let meta = match metadata_nofollow(&current) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                anyhow::bail!("symlink/reparse in store path: {}", current.display());
            }
            Err(err) => {
                return Err(err).with_context(|| format!("inspecting {}", current.display()));
            }
        };
        if index + 1 == components.len() {
            if !meta.is_file() {
                anyhow::bail!("not a regular file: {}", current.display());
            }
        } else if !meta.is_dir() {
            anyhow::bail!("not a directory: {}", current.display());
        }
    }
    Ok(())
}

/// Validate a state root and return its canonical path.
///
/// The final component must be a real directory, not a symlink or reparse
/// point. Canonicalizing also resolves any symlink in an ancestor; callers
/// that keep the returned path use the resolved tree for the rest of the
/// operation, so swapping the original link cannot redirect a later write.
pub fn validate_state_root(path: &Path, what: &str) -> Result<PathBuf> {
    ensure_windows_user_path(path, what)?;
    let Some(meta) = probe(path, what)? else {
        anyhow::bail!(
            "{} {} is a symlink/reparse or not a directory",
            what,
            path.display()
        );
    };
    if !meta.is_dir() {
        anyhow::bail!(
            "{} {} is a symlink/reparse or not a directory",
            what,
            path.display()
        );
    }
    let canonical =
        fs::canonicalize(path).with_context(|| format!("resolving {} {}", what, path.display()))?;
    let Some(meta) = probe(&canonical, what)? else {
        anyhow::bail!(
            "resolved {} {} is a symlink/reparse or not a directory",
            what,
            canonical.display()
        );
    };
    if !meta.is_dir() {
        anyhow::bail!(
            "resolved {} {} is a symlink/reparse or not a directory",
            what,
            canonical.display()
        );
    }
    Ok(canonical)
}

pub(crate) fn hash_reader<R: Read>(reader: &mut R) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(unix)]
pub(crate) fn sha256_file_fd(file: &mut File) -> std::io::Result<String> {
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    hash_reader(file)
}

/// Stream a decoded payload into `writer`, hashing it and refusing to grow
/// past `max_size`. Returns the decoded size and SHA-256.
pub(crate) fn copy_capped<R: Read, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    max_size: u64,
    what: &Path,
) -> Result<(u64, String)> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = reader
            .read(&mut buf)
            .with_context(|| format!("decoding {}", what.display()))?;
        if n == 0 {
            break;
        }
        size = size
            .checked_add(n as u64)
            .context("decoded size overflow")?;
        anyhow::ensure!(
            size <= max_size,
            "decoded {} exceeds its recorded size ({max_size} bytes)",
            what.display()
        );
        hasher.update(&buf[..n]);
        writer
            .write_all(&buf[..n])
            .with_context(|| format!("writing {}", what.display()))?;
    }
    Ok((size, format!("{:x}", hasher.finalize())))
}

/// Stream a decoded payload and require the recorded decoded size and hash.
pub(crate) fn copy_verified<R: Read, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    expected_size: u64,
    expected_hash: &str,
    what: &Path,
) -> Result<()> {
    let (size, hash) = copy_capped(reader, writer, expected_size, what)?;
    if size != expected_size || hash != expected_hash {
        anyhow::bail!(
            "blob integrity check failed for {} (recorded {} bytes/{}, found {} bytes/{})",
            what.display(),
            expected_size,
            &expected_hash[..expected_hash.len().min(12)],
            size,
            &hash[..hash.len().min(12)]
        );
    }
    Ok(())
}

/// Try a copy-on-write clone (Linux `FICLONE`). A clone is a **new inode**:
/// it preserves isolation while avoiding duplicate disk blocks on btrfs/XFS/
/// ZFS and other reflink-capable filesystems. `Unsupported`/`EOPNOTSUPP`
/// means the caller should fall back to a verified copy.
#[cfg(target_os = "linux")]
fn try_reflink(src: &File, dst: &File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    // FICLONE is _IOW(0x94, 9, int); libc does not expose it on every
    // version, so keep the stable value local.
    const FICLONE: libc::c_ulong = 0x4004_9409;
    let rc = unsafe { libc::ioctl(dst.as_raw_fd(), FICLONE, src.as_raw_fd()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn try_reflink(_src: &File, _dst: &File) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

#[cfg(unix)]
pub(crate) fn copy_fd_verified(
    src: &mut File,
    dst: &mut File,
    expected_size: u64,
    expected_hash: &str,
) -> Result<(u64, String)> {
    use std::io::{Seek, SeekFrom};
    src.seek(SeekFrom::Start(0))?;
    // Prefer a reflink (new inode, no duplicated blocks). Hash the clone
    // from its own descriptor; a clone is only trusted after verification.
    if try_reflink(src, dst).is_ok() {
        dst.seek(SeekFrom::Start(0))?;
        let hash = sha256_file_fd(dst)?;
        let size = dst.metadata()?.len();
        if size != expected_size || hash != expected_hash {
            anyhow::bail!(
                "integrity check failed (recorded {expected_size} bytes/{}, found {size} bytes/{})",
                &expected_hash[..expected_hash.len().min(12)],
                &hash[..hash.len().min(12)]
            );
        }
        return Ok((size, hash));
    }
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        dst.write_all(&buf[..n])?;
        size += n as u64;
    }
    dst.flush()?;
    let hash = format!("{:x}", hasher.finalize());
    if size != expected_size || hash != expected_hash {
        anyhow::bail!(
            "integrity check failed (recorded {expected_size} bytes/{}, found {size} bytes/{})",
            &expected_hash[..expected_hash.len().min(12)],
            &hash[..hash.len().min(12)]
        );
    }
    Ok((size, hash))
}

/// SHA-256 of a regular file (lowercase hex). The open is no-follow and
/// non-blocking, so a planted link or FIFO cannot redirect or hang the hash.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = open_regular(path, false)?;
    hash_reader(&mut file)
}

/// A random suffix for temp names, so a writer cannot predict and pre-plant
/// the next temp path.
pub(crate) fn temp_nonce() -> u64 {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes)
        .map(|_| u64::from_le_bytes(bytes))
        .unwrap_or(0)
}

/// Create a uniquely named file in `dir`, refusing to follow or replace an
/// existing entry. The mode is applied to the held descriptor on Unix.
pub(crate) fn create_temp(
    dir: &Path,
    prefix: &str,
    suffix: &str,
    mode: u32,
) -> Result<(PathBuf, File)> {
    #[cfg(not(unix))]
    let _ = mode;
    let nonce = temp_nonce();
    let mut last_error = None;
    for attempt in 0..100u32 {
        let path = dir.join(format!(
            ".{prefix}-{}-{nonce}-{attempt}{suffix}",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        match options.open(&path) {
            Ok(file) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    file.set_permissions(fs::Permissions::from_mode(mode))
                        .with_context(|| format!("securing {}", path.display()))?;
                }
                return Ok((path, file));
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                last_error = Some(err);
                break;
            }
        }
    }
    Err(last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("could not create a temp file in {}", dir.display())))
    .with_context(|| format!("creating a temp file in {}", dir.display()))
}

/// Run `write` on a fresh `O_EXCL` temp file in `dir`. The file is closed and
/// its path returned on success; any error (including an error raised by
/// `write`) unlinks the temp so a failed write leaves no debris.
pub(crate) fn with_temp_file<R>(
    dir: &Path,
    prefix: &str,
    suffix: &str,
    mode: u32,
    write: impl FnOnce(&mut File) -> Result<R>,
) -> Result<(PathBuf, R)> {
    let (path, mut file) = create_temp(dir, prefix, suffix, mode)?;
    match write(&mut file) {
        Ok(value) => {
            drop(file);
            Ok((path, value))
        }
        Err(err) => {
            drop(file);
            let _ = fs::remove_file(&path);
            Err(err)
        }
    }
}

/// Create a uniquely named staging directory in `dir`. `O_EXCL` semantics:
/// a pre-planted name is never reused, and the result is private on Unix.
pub(crate) fn create_temp_dir(dir: &Path, prefix: &str) -> Result<PathBuf> {
    let nonce = temp_nonce();
    for attempt in 0..100u32 {
        let path = dir.join(format!(
            ".{prefix}-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        match create_private_dir_excl(&path) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    // `mkdir` mode is masked by umask. Repair a pathological
                    // umask that stripped owner bits, but treat chmod as best
                    // effort: some FUSE/CIFS mounts refuse it, and the mkdir
                    // request already excluded group/other.
                    if let Ok(meta) = fs::symlink_metadata(&path) {
                        if meta.permissions().mode() & 0o700 != 0o700 {
                            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o700));
                        }
                    }
                }
                return Ok(path);
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("creating staging dir {}", path.display()));
            }
        }
    }
    anyhow::bail!("could not create a unique staging dir in {}", dir.display())
}

/// `mkdir` one directory, owner-only from the first instant on Unix.
fn create_private_dir_excl(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
    }
}

/// Create a uniquely named hard link to `src` in `dir`.
pub(crate) fn link_temp(src: &Path, dir: &Path, prefix: &str) -> Result<PathBuf> {
    let nonce = temp_nonce();
    for attempt in 0..100u32 {
        let path = dir.join(format!(
            ".{prefix}-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        match fs::hard_link(src, &path) {
            Ok(()) => return Ok(path),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("linking {} -> {}", src.display(), path.display()));
            }
        }
    }
    anyhow::bail!("could not create a temp hard link in {}", dir.display())
}

/// Atomically replace `dst` with `src`, which must be on the same filesystem.
pub(crate) fn replace_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };
        fn wide(path: &Path) -> Vec<u16> {
            path.as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect()
        }
        let src = wide(src);
        let dst = wide(dst);
        let rc = unsafe {
            MoveFileExW(
                src.as_ptr(),
                dst.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if rc == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    #[cfg(not(windows))]
    {
        fs::rename(src, dst)
    }
}

/// Atomically replace a private config file. The temp is created with
/// `O_EXCL` and mode 0600 in the same directory, then renamed over the
/// target. Renaming replaces a planted symlink instead of following it (on
/// Unix); on Windows a pre-existing symlink is removed first, never followed.
pub fn write_atomic_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    create_private_dir_all(parent)?;
    let base = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config".to_string());
    let (tmp, ()) = with_temp_file(parent, &format!("{base}.tmp"), "", 0o600, |file| {
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })
    .with_context(|| format!("writing {}", path.display()))?;
    // A real directory at the destination is not replaceable, and retrying
    // cannot help. Refuse before touching anything.
    if fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir()) {
        let _ = fs::remove_file(&tmp);
        anyhow::bail!(
            "{} is a directory — refusing to replace it with a file",
            path.display()
        );
    }
    let mut last_error = None;
    for attempt in 0..100u32 {
        match fs::rename(&tmp, path) {
            Ok(()) => return Ok(()),
            Err(err) => {
                // Never delete the destination first: a failed replace must
                // leave the old file intact. A directory at the destination is
                // not replaceable, so retrying cannot help.
                let retryable = err.kind() != std::io::ErrorKind::AlreadyExists;
                last_error = Some(err);
                if retryable && attempt < 99 {
                    continue;
                }
            }
        }
    }
    let _ = fs::remove_file(&tmp);
    Err(last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("could not atomically write {}", path.display())))
    .with_context(|| format!("writing {}", path.display()))
}

/// Copy a regular file into a **new** destination (`O_EXCL`) while hashing it.
/// Refuses symlinks/FIFOs/devices and never follows a destination symlink.
/// Returns (bytes, sha256).
pub fn copy_file_hashed(src: &Path, dst: &Path) -> Result<(u64, String)> {
    copy_file_hashed_mode(src, dst, true)
}

fn copy_file_hashed_mode(src: &Path, dst: &Path, require_owner: bool) -> Result<(u64, String)> {
    let Some(meta) = probe_file(src, "source")? else {
        anyhow::bail!(
            "{} is not a regular file (symlink/special file refused)",
            src.display()
        );
    };
    if require_owner && !owned_by_us(src, &meta) {
        anyhow::bail!(
            "{} is owned by another user — refusing to copy it into the vault",
            src.display()
        );
    }
    if meta.len() > MAX_FILE_BYTES {
        anyhow::bail!(
            "{} is {} bytes (cap {}) — refusing to copy an oversized artifact",
            src.display(),
            meta.len(),
            MAX_FILE_BYTES
        );
    }
    let mut input =
        open_regular(src, false).with_context(|| format!("opening {}", src.display()))?;
    let mut output_options = OpenOptions::new();
    output_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Create the destination private; the store makes it read-only after
        // stamping. Normal umasks leave it owner-writable for the stamp.
        output_options.mode(0o600);
    }
    let mut output = output_options
        .open(dst)
        .with_context(|| format!("creating {}", dst.display()))?;

    if !output.metadata()?.is_file() {
        anyhow::bail!("{} changed type while opening", dst.display());
    }

    // Copy-on-write clone when the filesystem supports it. The clone is a
    // new inode (no shared mutable state) and costs no duplicate blocks.
    if try_reflink(&input, &output).is_ok() {
        let hash = sha256_file(dst).with_context(|| format!("hashing cloned {}", dst.display()))?;
        return Ok((output.metadata()?.len(), hash));
    }

    let mut hasher = Sha256::new();
    // Small enough to keep the 3,000+ tiny fingerprint files cheap; the
    // harvest/restore pools parallelize across unit groups, so large rlibs
    // still keep the disk busy.
    let mut buf = [0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        output.write_all(&buf[..n])?;
        size += n as u64;
    }
    output.flush()?;
    Ok((size, format!("{:x}", hasher.finalize())))
}

/// Files below this size are stored raw; gzip headers would erase the win.
pub(crate) const COMPRESS_MIN_BYTES: u64 = 4 * 1024;

/// Compress one regular owned source into a content-addressed gzip blob.
///
/// The blob lives at `<generation>/blobs/<aa>/<sha256>.gz`. The return is
/// `(raw_size, sha256, object_path)` where `object_path` is relative to the
/// generation root. `None` means the file is too small or gzip did not make
/// it smaller; the caller should store it raw.
pub(crate) fn compress_file_hashed(
    src: &Path,
    generation_root: &Path,
) -> Result<Option<(u64, String, String)>> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let Some(meta) = probe_file(src, "source")? else {
        anyhow::bail!(
            "{} is not a regular file (symlink/special file refused)",
            src.display()
        );
    };
    if !owned_by_us(src, &meta) {
        anyhow::bail!(
            "{} is owned by another user — refusing to compress it into the vault",
            src.display()
        );
    }
    if meta.len() > MAX_FILE_BYTES {
        anyhow::bail!(
            "{} is {} bytes (cap {}) — refusing to compress an oversized artifact",
            src.display(),
            meta.len(),
            MAX_FILE_BYTES
        );
    }
    if meta.len() < COMPRESS_MIN_BYTES {
        return Ok(None);
    }

    let mut input =
        open_regular(src, false).with_context(|| format!("opening {}", src.display()))?;

    let blobs = generation_root.join("blobs");
    create_private_dir_all(&blobs)?;
    let (tmp_path, (sha, size, compressed_size)) =
        with_temp_file(&blobs, "tmp", ".gz", 0o600, |file| {
            let mut encoder = GzEncoder::new(&mut *file, Compression::fast());
            let mut hasher = Sha256::new();
            let mut buf = [0u8; 64 * 1024];
            let mut size = 0u64;
            loop {
                let n = input.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                encoder.write_all(&buf[..n])?;
                size += n as u64;
            }
            encoder.finish()?;
            file.sync_all()?;
            let compressed_size = file.metadata()?.len();
            Ok((format!("{:x}", hasher.finalize()), size, compressed_size))
        })
        .with_context(|| format!("compressing {}", src.display()))?;
    if compressed_size >= size {
        let _ = fs::remove_file(&tmp_path);
        return Ok(None);
    }

    let object = format!("blobs/{}/{sha}.gz", &sha[..2]);
    let final_path = generation_root.join(&object);
    if let Some(parent) = final_path.parent() {
        create_private_dir_all(parent)?;
    }
    // The blob name is its content hash. Never follow or replace a planted
    // symlink, and never silently accept bytes that do not match the name.
    let mut install = true;
    let existing = match probe_kind(&final_path) {
        Ok(probed) => probed,
        Err(err) => {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }
    };
    match existing {
        Probed::Real(meta) => {
            if !meta.is_file() {
                let _ = fs::remove_file(&tmp_path);
                anyhow::bail!(
                    "blob path {} is a symlink/reparse or not a regular file",
                    final_path.display()
                );
            }
            // The name is the hash of the *decoded* content, so hash the
            // blob after decompression; hashing the gzip bytes would reject
            // every duplicate artifact in the same harvest.
            let verified = decompress_file_hashed(&final_path, true, size)
                .with_context(|| format!("verifying existing blob {}", final_path.display()));
            let (existing_size, existing_sha) = match verified {
                Ok(pair) => pair,
                Err(err) => {
                    let _ = fs::remove_file(&tmp_path);
                    return Err(err);
                }
            };
            if existing_size != size || existing_sha != sha {
                let _ = fs::remove_file(&tmp_path);
                anyhow::bail!(
                    "content-addressed blob {} does not match its name",
                    final_path.display()
                );
            }
            install = false;
            let _ = fs::remove_file(&tmp_path);
        }
        Probed::Reparse => {
            let _ = fs::remove_file(&tmp_path);
            anyhow::bail!(
                "blob path {} is a symlink/reparse or not a regular file",
                final_path.display()
            );
        }
        Probed::Missing => {}
    }
    if install {
        match fs::rename(&tmp_path, &final_path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&tmp_path);
                let meta = match metadata_nofollow(&final_path) {
                    Ok(meta) => meta,
                    Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                        anyhow::bail!("blob path {} is not a regular file", final_path.display());
                    }
                    Err(err) => {
                        return Err(err)
                            .with_context(|| format!("inspecting {}", final_path.display()));
                    }
                };
                if !meta.is_file() {
                    anyhow::bail!("blob path {} is not a regular file", final_path.display());
                }
                let (existing_size, existing_sha) = decompress_file_hashed(&final_path, true, size)
                    .with_context(|| format!("verifying blob {}", final_path.display()))?;
                if existing_size != size || existing_sha != sha {
                    anyhow::bail!(
                        "content-addressed blob {} does not match its name",
                        final_path.display()
                    );
                }
            }
            Err(err) => {
                let _ = fs::remove_file(&tmp_path);
                return Err(err).with_context(|| format!("installing {}", final_path.display()));
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file = open_file_nofollow(&final_path)
            .with_context(|| format!("opening blob {}", final_path.display()))?;
        file.set_permissions(fs::Permissions::from_mode(0o444))
            .with_context(|| format!("securing blob {}", final_path.display()))?;
    }
    Ok(Some((size, sha, object)))
}

/// Hash the decoded content of a gzip blob.
pub(crate) fn decompress_file_hashed(
    src: &Path,
    require_owner: bool,
    max_size: u64,
) -> Result<(u64, String)> {
    use flate2::read::GzDecoder;
    let Some(meta) = probe(src, "blob")? else {
        anyhow::bail!("{} is not a regular blob", src.display());
    };
    if !meta.is_file() {
        anyhow::bail!("{} is not a regular blob", src.display());
    }
    if require_owner && !owned_by_us(src, &meta) {
        anyhow::bail!("{} is owned by another user", src.display());
    }
    let mut input =
        open_regular(src, false).with_context(|| format!("opening {}", src.display()))?;
    let mut decoder = GzDecoder::new(&mut input);
    copy_capped(&mut decoder, &mut std::io::sink(), max_size, src)
}

/// Decompress a blob into a new file and verify its decoded size/hash.
///
/// `dst` is created with `create_new`; creation failures keep their
/// `io::ErrorKind` (notably `AlreadyExists`) instead of being turned into an
/// integrity error. Once `dst` has been created, a decode/write/integrity
/// failure removes the file this call created and returns the specific error.
/// Callers must not unlink `dst` themselves on an error: only this function
/// knows whether the destination belonged to this operation.
#[cfg(not(unix))]
pub(crate) fn decompress_file_verified(
    src: &Path,
    dst: &Path,
    expected_size: u64,
    expected_hash: &str,
) -> Result<()> {
    use flate2::read::GzDecoder;
    if expected_size > MAX_FILE_BYTES {
        anyhow::bail!(
            "blob {} records {} bytes (cap {}) — refusing to decompress",
            src.display(),
            expected_size,
            MAX_FILE_BYTES
        );
    }
    let mut input =
        open_regular(src, false).with_context(|| format!("opening blob {}", src.display()))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)
        .with_context(|| format!("creating {}", dst.display()))?;
    let mut decoder = GzDecoder::new(&mut input);
    let result = (|| -> Result<()> {
        copy_verified(&mut decoder, &mut output, expected_size, expected_hash, src)?;
        output
            .flush()
            .with_context(|| format!("flushing {}", dst.display()))?;
        Ok(())
    })();
    if let Err(err) = result {
        let _ = fs::remove_file(dst);
        return Err(err);
    }
    Ok(())
}

/// (nominal, actually freed, released, file count) of a set of paths about to
/// be unlinked. A file frees its bytes only when every one of its links is in
/// the set; inodes are counted once, so hard links never inflate the total.
pub(crate) fn account_files(files: &[PathBuf]) -> (u64, u64, u64, u64) {
    #[cfg(unix)]
    {
        use std::collections::{HashMap, HashSet};
        use std::os::unix::fs::MetadataExt;

        let mut per_inode: HashMap<(u64, u64), (u64, u64, u64)> = HashMap::new();
        let mut seen: HashSet<&Path> = HashSet::new();
        let mut count = 0u64;
        for path in files {
            if !seen.insert(path.as_path()) {
                continue;
            }
            let Ok(meta) = fs::metadata(path) else {
                continue;
            };
            count += 1;
            let entry =
                per_inode
                    .entry((meta.dev(), meta.ino()))
                    .or_insert((meta.len(), meta.nlink(), 0));
            entry.2 += 1;
        }
        let mut nominal = 0u64;
        let mut freed = 0u64;
        for (size, links, planned) in per_inode.values() {
            nominal = nominal.saturating_add(*size);
            if planned >= links {
                freed = freed.saturating_add(*size);
            }
        }
        (nominal, freed, nominal.saturating_sub(freed), count)
    }
    #[cfg(windows)]
    {
        use std::collections::{HashMap, HashSet};

        // NTFS reports the volume/file index and link count; dedupe by inode
        // exactly like the Unix branch. A filesystem that cannot report them
        // is treated as one link per path (fail-open, never over-credits a
        // released link as freed).
        let mut per_inode: HashMap<(u32, u64), (u64, u64, u64)> = HashMap::new();
        let mut seen: HashSet<&Path> = HashSet::new();
        let mut count = 0u64;
        for path in files {
            if !seen.insert(path.as_path()) {
                continue;
            }
            let Ok(meta) = fs::metadata(path) else {
                continue;
            };
            count += 1;
            let (key, size, links) = match windows_file_identity(path) {
                Some((volume, index, links, size)) => ((volume, index), size, u64::from(links)),
                None => ((0, u64::MAX - count), meta.len(), 1),
            };
            let entry = per_inode.entry(key).or_insert((size, links, 0));
            entry.2 += 1;
        }
        let mut nominal = 0u64;
        let mut freed = 0u64;
        for (size, links, planned) in per_inode.values() {
            nominal = nominal.saturating_add(*size);
            if planned >= links {
                freed = freed.saturating_add(*size);
            }
        }
        (nominal, freed, nominal.saturating_sub(freed), count)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let mut seen: std::collections::HashSet<&Path> = std::collections::HashSet::new();
        let mut nominal = 0u64;
        let mut count = 0u64;
        for path in files {
            if !seen.insert(path.as_path()) {
                continue;
            }
            if let Ok(meta) = fs::metadata(path) {
                nominal = nominal.saturating_add(meta.len());
                count = count.saturating_add(1);
            }
        }
        (nominal, nominal, 0, count)
    }
}

/// Volume serial, file index, link count and size for one path.
///
/// `std`'s `MetadataExt` file-index helpers are still unstable, so ask the
/// kernel directly through the handle we already open.
#[cfg(windows)]
pub(crate) fn windows_file_identity(path: &Path) -> Option<(u32, u64, u32, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let file = fs::File::open(path).ok()?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return None;
    }
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    Some((
        info.dwVolumeSerialNumber,
        index,
        info.nNumberOfLinks,
        file.metadata().ok()?.len(),
    ))
}

/// Stable per-filesystem identity for hard-link dedupe.
pub(crate) fn file_identity(path: &Path, meta: &Metadata) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = path;
        Some((meta.dev(), meta.ino()))
    }
    #[cfg(windows)]
    {
        let _ = meta;
        windows_file_identity(path).map(|(volume, index, _, _)| (u64::from(volume), index))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, meta);
        None
    }
}

/// Hard-link a regular owned source into a new destination while hashing it.
///
/// `None` means the filesystem cannot link the pair (for example across
/// devices); the caller should copy instead. The source and destination must
/// be on one filesystem, and the destination is verified to be the same
/// regular inode before its content is hashed.
#[cfg(unix)]
pub fn try_link_file_hashed(src: &Path, dst: &Path) -> Result<Option<(u64, String)>> {
    use std::os::unix::fs::MetadataExt;

    let Some(before) = probe_file(src, "source")? else {
        anyhow::bail!(
            "{} is not a regular file (symlink/special file refused)",
            src.display()
        );
    };
    if !owned_by_us(src, &before) {
        anyhow::bail!(
            "{} is owned by another user — refusing to link it into the vault",
            src.display()
        );
    }

    match fs::hard_link(src, dst) {
        Ok(()) => {}
        Err(err) if link_fallback(&err) => return Ok(None),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("linking {} -> {}", src.display(), dst.display()));
        }
    }

    let after = match metadata_nofollow(dst) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            let _ = fs::remove_file(dst);
            return Ok(None);
        }
        Err(err) => {
            return Err(err).with_context(|| format!("inspecting linked file {}", dst.display()));
        }
    };
    if !after.is_file()
        || !owned_by_us(dst, &after)
        || after.dev() != before.dev()
        || after.ino() != before.ino()
    {
        let _ = fs::remove_file(dst);
        return Ok(None);
    }

    let size = after.len();
    let hash =
        sha256_file(dst).with_context(|| format!("hashing linked file {}", dst.display()))?;
    Ok(Some((size, hash)))
}

#[cfg(unix)]
pub(crate) fn link_fallback(err: &std::io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EXDEV)
            | Some(libc::EPERM)
            | Some(libc::EMLINK)
            | Some(libc::ENOSYS)
            | Some(libc::EOPNOTSUPP)
    )
}

/// Copy + verify a recorded size/hash. On mismatch the new destination is
/// removed and the operation fails (never installs unverified bytes).
pub fn copy_file_verified(
    src: &Path,
    dst: &Path,
    expected_size: u64,
    expected_hash: &str,
) -> Result<(u64, String)> {
    copy_file_verified_mode(src, dst, expected_size, expected_hash, true)
}

/// Copy a verified file whose source may be foreign-owned. Use only after the
/// store's read-only, signature-verified reader policy has accepted it.
pub fn copy_file_verified_unowned(
    src: &Path,
    dst: &Path,
    expected_size: u64,
    expected_hash: &str,
) -> Result<(u64, String)> {
    copy_file_verified_mode(src, dst, expected_size, expected_hash, false)
}

fn copy_file_verified_mode(
    src: &Path,
    dst: &Path,
    expected_size: u64,
    expected_hash: &str,
    require_owner: bool,
) -> Result<(u64, String)> {
    if expected_hash.is_empty() {
        anyhow::bail!(
            "{} has no recorded SHA-256 (re-harvest the vault before restoring)",
            src.display()
        );
    }
    let (size, hash) = copy_file_hashed_mode(src, dst, require_owner)?;
    if size != expected_size || hash != expected_hash {
        let _ = fs::remove_file(dst);
        anyhow::bail!(
            "integrity check failed for {} (recorded {} bytes/{}, found {} bytes/{})",
            src.display(),
            expected_size,
            &expected_hash[..expected_hash.len().min(12)],
            size,
            &hash[..hash.len().min(12)]
        );
    }
    Ok((size, hash))
}

/// Verify that `path` is a regular file of exactly `size` bytes whose SHA-256
/// is `sha256`. `what` names the object in errors (e.g. "CAS object").
pub(crate) fn verify_file_hash(path: &Path, size: u64, sha256: &str, what: &str) -> Result<()> {
    let meta =
        metadata_nofollow(path).with_context(|| format!("inspecting {what} {}", path.display()))?;
    anyhow::ensure!(
        meta.is_file(),
        "{what} {} is not a regular file",
        path.display()
    );
    anyhow::ensure!(
        meta.len() == size,
        "{what} {} has the wrong size (expected {size}, found {})",
        path.display(),
        meta.len()
    );
    anyhow::ensure!(
        sha256_file(path)? == sha256,
        "{what} {} failed its SHA-256 check",
        path.display()
    );
    Ok(())
}
