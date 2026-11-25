// ── lock: advisory file locks ──

use std::fs::{File, OpenOptions};
use std::path::Path;

use anyhow::{Context, Result};

use super::fs::create_private_dir_all;
#[cfg(windows)]
use super::platform::FILE_FLAG_OPEN_REPARSE_POINT;
use super::platform::is_reparse_point;

/// Advisory exclusive lock on a file. Held for the lifetime of the value.
pub struct FileLock {
    file: File,
}

/// Open an existing lock file without following a symlink/reparse point.
pub(crate) fn open_lock_file(path: &Path) -> Result<File> {
    let mut create = OpenOptions::new();
    create.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        create.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        create.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    match create.open(path) {
        Ok(file) => return Ok(file),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => {
            return Err(err).with_context(|| format!("creating lock {}", path.display()));
        }
    }

    let mut open = OpenOptions::new();
    open.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        open.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = open
        .open(path)
        .with_context(|| format!("opening lock {}", path.display()))?;
    let meta = file.metadata()?;
    if meta.file_type().is_symlink() || is_reparse_point(&meta) {
        anyhow::bail!("refusing symlinked/reparse lock file {}", path.display());
    }
    Ok(file)
}

impl FileLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            create_private_dir_all(parent)?;
        }
        let file = open_lock_file(path)?;
        file.lock()
            .with_context(|| format!("locking {}", path.display()))?;
        Ok(Self { file })
    }

    pub fn try_acquire(path: &Path) -> Result<Option<Self>> {
        if let Some(parent) = path.parent() {
            create_private_dir_all(parent)?;
        }
        let file = open_lock_file(path)?;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Some(Self { file })),
                // A signal from an unrelated child can interrupt the syscall.
                Err(std::fs::TryLockError::Error(err))
                    if err.kind() == std::io::ErrorKind::Interrupted =>
                {
                    continue;
                }
                // Contention (or an unsupported lock): fail closed as "in use".
                Err(_) => return Ok(None),
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}
