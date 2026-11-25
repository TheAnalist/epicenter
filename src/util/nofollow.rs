// ── nofollow: handle-based traversal without following links ──

use std::fs::{self, File, OpenOptions};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

#[cfg(unix)]
use super::platform::io_error;
#[cfg(windows)]
use super::platform::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ_WRITE,
    windows_no_reparse,
};
use super::platform::{is_not_found, is_reparse_point, metadata_nofollow};

/// Keeps Windows directory handles alive through the following file install.
#[derive(Default)]
pub struct DirChainGuard {
    #[cfg(windows)]
    #[allow(dead_code)] // held for its RAII side effect
    handles: Vec<File>,
}

/// Create a directory chain under an existing `base` without following any
/// symlink component. `rel` must already have been validated (only normal
/// components). New components are 0700. Keep the returned guard alive until
/// the file is installed; on Windows it prevents a parent rename/junction swap.
pub fn create_dir_chain_nofollow(base: &Path, rel: &Path) -> Result<DirChainGuard> {
    #[cfg(windows)]
    {
        return create_dir_chain_windows(base, rel);
    }
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
    for component in rel.components() {
        let Component::Normal(part) = component else {
            anyhow::bail!("refusing non-normal path component in {}", rel.display());
        };
        current.push(part);
        match metadata_nofollow(&current) {
            Ok(meta) => {
                if !meta.is_dir() {
                    anyhow::bail!("not a directory: {}", current.display());
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                anyhow::bail!("symlink/reparse in destination path: {}", current.display());
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    match fs::DirBuilder::new().mode(0o700).create(&current) {
                        Ok(()) => {}
                        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                            // Another worker created it between the lookup and
                            // mkdir; accept a real directory, never a link.
                            let meta = match metadata_nofollow(&current) {
                                Ok(meta) => meta,
                                Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                                    anyhow::bail!(
                                        "symlink/reparse in destination path: {}",
                                        current.display()
                                    );
                                }
                                Err(err) => {
                                    return Err(err).with_context(|| {
                                        format!("inspecting {}", current.display())
                                    });
                                }
                            };
                            if !meta.is_dir() {
                                anyhow::bail!(
                                    "symlink/reparse in destination path: {}",
                                    current.display()
                                );
                            }
                        }
                        Err(err) => {
                            return Err(err)
                                .with_context(|| format!("creating {}", current.display()));
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    match fs::create_dir(&current) {
                        Ok(()) => {}
                        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                            // Parallel restore workers race here on Windows.
                            let meta = match metadata_nofollow(&current) {
                                Ok(meta) => meta,
                                Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                                    anyhow::bail!(
                                        "symlink/reparse in destination path: {}",
                                        current.display()
                                    );
                                }
                                Err(err) => {
                                    return Err(err).with_context(|| {
                                        format!("inspecting {}", current.display())
                                    });
                                }
                            };
                            if !meta.is_dir() {
                                anyhow::bail!(
                                    "symlink/reparse in destination path: {}",
                                    current.display()
                                );
                            }
                        }
                        Err(err) => {
                            return Err(err)
                                .with_context(|| format!("creating {}", current.display()));
                        }
                    }
                }
            }
            Err(err) => {
                return Err(err).with_context(|| format!("inspecting {}", current.display()));
            }
        }
    }
    Ok(DirChainGuard::default())
}

#[cfg(windows)]
fn open_dir_handle(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    let file = fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("opening directory handle {}", path.display()))?;
    let meta = file.metadata()?;
    if !meta.is_dir() || meta.file_type().is_symlink() || is_reparse_point(&meta) {
        anyhow::bail!("{} is not a real directory", path.display());
    }
    Ok(file)
}

#[cfg(windows)]
fn create_dir_chain_windows(base: &Path, rel: &Path) -> Result<DirChainGuard> {
    // Hold a handle for every parent. Windows refuses to rename/delete a
    // directory while a handle without FILE_SHARE_DELETE is open, so a
    // directory->junction swap cannot redirect a later write.
    let mut handles = vec![open_dir_handle(base)?];
    let mut current = base.to_path_buf();
    for component in rel.components() {
        let Component::Normal(part) = component else {
            anyhow::bail!("refusing non-normal path component in {}", rel.display());
        };
        current.push(part);
        match open_dir_handle(&current) {
            Ok(file) => handles.push(file),
            Err(err) if is_not_found(&err) => {
                match fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(err) => {
                        return Err(err).with_context(|| format!("creating {}", current.display()));
                    }
                }
                handles.push(open_dir_handle(&current)?);
            }
            Err(err) => return Err(err),
        }
    }
    Ok(DirChainGuard { handles })
}

/// Capability-style directory handle for Unix restore. All child lookups
/// use openat()/mkdirat() with O_NOFOLLOW, and final installs use linkat(),
/// so a directory swapped for a symlink between a path check and the write
/// cannot redirect the operation.
#[cfg(unix)]
pub(crate) struct AtDir {
    file: File,
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum EntryKind {
    Directory,
    Other,
}

#[cfg(unix)]
impl AtDir {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::FromRawFd;
        let name = CString::new(path.as_os_str().as_bytes())
            .with_context(|| format!("path contains NUL: {}", path.display()))?;
        let fd = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("opening directory {}", path.display()));
        }
        Ok(Self {
            file: unsafe { File::from_raw_fd(fd) },
        })
    }

    pub(crate) fn open_or_create_child(&self, name: &std::ffi::OsStr) -> Result<Self> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::FromRawFd;
        let cname = CString::new(name.as_bytes())
            .with_context(|| format!("path component contains NUL: {:?}", name))?;
        loop {
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    cname.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd >= 0 {
                return Ok(Self {
                    file: unsafe { File::from_raw_fd(fd) },
                });
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::NotFound {
                return Err(err).with_context(|| format!("opening child {:?}", name));
            }
            let made = unsafe { libc::mkdirat(self.file.as_raw_fd(), cname.as_ptr(), 0o700) };
            if made != 0 {
                let mkerr = std::io::Error::last_os_error();
                // Another process may have created it; retry the open.
                if mkerr.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(mkerr).with_context(|| format!("creating child {:?}", name));
                }
            }
        }
    }

    /// Does `name` exist? A symlink/reparse is an error, never "existing".
    pub(crate) fn exists(&self, name: &std::ffi::OsStr) -> Result<bool> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::FromRawFd;
        let cname = CString::new(name.as_bytes())
            .with_context(|| format!("path component contains NUL: {:?}", name))?;
        #[cfg(target_os = "linux")]
        let flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let fd = unsafe { libc::openat(self.file.as_raw_fd(), cname.as_ptr(), flags) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::NotFound {
                return Ok(false);
            }
            return Err(err).with_context(|| format!("inspecting child {:?}", name));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file
            .metadata()
            .with_context(|| format!("inspecting child {:?}", name))?;
        if meta.file_type().is_symlink() || is_reparse_point(&meta) {
            anyhow::bail!("symlink/reparse in destination path: {:?}", name);
        }
        Ok(true)
    }

    /// Open an existing child directory without creating it or following a
    /// symlink/reparse point.
    pub(crate) fn open_child(&self, name: &std::ffi::OsStr) -> Result<Self> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::FromRawFd;
        let cname = CString::new(name.as_bytes())
            .with_context(|| format!("path component contains NUL: {:?}", name))?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                cname.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("opening child {:?}", name));
        }
        Ok(Self {
            file: unsafe { File::from_raw_fd(fd) },
        })
    }

    fn entry_kind(&self, name: &std::ffi::OsStr) -> Result<Option<EntryKind>> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let cname = CString::new(name.as_bytes())
            .with_context(|| format!("path component contains NUL: {:?}", name))?;
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                self.file.as_raw_fd(),
                cname.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(err).with_context(|| format!("inspecting child {:?}", name));
        }
        if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
            Ok(Some(EntryKind::Directory))
        } else {
            Ok(Some(EntryKind::Other))
        }
    }

    fn read_names(&self) -> Result<Vec<std::ffi::OsString>> {
        use std::ffi::{CStr, OsString};
        use std::os::unix::ffi::OsStringExt;
        let dup = unsafe { libc::dup(self.file.as_raw_fd()) };
        if dup < 0 {
            return Err(std::io::Error::last_os_error()).context("duplicating directory fd");
        }
        let dir = unsafe { libc::fdopendir(dup) };
        if dir.is_null() {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(dup) };
            return Err(err).context("opening directory stream");
        }
        let mut names = Vec::new();
        loop {
            let entry = unsafe { libc::readdir(dir) };
            if entry.is_null() {
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            let bytes = name.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            names.push(OsString::from_vec(bytes.to_vec()));
        }
        unsafe { libc::closedir(dir) };
        Ok(names)
    }

    fn remove_entry(&self, name: &std::ffi::OsStr) -> Result<()> {
        match self.unlink(name) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).with_context(|| format!("removing child {:?}", name)),
        }
    }

    fn remove_dir_entry(&self, name: &std::ffi::OsStr) -> Result<()> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let cname = CString::new(name.as_bytes())
            .with_context(|| format!("path component contains NUL: {:?}", name))?;
        let rc =
            unsafe { libc::unlinkat(self.file.as_raw_fd(), cname.as_ptr(), libc::AT_REMOVEDIR) };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        Err(err).with_context(|| format!("removing directory {:?}", name))
    }

    /// Remove one entry relative to this directory. A directory is opened with
    /// O_NOFOLLOW and enumerated through its fd; a symlink/reparse entry is
    /// unlinked itself, never followed.
    fn remove_tree_entry(&self, name: &std::ffi::OsStr) -> Result<()> {
        match self.entry_kind(name)? {
            None => Ok(()),
            Some(EntryKind::Other) => self.remove_entry(name),
            Some(EntryKind::Directory) => {
                let child = match self.open_child(name) {
                    Ok(child) => child,
                    Err(err) if is_nofollow_open_error(&err) => {
                        // The name changed to a symlink/non-directory after the
                        // lookup. Remove the entry itself; never follow it.
                        return self.remove_entry(name);
                    }
                    Err(err) => return Err(err),
                };
                for child_name in child.read_names()? {
                    child.remove_tree_entry(&child_name)?;
                }
                match self.remove_dir_entry(name) {
                    Ok(()) => Ok(()),
                    // The directory was replaced by a non-directory. Remove the
                    // replacement entry itself, but never recurse into it.
                    Err(err) if is_not_dir_error(&err) => self.remove_entry(name),
                    Err(err) => Err(err),
                }
            }
        }
    }

    /// Link the exact inode behind an already-open, hashed source descriptor.
    /// Linux exposes the held fd through /proc/self/fd, so a concurrent path
    /// swap in the store cannot substitute another inode between the hash
    /// check and the link. Other Unix platforms copy instead.
    #[cfg(target_os = "linux")]
    pub(crate) fn link_fd(&self, source: &File, dst_name: &std::ffi::OsStr) -> std::io::Result<()> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::AsRawFd;
        let src = CString::new(format!("/proc/self/fd/{}", source.as_raw_fd()))
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let dst = CString::new(dst_name.as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let rc = unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                src.as_ptr(),
                self.file.as_raw_fd(),
                dst.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn link_fd(
        &self,
        _source: &File,
        _dst_name: &std::ffi::OsStr,
    ) -> std::io::Result<()> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    pub(crate) fn create_excl(&self, name: &std::ffi::OsStr, mode: u32) -> Result<File> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::FromRawFd;
        let cname = CString::new(name.as_bytes())
            .with_context(|| format!("temporary name contains NUL: {:?}", name))?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                cname.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("creating temporary {:?}", name));
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub(crate) fn unlink(&self, name: &std::ffi::OsStr) -> std::io::Result<()> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let cname = CString::new(name.as_bytes())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in name"))?;
        let rc = unsafe { libc::unlinkat(self.file.as_raw_fd(), cname.as_ptr(), 0) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(unix)]
fn is_nofollow_open_error(err: &anyhow::Error) -> bool {
    io_error(err)
        .and_then(std::io::Error::raw_os_error)
        .is_some_and(|code| code == libc::ELOOP || code == libc::ENOTDIR)
}

#[cfg(unix)]
fn is_not_dir_error(err: &anyhow::Error) -> bool {
    io_error(err)
        .and_then(std::io::Error::raw_os_error)
        .is_some_and(|code| code == libc::ENOTDIR)
}

/// Relative components of `target` under `root`, rejecting `..`, absolute
/// targets, and the root itself. Both paths must name the same tree.
fn relative_under(root: &Path, target: &Path) -> Result<PathBuf> {
    let rel = target
        .strip_prefix(root)
        .with_context(|| format!("{} is outside {}", target.display(), root.display()))?;
    let mut out = PathBuf::new();
    for component in rel.components() {
        match component {
            Component::Normal(name) => out.push(name),
            Component::CurDir => {}
            _ => anyhow::bail!("refusing non-normal component in {}", target.display()),
        }
    }
    if out.as_os_str().is_empty() {
        anyhow::bail!("refusing to remove the root {}", root.display());
    }
    Ok(out)
}

/// Open a directory by absolute path, walking every component with
/// `O_NOFOLLOW`. The returned handle pins the directory object; a later rename
/// or symlink swap of the path cannot redirect operations on the handle.
#[cfg(unix)]
fn open_dir_path(path: &Path) -> Result<AtDir> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolving the current directory")?
            .join(path)
    };
    let mut dir = AtDir::open(Path::new("/"))?;
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => dir = dir.open_child(name)?,
            _ => anyhow::bail!("refusing non-normal component in {}", absolute.display()),
        }
    }
    Ok(dir)
}

/// Walk from a pinned root to the parent of `target`.
#[cfg(unix)]
fn open_parent_at(root: &Path, target: &Path) -> Result<Option<(AtDir, std::ffi::OsString)>> {
    let rel = relative_under(root, target)?;
    let mut dir = open_dir_path(root)?;
    let mut components = rel.components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            anyhow::bail!("refusing non-normal component in {}", target.display());
        };
        if components.peek().is_none() {
            return Ok(Some((dir, name.to_os_string())));
        }
        match dir.open_child(name) {
            Ok(child) => dir = child,
            Err(err) if is_not_found(&err) || is_nofollow_open_error(&err) => {
                return Ok(None);
            }
            Err(err) => {
                return Err(err).with_context(|| format!("opening parent of {}", target.display()));
            }
        }
    }
    Ok(None)
}

/// Remove a file or directory tree under `root` without following a symlink or
/// reparse point at any component. On Unix every lookup is `openat`-relative to
/// a held directory fd; on Windows the root and parent components are pinned
/// with no-delete-share handles, checked with `metadata_nofollow`, and reparse
/// entries are removed as links, never traversed.
///
/// A missing target, or a parent that is no longer a real directory, is a
/// successful no-op: the path cannot be safely resolved.
pub(crate) fn remove_tree(root: &Path, target: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let rel = relative_under(root, target)?;
        let mut dir = open_dir_path(root)?;
        let mut components = rel.components().peekable();
        while let Some(component) = components.next() {
            let Component::Normal(name) = component else {
                anyhow::bail!("refusing non-normal component in {}", target.display());
            };
            if components.peek().is_none() {
                return dir
                    .remove_tree_entry(name)
                    .with_context(|| format!("removing {}", target.display()));
            }
            match dir.open_child(name) {
                Ok(child) => dir = child,
                Err(err) if is_not_found(&err) || is_nofollow_open_error(&err) => {
                    return Ok(());
                }
                Err(err) => {
                    return Err(err)
                        .with_context(|| format!("opening parent of {}", target.display()));
                }
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let rel = relative_under(root, target)?;
        #[cfg(windows)]
        let Some(_pins) = pin_parent_handles_or_missing(root, &rel)? else {
            return Ok(());
        };
        check_parent_components(root, &rel)?;
        remove_tree_path(target)
    }
}

/// Remove one file (or a symlink/reparse entry) under `root`.
pub(crate) fn remove_file(root: &Path, target: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        match open_parent_at(root, target)? {
            Some((dir, name)) => dir.remove_entry(&name),
            None => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        let rel = relative_under(root, target)?;
        #[cfg(windows)]
        let Some(_pins) = pin_parent_handles_or_missing(root, &rel)? else {
            return Ok(());
        };
        check_parent_components(root, &rel)?;
        match std::fs::symlink_metadata(target) {
            Ok(meta) if meta.is_dir() => {
                anyhow::bail!("{} is a directory", target.display());
            }
            Ok(_) => std::fs::remove_file(target)
                .with_context(|| format!("removing {}", target.display())),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).with_context(|| format!("inspecting {}", target.display())),
        }
    }
}

/// Remove one empty directory under `root`; a non-empty directory is an error.
pub(crate) fn remove_empty_dir(root: &Path, target: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        match open_parent_at(root, target)? {
            Some((dir, name)) => dir.remove_dir_entry(&name),
            None => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        let rel = relative_under(root, target)?;
        #[cfg(windows)]
        let Some(_pins) = pin_parent_handles_or_missing(root, &rel)? else {
            return Ok(());
        };
        check_parent_components(root, &rel)?;
        match std::fs::symlink_metadata(target) {
            Ok(meta) if meta.is_dir() => std::fs::remove_dir(target)
                .with_context(|| format!("removing {}", target.display())),
            Ok(_) => anyhow::bail!("{} is not a directory", target.display()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).with_context(|| format!("inspecting {}", target.display())),
        }
    }
}

/// Hold Windows directory handles for the root and every parent component.
/// The handles use `FILE_SHARE_READ_WRITE` (no delete share), so another
/// process cannot rename or delete those directories while the deletion runs.
#[cfg(windows)]
fn pin_parent_handles(root: &Path, rel: &Path) -> Result<Vec<File>> {
    let mut handles = Vec::new();
    let mut current = root.to_path_buf();
    handles.push(open_dir_handle(&current)?);
    let count = rel.components().count();
    for (index, component) in rel.components().enumerate() {
        let Component::Normal(name) = component else {
            anyhow::bail!("refusing non-normal component in {}", rel.display());
        };
        if index + 1 == count {
            break;
        }
        current.push(name);
        handles.push(open_dir_handle(&current)?);
    }
    Ok(handles)
}

/// `None` when a parent is already gone: the target cannot exist, so removal
/// is a successful no-op (same contract as the Unix `open_parent_at` path).
#[cfg(windows)]
fn pin_parent_handles_or_missing(root: &Path, rel: &Path) -> Result<Option<Vec<File>>> {
    match pin_parent_handles(root, rel) {
        Ok(pins) => Ok(Some(pins)),
        Err(err) if is_not_found(&err) => Ok(None),
        Err(err) => Err(err),
    }
}

#[cfg(not(unix))]
fn check_parent_components(root: &Path, rel: &Path) -> Result<()> {
    match metadata_nofollow(root) {
        Ok(meta) if meta.is_dir() => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            anyhow::bail!("{} is a symlink/reparse point", root.display());
        }
        Ok(_) => anyhow::bail!("{} is not a directory", root.display()),
        Err(err) => return Err(err).with_context(|| format!("inspecting {}", root.display())),
    }
    let count = rel.components().count();
    let mut current = root.to_path_buf();
    for (index, component) in rel.components().enumerate() {
        let Component::Normal(name) = component else {
            anyhow::bail!("refusing non-normal component in {}", rel.display());
        };
        if index + 1 == count {
            break;
        }
        current.push(name);
        match metadata_nofollow(&current) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => anyhow::bail!("{} is not a directory", current.display()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                anyhow::bail!("{} is a symlink/reparse point", current.display());
            }
            Err(err) => {
                return Err(err).with_context(|| format!("inspecting {}", current.display()));
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn open_delete_dir_handle(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const GENERIC_READ: u32 = 0x8000_0000;
    const DELETE: u32 = 0x0001_0000;
    let file = fs::OpenOptions::new()
        .access_mode(GENERIC_READ | DELETE)
        .share_mode(FILE_SHARE_READ_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("opening directory handle {}", path.display()))?;
    let meta = file.metadata()?;
    if !meta.is_dir() || meta.file_type().is_symlink() || is_reparse_point(&meta) {
        anyhow::bail!("{} is not a real directory", path.display());
    }
    Ok(file)
}

#[cfg(windows)]
fn mark_delete_on_close(file: &File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
    };
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as _,
            FileDispositionInfo,
            &info as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error()).context("marking entry for deletion");
    }
    Ok(())
}

/// Remove a non-directory entry through a held handle. The handle pins the
/// exact object, so a rename/replacement after the type check cannot redirect
/// the delete to another file. `FILE_FLAG_OPEN_REPARSE_POINT` makes a junction
/// or symlink delete the link itself, never its target.
#[cfg(windows)]
fn remove_entry_by_handle(target: &Path) -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    const GENERIC_READ: u32 = 0x8000_0000;
    const DELETE: u32 = 0x0001_0000;
    let file = fs::OpenOptions::new()
        .access_mode(GENERIC_READ | DELETE)
        .share_mode(FILE_SHARE_READ_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(target)
        .with_context(|| format!("opening {}", target.display()))?;
    let meta = file.metadata()?;
    if meta.is_dir() && !meta.file_type().is_symlink() && !is_reparse_point(&meta) {
        anyhow::bail!("{} changed to a real directory", target.display());
    }
    mark_delete_on_close(&file)
}

#[cfg(not(unix))]
fn remove_tree_path(target: &Path) -> Result<()> {
    let meta = match std::fs::symlink_metadata(target) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("inspecting {}", target.display())),
    };
    if meta.is_dir() && !meta.file_type().is_symlink() && !is_reparse_point(&meta) {
        #[cfg(windows)]
        let guard = match open_delete_dir_handle(target) {
            Ok(guard) => guard,
            Err(err) => {
                // The name changed type after the lookup. Remove the exact
                // replacement entry (a link/file) by handle; a new real
                // directory is refused by remove_entry_by_handle.
                return remove_entry_by_handle(target).with_context(|| {
                    format!(
                        "removing {} after it changed type: {err:#}",
                        target.display()
                    )
                });
            }
        };
        // `read_dir` is path-based, but `guard` prevents this directory from
        // being renamed/replaced while its entries are enumerated.
        let entries: Vec<_> = std::fs::read_dir(target)
            .with_context(|| format!("reading {}", target.display()))?
            .collect::<std::io::Result<_>>()?;
        for entry in entries {
            remove_tree_path(&entry.path())?;
        }
        #[cfg(windows)]
        {
            // Delete through the same pinned handle, not by path: a swap after
            // enumeration cannot redirect the final remove.
            mark_delete_on_close(&guard)?;
        }
        #[cfg(not(windows))]
        std::fs::remove_dir(target).with_context(|| format!("removing {}", target.display()))?;
    } else {
        // Junction/reparse directory, symlink, or regular file: a handle pins
        // the entry and `FILE_FLAG_OPEN_REPARSE_POINT` keeps links as links.
        #[cfg(windows)]
        remove_entry_by_handle(target).with_context(|| format!("removing {}", target.display()))?;
        #[cfg(not(windows))]
        if meta.is_dir() {
            std::fs::remove_dir(target)
                .with_context(|| format!("removing {}", target.display()))?;
        } else {
            std::fs::remove_file(target)
                .with_context(|| format!("removing {}", target.display()))?;
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn open_dir_chain_at(base: &Path, rel: &Path) -> Result<AtDir> {
    let mut current = AtDir::open(base)?;
    for component in rel.components() {
        let Component::Normal(name) = component else {
            anyhow::bail!(
                "refusing non-normal destination component in {}",
                rel.display()
            );
        };
        current = current.open_or_create_child(name)?;
    }
    Ok(current)
}

/// Open a regular file, optionally following a final symlink. FIFOs and
/// devices are never opened (O_NONBLOCK on Unix), and reparse points are
/// rejected unless `follow` is explicitly requested.
pub(crate) fn open_regular(path: &Path, follow: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | if follow { 0 } else { libc::O_NOFOLLOW });
    }
    #[cfg(windows)]
    if !follow {
        windows_no_reparse(&mut options);
    }
    let file = options.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || is_reparse_point(&meta) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(unix)]
pub(crate) fn open_file_nofollow(path: &Path) -> Result<File> {
    open_regular(path, false).with_context(|| format!("opening {}", path.display()))
}

#[cfg(unix)]
pub(crate) fn set_stamp_fd(file: &File, stamp: u64) -> std::io::Result<()> {
    let times = [
        libc::timespec {
            tv_sec: stamp as libc::time_t,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: stamp as libc::time_t,
            tv_nsec: 0,
        },
    ];
    let rc = unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
