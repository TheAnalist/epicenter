//! Store layout: paths, locks, markers, root privacy and store access.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::paths::STORE_MARKER;
#[cfg(unix)]
use crate::util::metadata_nofollow;
use crate::util::{self, FileLock, owned_by_us};

/// Per-generation marker: only marked generation directories are eligible
/// for automatic debris cleanup. Unknown children are never deleted.
pub(crate) const GENERATION_MARKER: &str = ".epicenter-generation";

/// Bound the number of generation directories a directory scan will accept.
const MAX_GENERATIONS: usize = 4096;

// ── layout ──────────────────────────────────────────────────────────────────

/// `store/<parity-key>/units`.
pub fn units_dir(store_root: &Path, parity: &str) -> PathBuf {
    store_root.join(parity).join("units")
}

pub(crate) fn manifest_path(store_root: &Path, parity: &str) -> PathBuf {
    store_root.join(parity).join("manifest.json")
}

/// The per-generation lock lives **outside** the generation dir so an empty
/// generation can be removed while the lock is held (Windows).
pub(crate) fn store_lock_path(store_root: &Path, parity: &str) -> PathBuf {
    store_root.join(format!(".lock-{parity}"))
}

/// Acquire the writer lock for one generation. Shared by harvest/evict and
/// `store compact` so none of them can relink a unit mid-write.
pub(crate) fn lock_generation(store_root: &Path, generation: &str) -> Result<FileLock> {
    FileLock::acquire(&store_lock_path(store_root, generation))
}

/// Remove the per-generation lock file when its generation directory is
/// gone and no live process holds the lock. A held lock is left alone.
pub(crate) fn remove_generation_lock(store_root: &Path, generation: &str) {
    let dir = store_root.join(generation);
    let path = store_lock_path(store_root, generation);
    if dir.exists() || !path.exists() {
        return;
    }
    let Ok(Some(_lock)) = FileLock::try_acquire(&path) else {
        return; // a live harvest holds it
    };
    if !dir.exists() {
        let _ = fs::remove_file(&path);
    }
}

/// Clean the debris a crash or a manual deletion leaves in the store root:
/// `.lock-*` files whose generation is gone, and empty manifest-less
/// generation directories. Existing generations and held locks are kept.
pub fn sweep_store_debris(store_root: &Path) {
    let Ok(entries) = fs::read_dir(store_root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(generation) = name.strip_prefix(".lock-") {
            if !generation.is_empty() {
                remove_generation_lock(store_root, generation);
            }
        }
    }
    let Ok(names) = generation_names(store_root) else {
        return;
    };
    for generation in names {
        // Only a marked generation is ours to delete. A project-selected
        // store can point at an arbitrary user directory; unknown children
        // (`~/.cargo/registry`, `~/.config/*`, a sibling repo) must survive.
        if util::validate_component(&generation, "generation").is_err() {
            continue;
        }
        let dir = store_root.join(&generation);
        let Ok(meta) = util::metadata_nofollow(&dir) else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        let marker = dir.join(GENERATION_MARKER);
        if !util::metadata_nofollow(&marker).is_ok_and(|meta| meta.is_file()) {
            continue;
        }
        let units = units_dir(store_root, &generation);
        let empty = fs::read_dir(&units)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(true);
        // Only manifest-less husks: a manifest is owned by `drop_units`,
        // which removes its generation itself.
        if !empty || manifest_path(store_root, &generation).is_file() {
            continue;
        }
        let Ok(Some(_lock)) = FileLock::try_acquire(&store_lock_path(store_root, &generation))
        else {
            continue;
        };
        let still_empty = fs::read_dir(&units)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(true);
        if still_empty {
            let _ = util::remove_tree(store_root, &dir);
            drop(_lock);
            remove_generation_lock(store_root, &generation);
        }
    }
}

/// Delete one whole generation under its lock: units, manifest and the
/// lock file. Returns `false` when a live harvest holds the generation lock.
pub fn drop_generation(store_root: &Path, parity: &str) -> Result<bool> {
    util::validate_component(parity, "generation")?;
    ensure_writable_store(store_root, "removing a generation")?;
    let dir = store_root.join(parity);
    let Some(meta) = util::probe(&dir, "generation")? else {
        return Ok(false);
    };
    if !meta.is_dir() {
        anyhow::bail!("refusing symlinked/reparse generation {}", dir.display());
    }
    let lock_path = store_lock_path(store_root, parity);
    let Ok(Some(lock)) = FileLock::try_acquire(&lock_path) else {
        return Ok(false);
    };
    util::remove_tree(store_root, &dir)?;
    drop(lock);
    remove_generation_lock(store_root, parity);
    Ok(true)
}

/// Refuse a store writer before it stages or deletes anything. A missing store
/// is writable by definition; an existing one must be trusted, owned, not
/// read-only, and pass a real write probe.
pub(crate) fn ensure_writable_store(store_root: &Path, operation: &str) -> Result<()> {
    check_store_writable(store_root, operation)?;
    if !store_accepts_imports(store_root) {
        anyhow::bail!(
            "store {} is read-only or not writable — {operation} needs a writable store",
            store_root.display()
        );
    }
    Ok(())
}

/// Trust and read-only refusal without touching the store. Use before a repair
/// chmod: the create/delete probe must not run while the directory is still
/// group/world-writable.
fn check_store_writable(store_root: &Path, operation: &str) -> Result<()> {
    if store_root.exists() {
        check_store_trust(store_root)?;
    }
    if store_is_read_only(store_root) {
        anyhow::bail!(
            "store {} is read-only — {operation} needs a writable store",
            store_root.display()
        );
    }
    Ok(())
}

/// Create or validate the writable store root before a harvest.
///
/// A missing root is created with private permissions. An existing root must
/// be a real directory (never a symlink/reparse point) and is tightened to
/// 0700; on Windows its DACL must grant write access only to the owner,
/// SYSTEM or Administrators. The store marker is written last, so a
/// partially prepared directory is never mistaken for a valid store.
pub(crate) fn ensure_store_root(store_root: &Path) -> Result<()> {
    util::ensure_windows_user_path(store_root, "store")?;
    match util::probe_dir(store_root, "store root")? {
        Some(_) => {
            // Refuse a read-only store before Repair can chmod it. The write
            // probe runs after the repair if a later write needs it.
            check_store_writable(store_root, "harvest/import")?;
            // To avoid double checking of DACL
            #[cfg(unix)]
            util::check_private_dir(store_root, util::Privacy::Repair)?;
        }
        None => {
            util::create_private_dir_all(store_root)?;
            #[cfg(windows)]
            require_private_windows_acl(store_root, "store root")?;
        }
    }
    write_marker(&store_root.join(STORE_MARKER))?;
    Ok(())
}

/// A writable Windows directory may be owner-owned yet still writable by a
/// local group. Auto-linking or signing into such a store would let another
/// principal mutate the inode after the hash check.
#[cfg(windows)]
pub(crate) fn require_private_windows_acl(path: &Path, what: &str) -> Result<()> {
    match util::windows_acl_is_private(path) {
        Some(true) => Ok(()),
        Some(false) => anyhow::bail!(
            "{what} {} has a Windows ACL that grants write access to another principal — choose a private local directory",
            path.display()
        ),
        None => anyhow::bail!(
            "{what} {} has a Windows ACL that could not be inspected — choose a private local directory",
            path.display()
        ),
    }
}

/// Write a zero-byte marker once; O_EXCL keeps a planted symlink from being
/// followed. An existing regular marker is accepted.
pub(crate) fn write_marker(path: &Path) -> Result<()> {
    match util::probe(path, "marker")? {
        Some(meta) if meta.is_file() => return Ok(()),
        Some(_) => anyhow::bail!("marker {} is not a regular file", path.display()),
        None => {}
    }
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(b"epicenter-store-v1\n")?;
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(err).with_context(|| format!("creating {}", path.display())),
    }
}

/// Inspect a path component-by-component from the store root. Returns `true`
/// when a symlink/reparse point appears anywhere in the chain. A missing path
/// returns `false`: callers treat a missing generation/unit as an empty slot,
/// not as a reparse escape.
pub(crate) fn store_chain_has_reparse(store_root: &Path, target: &Path) -> Result<bool> {
    let root = util::metadata_nofollow(store_root)
        .with_context(|| format!("inspecting store {}", store_root.display()))?;
    if !root.is_dir() {
        anyhow::bail!("store {} is not a real directory", store_root.display());
    }
    let rel = target
        .strip_prefix(store_root)
        .with_context(|| format!("{} is outside {}", target.display(), store_root.display()))?;
    let mut current = store_root.to_path_buf();
    for component in rel.components() {
        match component {
            std::path::Component::Normal(name) => current.push(name),
            std::path::Component::CurDir => continue,
            _ => anyhow::bail!("refusing non-normal component in {}", target.display()),
        }
        match util::metadata_nofollow(&current) {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => return Ok(true),
            Err(err) => {
                return Err(err).with_context(|| format!("inspecting {}", current.display()));
            }
        }
    }
    Ok(false)
}

/// Names of the store generations (directories under `store/`).
pub fn generation_names(store_root: &Path) -> Result<Vec<String>> {
    match util::probe(store_root, "store")? {
        Some(meta) if meta.is_dir() => {}
        Some(_) | None => return Ok(Vec::new()),
    }
    let mut names = Vec::new();
    for entry in
        fs::read_dir(store_root).with_context(|| format!("reading {}", store_root.display()))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        if util::has_reparse_component(store_root, &entry.path()) {
            continue;
        }
        let Some(meta) = util::probe_lenient(&entry.path())? else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        if names.len() >= MAX_GENERATIONS {
            anyhow::bail!(
                "store {} has more than {} generation directories - refusing an unbounded scan",
                store_root.display(),
                MAX_GENERATIONS
            );
        }
        names.push(name);
    }
    names.sort();
    Ok(names)
}

#[cfg(unix)]
fn parent_is_private(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Some(parent) = path.parent() else {
        return false;
    };
    let Ok(meta) = metadata_nofollow(parent) else {
        return false;
    };

    if !meta.is_dir() {
        return false;
    }

    meta.mode() & 0o022 == 0 || meta.mode() & 0o1000 != 0
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct StoreAccess {
    /// Kernel/OS-enforced: the mount is read-only, or Windows denied a
    /// write-open. Strong enough to share inodes (hard links).
    pub(crate) mount_read_only: bool,
    /// Reader mode: treat the store as read-only for epicenter's own behavior.
    /// True for an OS-enforced read-only store, or a directory on a writable
    /// mount that denies writes (0555/ACL). This does not make the inodes
    /// immutable; hard-link decisions must use `mount_read_only`.
    pub(crate) read_only: bool,
}

pub(crate) fn store_access(store_root: &Path) -> StoreAccess {
    let mut access = StoreAccess {
        mount_read_only: false,
        read_only: false,
    };
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::FromRawFd;
        let Ok(cpath) = CString::new(store_root.as_os_str().as_bytes()) else {
            return access;
        };

        let fd = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_NOFOLLOW | libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return access;
        }
        let dir = unsafe { std::fs::File::from_raw_fd(fd) };
        let Ok(meta) = dir.metadata() else {
            return access;
        };
        if !meta.is_dir() {
            return access;
        }

        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        // in case of mount path
        if unsafe { libc::fstatvfs(fd, &mut stat) } == 0 {
            #[cfg(target_os = "macos")]
            const RO: libc::c_ulong = libc::MNT_RDONLY;
            #[cfg(not(target_os = "macos"))]
            const RO: libc::c_ulong = libc::ST_RDONLY;
            if stat.f_flag & RO != 0 {
                access.read_only = true;
                access.mount_read_only = true;
                return access;
            }
        }

        // Root can always write; 0555 is not read-only for root.
        // Or no write bits for owner/group/other.
        if util::euid() == 0 || meta.mode() & 0o222 != 0 {
            return access;
        }

        // ACL/capability-aware write check for this process
        if !unsafe { libc::access(cpath.as_ptr(), libc::W_OK) != 0 } {
            return access;
        }
        // The parent must not let another principal rename/replace the root.
        if !parent_is_private(store_root) {
            return access;
        }
        access.read_only = true;
        access
    }
    #[cfg(windows)]
    {
        // Windows has no statvfs. Open the directory for write access with
        // FILE_FLAG_BACKUP_SEMANTICS; this checks the DACL without creating
        // or modifying anything. A denied open is a read-only reader mount.
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        match fs::OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(store_root)
        {
            Ok(file) => {
                drop(file);
                access
            }
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                access.read_only = true;
                access.mount_read_only = true;
                access
            }
            Err(_) => access,
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = store_root;
        access
    }
}

/// A store on a read-only mount cannot be mutated through a view link, so
/// sharing its inodes is safe even across principals. A writable mount is
/// copied from: the owner could chmod a 0444 inode and rewrite it through the
/// view. Windows checks directory write access with FILE_FLAG_BACKUP_SEMANTICS
/// because it has no `statvfs`; a denied open is a read-only reader mount.
pub(crate) fn store_is_read_only(store_root: &Path) -> bool {
    store_access(store_root).read_only
}

/// An owner-only, real local directory. `auto` treats this as one trust
/// domain and may hard-link archive outputs on it.
pub(crate) fn store_is_private(store_root: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(meta) = util::metadata_nofollow(store_root) else {
            return false;
        };
        meta.is_dir() && util::owned_by_us(store_root, &meta) && meta.mode() & 0o077 == 0
    }
    #[cfg(windows)]
    {
        let Ok(meta) = util::metadata_nofollow(store_root) else {
            return false;
        };
        // A fixed local drive under the user profile is one machine. A remote
        // mapped drive or UNC share is the multi-VM case and copies. The DACL
        // must also grant write access only to the owner/SYSTEM/Administrators:
        // an owner-owned but group-writable store is still mutable in place.
        meta.is_dir()
            && util::owned_by_us(store_root, &meta)
            && !store_is_shared_mount(store_root)
            && util::ensure_windows_user_path(store_root, "store").is_ok()
            && util::windows_acl_is_private(store_root) == Some(true)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = store_root;
        false
    }
}

/// Does the store live on a shared/network filesystem? A writable network
/// mount is the multi-VM topology: another machine (or an uncontrolled agent)
/// can write the inode behind a hard link.
#[cfg(target_os = "linux")]
pub(crate) fn store_is_shared_mount(store_root: &Path) -> bool {
    let Ok(target) = fs::canonicalize(store_root) else {
        return true;
    };
    let Ok(text) = fs::read_to_string("/proc/self/mountinfo") else {
        return true;
    };
    let mut best: Option<(usize, String)> = None;
    for line in text.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        let Some(mount) = fields.get(4).map(|value| unescape_mount(value)) else {
            continue;
        };
        let mount_path = Path::new(&mount);
        if target != mount_path && !target.starts_with(mount_path) {
            continue;
        }
        let Some(separator) = fields.iter().position(|field| *field == "-") else {
            continue;
        };
        let Some(fstype) = fields.get(separator + 1) else {
            continue;
        };
        if best
            .as_ref()
            .map_or(true, |(length, _)| mount.len() > *length)
        {
            best = Some((mount.len(), (*fstype).to_string()));
        }
    }
    best.map_or(true, |(_, fstype)| is_network_fstype(&fstype))
}

#[cfg(target_os = "linux")]
fn unescape_mount(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[cfg(target_os = "linux")]
fn is_network_fstype(fstype: &str) -> bool {
    let fstype = fstype.to_ascii_lowercase();
    [
        "9p",
        "v9fs",
        "drvfs",
        "virtiofs",
        "nfs",
        "cifs",
        "smb",
        "sshfs",
        "fuse.sshfs",
        "fuse.rclone",
        "davfs",
        "webdav",
        "glusterfs",
        "ceph",
        "afs",
        "lustre",
        "gpfs",
        "beegfs",
        "ocfs2",
        "ncpfs",
    ]
    .iter()
    .any(|network| fstype == *network || fstype.starts_with(&format!("{network}.")))
}

#[cfg(target_os = "macos")]
pub(crate) fn store_is_shared_mount(store_root: &Path) -> bool {
    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt;
    let Ok(path) = CString::new(store_root.as_os_str().as_bytes()) else {
        return true;
    };
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path.as_ptr(), &mut stat) } != 0 {
        return true;
    }
    let fstype = unsafe { CStr::from_ptr(stat.f_fstypename.as_ptr()) }
        .to_string_lossy()
        .to_ascii_lowercase();
    matches!(
        fstype.as_str(),
        "nfs" | "smbfs" | "afpfs" | "webdav" | "9p" | "virtiofs"
    )
}

#[cfg(windows)]
pub(crate) fn store_is_shared_mount(store_root: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = store_root
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // DRIVE_REMOTE = 4.
    unsafe { GetDriveTypeW(wide.as_ptr()) == 4 }
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetDriveTypeW(root_path_name: *const u16) -> u32;
}

#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
fn store_is_shared_mount(_store_root: &Path) -> bool {
    // Unknown mount semantics on this Unix: copy rather than risk a shared
    // inode across a network filesystem.
    true
}

#[cfg(not(any(unix, windows)))]
fn store_is_shared_mount(_store_root: &Path) -> bool {
    true
}

/// Whether a writer may install units here. This is a preflight, not a
/// guarantee: a read-only mount, a 0555 directory, or a foreign-owned store
/// returns false before any unit is staged. A missing store returns true
/// because it can be created. A writable store is probed with a temporary
/// file; the caller must still trust-check it before importing.
pub fn store_accepts_imports(store_root: &Path) -> bool {
    match util::probe(store_root, "store") {
        // A missing store is writable by definition: the writer creates it.
        Ok(None) => true,
        Ok(Some(meta)) => {
            if !meta.is_dir() || !owned_by_us(store_root, &meta) || store_is_read_only(store_root) {
                return false;
            }
            let probe = store_root.join(format!(".import-probe-{}", util::temp_nonce()));
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&probe)
            {
                Ok(file) => {
                    drop(file);
                    let _ = fs::remove_file(&probe);
                    true
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

/// Read-side trust check for an existing store.
///
/// A writable store must be a real directory owned by the reader, with a
/// private DACL on Windows. A foreign, read-only mount is accepted: the OS
/// denies writes and the manifest signature is verified separately. Read
/// paths never chmod or repair an operator-selected directory; the writer
/// marks and tightens it in [`ensure_store_root`].
pub(crate) fn check_store_trust(store_root: &Path) -> Result<()> {
    let Some(meta) = util::probe_dir(store_root, "store")? else {
        anyhow::bail!("store {} is not a real directory", store_root.display());
    };
    let mount_read_only = store_access(store_root).mount_read_only;
    // A reader may accept a foreign, read-only mount: the OS denies writes,
    // and the manifest signature is verified separately. A writable foreign
    // store is never a reader; it is one trust domain with its writer.
    if !mount_read_only {
        util::ensure_windows_user_path(store_root, "store")?;
    }
    if !util::owned_by_us(store_root, &meta) && !mount_read_only {
        anyhow::bail!(
            "store {} is owned by another user — refusing to execute its artifacts",
            store_root.display()
        );
    }
    #[cfg(windows)]
    if !mount_read_only {
        require_private_windows_acl(store_root, "store")?;
    }
    // Read paths must not chmod an operator-selected directory. A store that
    // is ours but legacy-0755 stays readable; the writer marks and tightens
    // it in `ensure_store_root`.
    Ok(())
}

/// Create or validate a restore target. An existing root must be a real
/// directory owned by us (and not group/world-writable on Unix); Windows
/// additionally requires a private DACL. Existing roots are never chmodded,
/// so `restore --into /` or `--into ~` cannot change system/home modes.
pub(crate) fn prepare_view_root(view_root: &Path) -> Result<()> {
    match util::probe_dir(view_root, "view")? {
        Some(meta) => {
            if !util::owned_by_us(view_root, &meta) {
                anyhow::bail!(
                    "view {} is owned by another user — refusing to write into it",
                    view_root.display()
                );
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if meta.mode() & 0o022 != 0 {
                    anyhow::bail!(
                        "view {} is group/world-writable (mode {:o}) — refusing a shared restore target; use a 0700 dir",
                        view_root.display(),
                        meta.mode() & 0o777
                    );
                }
            }
        }
        None => util::create_private_dir_all(view_root)?,
    }
    #[cfg(windows)]
    require_private_windows_acl(view_root, "view")?;
    // Do NOT chmod an explicitly supplied view root here: `restore --into /`
    // or `--into ~` must never change the mode of a system/home directory.
    // New view roots are created 0700; the default cache root is repaired by
    // `cmd_restore` (which knows it is the shared cache), and per-job work
    // dirs are created 0700 by `exec`.
    Ok(())
}

/// The vault's own matcher: package prefix or hash fragment of a group name.
pub(crate) fn unit_name_matches(name: &str, query: &str) -> bool {
    name.contains(query)
}

/// The package part of a unit dir name (`serde_core-b468be6fa8c1f936` →
/// `serde_core`); `None` for a name that does not end in a 16-hex hash.
pub(crate) fn unit_package(name: &str) -> Option<&str> {
    let (package, hash) = name.rsplit_once('-')?;
    (hash.len() == 16 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(package)
}
