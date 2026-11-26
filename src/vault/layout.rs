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

// Lock files are NEVER unlinked. A writer can open the path and block in
// flock before a remover unlinks it; that writer would then hold a lock on an
// unlinked inode while a third writer locks a fresh file at the same path,
// and both would enter the critical section. `.lock-<parity>` files are
// empty, bounded by the number of generations, and outlive their generation
// on purpose.
/// Clean the debris a crash or a manual deletion leaves in the store root:
/// empty manifest-less generation directories. Existing generations and held
/// locks are kept, and `.lock-*` files always survive (see above).
pub fn sweep_store_debris(store_root: &Path) {
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
        // Recheck the manifest under the lock: a writer may have installed one
        // between the pre-lock check and acquiring the lock.
        if still_empty && !manifest_path(store_root, &generation).is_file() {
            let _ = util::remove_tree(store_root, &dir);
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
    // Bind the guard to `_lock` so it lives to the end of the scope and holds
    // the lock through removal, without an unused-binding warning.
    let Ok(Some(_lock)) = FileLock::try_acquire(&lock_path) else {
        return Ok(false);
    };
    util::remove_tree(store_root, &dir)?;
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
    /// Kernel/OS-enforced: the mount (or Windows volume) is read-only. Strong
    /// enough to share inodes (hard links). A DACL that merely denies writes
    /// is NOT an immutable mount and must stay out of this flag.
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
        // or modifying anything. A denied open is either a read-only volume
        // or a DACL that forbids writes: only a read-only volume is an
        // immutable mount; an ACL denial is a reader mode, not immutable.
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
                access.mount_read_only = volume_is_read_only(store_root) == Some(true);
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
/// view. Windows has no `statvfs`; its volume's read-only flag is the mount
/// fact, while a DACL-denied write-open is only a reader mode.
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

/// The volume root (`C:\`, `\\server\share\`) that the volume query APIs
/// require. They reject a directory path, so a store below the root must be
/// reduced to its mount point first.
#[cfg(windows)]
fn volume_root_wide(path: &Path) -> Option<Vec<u16>> {
    use std::path::{Component, Prefix};
    let root = match path.components().next()? {
        Component::Prefix(prefix) => match prefix.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => {
                format!("{}:\\", char::from(drive))
            }
            Prefix::UNC(server, share) => format!(
                "\\\\{}\\{}\\",
                server.to_string_lossy(),
                share.to_string_lossy()
            ),
            Prefix::VerbatimUNC(server, share) => format!(
                "\\\\?\\UNC\\{}\\{}\\",
                server.to_string_lossy(),
                share.to_string_lossy()
            ),
            _ => return None,
        },
        _ => return None,
    };
    Some(root.encode_utf16().chain(std::iter::once(0)).collect())
}

#[cfg(windows)]
pub(crate) fn store_is_shared_mount(store_root: &Path) -> bool {
    let Some(root) = volume_root_wide(store_root) else {
        // Unknown volume: copy rather than risk sharing an inode.
        return true;
    };
    // DRIVE_REMOTE = 4.
    unsafe { GetDriveTypeW(root.as_ptr()) == 4 }
}

/// Whether the volume holding `store_root` is mounted read-only. `None` when
/// the volume cannot be inspected, so a denied write-open is not mistaken for
/// an immutable mount.
#[cfg(windows)]
fn volume_is_read_only(store_root: &Path) -> Option<bool> {
    // FILE_READ_ONLY_VOLUME.
    const FILE_READ_ONLY_VOLUME: u32 = 0x0008_0000;
    let root = volume_root_wide(store_root)?;
    let mut flags: u32 = 0;
    let ok = unsafe {
        GetVolumeInformationW(
            root.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut flags,
            std::ptr::null_mut(),
            0,
        )
    };
    (ok != 0).then_some(flags & FILE_READ_ONLY_VOLUME != 0)
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetDriveTypeW(root_path_name: *const u16) -> u32;
    fn GetVolumeInformationW(
        root_path_name: *const u16,
        volume_name_buffer: *mut u16,
        volume_name_size: u32,
        volume_serial_number: *mut u32,
        maximum_component_length: *mut u32,
        file_system_flags: *mut u32,
        file_system_name_buffer: *mut u16,
        file_system_name_size: u32,
    ) -> i32;
}

#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
pub(crate) fn store_is_shared_mount(_store_root: &Path) -> bool {
    // Unknown mount semantics on this Unix: copy rather than risk a shared
    // inode across a network filesystem.
    true
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn store_is_shared_mount(_store_root: &Path) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn marked_generation(store: &Path, name: &str) -> Result<()> {
        fs::create_dir_all(units_dir(store, name))?;
        fs::write(store.join(name).join(GENERATION_MARKER), b"")?;
        Ok(())
    }

    #[test]
    fn drop_generation_honors_a_held_lock_and_keeps_the_lock_file() -> Result<()> {
        let home = tempfile::tempdir()?;
        let store = home.path().join("store");
        fs::create_dir(&store)?;
        marked_generation(&store, "gen")?;

        let held = FileLock::acquire(&store_lock_path(&store, "gen"))?;
        assert!(
            !drop_generation(&store, "gen")?,
            "a live lock refuses the drop"
        );
        assert!(store.join("gen").is_dir(), "the locked generation survives");
        drop(held);

        assert!(
            drop_generation(&store, "gen")?,
            "the unlocked generation drops"
        );
        assert!(!store.join("gen").exists());
        assert!(
            store_lock_path(&store, "gen").is_file(),
            "lock files are never unlinked"
        );
        Ok(())
    }

    #[test]
    fn sweep_keeps_a_manifest_and_removes_a_marked_husk() -> Result<()> {
        let home = tempfile::tempdir()?;
        let store = home.path().join("store");
        fs::create_dir(&store)?;
        marked_generation(&store, "husk")?;
        marked_generation(&store, "kept")?;
        fs::write(manifest_path(&store, "kept"), b"{}")?;

        sweep_store_debris(&store);

        assert!(
            !store.join("husk").exists(),
            "a manifest-less husk is swept"
        );
        assert!(
            store.join("kept").is_dir(),
            "a manifest-backed generation is kept"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_write_denied_directory_is_reader_mode_not_an_immutable_mount() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        if util::euid() == 0 {
            return Ok(()); // root can write 0555; the mode probe does not apply
        }
        let home = tempfile::tempdir()?;
        let store = home.path().join("store");
        fs::create_dir(&store)?;
        fs::set_permissions(&store, fs::Permissions::from_mode(0o555))?;

        let access = store_access(&store);
        assert!(access.read_only, "a denied write is reader mode");
        assert!(
            !access.mount_read_only,
            "a mode/ACL denial is not an immutable mount"
        );

        fs::set_permissions(&store, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_group_accessible_store_is_not_private() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir()?;
        let store = home.path().join("store");
        fs::create_dir(&store)?;

        fs::set_permissions(&store, fs::Permissions::from_mode(0o700))?;
        assert!(store_is_private(&store));
        fs::set_permissions(&store, fs::Permissions::from_mode(0o770))?;
        assert!(!store_is_private(&store), "group access is not private");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn drop_generation_refuses_a_symlinked_generation() -> Result<()> {
        let home = tempfile::tempdir()?;
        let store = home.path().join("store");
        fs::create_dir(&store)?;
        let target = home.path().join("target");
        fs::create_dir(&target)?;
        std::os::unix::fs::symlink(&target, store.join("gen"))?;

        let err = drop_generation(&store, "gen").unwrap_err();
        assert!(format!("{err:#}").contains("symlink"), "{err:#}");
        assert!(target.is_dir(), "the symlink target survives");
        Ok(())
    }

    // The volume-root helpers can only be exercised on a live Windows host:
    // `GetDriveTypeW`/`GetVolumeInformationW` need a real volume, and a
    // DACL-denied directory cannot be fabricated in a portable unit test.
    #[cfg(windows)]
    #[test]
    fn a_volume_root_ends_in_a_separator() {
        let path = Path::new(r"C:\Users\someone\store");
        let wide = volume_root_wide(path).expect("a drive path has a volume root");
        assert_eq!(String::from_utf16_lossy(&wide[..wide.len() - 1]), r"C:\");

        let unc = Path::new(r"\\server\share\dir");
        let wide = volume_root_wide(unc).expect("a UNC path has a volume root");
        assert_eq!(
            String::from_utf16_lossy(&wide[..wide.len() - 1]),
            r"\\server\share\"
        );
    }

    #[cfg(windows)]
    #[test]
    fn the_volume_read_only_probe_answers_on_a_local_drive() {
        assert!(
            volume_is_read_only(&std::env::temp_dir()).is_some(),
            "a local volume must be inspectable"
        );
    }
}
