// ── platform: identity, ownership, ACL, reparse and no-follow probes ──

use std::fs::{self, Metadata};
use std::path::Path;

use anyhow::{Context, Result};

#[cfg(windows)]
use std::fs::OpenOptions;

/// Effective uid. Only meaningful on Unix; Windows uses the owner SID check
/// in [`owned_by_us`] instead.
#[cfg(unix)]
pub fn euid() -> u32 {
    // SAFETY: geteuid(2) has no preconditions and never fails.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
pub fn euid() -> u32 {
    0
}

/// Is this file owned by the current effective user, or by a trusted Windows
/// system principal?
///
/// Unix checks the uid from the already-open metadata. Windows has no uid;
/// inspect the file's owner SID against the current process token. An owner
/// of `Administrators` or `SYSTEM` is trusted: those principals can already
/// modify the file, and a user profile `.cargo` created by an elevated
/// installer is commonly admin-owned while granting the user write access.
/// Callers that need integrity still check the DACL separately.
pub fn owned_by_us(path: &Path, meta: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = path;
        meta.uid() == euid()
    }
    #[cfg(windows)]
    {
        let _ = meta;
        windows_owner_is_trusted(path).unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, meta);
        true
    }
}

#[cfg(windows)]
fn windows_token_user() -> Option<Vec<usize>> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let mut needed = 0u32;
    unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
    }
    let words = (needed as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0usize; words.max(1)];
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    unsafe { CloseHandle(token) };
    (ok != 0).then_some(buffer)
}

#[cfg(windows)]
fn windows_owner_is_trusted(path: &Path) -> Option<bool> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        EqualSid, IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        TOKEN_USER, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };

    // Canonical Windows paths can carry a `\\?\` verbatim prefix; the
    // security API expects the ordinary DOS path.
    let text = strip_verbatim(&path.to_string_lossy());
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let mut owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if rc != 0 {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor) };
        }
        return None;
    }
    if owner.is_null() {
        unsafe { LocalFree(descriptor) };
        return None;
    }

    let Some(token_user) = windows_token_user() else {
        unsafe { LocalFree(descriptor) };
        return None;
    };
    let trusted = unsafe {
        let user = &*(token_user.as_ptr() as *const TOKEN_USER);
        EqualSid(owner, user.User.Sid) != 0
            || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
            || IsWellKnownSid(owner, WinLocalSystemSid) != 0
    };
    unsafe { LocalFree(descriptor) };
    Some(trusted)
}

/// Does this path's DACL grant write access only to the current user,
/// SYSTEM, Administrators and the object owner?
///
/// A NULL or missing DACL is public. `None` means the DACL could not be
/// inspected; callers must treat that as not private.
#[cfg(windows)]
pub fn windows_acl_is_private(path: &Path) -> Option<bool> {
    windows_acl_check(path, false)
}

/// A secrets policy: neither read nor mutation rights may reach an untrusted
/// principal. Credential files need this, not the config-file rule.
#[cfg(windows)]
pub fn windows_acl_is_secret(path: &Path) -> Option<bool> {
    windows_acl_check(path, true)
}

#[cfg(windows)]
fn windows_acl_check(path: &Path, secret: bool) -> Option<bool> {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACE_HEADER, ACE_INHERITED_OBJECT_TYPE_PRESENT, ACE_OBJECT_TYPE_PRESENT, ACL,
        ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetAclInformation, GetLengthSid, GetSecurityDescriptorDacl, IsValidSid, IsWellKnownSid,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_USER,
        WinBuiltinAdministratorsSid, WinCreatorOwnerRightsSid, WinCreatorOwnerSid,
        WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_READ_ATTRIBUTES, FILE_READ_DATA,
        FILE_READ_EA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC,
        WRITE_OWNER,
    };
    use windows_sys::Win32::System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
        ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    };

    let token_user = windows_token_user()?;
    let user = unsafe { &*(token_user.as_ptr() as *const TOKEN_USER) };
    if user.User.Sid.is_null() {
        return None;
    }

    let text = strip_verbatim(&path.to_string_lossy());
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let mut owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if rc != 0 || owner.is_null() {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor) };
        }
        return None;
    }

    let result = (|| -> Option<bool> {
        let mut present: i32 = 0;
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut defaulted: i32 = 0;
        if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
            == 0
        {
            return None;
        }
        // A missing or NULL DACL grants full access to everyone.
        if present == 0 || dacl.is_null() {
            return Some(false);
        }
        let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe {
            GetAclInformation(
                dacl,
                (&mut info as *mut ACL_SIZE_INFORMATION).cast::<c_void>(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return None;
        }

        // Mutation bits only. Do not use FILE_GENERIC_WRITE as a whole: it
        // also contains READ_CONTROL and SYNCHRONIZE, which read-only ACEs
        // already grant.
        const WRITE_MASK: u32 = FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_EA
            | FILE_WRITE_ATTRIBUTES
            | FILE_DELETE_CHILD
            | DELETE
            | WRITE_DAC
            | WRITE_OWNER
            | GENERIC_WRITE
            | GENERIC_ALL;

        // Secret files additionally refuse foreign readers. READ_CONTROL is
        // deliberately absent: reading the DACL is not reading the secret.
        const READ_MASK: u32 = FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | GENERIC_READ;
        let access_mask = if secret {
            WRITE_MASK | READ_MASK
        } else {
            WRITE_MASK
        };

        for index in 0..info.AceCount {
            let mut ace: *mut c_void = std::ptr::null_mut();
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
                return None;
            }
            let header = unsafe { &*(ace as *const ACE_HEADER) };
            let size = usize::from(header.AceSize);
            if size < std::mem::size_of::<ACE_HEADER>() {
                return Some(false);
            }
            let kind = u32::from(header.AceType);
            let (mask, sid_offset) = match kind {
                ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {
                    if size < 8 + 8 {
                        return Some(false);
                    }
                    let mask = unsafe {
                        std::ptr::read_unaligned((ace as *const u8).add(4) as *const u32)
                    };
                    (mask, 8usize)
                }
                ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
                    if size < 12 + 8 {
                        return Some(false);
                    }
                    let mask = unsafe {
                        std::ptr::read_unaligned((ace as *const u8).add(4) as *const u32)
                    };
                    let flags = unsafe {
                        std::ptr::read_unaligned((ace as *const u8).add(8) as *const u32)
                    };
                    let mut offset = 12usize;
                    if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
                        offset += 16;
                    }
                    if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
                        offset += 16;
                    }
                    (mask, offset)
                }
                // Obsolete compound ACEs are not expected on files. Do not
                // guess at their layout; fail closed if one appears.
                ACCESS_ALLOWED_COMPOUND_ACE_TYPE => return Some(false),
                _ => continue,
            };
            if mask & access_mask == 0 {
                continue;
            }
            if sid_offset + 8 > size {
                return Some(false);
            }
            let sid = unsafe { (ace as *const u8).add(sid_offset) as PSID };
            if unsafe { IsValidSid(sid) } == 0 {
                return Some(false);
            }
            let sid_len = unsafe { GetLengthSid(sid) } as usize;
            if sid_offset + sid_len > size {
                return Some(false);
            }
            let trusted = unsafe {
                EqualSid(sid, user.User.Sid) != 0
                    || EqualSid(sid, owner) != 0
                    || IsWellKnownSid(sid, WinLocalSystemSid) != 0
                    || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
                    || IsWellKnownSid(sid, WinCreatorOwnerSid) != 0
                    || IsWellKnownSid(sid, WinCreatorOwnerRightsSid) != 0
            };
            if !trusted {
                return Some(false);
            }
        }
        Some(true)
    })();

    unsafe { LocalFree(descriptor) };
    result
}

/// Windows reserved device names (case-insensitive, before the first dot).
/// `CON`, `NUL`, `COM1`, `CON.txt`, `LPT9.log`, ...
pub fn is_windows_reserved(value: &str) -> bool {
    let stem = value
        .trim_end_matches([' ', '.'])
        .split('.')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$"
    ) {
        return true;
    }
    for prefix in ["COM", "LPT"] {
        let Some(rest) = stem.strip_prefix(prefix) else {
            continue;
        };
        let mut chars = rest.chars();
        if let (Some(one), None) = (chars.next(), chars.next()) {
            if one.is_ascii_digit() || matches!(one, '¹' | '²' | '³') {
                return true;
            }
        }
    }
    false
}

/// Windows single-user policy: the cache/store/work must live under the
/// current `%USERPROFILE%`, and no path component may be a reparse point.
/// This does not inspect the DACL, but it rejects the shared `C:\Users\Public`
/// class of cache and junction redirection. No-op off Windows.
#[cfg(windows)]
fn strip_verbatim(path: &str) -> String {
    let path = path.replace('/', "\\");
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = path.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        path
    }
}

#[cfg(windows)]
fn normalize_windows_path_text(path: &str) -> String {
    strip_verbatim(path)
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

/// Volume serial number and file index for a file or directory. Directories
/// are opened with backup semantics so the handle is a directory handle.
#[cfg(windows)]
fn windows_path_identity(path: &Path) -> Option<(u32, u64)> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .ok()?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return None;
    }
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    Some((info.dwVolumeSerialNumber, index))
}

#[cfg(windows)]
pub fn ensure_windows_user_path(path: &Path, what: &str) -> Result<()> {
    use std::path::PathBuf;

    let profile = std::env::var_os("USERPROFILE")
        .with_context(|| format!("{what}: USERPROFILE is not set"))?;
    let profile = fs::canonicalize(&profile).unwrap_or_else(|_| PathBuf::from(profile));
    let profile_id = windows_path_identity(&profile).with_context(|| {
        format!(
            "{what}: cannot read the filesystem identity of %USERPROFILE% ({})",
            profile.display()
        )
    })?;
    let profile_text = normalize_windows_path_text(&profile.to_string_lossy());

    let full = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolving the current directory")?
            .join(path)
    };
    // `..` must never be allowed to look like an in-profile path lexically and
    // resolve outside after creation. Reject it before prefix/canonical checks.
    for component in full.components() {
        if matches!(component, std::path::Component::ParentDir) {
            anyhow::bail!(
                "{what} {} contains `..`; use a normalized path",
                full.display()
            );
        }
    }

    // Reparse check BEFORE canonicalize: canonicalize resolves a junction to
    // its target, which would hide the junction from the component loop.
    let mut current = PathBuf::new();
    for component in full.components() {
        current.push(component.as_os_str());
        match metadata_nofollow(&current) {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                anyhow::bail!(
                    "{what} path contains a reparse point: {}",
                    current.display()
                );
            }
            // A missing/unreadable component is handled by the canonical
            // checks below; the old code ignored metadata errors here too.
            Err(_) => {}
        }
    }

    let full_text = normalize_windows_path_text(&full.to_string_lossy());
    let inside = |candidate: &str| {
        candidate == profile_text || candidate.starts_with(&format!("{profile_text}\\"))
    };
    if !inside(&full_text) {
        anyhow::bail!(
            "{what} {} is outside %USERPROFILE% ({}); Windows shared caches are unsupported — use a per-user cache root",
            full.display(),
            profile.display()
        );
    }
    // A path that already exists can contain a junction deeper than the
    // lexical components; the canonical target must also stay inside.
    let canonical = fs::canonicalize(&full).unwrap_or_else(|_| full.clone());
    let canonical_text = normalize_windows_path_text(&canonical.to_string_lossy());
    if !inside(&canonical_text) {
        anyhow::bail!(
            "{what} {} resolves outside %USERPROFILE% ({}); Windows shared caches are unsupported",
            full.display(),
            profile.display()
        );
    }
    // The profile itself is not a cache root. Compare both the lexical and
    // canonical forms: `%USERPROFILE%\`, `%USERPROFILE%\.`, and
    // `%USERPROFILE%\.\.` all resolve to the profile even though their raw
    // strings differ.
    if full_text == profile_text || canonical_text == profile_text {
        anyhow::bail!(
            "{what} {} is %USERPROFILE% itself — choose a dedicated subdirectory",
            full.display()
        );
    }
    // Spelling is not containment: the directory at the profile's depth must
    // be the same filesystem object as `%USERPROFILE%`, so a case-folded or
    // short-name spelling reached through another volume is refused.
    let profile_depth = profile.components().count();
    let canonical_depth = canonical.components().count();
    let anchor = canonical
        .ancestors()
        .nth(canonical_depth.saturating_sub(profile_depth));
    if anchor.and_then(windows_path_identity) != Some(profile_id) {
        anyhow::bail!(
            "{what} {} is not inside %USERPROFILE% ({}); Windows shared caches are unsupported",
            canonical.display(),
            profile.display()
        );
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn ensure_windows_user_path(path: &Path, what: &str) -> Result<()> {
    let _ = (path, what);
    Ok(())
}

/// Is this a Windows reparse point (symlink/junction/mount point)? On Unix
/// symlinks are handled by `file_type().is_symlink`.
pub fn is_reparse_point(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        let _ = meta;
        false
    }
}

#[cfg(windows)]
pub(super) const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
pub(super) const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
#[cfg(windows)]
pub(super) const FILE_SHARE_READ_WRITE: u32 = 0x0000_0003;

#[cfg(windows)]
pub(super) fn windows_no_reparse(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

/// Read metadata without following a symlink or Windows reparse point.
///
/// Missing paths keep `ErrorKind::NotFound`, so every caller must decide
/// explicitly whether absence is acceptable. A path that exists but is a link
/// is rejected as `InvalidInput`.
pub fn metadata_nofollow(path: &Path) -> std::io::Result<Metadata> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || is_reparse_point(&meta) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is a symlink or reparse point", path.display()),
        ));
    }
    Ok(meta)
}

/// Probe a path without following symlinks or reparse points.
///
/// `Ok(None)` means the path is absent; `Ok(Some(meta))` means a real entry.
/// A link is rejected with a `what`-qualified message, and every other error
/// keeps its context. Callers decide whether absence is acceptable.
pub fn probe(path: &Path, what: &str) -> Result<Option<Metadata>> {
    match metadata_nofollow(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            anyhow::bail!("{what} {} is a symlink/reparse point", path.display())
        }
        Err(err) => Err(err).with_context(|| format!("inspecting {what} {}", path.display())),
    }
}

/// What a no-follow probe found, keeping reparse points distinct from absence.
pub(crate) enum Probed {
    /// The path does not exist.
    Missing,
    /// The entry is a symlink or reparse point.
    Reparse,
    /// A real entry (directory, file, or special file).
    Real(Metadata),
}

/// Probe without collapsing absence and a link: callers that must handle a
/// reparse entry differently from a missing one match on [`Probed`].
pub(crate) fn probe_kind(path: &Path) -> Result<Probed> {
    match metadata_nofollow(path) {
        Ok(meta) => Ok(Probed::Real(meta)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Probed::Missing),
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => Ok(Probed::Reparse),
        Err(err) => Err(err).with_context(|| format!("inspecting {}", path.display())),
    }
}

/// Probe for scan loops: absent and link/reparse entries both read as `None`.
/// Other I/O errors (for example a permission denial) are still reported.
pub(crate) fn probe_lenient(path: &Path) -> Result<Option<Metadata>> {
    match metadata_nofollow(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
            ) =>
        {
            Ok(None)
        }
        Err(err) => Err(err).with_context(|| format!("inspecting {}", path.display())),
    }
}

/// Probe an optional directory: absent reads as `None`, any other non-directory
/// entry is rejected.
pub(crate) fn probe_dir(path: &Path, what: &str) -> Result<Option<Metadata>> {
    let Some(meta) = probe(path, what)? else {
        return Ok(None);
    };
    if !meta.is_dir() {
        anyhow::bail!("{what} {} is not a real directory", path.display());
    }
    Ok(Some(meta))
}

/// Probe an optional regular file: absent reads as `None`; a directory,
/// symlink, or special file is rejected.
pub(crate) fn probe_file(path: &Path, what: &str) -> Result<Option<Metadata>> {
    let Some(meta) = probe(path, what)? else {
        return Ok(None);
    };
    if !meta.is_file() {
        anyhow::bail!(
            "{what} {} is not a regular file (symlink/special file refused)",
            path.display()
        );
    }
    Ok(Some(meta))
}

/// The entry type a trust check expects.
#[derive(Clone, Copy)]
pub(crate) enum PathKind {
    Dir,
    File,
}

/// Which permission policy a trusted path must satisfy.
#[derive(Clone, Copy)]
pub(crate) enum TrustPolicy {
    /// Group/world may read, but never write (config files, CARGO_HOME).
    NoForeignWrite,
    /// Only the owner may access it at all (stores and caches).
    OwnerOnly,
}

/// Verify an existing path is trusted: expected type, owned by us, and not
/// writable by another principal. `Ok(None)` means the path is absent; the
/// caller decides whether absence is acceptable. The returned no-follow
/// metadata lets callers apply further checks without a second stat.
pub(crate) fn check_trusted_path(
    path: &Path,
    kind: PathKind,
    policy: TrustPolicy,
    what: &str,
) -> Result<Option<Metadata>> {
    // Windows has one policy: owner/SYSTEM/Administrators may write.
    #[cfg(not(unix))]
    let _ = policy;
    let Some(meta) = probe(path, what)? else {
        return Ok(None);
    };
    match kind {
        PathKind::Dir => {
            anyhow::ensure!(
                meta.is_dir(),
                "{what} {} is not a real directory",
                path.display()
            );
        }
        PathKind::File => {
            anyhow::ensure!(
                meta.is_file(),
                "{what} {} is not a regular file",
                path.display()
            );
        }
    }
    if !owned_by_us(path, &meta) {
        anyhow::bail!(
            "{what} {} is owned by an untrusted principal",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode() & 0o777;
        match policy {
            TrustPolicy::NoForeignWrite if mode & 0o022 != 0 => anyhow::bail!(
                "{what} {} is group/world-writable (mode {mode:o})",
                path.display()
            ),
            TrustPolicy::OwnerOnly if mode & 0o077 != 0 => anyhow::bail!(
                "{what} {} is accessible by other users (mode {mode:o}); it must be 0700",
                path.display()
            ),
            _ => {}
        }
    }
    #[cfg(windows)]
    if windows_acl_is_private(path) != Some(true) {
        anyhow::bail!(
            "{what} {} DACL grants write access to an untrusted principal",
            path.display()
        );
    }
    Ok(Some(meta))
}

/// The I/O error at the root of an `anyhow` chain, if the chain ends in one.
pub fn io_error(err: &anyhow::Error) -> Option<&std::io::Error> {
    err.root_cause().downcast_ref::<std::io::Error>()
}

/// True when the chain's root cause is a `NotFound` I/O error.
pub fn is_not_found(err: &anyhow::Error) -> bool {
    io_error(err).is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
}
