//! Small formatting/parsing helpers shared by the other modules.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{IsTerminal, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use walkdir::WalkDir;

// ── terminal colors ─────────────────────────────────────────────────────────
//
// Palette: one brand green (#92D293) for headers/accents, dim gray for labels,
// amber strictly for warnings, red only for failures — calm by default, loud
// only when something is wrong. Colors auto-disable when stdout is not a
// terminal, when `NO_COLOR` is set, and force-enable with `CLICOLOR_FORCE`.

const GREEN: &str = "38;2;146;210;147"; // #92D293 — headers, success, accents
const WARN: &str = "38;2;230;180;85"; // #E6B455 — warnings only
const FAIL: &str = "38;2;224;108;117"; // #E06C75 — failures only
const INFO: &str = "38;2;126;166;224"; // #7EA6E0 — neutral tips
const DIM: &str = "2"; // labels, legends, secondary detail

fn colors_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        if std::env::var_os("NO_COLOR").is_some() {
            return false;
        }
        if let Some(force) = std::env::var_os("CLICOLOR_FORCE") {
            if force != "0" && !force.is_empty() {
                return true;
            }
        }
        std::io::stdout().is_terminal()
    })
}

fn paint(enabled: bool, code: &str, text: &str) -> String {
    if enabled {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// Brand-green text (`#92D293`) — section titles and success accents.
pub fn green(text: &str) -> String {
    paint(colors_enabled(), GREEN, text)
}

/// Bold brand green — top-level headings.
pub fn heading(text: &str) -> String {
    paint(colors_enabled(), &format!("1;{GREEN}"), text)
}

/// Amber — warnings.
pub fn warn(text: &str) -> String {
    paint(colors_enabled(), WARN, text)
}

/// Red — failures.
pub fn fail(text: &str) -> String {
    paint(colors_enabled(), FAIL, text)
}

/// Calm blue — neutral info.
pub fn info(text: &str) -> String {
    paint(colors_enabled(), INFO, text)
}

/// Dimmed — labels, legends, secondary detail.
pub fn dim(text: &str) -> String {
    paint(colors_enabled(), DIM, text)
}

// ── status glyphs ───────────────────────────────────────────────────────────
//
// Geometric, single-width, emoji-free: ✓ pass · ▲ warning · ✕ failure · ◆ info.

/// `✓`
pub const GLYPH_PASS: &str = "✓";
/// `▲`
pub const GLYPH_WARN: &str = "▲";
/// `✕`
pub const GLYPH_FAIL: &str = "✕";
/// `◆`
pub const GLYPH_INFO: &str = "◆";

/// `1234567` -> `"1.2 MB"` style, compact decimal units.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Render an untrusted name for a terminal without ANSI/control injection.
pub fn safe_display(value: &std::ffi::OsStr) -> String {
    value
        .to_string_lossy()
        .chars()
        .flat_map(|ch| {
            if ch.is_control() {
                ch.escape_default().collect::<Vec<_>>()
            } else {
                vec![ch]
            }
        })
        .collect()
}

/// Parse `"30d"`, `"2w"`, `"12h"`, `"90m"`, `"45s"` or plain seconds `"45"`.
pub fn parse_duration(text: &str) -> Result<Duration> {
    let text = text.trim();
    let split = text
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap_or(text.len());
    let (num, unit) = text.split_at(split);
    // Build the message explicitly: the raw integer-parse error ("cannot parse
    // integer from empty string") is noise for a CLI user.
    let n: u64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration {text:?} (expected e.g. 30d, 2w, 12h)"))?;
    let secs = match unit.to_ascii_lowercase().as_str() {
        "" | "s" => Some(n),
        "m" => n.checked_mul(60),
        "h" => n.checked_mul(3_600),
        "d" => n.checked_mul(86_400),
        "w" => n.checked_mul(604_800),
        other => anyhow::bail!("unknown time unit {other:?} in {text:?} (use s, m, h, d or w)"),
    }
    .with_context(|| format!("duration {text:?} is too large"))?;
    Ok(Duration::from_secs(secs))
}

/// Unix seconds, saturating at zero for clocks before the epoch.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Age of a timestamp, human-readable ("3.4 days").
pub fn human_age(at: SystemTime) -> String {
    match SystemTime::now().duration_since(at) {
        Ok(age) => human_duration(age),
        Err(_) => "in the future".to_string(),
    }
}

/// One failure rendered in the tool's visual language: a red `✕` line, the
/// message's own continuation lines indented beneath it, then any `anyhow`
/// causes as dim rows. Plain glyphs when colors are off.
pub fn error_block(err: &anyhow::Error) -> String {
    error_block_with(colors_enabled(), err)
}

/// Pure form of [`error_block`] so tests never depend on a TTY.
fn error_block_with(enabled: bool, err: &anyhow::Error) -> String {
    let mut chain = err.chain();
    let headline = chain
        .next()
        .map(|cause| cause.to_string())
        .unwrap_or_else(|| "unknown error".to_string());
    let mut lines = headline.lines();
    let mut out = format!(
        "{} {}",
        paint(enabled, FAIL, GLYPH_FAIL),
        lines.next().unwrap_or("")
    );
    for line in lines {
        out.push_str("\n  ");
        out.push_str(line);
    }
    for cause in chain {
        out.push_str(&format!(
            "\n  {} {cause}",
            paint(enabled, DIM, "caused by:")
        ));
    }
    out
}

/// Compact duration for humans ("3.4 s", "1.2 min", "2.1 h").
pub fn human_duration(duration: Duration) -> String {
    let secs = duration.as_secs_f64();
    if secs >= 86_400.0 {
        format!("{:.1} days", secs / 86_400.0)
    } else if secs >= 3_600.0 {
        format!("{:.1} h", secs / 3_600.0)
    } else if secs >= 60.0 {
        format!("{:.1} min", secs / 60.0)
    } else {
        format!("{} s", duration.as_secs())
    }
}

/// Candidate executables for `program`. Cargo installs `kache` as
/// `kache.exe` on Windows, so the suffix must be considered there.
fn exe_candidates(program: &str) -> Vec<String> {
    let mut names = vec![program.to_string()];
    if cfg!(windows) {
        names.push(format!("{program}.exe"));
    }
    names
}

/// Is `program` reachable through `PATH`? (bare `which`, no extra crate)
pub fn on_path(program: &str) -> bool {
    let names = exe_candidates(program);
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| names.iter().any(|name| dir.join(name).is_file()))
}

/// Absolute path of `program` if discoverable — first on `PATH`, then as a
/// fallback in Cargo's own bin dir (`$CARGO_HOME/bin`, e.g.
/// `C:\Users\<user>\.cargo\bin`), which rustup tools live in but isn't on
/// PATH in every shell. Returns `None` when not found anywhere.
pub fn which_path(program: &str) -> Option<PathBuf> {
    let names = exe_candidates(program);
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            // Never let an empty/relative PATH element (or `.`) make the
            // process search the current directory before the real tool.
            if dir.as_os_str().is_empty() || !dir.is_absolute() {
                continue;
            }
            for name in &names {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    let cargo_bin = crate::env::cargo_home().ok()?.join("bin");
    if !cargo_bin.is_absolute() {
        return None;
    }
    names
        .iter()
        .map(|name| cargo_bin.join(name))
        .find(|candidate| candidate.is_file())
}

/// Is `program` installed at all (PATH or cargo bin dir)?
pub fn which(program: &str) -> bool {
    which_path(program).is_some()
}

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

// ── security: identity, paths, private dirs, hashes ────────────────────────

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
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{GENERIC_ALL, GENERIC_WRITE, LocalFree};
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
        DELETE, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
        FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
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
            if mask & WRITE_MASK == 0 {
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

#[cfg(windows)]
pub fn ensure_windows_user_path(path: &Path, what: &str) -> Result<()> {
    let profile = std::env::var_os("USERPROFILE")
        .with_context(|| format!("{what}: USERPROFILE is not set"))?;
    let profile = fs::canonicalize(&profile).unwrap_or_else(|_| PathBuf::from(profile));
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

/// One path component: no separators, no `.`/`..`, no NUL, no Windows
/// drive/ADS separator, no trailing dot/space, no reserved device stem.
/// Use for manifest fields that must be one directory or file name
/// (`name`, `profile`, `memo`, parity keys).
pub fn validate_component(value: &str, what: &str) -> Result<()> {
    if value.is_empty()
        || value != value.trim_end_matches([' ', '.'])
        || value.trim_end_matches([' ', '.']) == "."
        || value.trim_end_matches([' ', '.']) == ".."
        || value.contains(['/', '\\', '\0', ':'])
        || value.chars().any(char::is_control)
        || is_windows_reserved(value)
    {
        anyhow::bail!("invalid {what} {value:?}: expected one plain path component");
    }
    Ok(())
}

/// A **relative** path with only normal components. Rejects absolute paths,
/// `..`, `.`, NUL, drive prefixes, and backslash/forward-slash tricks. This is
/// the single gate for every manifest path that reaches the filesystem.
pub fn validate_rel(value: &str, what: &str) -> Result<PathBuf> {
    if value.is_empty() || value.contains('\0') || value.ends_with(['/', '\\']) {
        anyhow::bail!("invalid {what} {value:?}: empty or trailing separator");
    }
    let normalized = value.replace('\\', "/");
    let mut out = PathBuf::new();
    for component in Path::new(&normalized).components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_string_lossy();
                validate_component(&part, what)?;
                out.push(&*part);
            }
            _ => anyhow::bail!("invalid {what} {value:?}: only relative components are allowed"),
        }
    }
    if out.as_os_str().is_empty() {
        anyhow::bail!("invalid {what} {value:?}: empty path");
    }
    Ok(out)
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
fn open_delete_dir_handle(path: &Path) -> Result<File> {
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

fn read_bounded(mut file: File, max_bytes: u64, message: &'static str) -> std::io::Result<String> {
    if file.metadata()?.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            message,
        ));
    }
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(text)
}

/// Read at most `max_bytes` from the start of a regular file, without
/// following a symlink/reparse point and without blocking on FIFOs/devices.
/// Use this for a bounded prefix of a file that may legitimately be large.
pub fn read_text_prefix(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    let file = open_regular(path, false)?;
    let mut text = String::new();
    file.take(max_bytes).read_to_string(&mut text)?;
    Ok(text)
}

/// Read a small regular file without following a symlink and without
/// blocking on FIFOs/devices. Returns an error on non-regular or oversized
/// inputs.
pub fn read_small_text(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    read_bounded(
        open_regular(path, false)?,
        max_bytes,
        "not a small regular file",
    )
}

/// Read a global config file from an already-open-like trusted path:
/// O_NOFOLLOW, regular-file-only, owned by the current euid, and not
/// group/world-writable. The ownership/mode checks use fstat on the opened
/// descriptor, so a symlink/file swap between a path check and this read
/// cannot redirect the trust anchor.
pub fn read_trusted_config(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    read_trusted_text(path, max_bytes, false)
}

/// Read a private secret file: no-follow, regular-file-only, owner-only
/// (`0600` on Unix, private DACL on Windows), and bounded in size.
pub fn read_private_text(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    read_trusted_text(path, max_bytes, true)
}

fn read_trusted_text(path: &Path, max_bytes: u64, private: bool) -> std::io::Result<String> {
    #[cfg(not(unix))]
    let _ = private;
    let mut file = open_regular(path, false)?;
    let meta = file.metadata()?;
    if meta.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a small regular config file",
        ));
    }
    if !owned_by_us(path, &meta) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "config file is owned by an untrusted principal",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mask = if private { 0o077 } else { 0o022 };
        if meta.mode() & mask != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                if private {
                    "private file is accessible by other users"
                } else {
                    "config file is group/world-writable"
                },
            ));
        }
    }
    #[cfg(windows)]
    if windows_acl_is_private(path) != Some(true) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "config file DACL grants write access to an untrusted principal",
        ));
    }
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(text)
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

/// Upper bound for one stored artifact. This is a disk-fill guard, not a
/// performance target: rustc artifacts are normally far smaller.
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Bound one tree scan so a hostile tree cannot burn CPU/IO indefinitely.
pub(crate) const MAX_SCAN_FILES: u64 = 2_000_000;

/// Bound the depth of a recursive scan; deeper trees are truncated.
pub(crate) const MAX_SCAN_DEPTH: usize = 64;

/// A shared entry budget for a tree walk. `spend` is for fallible scans that
/// should report the hostile tree; `take` is for infallible summaries that
/// truncate instead (a partial listing is safer than unbounded work).
pub(crate) struct ScanBudget {
    remaining: u64,
    limit: u64,
    what: &'static str,
}

impl ScanBudget {
    pub(crate) fn new(what: &'static str) -> Self {
        Self {
            remaining: MAX_SCAN_FILES,
            limit: MAX_SCAN_FILES,
            what,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_limit(limit: u64, what: &'static str) -> Self {
        Self {
            remaining: limit,
            limit,
            what,
        }
    }

    pub(crate) fn spend(&mut self) -> Result<()> {
        if self.take() {
            Ok(())
        } else {
            anyhow::bail!(
                "{} scan exceeded {} entries — refusing a hostile tree",
                self.what,
                self.limit
            )
        }
    }

    pub(crate) fn take(&mut self) -> bool {
        if self.remaining == 0 {
            false
        } else {
            self.remaining -= 1;
            true
        }
    }
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

/// Resolve an executable to an **absolute** path. This is the Windows
/// CWD-search fix: `Command::new("cargo")` must never be used directly.
pub fn tool_path(program: &str) -> Result<PathBuf> {
    let path = which_path(program)
        .with_context(|| format!("{program} not found on PATH or in the cargo bin directory"))?;
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(fs::canonicalize(&path).unwrap_or(path))
    }
}

/// A `Command` for a trusted tool (`cargo`, `rustc`) or a user program:
/// relative names are resolved through [`tool_path`] to an absolute path.
pub fn command_for(program: &str) -> Result<Command> {
    let path = if program.contains(['/', '\\']) {
        PathBuf::from(program)
    } else {
        tool_path(program)?
    };
    let mut command = Command::new(path);
    // Windows CreateProcess otherwise searches the CWD before PATH. The
    // variable is ignored on Unix but harmless and keeps the code uniform.
    command.env("NoDefaultCurrentDirectoryInExePath", "1");
    Ok(command)
}

/// Advisory exclusive lock on a file. Held for the lifetime of the value.
pub struct FileLock {
    file: File,
}

#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
#[cfg(windows)]
const FILE_SHARE_READ_WRITE: u32 = 0x0000_0003;

#[cfg(windows)]
fn windows_no_reparse(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
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

/// Minimal line diff for `setup --dry-run`: unchanged lines are prefixed with
/// two spaces, removals with `- `, additions with `+ `.
///
/// Config files are tiny, so the O(n·m) LCS is simpler than pulling in a diff
/// dependency and produces stable, readable output.
pub fn line_diff(before: &str, after: &str) -> String {
    let a: Vec<&str> = before.lines().collect();
    let b: Vec<&str> = after.lines().collect();
    let mut lcs = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }

    let mut out = String::new();
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if a[i] == b[j] {
            out.push_str("  ");
            out.push_str(a[i]);
            out.push('\n');
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push_str("- ");
            out.push_str(a[i]);
            out.push('\n');
            i += 1;
        } else {
            out.push_str("+ ");
            out.push_str(b[j]);
            out.push('\n');
            j += 1;
        }
    }
    while i < a.len() {
        out.push_str("- ");
        out.push_str(a[i]);
        out.push('\n');
        i += 1;
    }
    while j < b.len() {
        out.push_str("+ ");
        out.push_str(b[j]);
        out.push('\n');
        j += 1;
    }
    out
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

/// Does any component from `base` to `target` resolve through a symlink or
/// reparse point? The check includes `base` and the final component. A target
/// outside `base` also returns `true`, so callers can use this as a
/// `WalkDir::filter_entry` predicate and skip an entire junction subtree.
pub(crate) fn has_reparse_component(base: &Path, target: &Path) -> bool {
    if metadata_nofollow(base).is_err() {
        return true;
    }
    let Ok(rel) = target.strip_prefix(base) else {
        return true;
    };
    let mut current = base.to_path_buf();
    for component in rel.components() {
        match component {
            Component::Normal(name) => current.push(name),
            Component::CurDir => continue,
            _ => return true,
        }
        if metadata_nofollow(&current).is_err() {
            return true;
        }
    }
    false
}

/// `WalkDir::filter_entry` predicate: regular files pass; a symlink is
/// rejected; a directory is accepted only when it is not itself a reparse
/// point. Ancestors were already vetted when they were yielded (the walker
/// prunes a rejected subtree), so this is one entry check instead of a
/// component walk per entry.
///
/// The walker must also use `follow_links(false)` and
/// `follow_root_links(false)`: WalkDir follows a symlinked **root** by default
/// even when `follow_links(false)` is set, and the root entry is not yielded
/// when `min_depth(1)` is used, so this predicate never sees it.
pub(crate) fn walk_entry_is_safe(entry: &walkdir::DirEntry) -> bool {
    let kind = entry.file_type();
    if kind.is_symlink() {
        return false;
    }
    if !kind.is_dir() {
        return true;
    }
    // On Windows, Rust reports a name-surrogate reparse tag (symlink or
    // junction) as `is_symlink`, so those are already rejected. Other reparse
    // directory tags (cloud/dedup/NFS) report `is_dir` without `is_symlink`;
    // only a no-follow stat exposes the reparse attribute. On Unix a directory
    // entry is real.
    #[cfg(windows)]
    {
        metadata_nofollow(entry.path()).is_ok()
    }
    #[cfg(not(windows))]
    {
        true
    }
}

/// `WalkDir::filter_entry` predicate that prunes only reparse **directories**.
/// Use for scans that must still see symlinked files (a planted lock file must
/// be rejected, not hidden) but must never descend through a junction.
pub(crate) fn walk_dir_is_safe(entry: &walkdir::DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return true;
    }
    #[cfg(windows)]
    {
        metadata_nofollow(entry.path()).is_ok()
    }
    #[cfg(not(windows))]
    {
        true
    }
}

/// A bounded, junction-safe tree walk. The safety predicate is part of the
/// constructor so every scan skips a reparse subtree instead of traversing it.
/// Directory pruning requires top-down order; collect first, then sort by depth
/// when a removal has to happen children-first.
pub(crate) struct SafeWalk<'a> {
    base: &'a Path,
    depth: usize,
    keep_links: bool,
}

impl<'a> SafeWalk<'a> {
    pub(crate) fn new(base: &'a Path) -> Self {
        Self {
            base,
            depth: MAX_SCAN_DEPTH,
            keep_links: false,
        }
    }

    pub(crate) fn depth(mut self, depth: usize) -> Self {
        debug_assert!(depth >= 1, "max_depth is clamped up to min_depth(1)");
        self.depth = depth;
        self
    }

    /// Yield symlinked files while still pruning reparse directories.
    pub(crate) fn keep_links(mut self) -> Self {
        self.keep_links = true;
        self
    }

    pub(crate) fn walk(self) -> impl Iterator<Item = walkdir::Result<walkdir::DirEntry>> + 'a {
        // `follow_root_links(false)` stops a symlinked root. A Windows junction
        // is not a symlink for older platforms and non-surrogate reparse
        // directories are not either, so reject any reparse root explicitly.
        // (Do not encode "yield nothing" as `max_depth(0)`: walkdir clamps it
        // up to `min_depth(1)` and would yield the target's direct children.)
        let reject_root = matches!(
            metadata_nofollow(self.base),
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput
        );
        let filter: fn(&walkdir::DirEntry) -> bool = if self.keep_links {
            walk_dir_is_safe
        } else {
            walk_entry_is_safe
        };
        WalkDir::new(self.base)
            .min_depth(1)
            .max_depth(self.depth)
            .follow_links(false)
            .follow_root_links(false)
            .into_iter()
            .filter_entry(filter)
            .take(if reject_root { 0 } else { usize::MAX })
    }
}

/// Unicode format characters used for bidi spoofing or invisible names.
pub(crate) fn is_unsafe_format(ch: char) -> bool {
    matches!(
        ch,
        '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2028}'..='\u{2029}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub(crate) fn hex_decode(text: &str, what: &str) -> Result<Vec<u8>> {
    let text = text.trim();
    if text.len() % 2 != 0 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("{what} is not a valid hex string");
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(pair).expect("hex pair is ASCII");
        out.push(u8::from_str_radix(pair, 16).expect("validated hex pair"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn parses_time_units() {
        assert_eq!(
            parse_duration("30d").unwrap(),
            Duration::from_secs(30 * 86_400)
        );
        assert_eq!(
            parse_duration("2w").unwrap(),
            Duration::from_secs(2 * 604_800)
        );
        assert_eq!(
            parse_duration("12h").unwrap(),
            Duration::from_secs(12 * 3_600)
        );
        assert_eq!(parse_duration("45").unwrap(), Duration::from_secs(45));
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("5x").is_err());
    }

    #[test]
    fn command_for_resolves_bare_tools_and_sets_the_windows_guard() -> Result<()> {
        let command = command_for("rustc")?;
        assert!(
            Path::new(command.get_program()).is_absolute(),
            "bare tool names resolve to an absolute path"
        );
        assert!(
            command
                .get_envs()
                .any(|(key, value)| key == "NoDefaultCurrentDirectoryInExePath"
                    && value == Some(std::ffi::OsStr::new("1"))),
            "Windows CWD search is disabled for every spawned tool"
        );
        Ok(())
    }

    #[test]
    fn scan_budget_stops_at_the_limit() {
        let mut budget = ScanBudget::with_limit(2, "test");
        assert!(budget.take());
        assert!(budget.take());
        assert!(!budget.take(), "the budget is exhausted");
        let mut budget = ScanBudget::with_limit(1, "test");
        assert!(budget.spend().is_ok());
        assert!(budget.spend().is_err(), "fallible scans report the limit");
    }

    #[test]
    fn concurrent_dir_chain_creation_accepts_already_exists() {
        let root = tempfile::tempdir().unwrap();
        let mut handles = Vec::new();
        for _ in 0..8 {
            let base = root.path().to_path_buf();
            handles.push(std::thread::spawn(move || {
                create_dir_chain_nofollow(&base, Path::new("debug/deps"))
            }));
        }
        for handle in handles {
            handle.join().unwrap().unwrap();
        }
        assert!(root.path().join("debug/deps").is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn file_lock_refuses_a_symlink() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let victim = dir.path().join("victim");
        let lock = dir.path().join("lock");
        std::os::unix::fs::symlink(&victim, &lock)?;
        assert!(FileLock::acquire(&lock).is_err());
        assert!(!victim.exists(), "the symlink target must not be created");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn fifo_open_is_nonblocking_and_rejected() -> Result<()> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("fifo");
        let name = CString::new(path.as_os_str().as_bytes())?;
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let err = open_file_nofollow(&path).unwrap_err();
        assert!(format!("{err:#}").contains("regular file"), "{err:#}");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn remove_tree_unlinks_a_symlink_entry_without_following_it() -> Result<()> {
        let root = tempfile::tempdir()?;
        let victim = tempfile::tempdir()?;
        let unit = root.path().join("unit");
        fs::create_dir_all(&unit)?;
        fs::write(unit.join("file"), b"x")?;
        fs::write(victim.path().join("keep"), b"keep")?;
        std::os::unix::fs::symlink(victim.path(), unit.join("link"))?;

        remove_tree(root.path(), &unit)?;
        assert!(!unit.exists(), "the unit tree is gone");
        assert!(
            victim.path().join("keep").exists(),
            "the symlink target must survive"
        );
        Ok(())
    }

    #[test]
    fn with_temp_file_unlinks_on_failure_and_returns_the_path_on_success() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let err = with_temp_file(dir.path(), "probe", ".tmp", 0o600, |file| -> Result<()> {
            file.write_all(b"partial")?;
            anyhow::bail!("stop")
        });
        assert!(err.is_err());
        assert_eq!(fs::read_dir(dir.path())?.count(), 0, "no temp debris");

        let (path, written) = with_temp_file(dir.path(), "probe", ".tmp", 0o600, |file| {
            file.write_all(b"complete")?;
            file.sync_all()?;
            Ok(7u8)
        })?;
        assert_eq!(written, 7);
        assert_eq!(fs::read(&path)?, b"complete");
        assert_eq!(path.parent(), Some(dir.path()));
        Ok(())
    }

    #[test]
    fn create_temp_dir_names_are_unique() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let first = create_temp_dir(dir.path(), "stage")?;
        let second = create_temp_dir(dir.path(), "stage")?;
        assert_ne!(first, second);
        assert!(first.is_dir() && second.is_dir());
        Ok(())
    }

    #[test]
    fn write_atomic_private_leaves_a_directory_destination_intact() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let dest = dir.path().join("config.toml");
        fs::create_dir(&dest)?;
        fs::write(dest.join("keep"), b"x")?;
        assert!(write_atomic_private(&dest, b"new bytes").is_err());
        assert!(
            dest.join("keep").exists(),
            "a failed replace must not delete the destination"
        );
        Ok(())
    }

    #[test]
    fn probe_kind_separates_missing_reparse_and_real() -> Result<()> {
        let dir = tempfile::tempdir()?;
        assert!(matches!(
            probe_kind(&dir.path().join("missing"))?,
            Probed::Missing
        ));
        let file = dir.path().join("file");
        fs::write(&file, b"x")?;
        assert!(matches!(probe_kind(&file)?, Probed::Real(_)));
        assert!(probe_lenient(&file)?.is_some());
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&file, &link)?;
            assert!(matches!(probe_kind(&link)?, Probed::Reparse));
            assert!(probe_lenient(&link)?.is_none());
        }
        Ok(())
    }

    #[test]
    fn verify_file_hash_checks_size_and_digest() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("artifact");
        fs::write(&path, b"payload")?;
        let hash = sha256_file(&path)?;
        verify_file_hash(&path, 7, &hash, "test object")?;
        assert!(verify_file_hash(&path, 8, &hash, "test object").is_err());
        assert!(verify_file_hash(&path, 7, "deadbeef", "test object").is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn trusted_path_policy_distinguishes_world_write_from_owner_only() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        if euid() == 0 {
            return Ok(()); // root ignores mode bits; the policy test does not apply
        }
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("store");
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o750))?;
        assert!(
            check_trusted_path(&path, PathKind::Dir, TrustPolicy::NoForeignWrite, "store")?
                .is_some()
        );
        assert!(check_trusted_path(&path, PathKind::Dir, TrustPolicy::OwnerOnly, "store").is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        assert!(
            check_trusted_path(&path, PathKind::Dir, TrustPolicy::OwnerOnly, "store")?.is_some()
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn walk_filter_skips_a_symlinked_subtree() -> Result<()> {
        let root = tempfile::tempdir()?;
        let victim = tempfile::tempdir()?;
        fs::write(victim.path().join("keep"), b"keep")?;
        fs::create_dir(root.path().join("real"))?;
        fs::write(root.path().join("real/file"), b"x")?;
        std::os::unix::fs::symlink(victim.path(), root.path().join("link"))?;

        let visited: Vec<PathBuf> = SafeWalk::new(root.path())
            .walk()
            .filter_map(Result::ok)
            .map(|entry| entry.into_path())
            .collect();
        assert!(
            visited
                .iter()
                .any(|path| path == &root.path().join("real/file")),
            "regular files must still be visited"
        );
        assert!(
            !visited
                .iter()
                .any(|path| path.starts_with(root.path().join("link"))
                    || path.starts_with(victim.path())),
            "a symlink subtree must be skipped"
        );

        // WalkDir follows a symlinked root by default even with
        // follow_links(false); the shared constructor must stop it.
        let linked_root = root.path().join("linked-root");
        std::os::unix::fs::symlink(victim.path(), &linked_root)?;
        let visited: Vec<PathBuf> = SafeWalk::new(&linked_root)
            .walk()
            .filter_map(Result::ok)
            .map(|entry| entry.into_path())
            .collect();
        assert!(
            visited.is_empty(),
            "a symlinked root must not be traversed: {visited:?}"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn remove_tree_skips_a_symlinked_parent() -> Result<()> {
        let root = tempfile::tempdir()?;
        let victim = tempfile::tempdir()?;
        fs::create_dir_all(victim.path().join("child"))?;
        fs::write(victim.path().join("child/keep"), b"keep")?;
        std::os::unix::fs::symlink(victim.path(), root.path().join("link"))?;

        remove_tree(root.path(), &root.path().join("link/child"))?;
        assert!(
            victim.path().join("child/keep").exists(),
            "a symlinked parent must never redirect deletion"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn remove_file_and_empty_dir_stay_under_the_root() -> Result<()> {
        let root = tempfile::tempdir()?;
        let file = root.path().join("file");
        let empty = root.path().join("empty");
        let full = root.path().join("full");
        fs::write(&file, b"x")?;
        fs::create_dir(&empty)?;
        fs::create_dir(&full)?;
        fs::write(full.join("keep"), b"x")?;

        remove_file(root.path(), &file)?;
        assert!(!file.exists());
        remove_empty_dir(root.path(), &empty)?;
        assert!(!empty.exists());
        assert!(remove_empty_dir(root.path(), &full).is_err());
        assert!(full.join("keep").exists());
        Ok(())
    }

    #[cfg(windows)]
    fn make_junction(link: &Path, target: &Path) -> Result<()> {
        let script = format!(
            "New-Item -ItemType Junction -Path '{}' -Target '{}' -ErrorAction Stop | Out-Null",
            link.display(),
            target.display()
        );
        let status = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command"])
            .arg(script)
            .status()?;
        if !status.success() {
            anyhow::bail!("mklink /J failed for {}", link.display());
        }
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn remove_tree_deletes_a_regular_tree_on_windows() -> Result<()> {
        let root = tempfile::tempdir()?;
        let unit = root.path().join("unit");
        fs::create_dir_all(unit.join("sub"))?;
        fs::write(unit.join("sub/file"), b"x")?;
        remove_tree(root.path(), &unit)?;
        assert!(!unit.exists(), "the whole tree is gone");
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn remove_tree_unlinks_a_nested_junction_without_following_it() -> Result<()> {
        let root = tempfile::tempdir()?;
        let victim = tempfile::tempdir()?;
        let unit = root.path().join("unit");
        fs::create_dir_all(&unit)?;
        fs::write(victim.path().join("keep"), b"keep")?;
        make_junction(&unit.join("sub"), victim.path())?;

        remove_tree(root.path(), &unit)?;
        assert!(!unit.exists(), "the unit tree is gone");
        assert!(
            victim.path().join("keep").exists(),
            "the junction target must survive"
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn delete_dir_handle_pins_the_directory_against_rename() -> Result<()> {
        let root = tempfile::tempdir()?;
        let dir = root.path().join("pinned");
        fs::create_dir(&dir)?;
        let guard = open_delete_dir_handle(&dir)?;
        let renamed = root.path().join("renamed");
        assert!(
            fs::rename(&dir, &renamed).is_err(),
            "a no-delete-share handle must block rename"
        );
        drop(guard);
        assert!(dir.is_dir());
        remove_tree(root.path(), &dir)?;
        Ok(())
    }

    #[test]
    fn metadata_nofollow_preserves_missing_and_rejects_links() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let missing = dir.path().join("missing");
        let err = metadata_nofollow(&missing).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);

        let regular = dir.path().join("regular");
        fs::write(&regular, b"x")?;
        let meta = metadata_nofollow(&regular)?;
        assert!(meta.is_file());

        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&regular, &link)?;
            let err = metadata_nofollow(&link).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        }
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn windows_acl_rejects_a_users_write_ace() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let status = std::process::Command::new("icacls")
            .arg(dir.path())
            .args(["/grant", "*S-1-5-32-545:(OI)(CI)(M)"])
            .status()
            .context("running icacls")?;
        assert!(status.success(), "icacls could not add the test ACE");
        assert_eq!(windows_acl_is_private(dir.path()), Some(false));
        Ok(())
    }

    #[cfg(not(unix))]
    #[test]
    fn decompress_verified_preserves_already_exists() -> Result<()> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        let dir = tempfile::tempdir()?;
        let blob = dir.path().join("blob.gz");
        let file = fs::File::create(&blob)?;
        let mut encoder = GzEncoder::new(file, Compression::fast());
        encoder.write_all(b"payload")?;
        encoder.finish()?;
        let dst = dir.path().join("dst");
        fs::write(&dst, b"keep")?;

        let err = decompress_file_verified(&blob, &dst, 7, "unused").unwrap_err();
        assert_eq!(
            err.root_cause()
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::AlreadyExists)
        );
        assert_eq!(fs::read(&dst)?, b"keep", "an existing destination survives");
        Ok(())
    }

    #[test]
    fn decompression_respects_the_recorded_size() -> Result<()> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("blob.gz");
        let file = fs::File::create(&path)?;
        let mut encoder = GzEncoder::new(file, Compression::fast());
        encoder.write_all(&[0u8; 1024 * 1024])?;
        encoder.finish()?;
        let err = decompress_file_hashed(&path, true, 1024).unwrap_err();
        assert!(format!("{err:#}").contains("exceeds"), "{err:#}");
        Ok(())
    }

    #[test]
    fn recompressing_identical_content_accepts_the_existing_blob() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let root = dir.path().join("generation");
        fs::create_dir_all(&root)?;
        let src = dir.path().join("artifact");
        fs::write(&src, vec![b'x'; 8 * 1024])?;
        let first = compress_file_hashed(&src, &root)?.expect("compressed");
        let second = compress_file_hashed(&src, &root)?.expect("reused");
        assert_eq!(first, second);
        Ok(())
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1000), "1.0 KB");
        assert_eq!(human_bytes(1_000_000), "1.0 MB");
        assert_eq!(human_bytes(3_200_000), "3.2 MB");
        assert_eq!(human_bytes(1_000_000_000), "1.0 GB");
        assert_eq!(human_bytes(3_500_000_000), "3.5 GB");
        assert_eq!(human_bytes(1_000_000_000_000), "1.0 TB");
        assert_eq!(human_bytes(18_000_000_000_000), "18.0 TB");
    }

    #[test]
    fn exe_candidates_is_platform_aware() {
        let names = exe_candidates("kache");
        assert!(names.contains(&"kache".to_string()));
        #[cfg(windows)]
        assert!(names.contains(&"kache.exe".to_string()));
        #[cfg(not(windows))]
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn paint_is_pure() {
        assert_eq!(paint(false, "38;2;146;210;147", "hi"), "hi");
        assert_eq!(paint(true, "1", "hi"), "\x1b[1mhi\x1b[0m");
    }

    #[test]
    fn manifest_paths_stay_relative_and_normal() {
        assert!(validate_rel("deps/libx-abc.rlib", "path").is_ok());
        assert!(validate_rel(".fingerprint/x-abc/lib-x", "path").is_ok());
        assert!(validate_rel("/etc/passwd", "path").is_err());
        assert!(validate_rel("../escape", "path").is_err());
        assert!(validate_rel("deps/../../escape", "path").is_err());
        assert!(validate_rel("C:\\Windows\\x", "path").is_err());
        assert!(validate_rel("deps\\x", "path").is_ok());
        assert!(validate_rel("", "path").is_err());
        assert!(validate_component("debug", "profile").is_ok());
        assert!(validate_component("..", "profile").is_err());
        assert!(validate_component("a/b", "profile").is_err());
        assert!(validate_component("a\\b", "profile").is_err());
        // Windows aliases / device stems must never pass a manifest.
        assert!(validate_component(".. ", "profile").is_err());
        assert!(validate_component("...", "profile").is_err());
        assert!(validate_component("foo.", "profile").is_err());
        assert!(validate_component("foo ", "profile").is_err());
        assert!(validate_component("CON", "profile").is_err());
        assert!(validate_component("CON.txt", "profile").is_err());
        assert!(validate_component("CONIN$", "profile").is_err());
        assert!(validate_component("CONOUT$.txt", "profile").is_err());
        assert!(validate_component("COM¹", "profile").is_err());
        assert!(validate_component("LPT³.log", "profile").is_err());
        assert!(validate_component("bad\u{1b}[31m", "profile").is_err());
        assert!(validate_component("COM1.log", "profile").is_err());
        assert!(validate_component("foo.bar", "profile").is_ok());
        assert!(validate_rel(".. /x", "path").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn link_helper_hashes_and_shares_the_inode() -> Result<()> {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir()?;
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::write(&src, b"hello")?;
        let (size, hash) = try_link_file_hashed(&src, &dst)?.expect("hard link");
        assert_eq!(size, 5);
        assert_eq!(hash, sha256_file(&src)?);
        assert_eq!(fs::metadata(&src)?.nlink(), 2);
        assert_eq!(fs::metadata(&src)?.ino(), fs::metadata(&dst)?.ino());
        Ok(())
    }

    #[test]
    fn copies_are_hashed_and_verified() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::write(&src, b"hello")?;
        let (size, hash) = copy_file_hashed(&src, &dst)?;
        assert_eq!(size, 5);
        assert_eq!(hash, sha256_file(&src)?);
        assert_eq!(fs::read(&dst)?, b"hello");
        let bad = dir.path().join("bad");
        assert!(copy_file_verified(&src, &bad, 5, "00").is_err());
        assert!(
            !bad.exists(),
            "a failed verify must not leave the destination"
        );
        Ok(())
    }

    #[test]
    fn duration_overflow_is_rejected() {
        assert!(parse_duration("18446744073709551615d").is_err());
        assert!(parse_duration("18446744073709551615s").is_ok());
    }

    #[test]
    fn error_blocks_render_a_glyph_indent_and_causes() {
        let plain =
            anyhow::anyhow!("nothing selected — pass one selector:\n--stale   older toolchains");
        let block = error_block_with(false, &plain);
        assert_eq!(
            block,
            "✕ nothing selected — pass one selector:\n  --stale   older toolchains"
        );
        let colored = error_block_with(true, &plain);
        assert!(colored.contains("\u{1b}[38;2;224;108;117m✕\u{1b}[0m"));

        let chained = Err::<(), _>(anyhow::anyhow!("inner detail")).context("outer headline");
        let block = error_block_with(false, &chained.unwrap_err());
        assert_eq!(block, "✕ outer headline\n  caused by: inner detail");
    }

    #[test]
    fn line_diff_marks_changes() {
        let diff = line_diff("a\nb\nc\n", "a\nx\nc\n");
        assert!(diff.contains("- b"), "{diff}");
        assert!(diff.contains("+ x"), "{diff}");
        assert!(diff.contains("  a"), "{diff}");
        assert!(diff.contains("  c"), "{diff}");
        assert_eq!(line_diff("same\n", "same\n"), "  same\n");
    }
}

#[cfg(all(test, windows))]
mod windows_path_tests {
    use super::*;

    #[test]
    fn non_existent_in_profile_paths_are_accepted() {
        // tempdir is under %TEMP% (inside %USERPROFILE%); these children do
        // not exist yet, which is exactly the fresh setup/harvest/exec case.
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("cache").join("build");
        ensure_windows_user_path(&target, "cache root").unwrap();
    }

    #[test]
    fn profile_aliases_are_rejected() {
        let profile = std::env::var_os("USERPROFILE").expect("USERPROFILE");
        let profile = std::path::PathBuf::from(profile);
        let mut trailing = profile.as_os_str().to_os_string();
        trailing.push("\\");
        for target in [
            std::path::PathBuf::from(trailing),
            profile.join("."),
            profile.join(".").join("."),
            profile.join(".").join(".."),
        ] {
            assert!(
                ensure_windows_user_path(&target, "cache root").is_err(),
                "profile alias was accepted: {:?}",
                target
            );
        }
    }

    #[test]
    fn parent_dir_cannot_lexically_escape_the_profile() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("..").join("Public").join("ec");
        assert!(ensure_windows_user_path(&target, "cache root").is_err());
    }
}
