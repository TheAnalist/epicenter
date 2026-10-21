//! Small formatting/parsing helpers shared by the other modules.

use std::fs::{self, File, OpenOptions};
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

/// `1234567` -> `"1.2 MiB"` style, compact.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
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
    let cargo_bin = crate::paths::cargo_home().ok()?.join("bin");
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
    for entry in WalkDir::new(path) {
        let Ok(entry) = entry else { continue };
        // Never follow a symlink here: `set_permissions` on a symlink path
        // changes the *target* (possibly outside this tree).
        if entry.file_type().is_symlink() {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        let mut perms = meta.permissions();
        if perms.readonly() {
            perms.set_readonly(false);
            let _ = fs::set_permissions(entry.path(), perms);
        }
    }
    fs::remove_dir_all(path).map_err(|_| first)
}

// ── security: identity, paths, private dirs, hashes ────────────────────────

/// Effective uid. Only meaningful on Unix; 0 elsewhere (permission checks
/// are skipped there and documented as such).
#[cfg(unix)]
pub fn euid() -> u32 {
    // SAFETY: geteuid(2) has no preconditions and never fails.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
pub fn euid() -> u32 {
    0
}

/// Is this file owned by the current effective user? (always true off Unix)
pub fn owned_by_us(meta: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.uid() == euid()
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        true
    }
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
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit())
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
pub fn ensure_windows_user_path(path: &Path, what: &str) -> Result<()> {
    let profile = std::env::var_os("USERPROFILE")
        .with_context(|| format!("{what}: USERPROFILE is not set"))?;
    let profile = fs::canonicalize(&profile).unwrap_or_else(|_| PathBuf::from(profile));
    let profile_text = strip_verbatim(&profile.to_string_lossy())
        .trim_end_matches('\\')
        .to_ascii_lowercase();

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
        if let Ok(meta) = fs::symlink_metadata(&current) {
            if is_reparse_point(&meta) {
                anyhow::bail!(
                    "{what} path contains a reparse point: {}",
                    current.display()
                );
            }
        }
    }

    let full_text = strip_verbatim(&full.to_string_lossy()).to_ascii_lowercase();
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
    let canonical_text = strip_verbatim(&canonical.to_string_lossy()).to_ascii_lowercase();
    if !inside(&canonical_text) {
        anyhow::bail!(
            "{what} {} resolves outside %USERPROFILE% ({}); Windows shared caches are unsupported",
            full.display(),
            profile.display()
        );
    }
    if full_text == profile_text {
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

/// Directories this process must never chmod as a "private cache": the
/// filesystem root, the user's home, and the system temp directory. A
/// mistyped `--cache-root /tmp` must not turn /tmp into 0700.
fn refuse_destructive_chmod(path: &Path) -> Result<()> {
    let is_root = path.parent().is_none() || path == Path::new("/");
    let is_home = crate::paths::home()
        .map(|home| home == path)
        .unwrap_or(false);
    let is_temp = std::env::temp_dir() == path;
    if is_root || is_home || is_temp {
        anyhow::bail!(
            "refusing to change permissions of protected directory {} — choose a dedicated cache subdirectory",
            path.display()
        );
    }
    Ok(())
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
        let meta =
            fs::symlink_metadata(path).with_context(|| format!("inspecting {}", path.display()))?;
        if !meta.is_dir() || meta.file_type().is_symlink() || is_reparse_point(&meta) {
            anyhow::bail!("{} is not a real directory", path.display());
        }
        if !owned_by_us(&meta) {
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

/// Verify (and, when possible, repair) an existing private directory.
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    refuse_destructive_chmod(path)?;
    let meta =
        fs::symlink_metadata(path).with_context(|| format!("inspecting {}", path.display()))?;
    if !meta.is_dir() || meta.file_type().is_symlink() || is_reparse_point(&meta) {
        anyhow::bail!("{} is not a real directory", path.display());
    }
    if !owned_by_us(&meta) {
        anyhow::bail!(
            "{} is owned by another user — refusing a shared/untrusted cache",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.mode() & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("securing {}", path.display()))?;
        }
    }
    Ok(())
}

/// Check that `base/rel` is a chain of real directories ending in a regular
/// file, with no symlink at any component. Read-only; used before hashing or
/// restoring a store file.
pub fn check_regular_chain(base: &Path, rel: &Path) -> Result<()> {
    let base_meta =
        fs::symlink_metadata(base).with_context(|| format!("inspecting {}", base.display()))?;
    if !base_meta.is_dir() || base_meta.file_type().is_symlink() || is_reparse_point(&base_meta) {
        anyhow::bail!("{} is not a real directory", base.display());
    }
    let mut current = base.to_path_buf();
    let components: Vec<_> = rel.components().collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(part) = component else {
            anyhow::bail!("refusing non-normal path component in {}", rel.display());
        };
        current.push(part);
        let meta = fs::symlink_metadata(&current)
            .with_context(|| format!("inspecting {}", current.display()))?;
        if meta.file_type().is_symlink() || is_reparse_point(&meta) {
            anyhow::bail!("symlink/reparse in store path: {}", current.display());
        }
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

/// Create a directory chain under an existing `base` without following any
/// symlink component. `rel` must already have been validated (only normal
/// components). New components are 0700.
pub fn create_dir_chain_nofollow(base: &Path, rel: &Path) -> Result<()> {
    let base_meta =
        fs::symlink_metadata(base).with_context(|| format!("inspecting {}", base.display()))?;
    if !base_meta.is_dir() || base_meta.file_type().is_symlink() || is_reparse_point(&base_meta) {
        anyhow::bail!("{} is not a real directory", base.display());
    }
    let mut current = base.to_path_buf();
    for component in rel.components() {
        let Component::Normal(part) = component else {
            anyhow::bail!("refusing non-normal path component in {}", rel.display());
        };
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || is_reparse_point(&meta) {
                    anyhow::bail!("symlink/reparse in destination path: {}", current.display());
                }
                if !meta.is_dir() {
                    anyhow::bail!("not a directory: {}", current.display());
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    fs::DirBuilder::new()
                        .mode(0o700)
                        .create(&current)
                        .with_context(|| format!("creating {}", current.display()))?;
                }
                #[cfg(not(unix))]
                fs::create_dir(&current)
                    .with_context(|| format!("creating {}", current.display()))?;
            }
            Err(err) => {
                return Err(err).with_context(|| format!("inspecting {}", current.display()));
            }
        }
    }
    Ok(())
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

    /// Portable fallback for platforms without /proc/self/fd: linkat with a
    /// source path but a held destination directory fd. The destination is
    /// still race-free; the source is store-owned and pre-checked.
    pub(crate) fn link_path(&self, source: &Path, dst_name: &std::ffi::OsStr) -> Result<()> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let src = CString::new(source.as_os_str().as_bytes())
            .with_context(|| format!("source path contains NUL: {}", source.display()))?;
        let dst = CString::new(dst_name.as_bytes())
            .with_context(|| format!("destination name contains NUL: {:?}", dst_name))?;
        let rc = unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                src.as_ptr(),
                self.file.as_raw_fd(),
                dst.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("linking {:?}", dst_name));
        }
        Ok(())
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

#[cfg(unix)]
pub(crate) fn open_file_nofollow(path: &Path) -> Result<File> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::FromRawFd;
    let name = CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("path contains NUL: {}", path.display()))?;
    let fd = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("opening {}", path.display()));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
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

#[cfg(unix)]
pub(crate) fn sha256_file_fd(file: &mut File) -> std::io::Result<String> {
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
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

/// SHA-256 of a regular file (lowercase hex). Callers that accept untrusted
/// paths must reject symlinks with `symlink_metadata` first.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    if is_reparse_point(&file.metadata()?) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "reparse point refused",
        ));
    }
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Like [`read_small_text`] but follows a user's config symlink (dotfiles);
/// still refuses FIFOs/devices and oversized inputs.
pub fn read_small_text_follow(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    let meta = fs::metadata(path)?;
    if !meta.is_file() || meta.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a small regular file",
        ));
    }
    fs::read_to_string(path)
}

/// Read a small regular file without following a symlink and without
/// blocking on FIFOs/devices. Returns an error on non-regular or oversized
/// inputs.
pub fn read_small_text(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || is_reparse_point(&meta) || meta.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a small regular file",
        ));
    }
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(text)
}

/// Read a global config file from an already-open-like trusted path:
/// O_NOFOLLOW, regular-file-only, owned by the current euid, and not
/// group/world-writable. The ownership/mode checks use fstat on the opened
/// descriptor, so a symlink/file swap between a path check and this read
/// cannot redirect the trust anchor.
pub fn read_trusted_config(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || is_reparse_point(&meta) || meta.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a small regular config file",
        ));
    }
    if !owned_by_us(&meta) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "config file is owned by another user",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o022 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "config file is group/world-writable",
            ));
        }
    }
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(text)
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
    let mut last_error = None;
    for attempt in 0..100u32 {
        let tmp = parent.join(format!(".{base}.tmp-{}-{attempt}", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = match options.open(&tmp) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| format!("creating {}", tmp.display()));
            }
        };
        if let Err(err) = file.write_all(bytes).and_then(|_| file.sync_all()) {
            let _ = fs::remove_file(&tmp);
            return Err(err).with_context(|| format!("writing {}", tmp.display()));
        }
        drop(file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("securing {}", tmp.display()))?;
        }
        match fs::rename(&tmp, path) {
            Ok(()) => return Ok(()),
            #[cfg(windows)]
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                // Windows does not replace an existing file with rename().
                // Removing the link itself (never following it) is safe; the
                // subsequent rename replaces whatever appears next.
                let _ = fs::remove_file(path);
                if let Err(err2) = fs::rename(&tmp, path) {
                    let _ = fs::remove_file(&tmp);
                    return Err(err2).with_context(|| format!("installing {}", path.display()));
                }
                return Ok(());
            }
            Err(err) => {
                last_error = Some(err);
                let _ = fs::remove_file(&tmp);
                if attempt < 99 {
                    continue;
                }
            }
        }
    }
    Err(last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("could not atomically write {}", path.display())))
    .with_context(|| format!("writing {}", path.display()))
}

/// Copy a regular file into a **new** destination (`O_EXCL`) while hashing it.
/// Refuses symlinks/FIFOs/devices and never follows a destination symlink.
/// Returns (bytes, sha256).
pub fn copy_file_hashed(src: &Path, dst: &Path) -> Result<(u64, String)> {
    let meta = fs::symlink_metadata(src)
        .with_context(|| format!("inspecting source {}", src.display()))?;
    if !meta.file_type().is_file() || is_reparse_point(&meta) {
        anyhow::bail!(
            "{} is not a regular file (symlink/special file refused)",
            src.display()
        );
    }
    if !owned_by_us(&meta) {
        anyhow::bail!(
            "{} is owned by another user — refusing to copy it into the vault",
            src.display()
        );
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut input = options
        .open(src)
        .with_context(|| format!("opening source {}", src.display()))?;
    if !input.metadata()?.is_file() {
        anyhow::bail!("{} changed type while opening", src.display());
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)
        .with_context(|| format!("creating {}", dst.display()))?;
    let mut hasher = Sha256::new();
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

/// Copy + verify a recorded size/hash. On mismatch the new destination is
/// removed and the operation fails (never installs unverified bytes).
pub fn copy_file_verified(
    src: &Path,
    dst: &Path,
    expected_size: u64,
    expected_hash: &str,
) -> Result<(u64, String)> {
    if expected_hash.is_empty() {
        anyhow::bail!(
            "{} has no recorded SHA-256 (re-harvest the vault before restoring)",
            src.display()
        );
    }
    let (size, hash) = copy_file_hashed(src, dst)?;
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

impl FileLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            create_private_dir_all(parent)?;
        }
        if fs::symlink_metadata(path)
            .map(|meta| meta.file_type().is_symlink())
            .unwrap_or(false)
        {
            anyhow::bail!("refusing symlinked lock file {}", path.display());
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .with_context(|| format!("opening lock {}", path.display()))?;
        file.lock()
            .with_context(|| format!("locking {}", path.display()))?;
        Ok(Self { file })
    }

    pub fn try_acquire(path: &Path) -> Result<Option<Self>> {
        if let Some(parent) = path.parent() {
            create_private_dir_all(parent)?;
        }
        if fs::symlink_metadata(path)
            .map(|meta| meta.file_type().is_symlink())
            .unwrap_or(false)
        {
            anyhow::bail!("refusing symlinked lock file {}", path.display());
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .with_context(|| format!("opening lock {}", path.display()))?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { file })),
            // Contention (or an unsupported lock): fail closed as "in use".
            Err(_) => Ok(None),
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
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
    fn human_sizes() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(3 * 1_048_576 + 200_000), "3.2 MiB");
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
        assert!(validate_component("COM1.log", "profile").is_err());
        assert!(validate_component("foo.bar", "profile").is_ok());
        assert!(validate_rel(".. /x", "path").is_err());
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
}

#[cfg(all(test, windows))]
mod windows_path_tests {
    use super::*;

    #[test]
    fn non_existent_in_profile_paths_are_accepted() {
        // tempdir is under %TEMP% (inside %USERPROFILE%); these children do
        // not exist yet, which is exactly the W-9 setup/harvest/exec case.
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("cache").join("build");
        ensure_windows_user_path(&target, "cache root").unwrap();
    }

    #[test]
    fn parent_dir_cannot_lexically_escape_the_profile() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("..").join("Public").join("ec");
        assert!(ensure_windows_user_path(&target, "cache root").is_err());
    }
}
