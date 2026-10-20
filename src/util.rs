//! Small formatting/parsing helpers shared by the other modules.

use std::fs::{self, File, OpenOptions};
use std::io::{IsTerminal, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
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
            for name in &names {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    let cargo_bin = crate::paths::cargo_home().ok()?.join("bin");
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

/// One path component: no separators, no `.`/`..`, no NUL, no Windows
/// drive/ADS separator. Use for manifest fields that must be one directory
/// or file name (`name`, `profile`, `memo`, parity keys).
pub fn validate_component(value: &str, what: &str) -> Result<()> {
    if value.is_empty() || value == "." || value == ".." || value.contains(['/', '\\', '\0', ':']) {
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
                if part.contains(['\0', ':']) {
                    anyhow::bail!("invalid {what} {value:?}: forbidden character");
                }
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

/// Create a directory tree with mode 0700 (Unix), refusing a symlinked or
/// foreign-owned final directory. Existing directories are tightened to 0700.
pub fn create_private_dir_all(path: &Path) -> Result<()> {
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
        if !meta.is_dir() || meta.file_type().is_symlink() {
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
    let meta =
        fs::symlink_metadata(path).with_context(|| format!("inspecting {}", path.display()))?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
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
    if !base_meta.is_dir() || base_meta.file_type().is_symlink() {
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
        if meta.file_type().is_symlink() {
            anyhow::bail!("symlink in store path: {}", current.display());
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
    if !base_meta.is_dir() || base_meta.file_type().is_symlink() {
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
                if meta.file_type().is_symlink() {
                    anyhow::bail!("symlink in destination path: {}", current.display());
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
    if !meta.is_file() || meta.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a small regular file",
        ));
    }
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(text)
}

/// Copy a regular file into a **new** destination (`O_EXCL`) while hashing it.
/// Refuses symlinks/FIFOs/devices and never follows a destination symlink.
/// Returns (bytes, sha256).
pub fn copy_file_hashed(src: &Path, dst: &Path) -> Result<(u64, String)> {
    let meta = fs::symlink_metadata(src)
        .with_context(|| format!("inspecting source {}", src.display()))?;
    if !meta.file_type().is_file() {
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
