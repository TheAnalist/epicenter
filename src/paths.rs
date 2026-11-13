//! Where things live: the per-user policy root, `$CARGO_HOME`, and the shared
//! cache root.
//!
//! Everything epicenter touches derives from three roots:
//! - the policy root (`$XDG_CONFIG_HOME`, Application Support or `%APPDATA%`):
//!   the machine-level `epicenter.toml`, deliberately independent of Cargo;
//! - Cargo's home (`$CARGO_HOME` or `~/.cargo`): global `config.toml`,
//!   the already-shared source registry — and the shared build cache.
//! - epicenter's own dir (`~/.epicenter`): reserved for epicenter files.
//!
//! The default cache path is expressed ONCE as a cargo template
//! (`{cargo-cache-home}/epicenter/build`): cargo expands it at *build* time,
//! and `resolve_template` expands it identically for epicenter's own file
//! operations — so the two mechanisms can never drift apart. Same story on
//! WSL (ext4) and native Windows (NTFS).

use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};

use anyhow::{Context, Result};

/// The shared-build-dir template, as written into Cargo's global config —
/// THE canonical value, identical on every OS, written with FORWARD slashes:
/// it is the one form verified to work on Linux (backslash variants expand
/// into paths whose separators cargo treats inconsistently on Linux — the
/// artifacts never materialize on disk, basename-level `listdir` proves it)
/// and forward slashes are legal path separators on Windows, too. Never
/// write an expanded path into a config file: cargo expands
/// `{cargo-cache-home}` itself at every build, per platform.
pub const DEFAULT_BUILD_DIR: &str = "{cargo-cache-home}/epicenter/build";

/// The user's home directory (`$HOME`, with a portable fallback).
pub fn home() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            return Ok(PathBuf::from(home));
        }
    }
    // Fallback (also correct when running natively on Windows).
    std::env::home_dir()
        .filter(|p| !p.as_os_str().is_empty())
        .with_context(|| "could not determine the user home directory")
}

/// Process-wide effective Cargo home, installed once the policy is loaded.
static CARGO_HOME_OVERRIDE: OnceLock<RwLock<Option<PathBuf>>> = OnceLock::new();

fn cargo_home_override() -> &'static RwLock<Option<PathBuf>> {
    CARGO_HOME_OVERRIDE.get_or_init(|| RwLock::new(None))
}

/// Install the resolved effective Cargo home for this process. `None` restores
/// the shell/default `CARGO_HOME` fallback.
pub fn set_cargo_home_override(path: Option<PathBuf>) {
    let mut guard = cargo_home_override()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = path;
}

/// Cargo's home dir: the effective policy override when installed, otherwise
/// `$CARGO_HOME` or `~/.cargo`.
pub fn cargo_home() -> Result<PathBuf> {
    {
        let guard = cargo_home_override()
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(path) = guard.as_ref() {
            return Ok(path.clone());
        }
    }
    ambient_cargo_home()
}

/// The shell/default Cargo home, ignoring the epicenter `cargo_home` policy.
/// This is the fallback for the global policy value and for legacy state
/// migration; internal callers normally want [`cargo_home`].
pub fn ambient_cargo_home() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("CARGO_HOME") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    Ok(home()?.join(".cargo"))
}

/// Per-user state (vault keys, last-build diagnostics), independent of both
/// `CARGO_HOME` and the policy config path.
pub fn state_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        if let Some(base) = std::env::var_os("LOCALAPPDATA").filter(|value| !value.is_empty()) {
            let base = PathBuf::from(base);
            if base.is_absolute() {
                return Ok(base.join("epicenter"));
            }
        }
        return Ok(home()?.join("AppData").join("Local").join("epicenter"));
    }
    #[cfg(target_os = "macos")]
    {
        return Ok(home()?
            .join("Library")
            .join("Application Support")
            .join("epicenter"));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(base) = std::env::var_os("XDG_STATE_HOME").filter(|value| !value.is_empty()) {
            let base = PathBuf::from(base);
            if base.is_absolute() {
                return Ok(base.join("epicenter"));
            }
        }
        return Ok(home()?.join(".local").join("state").join("epicenter"));
    }
    #[cfg(not(any(unix, windows)))]
    {
        anyhow::bail!("no supported state directory on this platform")
    }
}

/// The per-user directory that holds epicenter's machine-level policy.
///
/// This is intentionally independent of `CARGO_HOME`: the global
/// `epicenter.toml` can set `cargo_home`, so it must be readable before the
/// effective Cargo home is known. A relative `XDG_CONFIG_HOME`/`APPDATA` is
/// ignored, as the XDG base-directory spec requires.
pub fn global_config_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        if let Some(base) = std::env::var_os("APPDATA").filter(|value| !value.is_empty()) {
            let base = PathBuf::from(base);
            if base.is_absolute() {
                return Ok(base.join("epicenter"));
            }
        }
        return Ok(home()?.join("AppData").join("Roaming").join("epicenter"));
    }
    #[cfg(target_os = "macos")]
    {
        return Ok(home()?
            .join("Library")
            .join("Application Support")
            .join("epicenter"));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(base) = std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
            let base = PathBuf::from(base);
            if base.is_absolute() {
                return Ok(base.join("epicenter"));
            }
        }
        return Ok(home()?.join(".config").join("epicenter"));
    }
    #[cfg(not(any(unix, windows)))]
    {
        anyhow::bail!("no supported global config directory on this platform")
    }
}

/// The one machine-level policy file.
pub fn global_config_path() -> Result<PathBuf> {
    Ok(global_config_dir()?.join(crate::settings::FILE_NAME))
}

/// The pre-0.1.0 global policy location. Only the doctor uses this to print a
/// migration hint; it is never read as policy. Always uses the ambient
/// `CARGO_HOME`, not the configured `cargo_home`.
pub fn legacy_global_config_path() -> Result<PathBuf> {
    Ok(ambient_cargo_home()?.join(crate::settings::FILE_NAME))
}

/// The `[build] build-dir` value from the **global**
/// `$CARGO_HOME/config.toml`. This is the only trusted source for epicenter
/// state. A relative config path, or a symlinked `config.toml`, is refused.
pub fn cargo_build_dir() -> Result<Option<String>> {
    let config_path = crate::config::cargo_config_path()?;
    if !config_path.exists() {
        return Ok(None);
    }
    let text = crate::util::read_trusted_config(&config_path, 1024 * 1024)
        .with_context(|| format!("reading {}", config_path.display()))?;
    Ok(crate::config::read_table_key(&text, "build", "build-dir")
        .filter(|value| !value.trim().is_empty()))
}

/// Default per-user, per-machine work root for disposable job dirs. Never
/// derived from the shared build root: a shared build dir must not imply a
/// shared, attacker-seedable work directory.
pub fn default_work_root() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        if let Some(base) = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
            return Ok(PathBuf::from(base).join("epicenter").join("work"));
        }
        return Ok(home()?
            .join("AppData")
            .join("Local")
            .join("epicenter")
            .join("work"));
    }
    #[cfg(target_os = "macos")]
    {
        return Ok(home()?
            .join("Library")
            .join("Caches")
            .join("epicenter")
            .join("work"));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(base) = std::env::var_os("XDG_CACHE_HOME").filter(|v| !v.is_empty()) {
            let base = PathBuf::from(base);
            if base.is_absolute() {
                return Ok(base.join("epicenter").join("work"));
            }
        }
        return Ok(home()?.join(".cache").join("epicenter").join("work"));
    }
}

/// Default local cache for verified remote imports. Never the shared vault:
/// a reader may have a read-only store.
pub fn default_remote_cache() -> Result<PathBuf> {
    Ok(default_work_root()?.with_file_name("remote"))
}

/// epicenter's (former) own directory — only kept for the doctor's
/// legacy-file advisory; the shared-cache decision lives in
/// `~/.cargo/config.toml` now.
pub fn epicenter_dir() -> Result<PathBuf> {
    Ok(home()?.join(".epicenter"))
}

/// The canonical build-dir template, exactly as it is written into cargo's
/// config. This is not a filesystem path; commands that touch files use
/// [`cargo_resolved_build_dir`].
pub fn default_cache_root() -> Result<PathBuf> {
    Ok(PathBuf::from(DEFAULT_BUILD_DIR))
}

/// Expand a cargo-style build-dir template value into a concrete path —
/// for epicenter's local file operations only (never for writing configs).
///
/// - `{cargo-cache-home}` expands to `$CARGO_HOME` (or `~/.cargo`).
/// - Separators are normalized to the HOST separator, mirroring cargo's own
///   template expansion (verified: `...\epicenter\build` under Linux expands
///   to `.../epicenter/build`) — so one canonical value serves both OSes.
/// - Other template tokens (`{workspace-root}`, `{workspace-path-hash}`) are
///   per-invocation in cargo: epicenter cannot resolve them in a *global*
///   setting and errors out with an explanation instead of guessing.
pub fn resolve_template(value: &str) -> Result<PathBuf> {
    for token in brace_tokens(value) {
        if token != "cargo-cache-home" {
            anyhow::bail!(
                "unsupported template variable {{{token}}} in {value:?}: \
                 epicenter can only resolve {{cargo-cache-home}}"
            );
        }
    }
    let expanded = value.replace("{cargo-cache-home}", &cargo_home()?.to_string_lossy());
    Ok(PathBuf::from(
        expanded.replace('\\', &std::path::MAIN_SEPARATOR.to_string()),
    ))
}

/// Collect the `{...}` token names inside a template value.
fn brace_tokens(value: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut rest = value;
    while let Some(start) = rest.find('{') {
        match rest[start..].find('}') {
            Some(end) => {
                tokens.push(rest[start + 1..start + end].to_string());
                rest = &rest[start + end + 1..];
            }
            None => break,
        }
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_the_default_template() {
        assert_eq!(
            resolve_template(DEFAULT_BUILD_DIR).unwrap(),
            cargo_home().unwrap().join("epicenter").join("build")
        );
    }

    #[test]
    fn plain_paths_pass_through_untouched() {
        assert_eq!(
            resolve_template("/tmp/cache").unwrap(),
            PathBuf::from("/tmp/cache")
        );
    }

    #[test]
    fn backslash_template_mirrors_cargo_normalization() {
        // Cargo normalizes `\` separators at template-expansion time (the
        // same string is the canonical config line on EVERY OS) — the
        // resolver must land on the same directory cargo builds into.
        assert_eq!(
            resolve_template(r"{cargo-cache-home}\epicenter\build").unwrap(),
            cargo_home().unwrap().join("epicenter").join("build")
        );
    }

    #[test]
    fn unknown_template_tokens_are_rejected() {
        assert!(resolve_template("{workspace-root}/build").is_err());
    }

    #[test]
    fn state_dir_is_absolute_and_named() {
        let state = state_dir().unwrap();
        assert!(state.is_absolute(), "{} must be absolute", state.display());
        assert_eq!(state.file_name(), Some(std::ffi::OsStr::new("epicenter")));
    }
}
