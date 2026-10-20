//! Where things live: `$HOME`, `$CARGO_HOME`, and the shared cache root.
//!
//! Everything epicenter touches derives from two roots:
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

/// Cargo's home dir: `$CARGO_HOME`, or `~/.cargo`. Holds the global
/// `config.toml`, the already-shared source cache (`registry/`) — and,
/// and the shared build cache.
pub fn cargo_home() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("CARGO_HOME") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    Ok(home()?.join(".cargo"))
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
}
