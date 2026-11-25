//! The process environment epicenter derives its roots from: the user's home
//! directory, Cargo's home (with the policy override), and the OS config,
//! state and cache directories.
//!
//! This module is a leaf: it reads the environment and nothing else, so the
//! modules that lay out paths can depend on it without growing a cycle.

use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};

use anyhow::{Context, Result};

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

#[derive(Clone, Copy)]
pub(crate) enum UserDir {
    Config,
    State,
    Cache,
}

fn absolute_env(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

/// One XDG/APPDATA/LOCALAPPDATA branch for epicenter's config, state and
/// cache roots. The environment value is used only when it is absolute, as
/// the XDG base-directory spec requires.
pub(crate) fn user_dir(kind: UserDir) -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let (name, fallback) = match kind {
            UserDir::Config => ("APPDATA", &["AppData", "Roaming"][..]),
            UserDir::State | UserDir::Cache => ("LOCALAPPDATA", &["AppData", "Local"][..]),
        };
        if let Some(base) = absolute_env(name) {
            return Ok(base.join("epicenter"));
        }
        let mut path = home()?;
        for part in fallback {
            path.push(part);
        }
        Ok(path.join("epicenter"))
    }
    #[cfg(target_os = "macos")]
    {
        let leaf = match kind {
            UserDir::Config | UserDir::State => "Application Support",
            UserDir::Cache => "Caches",
        };
        return Ok(home()?.join("Library").join(leaf).join("epicenter"));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let (name, fallback) = match kind {
            UserDir::Config => ("XDG_CONFIG_HOME", &[".config"][..]),
            UserDir::State => ("XDG_STATE_HOME", &[".local", "state"][..]),
            UserDir::Cache => ("XDG_CACHE_HOME", &[".cache"][..]),
        };
        if let Some(base) = absolute_env(name) {
            return Ok(base.join("epicenter"));
        }
        let mut path = home()?;
        for part in fallback {
            path.push(part);
        }
        return Ok(path.join("epicenter"));
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = kind;
        anyhow::bail!("no supported user directory on this platform")
    }
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
