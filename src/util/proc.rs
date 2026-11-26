// ── proc: locating executables and building commands ──

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};

/// Candidate executables for `program`. Cargo installs `kache` as
/// `kache.exe` on Windows, so the suffix must be considered there.
pub(super) fn exe_candidates(program: &str) -> Vec<String> {
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
