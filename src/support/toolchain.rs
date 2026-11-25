//! One toolchain probe shared by the vault, remote compatibility, linker
//! detection and `doctor`.
//!
//! `rustc -vV` is the source of the release/commit/host/LLVM tuple; the
//! sysroot and `cargo -V` are separate, equally small probes. Keeping the
//! command shape and parsing here means a rustup selector is handled the same
//! way everywhere.

use anyhow::{Context, Result, bail};
use std::path::PathBuf;

/// The stable part of `rustc -vV`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustcInfo {
    /// `1.99.0`
    pub release: String,
    /// Short commit hash as rustc prints it (`b940084d7`).
    pub commit: String,
    /// `x86_64-unknown-linux-gnu`
    pub host: String,
    /// `LLVM version:` value, or empty when rustc omits it.
    pub llvm: String,
}

impl RustcInfo {
    /// `rustc 1.99.0 (b940084d7)` — for humans, not for keys.
    pub fn version_line(&self) -> String {
        format!("rustc {} ({})", self.release, self.commit)
    }
}

fn rustc(selector: Option<&str>) -> Result<std::process::Command> {
    let mut command = crate::util::command_for("rustc")?;
    if let Some(selector) = selector {
        command.arg(format!("+{selector}"));
    }
    Ok(command)
}

/// Read and validate the `rustc -vV` tuple.
pub fn rustc_info(selector: Option<&str>) -> Result<RustcInfo> {
    let output = rustc(selector)?
        .arg("-vV")
        .output()
        .context("running `rustc -vV`")?;
    if !output.status.success() {
        bail!("`rustc -vV` failed — is a toolchain installed?");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut release = String::new();
    let mut commit = String::new();
    let mut host = String::new();
    let mut llvm = String::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("rustc ") {
            let mut parts = rest.split_whitespace();
            if let Some(version) = parts.next() {
                release = version.to_string();
            }
            if let Some(value) = parts.next() {
                commit = value.trim_start_matches('(').to_string();
            }
        } else if let Some(value) = line.strip_prefix("host: ") {
            host = value.trim().to_string();
        } else if let Some(value) = line.strip_prefix("LLVM version: ") {
            llvm = value.trim().to_string();
        }
    }
    if release.is_empty() || commit.is_empty() || host.is_empty() {
        bail!("`rustc -vV` did not report a complete toolchain identity");
    }
    crate::util::validate_component(&release, "rustc release")?;
    crate::util::validate_component(&commit, "rustc commit")?;
    crate::util::validate_component(&host, "rustc host")?;
    Ok(RustcInfo {
        release,
        commit,
        host,
        llvm,
    })
}

/// The active toolchain's sysroot.
pub fn sysroot(selector: Option<&str>) -> Result<PathBuf> {
    let output = rustc(selector)?
        .args(["--print", "sysroot"])
        .output()
        .context("running `rustc --print sysroot`")?;
    if !output.status.success() {
        bail!("`rustc --print sysroot` failed — is a toolchain installed?");
    }
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    if path.as_os_str().is_empty() {
        bail!("`rustc --print sysroot` returned an empty path");
    }
    Ok(path)
}

/// `cargo -V` for the default toolchain or a rustup selector.
pub fn cargo_version(selector: Option<&str>) -> Result<String> {
    let mut command = crate::util::command_for("cargo")?;
    if let Some(selector) = selector {
        command.arg(format!("+{selector}"));
    }
    let output = command.arg("-V").output().context("running `cargo -V`")?;
    if !output.status.success() {
        bail!("`cargo -V` failed — is Cargo installed?");
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        bail!("`cargo -V` returned an empty version");
    }
    Ok(text)
}
