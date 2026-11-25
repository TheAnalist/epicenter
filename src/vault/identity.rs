use std::fs;
use std::time::SystemTime;

use anyhow::Result;

use crate::util;

/// Seed for the flag digest, versioned: bumping it retires old generations.
const PARITY_SEED: &str = "epicenter-parity-v3";

// ── toolchain identity ──────────────────────────────────────────────────────

/// The `rustc -vV` facts that name a vault generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toolchain {
    /// `1.99.0`
    pub release: String,
    /// Short commit hash (`b940084d7`) as rustc prints it.
    pub commit: String,
    /// `x86_64-unknown-linux-gnu`
    pub host: String,
}

impl Toolchain {
    /// `rustc 1.99.0 (b940084d7)` — for humans, not for keys.
    pub fn version_line(&self) -> String {
        format!("rustc {} ({})", self.release, self.commit)
    }
}

/// Parse `rustc -vV` (first line + `host:`) for the default toolchain.
pub fn toolchain() -> Result<Toolchain> {
    toolchain_of(None)
}

/// Parse `rustc -vV` for a rustup selector (`nightly`, `1.98.0`, …;
/// `None` = the default toolchain). `exec` uses this for `cargo +nightly`.
pub fn toolchain_of(selector: Option<&str>) -> Result<Toolchain> {
    let info = crate::toolchain::rustc_info(selector)?;
    Ok(Toolchain {
        release: info.release,
        commit: info.commit,
        host: info.host,
    })
}

/// Install time of the active toolchain: the real `rustc` binary in the
/// sysroot (falling back to the sysroot directory). This is the reference
/// for "was this unit built by the installed toolchain?".
pub fn toolchain_install_time() -> Option<SystemTime> {
    toolchain_install_time_of(None)
}

/// Install time of `selector`'s toolchain (same shape as the default).
pub fn toolchain_install_time_of(selector: Option<&str>) -> Option<SystemTime> {
    let sysroot = crate::toolchain::sysroot(selector).ok()?;
    let rustc = sysroot
        .join("bin")
        .join(if cfg!(windows) { "rustc.exe" } else { "rustc" });
    fs::metadata(&rustc)
        .and_then(|meta| meta.modified())
        .ok()
        .or_else(|| fs::metadata(&sysroot).and_then(|meta| meta.modified()).ok())
}

// ── parity key ──────────────────────────────────────────────────────────────

/// One vault generation = toolchain + host + flag environment:
/// `1.99.0-b940084d7-x86_64-unknown-linux-gnu-3f9a2c1b`.
pub fn parity_key() -> Result<String> {
    parity_key_of(None)
}

/// Parity key for a rustup selector (`exec` with a `+toolchain` child).
pub fn parity_key_of(selector: Option<&str>) -> Result<String> {
    let tc = toolchain_of(selector)?;
    parity_key_with(&tc)
}

/// Parity key for an already-resolved toolchain (avoid a second `rustc`).
pub(crate) fn parity_key_with(tc: &Toolchain) -> Result<String> {
    let key = format!(
        "{}-{}-{}-{}",
        tc.release,
        tc.commit,
        tc.host,
        flags_digest(&tc.host)
    );
    // The key becomes a directory name: never allow traversal via a fake
    // `rustc -vV` on PATH (e.g. release `../../x`).
    util::validate_component(&key, "parity key")?;
    Ok(key)
}

/// Digest of the flags that live outside the fingerprint: the flag
/// environment plus the flag-relevant keys of Cargo's global config.
pub(crate) fn flags_digest(host: &str) -> String {
    flags_digest_of(host, None)
}

/// Same digest for a rustup selector; the child Cargo version is part of the
/// fingerprint, so `exec +nightly` must not compare against the default one.
pub(crate) fn flags_digest_of(host: &str, selector: Option<&str>) -> String {
    let mut input = String::from(PARITY_SEED);
    for name in [
        "RUSTFLAGS",
        "RUSTDOCFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_BUILD_RUSTDOCFLAGS",
        "CARGO_BUILD_TARGET",
        "RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "RUSTC",
    ] {
        input.push('\0');
        input.push_str(name);
        input.push('=');
        input.push_str(&std::env::var(name).unwrap_or_default());
    }
    if let Ok(path) = crate::config::cargo_config_path() {
        if let Ok(text) = crate::util::read_trusted_config(&path, 1024 * 1024) {
            for key in ["rustflags", "rustdocflags", "target", "rustc-wrapper"] {
                if let Some(value) = crate::config::read_table_key(&text, "build", key) {
                    input.push('\0');
                    input.push_str(key);
                    input.push('=');
                    input.push_str(&value);
                }
            }
            // Target-scoped flags are part of the fingerprint too — `setup
            // --linker` writes them, so the vault generation must follow.
            let target_table = format!("target.{host}");
            for key in ["rustflags", "rustdocflags", "linker"] {
                if let Some(value) = crate::config::read_table_key(&text, &target_table, key) {
                    input.push('\0');
                    input.push_str(&target_table);
                    input.push('.');
                    input.push_str(key);
                    input.push('=');
                    input.push_str(&value);
                }
            }
        }
    }
    if let Ok(mut cargo) = util::command_for("cargo") {
        if let Some(selector) = selector {
            cargo.arg(format!("+{selector}"));
        }
        if let Ok(output) = cargo.arg("-V").output() {
            if output.status.success() {
                input.push('\0');
                input.push_str("cargo=");
                input.push_str(String::from_utf8_lossy(&output.stdout).trim());
            }
        }
    }
    format!("{:08x}", (fnv1a64(input.as_bytes()) >> 32) as u32)
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
