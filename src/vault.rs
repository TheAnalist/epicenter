//! The vault: a durable store of Cargo unit groups, addressed by Cargo's
//! own fingerprint hashes.
//!
//! A *unit group* is exactly what Cargo needs to consider one built unit
//! fresh: the 16-hex fingerprint hash file, the serialized `Fingerprint`
//! JSON, the binary dep-info, and the unit's artifacts (`deps/…`, and the
//! `build/<anchor>/…` tree for build-script units). The vault keeps one
//! directory per generation, where a generation is one toolchain plus one
//! flag environment (the *parity key*):
//!
//! ```text
//! {cargo-cache-home}/epicenter/
//!   store/<parity-key>/
//!     manifest.json                file list, sizes, canonical stamps
//!     units/<pkg>-<unit-hash>/     one unit group
//!       <memo-file>                the authoritative 16-hex hash
//!       <memo-file>.json           the serialized Fingerprint
//!       dep-<memo-file>            EncodedDepInfo (mandatory for freshness)
//!       deps/…  build/…            artifacts, as the profile dir holds them
//!   build/…                        the shared working dir (a disposable view)
//! ```
//!
//! Timestamps are the only lever besides the hash in Cargo's freshness
//! check, so every file of a unit group carries ONE canonical second
//! (`stamp`): the ceiling of the group's metadata output (`.rmeta`) when it
//! has one — the moment dependents can compile against it — else of its
//! newest file, and always ≥ every dependency's stamp (harvest clamps the
//! store). Restore never stamps hard links: they share the store's inode,
//! and a `touch` on a restored file would rewrite the store itself.

use std::fs;
#[cfg(unix)]
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::sync::OnceLock;

static STORE_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

use anyhow::{Context, Result};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::settings::LinkPolicy;
use crate::util::{self, FileLock};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::fingerprint::{self, ArtifactInfo, Unit};

/// Seed for the flag digest, versioned: bumping it retires old generations.
const PARITY_SEED: &str = "epicenter-parity-v3";

/// Per-store marker: identifies a directory as an epicenter store. A
/// project-selected store must already contain it (or be empty), so a
/// repository cannot point the sweep at `~/.cargo`, `~/.config`, or a sibling.
pub const STORE_MARKER: &str = ".epicenter-store";

/// Per-generation marker: only marked generation directories are eligible
/// for automatic debris cleanup. Unknown children are never deleted.
pub(crate) const GENERATION_MARKER: &str = ".epicenter-generation";

/// Public Ed25519 key for the store manifest, written by the trusted writer
/// next to the store marker. Readers need no private key.
pub const PUBKEY_FILE: &str = ".epicenter-pubkey";

/// Bound the number of generation directories a directory scan will accept.
const MAX_GENERATIONS: usize = 4096;
/// Bound a full store scan so a hostile tree cannot burn CPU/IO indefinitely.
const MAX_SCAN_FILES: u64 = 2_000_000;

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
    let mut command = util::command_for("rustc")?;
    if let Some(selector) = selector {
        command.arg(format!("+{selector}"));
    }
    let output = command.arg("-vV").output().context("running `rustc -vV`")?;
    if !output.status.success() {
        anyhow::bail!("`rustc -vV` failed — is a toolchain installed?");
    }
    let text = String::from_utf8_lossy(&output.stdout);

    let mut release = "unknown".to_string();
    let mut commit = "unknown".to_string();
    let mut host = "unknown".to_string();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("rustc ") {
            let mut parts = rest.split_whitespace();
            if let Some(version) = parts.next() {
                release = version.to_string();
            }
            // `rustc 1.99.0 (b940084d7 2026-09-28)` — the token starts `(`.
            if let Some(commit_part) = parts.next() {
                let value = commit_part.trim_start_matches('(');
                if !value.is_empty() {
                    commit = value.to_string();
                }
            }
        } else if let Some(value) = line.strip_prefix("host: ") {
            host = value.trim().to_string();
        }
    }
    util::validate_component(&release, "rustc release")?;
    util::validate_component(&commit, "rustc commit")?;
    util::validate_component(&host, "rustc host")?;
    Ok(Toolchain {
        release,
        commit,
        host,
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
    let mut command = util::command_for("rustc").ok()?;
    if let Some(selector) = selector {
        command.arg(format!("+{selector}"));
    }
    let output = command.args(["--print", "sysroot"]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let sysroot = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
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
fn parity_key_with(tc: &Toolchain) -> Result<String> {
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
fn flags_digest(host: &str) -> String {
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

// ── layout ──────────────────────────────────────────────────────────────────

/// `<build>/../store` — the vault lives beside the shared build dir, so
/// `cargo clean` can never touch it.
pub fn store_root(build_root: &Path) -> PathBuf {
    STORE_OVERRIDE
        .get()
        .cloned()
        .unwrap_or_else(|| build_root.parent().unwrap_or(build_root).join("store"))
}

/// Install a store path from `epicenter.toml` (once per process).
pub fn set_store_override(path: PathBuf) -> Result<()> {
    STORE_OVERRIDE
        .set(path)
        .map_err(|_| anyhow::anyhow!("store override is already installed"))
}

/// `store/<parity-key>/units`.
pub fn units_dir(store_root: &Path, parity: &str) -> PathBuf {
    store_root.join(parity).join("units")
}

fn manifest_path(store_root: &Path, parity: &str) -> PathBuf {
    store_root.join(parity).join("manifest.json")
}

/// The per-generation lock lives **outside** the generation dir so an empty
/// generation can be removed while the lock is held (Windows).
fn store_lock_path(store_root: &Path, parity: &str) -> PathBuf {
    store_root.join(format!(".lock-{parity}"))
}

/// Remove the per-generation lock file when its generation directory is
/// gone and no live process holds the lock. A held lock is left alone.
pub(crate) fn remove_generation_lock(store_root: &Path, generation: &str) {
    let dir = store_root.join(generation);
    let path = store_lock_path(store_root, generation);
    if dir.exists() || !path.exists() {
        return;
    }
    let Ok(Some(_lock)) = FileLock::try_acquire(&path) else {
        return; // a live harvest holds it
    };
    if !dir.exists() {
        let _ = fs::remove_file(&path);
    }
}

/// Clean the debris a crash or a manual deletion leaves in the store root:
/// `.lock-*` files whose generation is gone, and empty manifest-less
/// generation directories. Existing generations and held locks are kept.
pub fn sweep_store_debris(store_root: &Path) {
    let Ok(entries) = fs::read_dir(store_root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(generation) = name.strip_prefix(".lock-") {
            if !generation.is_empty() {
                remove_generation_lock(store_root, generation);
            }
        }
    }
    let Ok(names) = generation_names(store_root) else {
        return;
    };
    for generation in names {
        // Only a marked generation is ours to delete. A project-selected
        // store can point at an arbitrary user directory; unknown children
        // (`~/.cargo/registry`, `~/.config/*`, a sibling repo) must survive.
        if util::validate_component(&generation, "generation").is_err() {
            continue;
        }
        let dir = store_root.join(&generation);
        let Ok(meta) = util::metadata_nofollow(&dir) else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        let marker = dir.join(GENERATION_MARKER);
        if !util::metadata_nofollow(&marker).is_ok_and(|meta| meta.is_file()) {
            continue;
        }
        let units = units_dir(store_root, &generation);
        let empty = fs::read_dir(&units)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(true);
        // Only manifest-less husks: a manifest is owned by `drop_units`,
        // which removes its generation itself.
        if !empty || manifest_path(store_root, &generation).is_file() {
            continue;
        }
        let Ok(Some(_lock)) = FileLock::try_acquire(&store_lock_path(store_root, &generation))
        else {
            continue;
        };
        let still_empty = fs::read_dir(&units)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(true);
        if still_empty {
            let _ = crate::util::force_remove_dir(&dir);
            drop(_lock);
            remove_generation_lock(store_root, &generation);
        }
    }
}

/// Delete one whole generation under its lock: units, manifest and the
/// lock file. Returns `false` when a live harvest holds the generation lock.
pub fn drop_generation(store_root: &Path, parity: &str) -> Result<bool> {
    util::validate_component(parity, "generation")?;
    if store_root.exists() {
        check_store_trust(store_root)?;
    }
    let dir = store_root.join(parity);
    let meta = match util::metadata_nofollow(&dir) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            anyhow::bail!("refusing symlinked/reparse generation {}", dir.display());
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err).context("inspecting generation"),
    };
    if !meta.is_dir() {
        anyhow::bail!("refusing symlinked/reparse generation {}", dir.display());
    }
    let lock_path = store_lock_path(store_root, parity);
    let Ok(Some(lock)) = FileLock::try_acquire(&lock_path) else {
        return Ok(false);
    };
    crate::util::force_remove_dir(&dir)?;
    drop(lock);
    remove_generation_lock(store_root, parity);
    Ok(true)
}

/// Unit dir names of one generation: the manifest when readable, else the
/// `units/` directory (so an orphan generation can still be fully deleted).
pub fn generation_unit_names(store_root: &Path, parity: &str) -> Result<Vec<String>> {
    util::validate_component(parity, "generation")?;
    if let Ok(Some(manifest)) = load_manifest(store_root, parity) {
        return Ok(manifest
            .units
            .iter()
            .map(|entry| entry.name.clone())
            .collect());
    }
    let mut names = Vec::new();
    if let Ok(entries) = fs::read_dir(units_dir(store_root, parity)) {
        for entry in entries.flatten() {
            if !entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if util::validate_component(&name, "unit name").is_ok() {
                names.push(name);
            }
        }
    }
    names.sort();
    Ok(names)
}

fn ensure_store_root(store_root: &Path) -> Result<()> {
    util::ensure_windows_user_path(store_root, "store")?;
    match util::metadata_nofollow(store_root) {
        Ok(meta) => {
            if !meta.is_dir() {
                anyhow::bail!(
                    "store root {} is not a real directory",
                    store_root.display()
                );
            }
            util::ensure_private_dir(store_root)?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            anyhow::bail!(
                "store root {} is not a real directory",
                store_root.display()
            );
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            util::create_private_dir_all(store_root)?;
        }
        Err(err) => {
            return Err(err).with_context(|| format!("inspecting {}", store_root.display()));
        }
    }
    #[cfg(windows)]
    require_private_windows_acl(store_root, "store root")?;
    write_marker(&store_root.join(STORE_MARKER))?;
    Ok(())
}

/// A writable Windows directory may be owner-owned yet still writable by a
/// local group. Auto-linking or signing into such a store would let another
/// principal mutate the inode after the hash check.
#[cfg(windows)]
fn require_private_windows_acl(path: &Path, what: &str) -> Result<()> {
    match util::windows_acl_is_private(path) {
        Some(true) => Ok(()),
        Some(false) => anyhow::bail!(
            "{what} {} has a Windows ACL that grants write access to another principal — choose a private local directory",
            path.display()
        ),
        None => anyhow::bail!(
            "{what} {} has a Windows ACL that could not be inspected — choose a private local directory",
            path.display()
        ),
    }
}

/// Write a zero-byte marker once; O_EXCL keeps a planted symlink from being
/// followed. An existing regular marker is accepted.
fn write_marker(path: &Path) -> Result<()> {
    match util::metadata_nofollow(path) {
        Ok(meta) if meta.is_file() => return Ok(()),
        Ok(_) => anyhow::bail!("marker {} is not a regular file", path.display()),
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            anyhow::bail!("marker {} is not a regular file", path.display());
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).with_context(|| format!("inspecting {}", path.display())),
    }
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(b"epicenter-store-v1\n")?;
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(err).with_context(|| format!("creating {}", path.display())),
    }
}

// ── manifest ────────────────────────────────────────────────────────────────

/// `manifest.json` of one generation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    pub parity_key: String,
    pub toolchain: String,
    /// Unix seconds of the first harvest of this generation.
    pub created: u64,
    /// Unix seconds of the last harvest.
    pub updated: u64,
    pub units: Vec<UnitEntry>,
    /// HMAC-SHA256 over the manifest body (excluding this field), keyed by
    /// the per-user vault key. An empty value is old/untrusted and refused.
    /// Kept for local, single-trust-domain stores and old manifests.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mac: String,
    /// Ed25519 signature over the same body, verifiable with the public key
    /// stored in the vault. Required for read-only/foreign readers.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

/// One stored unit group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitEntry {
    /// Fingerprint dir name: `<pkg>-<16hex>`.
    pub name: String,
    pub profile: String,
    /// Memo file name, e.g. `lib-serde`.
    pub memo: String,
    /// Memo file content — the authoritative 16-hex hash.
    pub hash: String,
    /// Canonical mtime of the whole group (whole seconds).
    pub stamp: u64,
    /// Build-dir layout this group reconstructs. Absent in manifests written
    /// before the new layout; inferred from the destinations when missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout: Option<fingerprint::UnitLayout>,
    pub files: Vec<FileEntry>,
}

impl UnitEntry {
    /// The layout this group reconstructs (recorded, or inferred).
    pub fn layout(&self) -> fingerprint::UnitLayout {
        self.layout.unwrap_or_else(|| {
            if self
                .files
                .iter()
                .any(|file| file.dest.starts_with(".fingerprint/"))
            {
                fingerprint::UnitLayout::Classic
            } else if self
                .files
                .iter()
                .any(|file| file.dest.contains("/fingerprint/"))
            {
                fingerprint::UnitLayout::New
            } else {
                fingerprint::UnitLayout::Classic
            }
        })
    }
}

/// One stored file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Path inside the unit group.
    pub path: String,
    /// Path relative to the profile dir in a build dir.
    pub dest: String,
    pub size: u64,
    /// SHA-256 of the file content (empty only in pre-fix manifests).
    #[serde(default)]
    pub sha256: String,
    /// `memo` | `fingerprint` | `dep-info` | `artifact` | `build-tree`.
    pub role: String,
    /// Content-addressed gzip blob relative to the generation root, when the
    /// stored bytes are compressed. Old manifests omit this and stay raw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
}

impl UnitEntry {
    /// Reject every path that could escape the store or the view.
    fn validate(&self) -> Result<()> {
        util::validate_component(&self.name, "unit name")?;
        util::validate_component(&self.profile, "profile")?;
        util::validate_component(&self.memo, "memo file")?;
        if !self.hash.is_empty() && !fingerprint::looks_like_hash(&self.hash) {
            let shown: String = self.hash.chars().take(32).collect();
            anyhow::bail!("invalid memo hash {shown:?} in unit {}", self.name);
        }
        let mut paths = std::collections::HashSet::with_capacity(self.files.len());
        for file in &self.files {
            util::validate_rel(&file.path, "stored file path")?;
            util::validate_rel(&file.dest, "destination path")?;
            if !paths.insert(file.path.to_lowercase()) {
                anyhow::bail!(
                    "duplicate case-insensitive file path {:?} in unit {}",
                    file.path,
                    self.name
                );
            }
            if !file.sha256.is_empty()
                && (file.sha256.len() != 64
                    || !file.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()))
            {
                anyhow::bail!("invalid SHA-256 for {} in unit {}", file.path, self.name);
            }
            if file.size > util::MAX_FILE_BYTES {
                anyhow::bail!(
                    "file {} in unit {} is {} bytes (cap {})",
                    file.path,
                    self.name,
                    file.size,
                    util::MAX_FILE_BYTES
                );
            }
            if let Some(object) = &file.object {
                util::validate_rel(object, "object path")?;
                if !object.starts_with("blobs/") || !object.ends_with(".gz") {
                    anyhow::bail!("invalid object path {object:?} in unit {}", self.name);
                }
            }
        }
        Ok(())
    }
}

impl Manifest {
    /// Reject every path that could escape the store or the view. This runs
    /// before any consumer (restore/verify/evict) touches a manifest path.
    pub fn validate(&self) -> Result<()> {
        let mut names = std::collections::HashSet::with_capacity(self.units.len());
        for unit in &self.units {
            unit.validate()?;
            // Windows/macOS/SMB map these to one directory. Reject the
            // collision instead of producing a platform-dependent restore.
            if !names.insert(unit.name.to_lowercase()) {
                anyhow::bail!(
                    "duplicate case-insensitive unit name {:?} in the manifest",
                    unit.name
                );
            }
        }
        Ok(())
    }
}

/// Where the per-user vault MAC key lives. Outside the store on purpose:
/// a store-write attacker must not be able to rewrite the key as well.
fn manifest_key_path() -> Result<PathBuf> {
    let path = crate::paths::cargo_home()?
        .join("epicenter")
        .join("manifest.key");
    #[cfg(windows)]
    crate::util::ensure_windows_user_path(&path, "vault key")?;
    Ok(path)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > block.len() {
        let digest = Sha256::digest(key);
        block[..32].copy_from_slice(&digest);
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    let mut outer = Sha256::new();
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for index in 0..64 {
        ipad[index] ^= block[index];
        opad[index] ^= block[index];
    }
    inner.update(ipad);
    inner.update(data);
    let inner = inner.finalize();
    outer.update(opad);
    outer.update(inner);
    let out = outer.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hex_decode(text: &str, what: &str) -> Result<Vec<u8>> {
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

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

fn read_key_file(path: &Path) -> Result<Vec<u8>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("opening vault key {}", path.display()))?;
    let meta = file.metadata()?;
    if !meta.is_file() || util::is_reparse_point(&meta) {
        anyhow::bail!("vault key {} is not a regular file", path.display());
    }
    if !util::owned_by_us(path, &meta) {
        anyhow::bail!("vault key {} is owned by another user", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o077 != 0 {
            anyhow::bail!(
                "vault key {} is accessible by other users (mode {:o})",
                path.display(),
                meta.mode() & 0o777
            );
        }
    }
    let mut key = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut key)?;
    if key.len() != 32 {
        anyhow::bail!("vault key {} is malformed", path.display());
    }
    Ok(key)
}

fn write_new_key_file(path: &Path, key: &[u8; 32]) -> Result<Vec<u8>> {
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent", path.display()))?;
    util::create_private_dir_all(parent)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(key)?;
            file.sync_all()?;
            Ok(key.to_vec())
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => read_key_file(path),
        Err(err) => Err(err).with_context(|| format!("creating vault key {}", path.display())),
    }
}

fn manifest_key() -> Result<Vec<u8>> {
    let path = manifest_key_path()?;
    if let Ok(key) = read_key_file(&path) {
        return Ok(key);
    }
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|err| anyhow::anyhow!("generating vault key: {err}"))?;
    write_new_key_file(&path, &key)
}

fn manifest_signing_key_path() -> Result<PathBuf> {
    let path = crate::paths::cargo_home()?
        .join("epicenter")
        .join("manifest.ed25519");
    #[cfg(windows)]
    crate::util::ensure_windows_user_path(&path, "vault signing key")?;
    Ok(path)
}

fn manifest_signing_key() -> Result<SigningKey> {
    let path = manifest_signing_key_path()?;
    let bytes = if let Ok(key) = read_key_file(&path) {
        key
    } else {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key)
            .map_err(|err| anyhow::anyhow!("generating signing key: {err}"))?;
        write_new_key_file(&path, &key)?
    };
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing key {} is malformed", path.display()))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn existing_signing_key() -> Result<Option<SigningKey>> {
    let path = manifest_signing_key_path()?;
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = read_key_file(&path)?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing key {} is malformed", path.display()))?;
    Ok(Some(SigningKey::from_bytes(&seed)))
}

fn manifest_body(manifest: &Manifest) -> Result<Vec<u8>> {
    let mut unsigned = manifest.clone();
    unsigned.mac.clear();
    unsigned.signature.clear();
    Ok(serde_json::to_vec(&unsigned)?)
}

fn manifest_mac(manifest: &Manifest) -> Result<String> {
    Ok(hex_encode(&hmac_sha256(
        &manifest_key()?,
        &manifest_body(manifest)?,
    )))
}

fn manifest_signature(manifest: &Manifest, key: &SigningKey) -> Result<String> {
    let signature = key.sign(&manifest_body(manifest)?);
    Ok(hex_encode(&signature.to_bytes()))
}

fn store_public_key_path(store_root: &Path) -> PathBuf {
    store_root.join(PUBKEY_FILE)
}

fn read_store_public_key(store_root: &Path) -> Result<VerifyingKey> {
    let path = store_public_key_path(store_root);
    let text = crate::util::read_small_text(&path, 16 * 1024)
        .with_context(|| format!("reading vault public key {}", path.display()))?;
    let bytes = hex_decode(&text, "vault public key")?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("vault public key {} is malformed", path.display()))?;
    VerifyingKey::from_bytes(&key)
        .map_err(|err| anyhow::anyhow!("vault public key {} is invalid: {err}", path.display()))
}

fn write_store_public_key(store_root: &Path, key: &SigningKey) -> Result<()> {
    let path = store_public_key_path(store_root);
    let wanted = format!("{}\n", hex_encode(&key.verifying_key().to_bytes()));
    if let Ok(existing) = crate::util::read_small_text(&path, 16 * 1024) {
        if existing.trim() == wanted.trim() {
            return Ok(());
        }
        anyhow::bail!(
            "store public key {} does not match the writer's signing key; rotation is not automatic",
            path.display()
        );
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Public key: readable by every reader; the store root itself may be
        // 0755 for a shared read-only mount.
        options.mode(0o644);
    }
    match options.open(&path) {
        Ok(mut file) => {
            file.write_all(wanted.as_bytes())?;
            file.sync_all()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // The process umask must not hide the public key from readers.
                // Use the held fd, never a path that could be swapped.
                file.set_permissions(fs::Permissions::from_mode(0o644))
                    .with_context(|| format!("making {} readable", path.display()))?;
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = crate::util::read_small_text(&path, 16 * 1024)
                .with_context(|| format!("reading {}", path.display()))?;
            if existing.trim() == wanted.trim() {
                Ok(())
            } else {
                anyhow::bail!(
                    "store public key {} does not match the writer's signing key; rotation is not automatic",
                    path.display()
                )
            }
        }
        Err(err) => Err(err).with_context(|| format!("creating {}", path.display())),
    }
}

fn verify_manifest_signature(store_root: &Path, manifest: &Manifest, path: &Path) -> Result<()> {
    let body = manifest_body(manifest)?;
    let signature = hex_decode(&manifest.signature, "manifest signature")?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| anyhow::anyhow!("manifest {} has a malformed signature", path.display()))?;
    let signature = Signature::from_bytes(&signature);
    let key = match read_store_public_key(store_root) {
        Ok(key) => key,
        Err(err) => {
            if let Some(signing) = existing_signing_key()? {
                signing.verifying_key()
            } else {
                return Err(err).with_context(|| {
                    format!(
                        "manifest {} is signed but the reader has no public key",
                        path.display()
                    )
                });
            }
        }
    };
    key.verify_strict(&body, &signature).map_err(|_| {
        anyhow::anyhow!(
            "manifest {} failed its Ed25519 signature check",
            path.display()
        )
    })
}

fn store_is_owned(store_root: &Path) -> bool {
    util::metadata_nofollow(store_root)
        .map(|meta| util::owned_by_us(store_root, &meta))
        .unwrap_or(false)
}

fn load_manifest(store_root: &Path, parity: &str) -> Result<Option<Manifest>> {
    load_manifest_at(store_root, parity, false)
}

/// Load a manifest. `repair` is true only for writer paths that already hold
/// the generation lock; readers never delete units or rewrite the manifest.
fn load_manifest_at(store_root: &Path, parity: &str, repair: bool) -> Result<Option<Manifest>> {
    let path = manifest_path(store_root, parity);
    let meta = match util::metadata_nofollow(&path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            anyhow::bail!("{} is not a regular manifest file", path.display());
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("inspecting {}", path.display()));
        }
    };
    // The manifest is the list of files that will be executed/linked. Never
    // parse one that is a symlink. A foreign, writable manifest is not a
    // reader; only a read-only mount may be foreign.
    if !meta.is_file() {
        anyhow::bail!("{} is not a regular manifest file", path.display());
    }
    let read_only = store_is_read_only(store_root);
    let owned = store_is_owned(store_root);
    if !util::owned_by_us(&path, &meta) && !read_only {
        anyhow::bail!("{} is owned by another user", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !read_only && meta.mode() & 0o022 != 0 {
            anyhow::bail!(
                "{} is group/world-writable (mode {:o})",
                path.display(),
                meta.mode() & 0o777
            );
        }
    }
    let text = if read_only {
        crate::util::read_small_text(&path, 16 * 1024 * 1024)
            .with_context(|| format!("reading {}", path.display()))?
    } else {
        crate::util::read_trusted_config(&path, 16 * 1024 * 1024)
            .with_context(|| format!("reading {}", path.display()))?
    };
    let mut manifest: Manifest =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    if !manifest.signature.is_empty() {
        verify_manifest_signature(store_root, &manifest, &path)?;
    } else {
        let local_hmac_key = manifest_key_path()?.is_file();
        if !local_hmac_key {
            anyhow::bail!(
                "manifest {} has no Ed25519 signature and the local HMAC key is missing; re-harvest it on the writer",
                path.display()
            );
        }
        if manifest.mac.len() != 64 {
            anyhow::bail!(
                "manifest {} is unsigned (re-harvest this generation)",
                path.display()
            );
        }
        let expected = manifest_mac(&manifest)?;
        if !constant_time_eq(manifest.mac.as_bytes(), expected.as_bytes()) {
            anyhow::bail!("manifest {} failed its MAC check", path.display());
        }
    }
    // A valid signature/MAC with an invalid entry used to brick the whole
    // generation. A writer may repair in place; a reader only filters the
    // invalid entries in memory and never writes the store.
    if let Err(err) = manifest.validate() {
        let can_repair = repair && !read_only && owned;
        let mut kept = Vec::with_capacity(manifest.units.len());
        let mut dropped = Vec::new();
        for unit in manifest.units.drain(..) {
            if unit.validate().is_ok() {
                kept.push(unit);
            } else {
                dropped.push(unit);
            }
        }
        manifest.units = kept;
        eprintln!(
            "warning: {} {} invalid unit(s) from {} ({err:#})",
            if can_repair { "dropped" } else { "ignored" },
            dropped.len(),
            path.display()
        );
        if can_repair {
            // Their stored groups are unreachable now (no valid memo hash to
            // restore), so remove them instead of leaving verify to flag
            // orphans.
            let units = units_dir(store_root, parity);
            for unit in &dropped {
                if util::validate_component(&unit.name, "unit name").is_err() {
                    continue;
                }
                let dir = units.join(&unit.name);
                if util::metadata_nofollow(&dir).is_ok_and(|meta| meta.is_dir()) {
                    let _ = fs::remove_dir_all(&dir);
                }
            }
            let _ = save_manifest(store_root, parity, &manifest);
        }
    }
    Ok(Some(manifest))
}

pub(crate) fn save_manifest(store_root: &Path, parity: &str, manifest: &Manifest) -> Result<()> {
    util::validate_component(parity, "generation")?;
    manifest.validate()?;
    let dir = store_root.join(parity);
    util::create_private_dir_all(&dir)?;
    write_marker(&dir.join(GENERATION_MARKER))?;
    let signing_key = manifest_signing_key()?;
    write_store_public_key(store_root, &signing_key)?;
    let mut signed = manifest.clone();
    signed.mac.clear();
    signed.signature.clear();
    signed.mac = manifest_mac(&signed)?;
    signed.signature = manifest_signature(&signed, &signing_key)?;
    let what = serde_json::to_string_pretty(&signed)?;
    // O_EXCL + a random, symlink-free temp path: never write through a
    // planted temp link.
    let nonce = util::temp_nonce();
    let mut tmp = None;
    for attempt in 0..100u32 {
        let candidate = dir.join(format!(
            "manifest.json.tmp-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
                }
                tmp = Some((candidate, file));
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| format!("creating {}", candidate.display()));
            }
        }
    }
    let Some((tmp, mut file)) = tmp else {
        anyhow::bail!(
            "could not create a unique manifest temp file in {}",
            dir.display()
        );
    };
    file.write_all(what.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, manifest_path(store_root, parity))?;
    #[cfg(unix)]
    if let Ok(parent) = fs::File::open(&dir) {
        let _ = parent.sync_all();
    }
    Ok(())
}

/// Names of the store generations (directories under `store/`).
pub fn generation_names(store_root: &Path) -> Result<Vec<String>> {
    if !store_root.is_dir() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in
        fs::read_dir(store_root).with_context(|| format!("reading {}", store_root.display()))?
    {
        let entry = entry?;
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !entry.file_type()?.is_dir() || util::is_reparse_point(&meta) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with('.') {
            if names.len() >= MAX_GENERATIONS {
                anyhow::bail!(
                    "store {} has more than {} generation directories — refusing an unbounded scan",
                    store_root.display(),
                    MAX_GENERATIONS
                );
            }
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

// ── stored units (read / remove) ─────────────────────────────────────────────

/// One unit as the vault holds it.
#[derive(Debug, Clone)]
pub struct StoredUnit {
    /// The generation directory the unit lives in (the parity key).
    pub generation: String,
    /// The manifest entry: name, profile, hash, stamp, files.
    pub entry: UnitEntry,
    /// `store/<generation>/units/<name>`.
    pub dir: PathBuf,
}

/// Every stored unit across all generations, manifest-driven.
pub fn stored_units(store_root: &Path) -> Result<Vec<StoredUnit>> {
    if store_root.exists() {
        check_store_trust(store_root)?;
    }
    let mut out = Vec::new();
    for generation in generation_names(store_root)? {
        let Some(manifest) = load_manifest(store_root, &generation)? else {
            continue;
        };
        let units = units_dir(store_root, &generation);
        for entry in manifest.units {
            let dir = units.join(&entry.name);
            out.push(StoredUnit {
                generation: generation.clone(),
                entry,
                dir,
            });
        }
    }
    Ok(out)
}

/// The `rustc` identity recorded in a stored unit's Fingerprint JSON.
pub fn stored_unit_rustc(unit: &StoredUnit) -> Option<String> {
    let dir_meta = util::metadata_nofollow(&unit.dir).ok()?;
    if !dir_meta.is_dir() {
        return None;
    }
    let rel = PathBuf::from(format!("{}.json", unit.entry.memo));
    util::check_regular_chain(&unit.dir, &rel).ok()?;
    let text = fs::read_to_string(unit.dir.join(&rel)).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    match value.get("rustc") {
        Some(serde_json::Value::Number(number)) => Some(number.to_string()),
        Some(serde_json::Value::String(text)) => Some(text.clone()),
        _ => None,
    }
}

/// Remove stored unit groups: their directories go, the manifest is pruned,
/// and a generation left without units disappears entirely. Returns how many
/// groups were dropped; groups that could not be removed stay recorded.
pub fn drop_units(store_root: &Path, generation: &str, names: &[String]) -> Result<usize> {
    util::validate_component(generation, "generation")?;
    if store_root.exists() {
        check_store_trust(store_root)?;
    }
    let lock = FileLock::acquire(&store_lock_path(store_root, generation))?;
    let Some(mut manifest) = load_manifest_at(store_root, generation, true)? else {
        return Ok(0);
    };
    let units = units_dir(store_root, generation);
    match util::metadata_nofollow(&units) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            anyhow::bail!(
                "units dir {} is a symlink/reparse or not a directory",
                units.display()
            );
        }
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            anyhow::bail!(
                "units dir {} is a symlink/reparse or not a directory",
                units.display()
            );
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // Nothing to remove; the manifest may still be pruned.
        }
        Err(err) => {
            return Err(err).with_context(|| format!("inspecting {}", units.display()));
        }
    }
    let mut kept = Vec::with_capacity(manifest.units.len());
    let mut dropped = 0;
    for entry in manifest.units.drain(..) {
        if !names.contains(&entry.name) {
            kept.push(entry);
            continue;
        }
        util::validate_component(&entry.name, "unit name")?;
        let dir = units.join(&entry.name);
        match util::metadata_nofollow(&dir) {
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                eprintln!(
                    "could not remove symlinked/reparse unit {}: refused",
                    dir.display()
                );
                kept.push(entry);
            }
            Ok(meta) if meta.is_dir() => {
                // Defense in depth even after the component validator: the
                // target must be a direct child of the units directory.
                if let Ok(base) = fs::canonicalize(&units) {
                    match fs::canonicalize(&dir) {
                        Ok(canon) if canon.parent() == Some(base.as_path()) && canon != base => {}
                        _ => {
                            eprintln!(
                                "could not remove {}: escapes {}",
                                dir.display(),
                                units.display()
                            );
                            kept.push(entry);
                            continue;
                        }
                    }
                }
                match fs::remove_dir_all(&dir) {
                    Ok(()) => {
                        dropped += 1;
                    }
                    Err(err) => {
                        eprintln!("could not remove {}: {err}", dir.display());
                        kept.push(entry);
                    }
                }
            }
            Ok(_) => {
                eprintln!("could not remove {}: not a directory", dir.display());
                kept.push(entry);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                dropped += 1;
            }
            Err(err) => {
                eprintln!("could not remove {}: {err}", dir.display());
                kept.push(entry);
            }
        }
    }
    manifest.units = kept;
    let empty = manifest.units.is_empty();
    if empty {
        let _ = crate::util::force_remove_dir(&store_root.join(generation));
    } else if dropped > 0 {
        manifest.updated = now_secs();
        save_manifest(store_root, generation, &manifest)?;
        sweep_blobs(store_root, generation, &manifest);
    }
    drop(lock);
    if empty {
        // The parity-key store is gone; its outside lock file is debris.
        remove_generation_lock(store_root, generation);
    }
    Ok(dropped)
}
/// Remove gzip blobs no longer referenced by the surviving manifest.
fn sweep_blobs(store_root: &Path, generation: &str, manifest: &Manifest) {
    let referenced: std::collections::HashSet<&str> = manifest
        .units
        .iter()
        .flat_map(|unit| unit.files.iter())
        .filter_map(|file| file.object.as_deref())
        .collect();
    let blobs = store_root.join(generation).join("blobs");
    let generation_root = store_root.join(generation);
    for entry in WalkDir::new(&blobs).min_depth(1).contents_first(true) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path();
        if entry.file_type().is_file() {
            let rel = path
                .strip_prefix(&generation_root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            if !referenced.contains(rel.as_str()) {
                let _ = fs::remove_file(path);
            }
        } else if entry.file_type().is_dir() {
            let _ = fs::remove_dir(path);
        }
    }
}

// ── harvest ─────────────────────────────────────────────────────────────────

/// What one harvest did.
#[derive(Debug, Default)]
pub struct HarvestReport {
    pub parity: String,
    pub toolchain: String,
    pub stored: usize,
    pub refreshed: usize,
    pub unchanged: usize,
    pub skipped_stale: usize,
    pub skipped_incomplete: usize,
    pub files: usize,
    pub bytes: u64,
    pub note: Option<String>,
}

/// Store unit groups from a build dir into the vault.
///
/// Only units built by the installed toolchain are stored: the newest unit's
/// rustc cohort marks the active generation, and a cache that as a whole
/// predates the installed toolchain produces a note instead of stale copies
/// filed under the current parity key.
pub fn harvest(
    build_root: &Path,
    store_root: &Path,
    unit_filter: Option<&str>,
    dry_run: bool,
) -> Result<HarvestReport> {
    harvest_with(
        build_root,
        store_root,
        unit_filter,
        dry_run,
        None,
        None,
        true,
    )
}

/// Harvest for a specific toolchain and/or layout (`exec` with a `+toolchain`
/// child). The plain [`harvest`] uses the default toolchain and derives the
/// layout from `cargo --version`.
pub fn harvest_with(
    build_root: &Path,
    store_root: &Path,
    unit_filter: Option<&str>,
    dry_run: bool,
    selector: Option<&str>,
    layout: Option<fingerprint::UnitLayout>,
    compress: bool,
) -> Result<HarvestReport> {
    let build_root = validate_build_root(build_root)?;
    // Fence the writer against a live Cargo build. A lock check that drops the
    // handles races the build that starts one instruction later.
    let _build_locks = match crate::exec::cargo_locks(&build_root)? {
        Some(locks) => Some(locks),
        None => anyhow::bail!(
            "build dir {} is in use by a live build — harvest skipped",
            build_root.display()
        ),
    };
    let tc = toolchain_of(selector)?;
    let parity = parity_key_with(&tc)?;
    let mut report = HarvestReport {
        parity: parity.clone(),
        toolchain: tc.version_line(),
        ..Default::default()
    };

    // Serialize every manifest read-modify-write. Parallel `exec --harvest`
    // jobs otherwise lose each other's units (last writer wins).
    let _lock = if dry_run {
        None
    } else {
        ensure_store_root(store_root)?;
        util::create_private_dir_all(&store_root.join(&parity))?;
        write_marker(&store_root.join(&parity).join(GENERATION_MARKER))?;
        util::create_private_dir_all(&units_dir(store_root, &parity))?;
        let lock = FileLock::acquire(&store_lock_path(store_root, &parity))?;
        // Self-heal debris from a crashed or failed store run (dot-dirs whose
        // copies may have inherited read-only sources) before planning.
        sweep_staging(&units_dir(store_root, &parity));
        Some(lock)
    };

    let generation_root = store_root.join(&parity);
    let blobs = if compress && !dry_run {
        Some(generation_root.clone())
    } else {
        None
    };
    if let Some(root) = &blobs {
        util::create_private_dir_all(&root.join("blobs"))?;
    }

    let workers = crate::settings::copy_workers();
    let pool = if workers > 1 {
        Some(
            rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .context("building the harvest copy pool")?,
        )
    } else {
        None
    };

    let mut rows = read_rows(&build_root, pool.as_ref())?;

    // A view that mixes both layouts is ambiguous: keep the layout of the
    // harvest toolchain (stable classic vs nightly new) and drop the other.
    let mut has_classic = false;
    let mut has_new = false;
    for (unit, _) in &rows {
        has_classic |= unit.layout == fingerprint::UnitLayout::Classic;
        has_new |= unit.layout == fingerprint::UnitLayout::New;
    }
    let expected_layout = layout.or_else(|| {
        (has_classic && has_new).then(|| fingerprint::layout_for_cargo(&tc.release, &[]))
    });
    if let Some(wanted) = expected_layout {
        let before = rows.len();
        rows.retain(|(unit, _)| unit.layout == wanted);
        report.skipped_stale += before - rows.len();
    }

    // Freshness gate for the whole cache and the active rustc cohort. Both
    // read the same newest-artifact information, so keep it in one pass.
    let mut newest_activity: Option<SystemTime> = None;
    let mut active_gen = String::from("unknown");
    let mut active_newest: Option<SystemTime> = None;
    for (unit, arts) in &rows {
        if let Some(time) = arts.newest {
            newest_activity = Some(newest_activity.map_or(time, |current| current.max(time)));
        }
        if crate::who::rustc_of(unit) != "unknown"
            && active_newest.map_or(true, |current| arts.newest >= Some(current))
        {
            active_newest = arts.newest;
            active_gen = crate::who::rustc_of(unit);
        }
    }
    if let (Some(newest), Some(installed)) = (newest_activity, toolchain_install_time_of(selector))
    {
        if newest < installed {
            report.note = Some(format!(
                "the shared cache predates the installed toolchain ({}) — build once, then harvest",
                tc.version_line()
            ));
            return Ok(report);
        }
    }

    let loaded = load_manifest_at(store_root, &parity, !dry_run)?;
    let had_manifest = loaded.is_some();
    let mut manifest = loaded.unwrap_or_else(|| Manifest {
        parity_key: parity.clone(),
        toolchain: tc.version_line(),
        created: now_secs(),
        updated: 0,
        units: Vec::new(),
        mac: String::new(),
        signature: String::new(),
    });

    let mut plans = Vec::with_capacity(rows.len());
    for (unit, arts) in rows {
        if let Some(query) = unit_filter {
            if !unit_name_matches(&unit.dir_name, query) {
                continue;
            }
        }
        let cohort = crate::who::rustc_of(&unit);
        if cohort != "unknown" && active_gen != "unknown" && cohort != active_gen {
            report.skipped_stale += 1;
            continue;
        }
        match plan_unit(unit, &arts, &build_root)? {
            Some(plan) => plans.push(plan),
            None => report.skipped_incomplete += 1,
        }
    }

    resolve_plan_graph(&mut plans, &manifest);

    let mut manifest_index: std::collections::HashMap<String, usize> =
        std::collections::HashMap::with_capacity(manifest.units.len());
    for (index, entry) in manifest.units.iter().enumerate() {
        manifest_index.entry(entry.name.clone()).or_insert(index);
    }

    // Select work once: compare the planned file set with the manifest, then
    // keep only the plans that need a copy.
    let mut pending: Vec<usize> = Vec::new();
    for (at, plan) in plans.iter().enumerate() {
        let unit = &plan.unit;
        let group_dir = units_dir(store_root, &parity).join(&unit.dir_name);
        let mut new_entries: Vec<(&str, &str, &str)> = plan
            .files
            .iter()
            .map(|file| (file.path.as_str(), file.dest.as_str(), file.role))
            .collect();
        new_entries.sort_unstable();
        let already = manifest_index
            .get(&unit.dir_name)
            .and_then(|&index| manifest.units.get(index))
            .map(|entry| {
                let mut stored: Vec<(&str, &str, &str)> = entry
                    .files
                    .iter()
                    .map(|file| (file.path.as_str(), file.dest.as_str(), file.role.as_str()))
                    .collect();
                stored.sort_unstable();
                entry.hash == plan.hash
                    && entry.profile == unit.profile
                    && entry.stamp == plan.stamp
                    && stored == new_entries
                    && entry.files.iter().all(|file| {
                        if file.sha256.is_empty() || !group_dir.join(&file.path).is_file() {
                            return false;
                        }
                        file.object
                            .as_ref()
                            .map(|object| generation_root.join(object).is_file())
                            .unwrap_or(true)
                    })
            })
            .unwrap_or(false);
        if already {
            report.unchanged += 1;
            continue;
        }
        if dry_run {
            report.stored += 1;
            report.files += plan.files.len();
            report.bytes += plan.bytes;
            continue;
        }
        pending.push(at);
    }

    let changed = !pending.is_empty();
    if changed {
        let store_one = |at: usize| -> Result<Vec<FileEntry>> {
            let plan = &plans[at];
            let mut entries = Vec::with_capacity(plan.files.len());
            store_group(
                store_root,
                &parity,
                &plan.unit.dir_name,
                plan.stamp,
                &plan.files,
                blobs.as_deref(),
                &mut entries,
            )
            .with_context(|| format!("storing unit {}", plan.unit.dir_name))?;
            Ok(entries)
        };
        let stored: Vec<Result<Vec<FileEntry>>> = if pending.len() <= 1 || pool.is_none() {
            pending.iter().map(|&at| store_one(at)).collect()
        } else {
            pool.as_ref()
                .unwrap()
                .install(|| pending.par_iter().map(|&at| store_one(at)).collect())
        };

        for (at, entries) in pending.into_iter().zip(stored) {
            let entries = entries?;
            let plan = &plans[at];
            let entry = UnitEntry {
                name: plan.unit.dir_name.clone(),
                profile: plan.unit.profile.clone(),
                memo: plan.memo.clone(),
                hash: plan.hash.clone(),
                stamp: plan.stamp,
                layout: Some(plan.unit.layout),
                files: entries,
            };
            match manifest_index.get(&entry.name).copied() {
                Some(slot) => {
                    manifest.units[slot] = entry;
                    report.refreshed += 1;
                }
                None => {
                    manifest_index.insert(entry.name.clone(), manifest.units.len());
                    manifest.units.push(entry);
                    report.stored += 1;
                }
            }
            report.files += plan.files.len();
            report.bytes += plan.bytes;
        }
    }

    if !dry_run && (changed || !had_manifest || manifest.units.is_empty()) {
        manifest.units.sort_by(|a, b| {
            (a.profile.as_str(), a.name.as_str()).cmp(&(b.profile.as_str(), b.name.as_str()))
        });
        manifest.updated = now_secs();
        save_manifest(store_root, &parity, &manifest)?;
    }
    Ok(report)
}

struct PlannedFile {
    src: PathBuf,
    path: String,
    dest: String,
    role: &'static str,
    size: u64,
    modified: SystemTime,
}

struct UnitPlan {
    unit: Unit,
    files: Vec<PlannedFile>,
    memo: String,
    hash: String,
    base: u64,
    bytes: u64,
    deps: Vec<usize>,
    stamp: u64,
}

/// Read every unit's artifact list. The directory walk is sequential, but
/// per-unit artifact discovery is independent and dominates the scan.
fn read_rows(
    build_root: &Path,
    pool: Option<&rayon::ThreadPool>,
) -> Result<Vec<(Unit, ArtifactInfo)>> {
    let units = fingerprint::read_units(build_root)?;
    let scan = |unit: Unit| {
        let arts = fingerprint::artifacts_for(build_root, &unit);
        (unit, arts)
    };
    Ok(match pool {
        Some(pool) if units.len() > 1 => pool.install(|| units.into_par_iter().map(scan).collect()),
        _ => units.into_iter().map(scan).collect(),
    })
}

/// Turn one discovered unit into a copy plan. File size and mtime are read
/// once here, so later phases never walk the same files again.
fn plan_unit(unit: Unit, arts: &ArtifactInfo, build_root: &Path) -> Result<Option<UnitPlan>> {
    let unit_dir = &unit.fingerprint_dir;
    let profile_dir = build_root.join(&unit.profile);
    let memo = unit.memo_file.clone();
    let hash = unit.memo_hash.clone().unwrap_or_default();
    // A fingerprint dir without a memo hash is an incomplete build (cargo
    // may leave only `output-*` diagnostics when compilation or linking
    // failed). There is nothing to restore, and recording the diagnostic
    // text as a hash would poison the manifest.
    if !fingerprint::looks_like_hash(&hash) {
        return Ok(None);
    }
    // Provenance gate: harvest is a signing step, so only a complete Cargo
    // fingerprint may enter the vault. A hand-written shape (memo + .so) has
    // no `<memo>.json`, no dep-info and no unit hashes; it is not a unit.
    let Some(json) = unit.json.as_ref() else {
        return Ok(None);
    };
    if json.rustc.is_empty()
        || json.target.is_empty()
        || json.profile.is_empty()
        || json.path.is_empty()
    {
        return Ok(None);
    }
    if unit.kind != fingerprint::UnitKind::BuildScriptRun && unit.dep_info.is_none() {
        return Ok(None);
    }
    let memo_json = unit
        .fingerprint_dir
        .join(format!("{}.json", unit.memo_file));
    match util::metadata_nofollow(&memo_json) {
        Ok(meta) if meta.is_file() => {}
        _ => return Ok(None),
    }
    let mut files: Vec<PlannedFile> = Vec::new();

    for entry in
        fs::read_dir(unit_dir).with_context(|| format!("reading {}", unit_dir.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_volatile(&name) {
            continue;
        }
        let role = if name.starts_with("dep-") {
            "dep-info"
        } else if name.ends_with(".json") {
            "fingerprint"
        } else if read_small_regular(&entry.path())
            .map(|text| crate::fingerprint::looks_like_hash(text.trim()))
            .unwrap_or(false)
        {
            "memo"
        } else {
            // Cached diagnostics (`output-*`) and other cargo state.
            "extra"
        };
        let meta = entry
            .metadata()
            .with_context(|| format!("inspecting {}", entry.path().display()))?;
        let modified = meta
            .modified()
            .with_context(|| format!("reading mtime of {}", entry.path().display()))?;
        let src = entry.path();
        files.push(PlannedFile {
            src,
            path: name.clone(),
            dest: format!("{}/{name}", unit.fingerprint_rel()),
            role,
            size: meta.len(),
            modified,
        });
    }

    // Artifacts: `deps/…` and the `build/<anchor>/…` tree of build scripts.
    // Wrapper internals and rustc's `.d` side files stay out.
    let mut artifact_count = 0;
    for (path, size, modified) in &arts.paths {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if is_volatile(&name) {
            continue;
        }
        let Ok(rel) = path.strip_prefix(&profile_dir) else {
            continue;
        };
        let rel = rel.to_string_lossy().replace('\\', "/");
        if rel.ends_with(".d")
            && (rel.starts_with("deps/") || unit.layout == fingerprint::UnitLayout::New)
        {
            continue;
        }
        let role = if rel.starts_with("deps/") || rel.contains("/out/") {
            "artifact"
        } else if rel.starts_with("build/") {
            "build-tree"
        } else {
            "artifact"
        };
        let modified = match modified {
            Some(modified) => *modified,
            None => fs::metadata(path)
                .and_then(|meta| meta.modified())
                .with_context(|| format!("reading mtime of {}", path.display()))?,
        };
        files.push(PlannedFile {
            src: path.clone(),
            path: rel.clone(),
            dest: rel,
            role,
            size: *size,
            modified,
        });
        artifact_count += 1;
    }
    if artifact_count == 0 {
        return Ok(None);
    }

    let bytes = files.iter().map(|file| file.size).sum();
    let base = group_base(&files);
    Ok(Some(UnitPlan {
        unit,
        files,
        memo,
        hash,
        base,
        bytes,
        deps: Vec::new(),
        stamp: base,
    }))
}

/// Resolve dependency edges and raise each unit's stamp to every stored or
/// planned dependency. Kahn's queue replaces the repeated full-array scan;
/// the final walk keeps the same one-pass behavior for an unexpected cycle.
fn resolve_plan_graph(plans: &mut [UnitPlan], manifest: &Manifest) {
    let stored_stamps: std::collections::HashMap<String, u64> = manifest
        .units
        .iter()
        .map(|entry| (entry.hash.clone(), entry.stamp))
        .collect();
    let index: std::collections::HashMap<String, usize> = plans
        .iter()
        .enumerate()
        .map(|(position, plan)| (plan.hash.clone(), position))
        .collect();

    for plan in plans.iter_mut() {
        let (deps, stamp) = {
            let mut deps = Vec::new();
            let mut stamp = plan.base;
            if let Some(json) = plan.unit.json.as_ref() {
                for dep in &json.deps {
                    let Some(hash) = dep.memo_hash() else {
                        continue;
                    };
                    if let Some(&at) = index.get(hash.as_str()) {
                        deps.push(at);
                    } else if let Some(known) = stored_stamps.get(hash.as_str()) {
                        stamp = stamp.max(*known);
                    }
                }
            }
            (deps, stamp)
        };
        plan.deps = deps;
        plan.stamp = stamp;
    }

    let count = plans.len();
    let mut indegree = vec![0usize; count];
    let mut followers: Vec<Vec<usize>> = vec![Vec::new(); count];
    for (at, plan) in plans.iter().enumerate() {
        for &dep in &plan.deps {
            if dep == at {
                continue;
            }
            indegree[at] += 1;
            followers[dep].push(at);
        }
    }
    let mut queue: std::collections::VecDeque<usize> =
        (0..count).filter(|&at| indegree[at] == 0).collect();
    let mut order = Vec::with_capacity(count);
    while let Some(at) = queue.pop_front() {
        order.push(at);
        for &next in &followers[at] {
            indegree[next] -= 1;
            if indegree[next] == 0 {
                queue.push_back(next);
            }
        }
    }
    if order.len() < count {
        let mut ordered = vec![false; count];
        for &at in &order {
            ordered[at] = true;
        }
        for at in 0..count {
            if !ordered[at] {
                order.push(at);
            }
        }
    }
    for &at in &order {
        let mut stamp = plans[at].stamp;
        for &dep in &plans[at].deps {
            stamp = stamp.max(plans[dep].stamp);
        }
        plans[at].stamp = stamp;
    }
}

/// The canonical stamp: the ceiling of the newest `.rmeta` when present,
/// otherwise of the newest file.
fn group_base(files: &[PlannedFile]) -> u64 {
    let mut newest: Option<SystemTime> = None;
    let mut metadata: Option<SystemTime> = None;
    for file in files {
        if newest.map_or(true, |current| file.modified > current) {
            newest = Some(file.modified);
        }
        if file.path.ends_with(".rmeta") && metadata.map_or(true, |current| file.modified > current)
        {
            metadata = Some(file.modified);
        }
    }
    match metadata.or(newest) {
        Some(time) => ceil_secs(time),
        None => now_secs(),
    }
}

/// Copy one unit group into its final place: a temporary directory next to
/// the target, stamped read-only files, then a swap that never leaves the
/// group half-written under its real name.
fn store_group(
    store_root: &Path,
    parity: &str,
    name: &str,
    stamp: u64,
    files: &[PlannedFile],
    blobs: Option<&Path>,
    entries: &mut Vec<FileEntry>,
) -> Result<()> {
    util::validate_component(name, "unit name")?;
    let units = units_dir(store_root, parity);
    let final_dir = units.join(name);
    // Unique staging names + O_EXCL directory creation: a pre-planted symlink
    // or temp dir can never be followed/truncated.
    let mut tmp = None;
    for attempt in 0..100u32 {
        let candidate = units.join(format!(".{name}.tmp-{}-{attempt}", std::process::id()));
        match fs::create_dir(&candidate) {
            Ok(()) => {
                tmp = Some(candidate);
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("creating staging dir {}", candidate.display()));
            }
        }
    }
    let Some(tmp) = tmp else {
        anyhow::bail!(
            "could not create a unique staging dir in {}",
            units.display()
        );
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o700));
    }

    if let Err(err) = stage_group(&tmp, files, stamp, blobs, entries) {
        // Never leave a half-written staging dir behind: it would keep a
        // failed unit's bytes on disk and hide the failure from the next run.
        let _ = crate::util::force_remove_dir(&tmp);
        return Err(err);
    }

    let old = units.join(format!(".{name}.old-{}-{}", std::process::id(), now_secs()));
    match util::metadata_nofollow(&final_dir) {
        Ok(meta) if meta.is_dir() => fs::rename(&final_dir, &old)?,
        Ok(_) => {
            let _ = crate::util::force_remove_dir(&tmp);
            anyhow::bail!("store unit path {} is not a directory", final_dir.display());
        }
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            let _ = crate::util::force_remove_dir(&tmp);
            anyhow::bail!(
                "refusing symlinked/reparse store unit {}",
                final_dir.display()
            );
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).context("inspecting store unit"),
    }
    fs::rename(&tmp, &final_dir)?;
    if util::metadata_nofollow(&old).is_ok_and(|meta| meta.is_dir()) {
        let _ = fs::remove_dir_all(&old);
    }
    Ok(())
}

/// Library outputs bypass gzip (rustc reads them directly at restore time);
/// all other artifacts are compressed when it wins.
#[cfg(unix)]
fn is_library_output(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let extension = name.rsplit_once('.').map(|(_, extension)| extension);
    if path.starts_with("deps/") {
        matches!(extension, Some("rlib" | "so" | "dylib" | "a"))
    } else if path.contains("/out/") {
        matches!(extension, Some("rlib" | "so"))
    } else {
        false
    }
}

/// Copy one staged file. Never hard-link the live build tree into the store:
/// the store stamps files read-only and the build tree stays writable, so a
/// shared inode can be rewritten through either path (and Cargo cannot
/// replace a read-only output in place). Reflink is attempted by
/// `copy_file_hashed`; otherwise this is a verified copy.
fn materialize_file(file: &PlannedFile, dst: &Path) -> Result<(u64, String)> {
    util::copy_file_hashed(&file.src, dst)
}

/// Copy or link one unit group's files into its staging dir. `materialize_file`
/// leaves every destination writable; stamping and the read-only store mode
/// happen after that.
fn stage_group(
    tmp: &Path,
    files: &[PlannedFile],
    stamp: u64,
    blobs: Option<&Path>,
    entries: &mut Vec<FileEntry>,
) -> Result<()> {
    for file in files {
        let rel = util::validate_rel(&file.path, "stored file path")?;
        let dst = tmp.join(&rel);
        if let Some(parent) = dst.parent() {
            util::create_private_dir_all(parent)?;
        }
        #[cfg(unix)]
        let library = is_library_output(&file.path);
        #[cfg(not(unix))]
        let library = false;
        if let Some(root) = blobs {
            if !library && matches!(file.role, "artifact" | "build-tree") {
                if let Some((size, sha256, object)) = util::compress_file_hashed(&file.src, root)
                    .with_context(|| format!("compressing {}", file.src.display()))?
                {
                    let blob = root.join(&object);
                    fs::hard_link(&blob, &dst).with_context(|| {
                        format!("linking {} -> {}", blob.display(), dst.display())
                    })?;
                    entries.push(FileEntry {
                        path: file.path.clone(),
                        dest: file.dest.clone(),
                        size,
                        sha256,
                        role: file.role.to_string(),
                        object: Some(object),
                    });
                    continue;
                }
            }
        }
        let (size, sha256) = materialize_file(file, &dst)
            .with_context(|| format!("storing {} -> {}", file.src.display(), dst.display()))?;
        set_stamp(&dst, stamp)?;
        make_read_only(&dst)?;
        entries.push(FileEntry {
            path: file.path.clone(),
            dest: file.dest.clone(),
            size,
            sha256,
            role: file.role.to_string(),
            object: None,
        });
    }
    Ok(())
}

/// Remove staging leftovers (`.{unit}.tmp-{pid}`, `.{unit}.old-{pid}`) that a
/// crashed or failed run left in the units dir. Fresh dirs are left alone: a
/// concurrent harvest may be filling them right now.
fn sweep_staging(units: &Path) {
    let Ok(entries) = fs::read_dir(units) else {
        return;
    };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !(name.contains(".tmp-") || name.contains(".old-")) {
            continue;
        }
        let meta = match util::metadata_nofollow(&entry.path()) {
            Ok(meta) => meta,
            // Unlink a planted symlink/reparse name itself; never traverse it.
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                let _ = fs::remove_file(entry.path());
                continue;
            }
            Err(_) => continue,
        };
        if !meta.is_dir() {
            continue;
        }
        let stale = meta
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age > Duration::from_secs(600));
        if stale {
            let _ = crate::util::force_remove_dir(&entry.path());
        }
    }
}

/// Round a timestamp up to whole seconds.
fn ceil_secs(time: SystemTime) -> u64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs();
            if duration.subsec_nanos() > 0 {
                secs + 1
            } else {
                secs
            }
        }
        Err(_) => 0,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn set_stamp(path: &Path, stamp: u64) -> Result<()> {
    let time = UNIX_EPOCH + Duration::from_secs(stamp);
    // Unix allows futimens on a read-only fd owned by us; Windows requires a
    // handle with FILE_WRITE_ATTRIBUTES (GENERIC_READ's set_modified is
    // denied). A 0444 store file must still be stampable on Windows.
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let file = fs::OpenOptions::new()
            .access_mode(0x0100) // FILE_WRITE_ATTRIBUTES
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .or_else(|_| {
                fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(path)
            })
            .with_context(|| format!("opening {} to stamp it", path.display()))?;
        let meta = file.metadata()?;
        if meta.file_type().is_symlink() || util::is_reparse_point(&meta) {
            anyhow::bail!("refusing symlink/reparse stamp target {}", path.display());
        }
        file
    };
    #[cfg(unix)]
    let file = util::open_file_nofollow(path)
        .with_context(|| format!("opening {} to stamp it", path.display()))?;
    #[cfg(not(any(unix, windows)))]
    let file =
        fs::File::open(path).with_context(|| format!("opening {} to stamp it", path.display()))?;
    file.set_modified(time)
        .with_context(|| format!("stamping {}", path.display()))?;
    Ok(())
}

/// On Unix the store is read-only (owner can still stamp and delete; only
/// content edits are refused). On Windows a read-only file blocks rename
/// and delete, so the store keeps normal permissions there.
fn make_read_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file = util::open_file_nofollow(path)
            .with_context(|| format!("opening {} to mark it read-only", path.display()))?;
        file.set_permissions(fs::Permissions::from_mode(0o444))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Files that never enter the store: the volatile invocation timestamp,
/// and wrapper bookkeeping (`*.kache-*`, `.kache*`) that lives in the build
/// dir but is no part of Cargo's state.
#[inline]
fn is_volatile(name: &str) -> bool {
    name == "invoked.timestamp" || name.contains(".kache")
}

// ── restore ─────────────────────────────────────────────────────────────────

/// What one restore did.
#[derive(Debug, Default)]
pub struct RestoreReport {
    pub parity: String,
    pub target: PathBuf,
    pub units_linked: usize,
    pub units_already: usize,
    pub files_linked: usize,
    pub files_copied: usize,
    pub files_existing: usize,
    pub files_missing: usize,
    pub bytes: u64,
    pub errors: usize,
    /// Integrity failures (hash/size/owner/symlink). These abort `exec` and
    /// make `restore` exit non-zero; a merely missing unit stays fail-open.
    pub fatal_errors: usize,
    pub note: Option<String>,
}

enum RestoreOutcome {
    Existing,
    Missing,
    Linked,
    Copied,
}

/// fd-relative restore on Unix: destination parents are opened with
/// openat(O_NOFOLLOW), the source inode is opened once, and the final name is
/// installed with linkat. No path component can be swapped for a symlink
/// after the check.
#[cfg(unix)]
fn restore_compressed_at(
    view_root: &Path,
    dest_rel: &Path,
    blob: &Path,
    stamp: u64,
    file: &FileEntry,
) -> Result<RestoreOutcome> {
    use flate2::read::GzDecoder;
    let parent_rel = dest_rel.parent().unwrap_or_else(|| Path::new(""));
    let dst_name = dest_rel
        .file_name()
        .with_context(|| format!("destination {} has no file name", dest_rel.display()))?;
    let parent = util::open_dir_chain_at(view_root, parent_rel)?;
    if parent.exists(dst_name)? {
        return Ok(RestoreOutcome::Existing);
    }
    let input = match util::open_file_nofollow(blob) {
        Ok(file) => file,
        Err(err)
            if err
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .map_or(false, |io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(RestoreOutcome::Missing);
        }
        Err(err) => return Err(err),
    };
    let mut decoder = GzDecoder::new(input);
    let mut tmp = parent.create_excl(dst_name, 0o600)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut size = 0u64;
    let result = (|| -> Result<()> {
        loop {
            let n = decoder.read(&mut buf)?;
            if n == 0 {
                break;
            }
            size = size.saturating_add(n as u64);
            if size > file.size {
                anyhow::bail!(
                    "blob {} exceeds its recorded size ({} bytes)",
                    file.path,
                    file.size
                );
            }
            hasher.update(&buf[..n]);
            tmp.write_all(&buf[..n])?;
        }
        let hash = format!("{:x}", hasher.finalize());
        if size != file.size || hash != file.sha256 {
            anyhow::bail!(
                "blob integrity check failed (recorded {} bytes/{}, found {} bytes/{})",
                file.size,
                &file.sha256[..file.sha256.len().min(12)],
                size,
                &hash[..hash.len().min(12)]
            );
        }
        util::set_stamp_fd(&tmp, stamp)?;
        Ok(())
    })();
    if let Err(err) = result {
        let _ = parent.unlink(dst_name);
        return Err(err);
    }
    Ok(RestoreOutcome::Copied)
}

#[cfg(not(unix))]
fn install_compressed_copy(
    blob: &Path,
    dst: &Path,
    stamp: u64,
    file: &FileEntry,
) -> Result<RestoreOutcome> {
    // Decompress into a private temp in the destination directory. Only this
    // operation ever removes that temp; `dst` is installed with a no-overwrite
    // link/copy, so a racing restore cannot lose its file here.
    let parent = dst.parent().unwrap_or_else(|| Path::new(""));
    let nonce = util::temp_nonce();
    let mut temp = None;
    for attempt in 0..100u32 {
        let candidate = parent.join(format!(
            ".epicenter-tmp-{}-{nonce:016x}-{attempt}",
            std::process::id()
        ));
        match util::decompress_file_verified(blob, &candidate, file.size, &file.sha256) {
            Ok(()) => {
                temp = Some(candidate);
                break;
            }
            Err(err) if matches!(io_error_kind(&err), Some(std::io::ErrorKind::AlreadyExists)) => {
                continue;
            }
            Err(err) if matches!(io_error_kind(&err), Some(std::io::ErrorKind::NotFound)) => {
                // A partial vault is fail-open: Cargo rebuilds the unit.
                return Ok(RestoreOutcome::Missing);
            }
            Err(err) => return Err(err),
        }
    }
    let Some(temp) = temp else {
        anyhow::bail!(
            "could not create a temporary file next to {}",
            dst.display()
        );
    };

    if let Err(err) = set_stamp(&temp, stamp) {
        let _ = fs::remove_file(&temp);
        return Err(err);
    }

    // A hard link is an atomic no-overwrite install on every platform that
    // supports it. Fall back to an exclusive copy where links are unavailable
    // (for example FAT/exFAT).
    match fs::hard_link(&temp, dst) {
        Ok(()) => {
            let _ = fs::remove_file(&temp);
            return Ok(RestoreOutcome::Copied);
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temp);
            return existing_destination(dst);
        }
        Err(_) => {}
    }

    let mut output = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)
    {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temp);
            return existing_destination(dst);
        }
        Err(err) => {
            let _ = fs::remove_file(&temp);
            return Err(err).with_context(|| format!("creating {}", dst.display()));
        }
    };
    let mut input = match fs::File::open(&temp) {
        Ok(file) => file,
        Err(err) => {
            drop(output);
            let _ = fs::remove_file(dst);
            let _ = fs::remove_file(&temp);
            return Err(err).with_context(|| format!("opening {}", temp.display()));
        }
    };
    let copied = std::io::copy(&mut input, &mut output)
        .with_context(|| format!("copying verified temporary file to {}", dst.display()));
    let flushed = copied.and_then(|_| {
        output
            .flush()
            .with_context(|| format!("flushing {}", dst.display()))
    });
    drop(input);
    drop(output);
    let result = flushed.and_then(|_| set_stamp(dst, stamp));
    if let Err(err) = result {
        let _ = fs::remove_file(dst);
        let _ = fs::remove_file(&temp);
        return Err(err);
    }
    let _ = fs::remove_file(&temp);
    Ok(RestoreOutcome::Copied)
}

#[cfg(not(unix))]
fn io_error_kind(err: &anyhow::Error) -> Option<std::io::ErrorKind> {
    err.root_cause()
        .downcast_ref::<std::io::Error>()
        .map(std::io::Error::kind)
}

#[cfg(not(unix))]
fn existing_destination(dst: &Path) -> Result<RestoreOutcome> {
    let meta = match util::metadata_nofollow(dst) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            anyhow::bail!("destination {} is not a regular file", dst.display());
        }
        Err(err) => {
            return Err(err)
                .with_context(|| format!("inspecting raced destination {}", dst.display()));
        }
    };
    if !meta.is_file() {
        anyhow::bail!("destination {} is not a regular file", dst.display());
    }
    Ok(RestoreOutcome::Existing)
}

#[cfg(unix)]
fn restore_file_at(
    view_root: &Path,
    dest_rel: &Path,
    src: &Path,
    stamp: u64,
    file: &FileEntry,
    linkable: bool,
    link: LinkPlan,
) -> Result<RestoreOutcome> {
    let parent_rel = dest_rel.parent().unwrap_or_else(|| Path::new(""));
    let dst_name = dest_rel
        .file_name()
        .with_context(|| format!("destination {} has no file name", dest_rel.display()))?;
    let parent = util::open_dir_chain_at(view_root, parent_rel)?;
    if parent.exists(dst_name)? {
        return Ok(RestoreOutcome::Existing);
    }
    let mut source = match util::open_file_nofollow(src) {
        Ok(file) => file,
        Err(err)
            if err
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .map_or(false, |io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(RestoreOutcome::Missing);
        }
        Err(err)
            if err
                .downcast_ref::<std::io::Error>()
                .map_or(false, |io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(RestoreOutcome::Missing);
        }
        Err(err) => return Err(err),
    };
    let meta = source.metadata()?;
    if !meta.is_file() || (!util::owned_by_us(src, &meta) && !link.read_only) {
        anyhow::bail!(
            "stored file {} is not a regular file owned by this user",
            src.display()
        );
    }
    if meta.len() != file.size {
        anyhow::bail!(
            "stored file {} size drift (recorded {}, found {})",
            src.display(),
            file.size,
            meta.len()
        );
    }
    // A hard link is only safe when the view cannot mutate the store inode:
    // the store is on a read-only mount, or the source inode is foreign and
    // carries no write bits at all.
    #[cfg(unix)]
    let foreign_immutable = {
        use std::os::unix::fs::PermissionsExt;
        !util::owned_by_us(src, &meta) && meta.permissions().mode() & 0o222 == 0
    };
    #[cfg(not(unix))]
    let foreign_immutable = false;
    let may_link = linkable && link.may_link(foreign_immutable);
    if may_link {
        if file.sha256.is_empty() {
            anyhow::bail!("{} has no recorded SHA-256", src.display());
        }
        let found = util::sha256_file_fd(&mut source)?;
        if found != file.sha256 {
            anyhow::bail!("{} failed its SHA-256 check", src.display());
        }
        match parent.link_fd(&source, dst_name) {
            Ok(()) => return Ok(RestoreOutcome::Linked),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                return Ok(RestoreOutcome::Existing);
            }
            Err(err)
                if util::link_fallback(&err) || err.kind() == std::io::ErrorKind::Unsupported =>
            {
                // Cross-device or a filesystem without hard links: fall
                // through to a verified private copy.
            }
            Err(err) => {
                return Err(err).with_context(|| format!("linking {:?}", dst_name));
            }
        }
    }
    // Write the private copy directly at the final name with O_EXCL. The
    // destination name is created once, at the held parent fd; on any
    // integrity/stamp failure the partial file is removed. No temp-path
    // lookup is needed, which keeps this portable on non-Linux Unix.
    let mut tmp = match parent.create_excl(dst_name, 0o600) {
        Ok(tmp) => tmp,
        Err(err)
            if err
                .downcast_ref::<std::io::Error>()
                .map_or(false, |io| io.kind() == std::io::ErrorKind::AlreadyExists) =>
        {
            return Ok(RestoreOutcome::Existing);
        }
        Err(err) => return Err(err),
    };
    let result = util::copy_fd_verified(&mut source, &mut tmp, file.size, &file.sha256)
        .and_then(|_| util::set_stamp_fd(&tmp, stamp).map_err(anyhow::Error::from));
    if let Err(err) = result {
        let _ = parent.unlink(dst_name);
        return Err(err);
    }
    Ok(RestoreOutcome::Copied)
}

/// Immutable rustc outputs that may be shared by inode. Build-script
/// executables, `.rmeta`, `.d`, `.o` and other deps files are mutable.
///
/// `auto` links the large archive outputs (`.rlib`, `.a`); proc-macro
/// `.so`/`.dylib` stay private writable copies because Cargo may rewrite
/// them in place during a rebuild. The explicit `link` policy links all four.
fn is_linkable_artifact(path: &str, policy: LinkPolicy) -> bool {
    if !(path.starts_with("deps/") || path.contains("/out/")) {
        return false;
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    let extension = name.rsplit_once('.').map(|(_, extension)| extension);
    match policy {
        LinkPolicy::Copy => false,
        LinkPolicy::Link => matches!(extension, Some("rlib" | "a" | "so" | "dylib")),
        LinkPolicy::Auto => matches!(extension, Some("rlib" | "a")),
    }
}

#[derive(Clone, Copy)]
struct LinkPlan {
    policy: LinkPolicy,
    read_only: bool,
    shared_mount: bool,
    private_store: bool,
}

impl LinkPlan {
    #[cfg(unix)]
    fn may_link(self, foreign_immutable: bool) -> bool {
        match self.policy {
            LinkPolicy::Copy => false,
            LinkPolicy::Link => true,
            LinkPolicy::Auto => {
                self.read_only || foreign_immutable || (self.private_store && !self.shared_mount)
            }
        }
    }

    /// Dry-run prediction: a foreign immutable source cannot be known before
    /// opening it, so only the mount/store facts are used.
    fn predicts_link(self) -> bool {
        match self.policy {
            LinkPolicy::Copy => false,
            LinkPolicy::Link => {
                #[cfg(windows)]
                {
                    self.read_only || self.private_store
                }
                #[cfg(not(windows))]
                {
                    true
                }
            }
            LinkPolicy::Auto => self.read_only || (self.private_store && !self.shared_mount),
        }
    }

    #[cfg(windows)]
    fn windows_link(self) -> bool {
        match self.policy {
            LinkPolicy::Copy => false,
            // An immutable mount is safe to link even when it is foreign.
            LinkPolicy::Link => self.read_only || self.private_store,
            LinkPolicy::Auto => self.read_only || (self.private_store && !self.shared_mount),
        }
    }
}

/// A store on a read-only mount cannot be mutated through a view link, so
/// sharing its inodes is safe even across principals. A writable mount is
/// copied from: the owner could chmod a 0444 inode and rewrite it through the
/// view. Windows checks directory write access with FILE_FLAG_BACKUP_SEMANTICS
/// because it has no `statvfs`; a denied open is a read-only reader mount.
fn store_is_read_only(store_root: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let Ok(path) = CString::new(store_root.as_os_str().as_bytes()) else {
            return false;
        };
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
            return false;
        }
        // `statvfs` reports the mount flags with different constant names on
        // Linux/BSD (`ST_RDONLY`) and Apple (`MNT_RDONLY`).
        #[cfg(target_os = "macos")]
        const READ_ONLY: libc::c_ulong = libc::MNT_RDONLY;
        #[cfg(not(target_os = "macos"))]
        const READ_ONLY: libc::c_ulong = libc::ST_RDONLY;
        stat.f_flag & READ_ONLY != 0
    }
    #[cfg(windows)]
    {
        // Windows has no statvfs. Open the directory for write access with
        // FILE_FLAG_BACKUP_SEMANTICS; this checks the DACL without creating
        // or modifying anything. A denied open is a read-only reader mount.
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        match fs::OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(store_root)
        {
            Ok(file) => {
                drop(file);
                false
            }
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => true,
            Err(_) => false,
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = store_root;
        false
    }
}

/// An owner-only, real local directory. `auto` treats this as one trust
/// domain and may hard-link archive outputs on it.
fn store_is_private(store_root: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(meta) = util::metadata_nofollow(store_root) else {
            return false;
        };
        meta.is_dir() && util::owned_by_us(store_root, &meta) && meta.mode() & 0o077 == 0
    }
    #[cfg(windows)]
    {
        let Ok(meta) = util::metadata_nofollow(store_root) else {
            return false;
        };
        // A fixed local drive under the user profile is one machine. A remote
        // mapped drive or UNC share is the multi-VM case and copies. The DACL
        // must also grant write access only to the owner/SYSTEM/Administrators:
        // an owner-owned but group-writable store is still mutable in place.
        meta.is_dir()
            && util::owned_by_us(store_root, &meta)
            && !store_is_shared_mount(store_root)
            && util::ensure_windows_user_path(store_root, "store").is_ok()
            && util::windows_acl_is_private(store_root) == Some(true)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = store_root;
        false
    }
}

/// Does the store live on a shared/network filesystem? A writable network
/// mount is the multi-VM topology: another machine (or an uncontrolled agent)
/// can write the inode behind a hard link.
#[cfg(target_os = "linux")]
fn store_is_shared_mount(store_root: &Path) -> bool {
    let Ok(target) = fs::canonicalize(store_root) else {
        return true;
    };
    let Ok(text) = fs::read_to_string("/proc/self/mountinfo") else {
        return true;
    };
    let mut best: Option<(usize, String)> = None;
    for line in text.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        let Some(mount) = fields.get(4).map(|value| unescape_mount(value)) else {
            continue;
        };
        let mount_path = Path::new(&mount);
        if target != mount_path && !target.starts_with(mount_path) {
            continue;
        }
        let Some(separator) = fields.iter().position(|field| *field == "-") else {
            continue;
        };
        let Some(fstype) = fields.get(separator + 1) else {
            continue;
        };
        if best
            .as_ref()
            .map_or(true, |(length, _)| mount.len() > *length)
        {
            best = Some((mount.len(), (*fstype).to_string()));
        }
    }
    best.map_or(true, |(_, fstype)| is_network_fstype(&fstype))
}

#[cfg(target_os = "linux")]
fn unescape_mount(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[cfg(target_os = "linux")]
fn is_network_fstype(fstype: &str) -> bool {
    let fstype = fstype.to_ascii_lowercase();
    [
        "9p",
        "v9fs",
        "drvfs",
        "virtiofs",
        "nfs",
        "cifs",
        "smb",
        "sshfs",
        "fuse.sshfs",
        "fuse.rclone",
        "davfs",
        "webdav",
        "glusterfs",
        "ceph",
        "afs",
        "lustre",
        "gpfs",
        "beegfs",
        "ocfs2",
        "ncpfs",
    ]
    .iter()
    .any(|network| fstype == *network || fstype.starts_with(&format!("{network}.")))
}

#[cfg(target_os = "macos")]
fn store_is_shared_mount(store_root: &Path) -> bool {
    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt;
    let Ok(path) = CString::new(store_root.as_os_str().as_bytes()) else {
        return true;
    };
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path.as_ptr(), &mut stat) } != 0 {
        return true;
    }
    let fstype = unsafe { CStr::from_ptr(stat.f_fstypename.as_ptr()) }
        .to_string_lossy()
        .to_ascii_lowercase();
    matches!(
        fstype.as_str(),
        "nfs" | "smbfs" | "afpfs" | "webdav" | "9p" | "virtiofs"
    )
}

#[cfg(windows)]
fn store_is_shared_mount(store_root: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = store_root
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // DRIVE_REMOTE = 4.
    unsafe { GetDriveTypeW(wide.as_ptr()) == 4 }
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetDriveTypeW(root_path_name: *const u16) -> u32;
}

#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
fn store_is_shared_mount(_store_root: &Path) -> bool {
    // Unknown mount semantics on this Unix: copy rather than risk a shared
    // inode across a network filesystem.
    true
}

#[cfg(not(any(unix, windows)))]
fn store_is_shared_mount(_store_root: &Path) -> bool {
    true
}

/// Link matching unit groups from the vault into a working dir.
///
/// `deps/` link outputs (`.rlib`, proc-macro `.so`) are hard-linked — rustc
/// only ever replaces those atomically. Fingerprint state, build-script
/// trees and `deps/*.rmeta` become private writable copies: rustc writes
/// `.rmeta` in place, so a read-only link turns any rebuild of that unit
/// into `output file … .rmeta is not writeable`. Hard links share the
/// store's canonical stamp; private copies are stamped after copying. Never
/// overwrites a file that already exists, never touches sources, and a
/// partial vault is fine: Cargo recompiles whatever is missing.
///
/// `unit_filter` narrows by substring (`restore --unit`); `packages` narrows
/// to a package set (`exec` passes the project's `Cargo.lock` packages, so a
/// job never inherits every other project's units). Unit names that cannot be
/// split into package + hash are kept rather than dropped (fail-open).
pub fn restore(
    view_root: &Path,
    store_root: &Path,
    unit_filter: Option<&str>,
    packages: Option<&std::collections::HashSet<String>>,
    dry_run: bool,
) -> Result<RestoreReport> {
    restore_with(
        view_root,
        store_root,
        unit_filter,
        packages,
        None,
        None,
        dry_run,
        LinkPolicy::Auto,
    )
}

/// Restore with an explicit link policy (`epicenter.toml`).
pub fn restore_policy(
    view_root: &Path,
    store_root: &Path,
    unit_filter: Option<&str>,
    dry_run: bool,
    link: LinkPolicy,
) -> Result<RestoreReport> {
    restore_with(
        view_root,
        store_root,
        unit_filter,
        None,
        None,
        None,
        dry_run,
        link,
    )
}

/// Restore for a specific toolchain/layout (`exec` with a `+toolchain` or a
/// new-layout child). `layout` skips units stored in the other build-dir
/// layout; the plain [`restore`] accepts every stored unit.
pub fn restore_with(
    view_root: &Path,
    store_root: &Path,
    unit_filter: Option<&str>,
    packages: Option<&std::collections::HashSet<String>>,
    layout: Option<fingerprint::UnitLayout>,
    selector: Option<&str>,
    dry_run: bool,
    link: LinkPolicy,
) -> Result<RestoreReport> {
    let parity = parity_key_of(selector)?;
    let mut report = RestoreReport {
        parity: parity.clone(),
        target: view_root.to_path_buf(),
        ..Default::default()
    };
    // Verify store ownership/mode before parsing its manifest. A fresh store
    // is allowed to be absent (cold start); a present-but-unsafe one is not.
    if store_root.exists() {
        check_store_trust(store_root)?;
    }
    let link_plan = LinkPlan {
        policy: link,
        read_only: store_is_read_only(store_root),
        shared_mount: store_is_shared_mount(store_root),
        private_store: store_is_private(store_root),
    };
    let Some(manifest) = load_manifest(store_root, &parity)? else {
        report.note = Some(
            "the vault holds no units for this generation yet — run `epicenter harvest` after a build"
                .into(),
        );
        return Ok(report);
    };
    if !dry_run {
        prepare_view_root(view_root)?;
    }

    let units = units_dir(store_root, &parity);
    let generation_root = store_root.join(&parity);

    // Select units once. `already` is a pure read of the view, so it is safe
    // to decide before any worker starts.
    let mut jobs: Vec<(usize, &UnitEntry)> = Vec::new();
    for (at, entry) in manifest.units.iter().enumerate() {
        if let Some(query) = unit_filter {
            if !unit_name_matches(&entry.name, query) {
                continue;
            }
        }
        if let Some(packages) = packages {
            if let Some(package) = unit_package(&entry.name) {
                if !packages.contains(package) {
                    continue;
                }
            }
        }
        if let Some(layout) = layout {
            if entry.layout() != layout {
                continue;
            }
        }
        // The memo's destination in the manifest is layout-agnostic.
        let already = entry
            .files
            .iter()
            .find(|file| file.path == entry.memo)
            .and_then(|file| read_small_regular(&view_root.join(&entry.profile).join(&file.dest)))
            .map(|text| text.trim() == entry.hash)
            .unwrap_or(false);
        if already {
            report.units_already += 1;
            continue;
        }
        jobs.push((at, entry));
    }

    // Two units can share fingerprint files (and a manifest is not required
    // to prove uniqueness). Give every destination to the first selected unit
    // in manifest order, so concurrent restores never write the same path.
    let mut owners: std::collections::HashMap<String, usize> =
        std::collections::HashMap::with_capacity(
            jobs.iter().map(|(_, entry)| entry.files.len()).sum(),
        );
    if !dry_run {
        for (at, entry) in &jobs {
            for file in &entry.files {
                owners.entry(dest_key(entry, file)).or_insert(*at);
            }
        }
    }

    let workers = crate::settings::copy_workers();
    let outcomes: Vec<RestoreUnitResult> = if dry_run || jobs.len() <= 1 || workers <= 1 {
        jobs.iter()
            .map(|(at, entry)| {
                restore_unit(
                    view_root,
                    &units,
                    &generation_root,
                    *at,
                    entry,
                    None,
                    dry_run,
                    link_plan,
                )
            })
            .collect()
    } else {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .context("building the restore copy pool")?;
        pool.install(|| {
            jobs.par_iter()
                .map(|(at, entry)| {
                    restore_unit(
                        view_root,
                        &units,
                        &generation_root,
                        *at,
                        entry,
                        Some(&owners),
                        false,
                        link_plan,
                    )
                })
                .collect()
        })
    };

    for outcome in outcomes {
        report.files_existing += outcome.files_existing;
        report.files_missing += outcome.files_missing;
        report.files_linked += outcome.files_linked;
        report.files_copied += outcome.files_copied;
        report.bytes += outcome.bytes;
        report.errors += outcome.errors;
        report.fatal_errors += outcome.fatal_errors;
        if outcome.touched {
            report.units_linked += 1;
        }
        for message in outcome.messages {
            eprintln!("{message}");
        }
    }
    Ok(report)
}

fn dest_key(entry: &UnitEntry, file: &FileEntry) -> String {
    format!("{}/{}", entry.profile, file.dest)
}

#[derive(Default)]
struct RestoreUnitResult {
    files_existing: usize,
    files_missing: usize,
    files_linked: usize,
    files_copied: usize,
    bytes: u64,
    errors: usize,
    fatal_errors: usize,
    touched: bool,
    messages: Vec<String>,
}

/// Restore one unit group. Runs on a worker; every mutable report is local
/// and merged in manifest order by the caller.
fn restore_unit(
    view_root: &Path,
    units: &Path,
    generation_root: &Path,
    at: usize,
    entry: &UnitEntry,
    owners: Option<&std::collections::HashMap<String, usize>>,
    dry_run: bool,
    link: LinkPlan,
) -> RestoreUnitResult {
    let mut out = RestoreUnitResult::default();

    for file in &entry.files {
        if let Some(owners) = owners {
            if owners
                .get(&dest_key(entry, file))
                .is_some_and(|owner| *owner != at)
            {
                // Another selected unit owns this destination; it will land
                // there exactly once, in manifest order, just as the serial
                // walk would have left it.
                out.files_existing += 1;
                continue;
            }
        }
        // Both components were validated by Manifest::validate; keep the
        // join explicit and reject any symlink in the destination chain.
        let dest_rel = Path::new(&entry.profile).join(&file.dest);
        let dst = view_root.join(&dest_rel);
        match util::metadata_nofollow(&dst) {
            Ok(_) => {
                out.files_existing += 1;
                continue;
            }
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                out.errors += 1;
                out.fatal_errors += 1;
                out.messages.push(format!(
                    "restore: refusing symlink/reparse destination {}",
                    dst.display()
                ));
                continue;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                out.errors += 1;
                out.messages
                    .push(format!("restore: inspecting {}: {err}", dst.display()));
                continue;
            }
        }
        // Only immutable rustc outputs may share the store inode. Everything
        // else (`.rmeta`, build-script executables, `.d`, object files) is a
        // private verified copy: rustc/cargo/build scripts write those in
        // place, and a read-only link would break the rebuild.
        let linkable = is_linkable_artifact(&file.path, link.policy);
        let shared = linkable;
        if dry_run {
            out.touched = true;
            if shared && link.predicts_link() && file.object.is_none() {
                out.files_linked += 1;
            } else {
                out.files_copied += 1;
            }
            out.bytes += file.size;
            continue;
        }
        // The Windows restore path is path-based, so create and hold every
        // destination parent before either the compressed or the uncompressed
        // installer opens the final name. The guard stays alive through the
        // whole loop iteration, including decompression.
        #[cfg(not(unix))]
        let _dir_guard = match dest_rel.parent() {
            Some(parent) => match util::create_dir_chain_nofollow(view_root, parent) {
                Ok(guard) => guard,
                Err(err) => {
                    out.errors += 1;
                    out.fatal_errors += 1;
                    out.messages
                        .push(format!("restore: creating {}: {err}", parent.display()));
                    continue;
                }
            },
            None => util::DirChainGuard::default(),
        };
        if let Some(object) = &file.object {
            let blob = generation_root.join(object);
            #[cfg(unix)]
            let result = restore_compressed_at(view_root, &dest_rel, &blob, entry.stamp, file);
            #[cfg(not(unix))]
            let result = install_compressed_copy(&blob, &dst, entry.stamp, file);
            match result {
                Ok(RestoreOutcome::Existing) => out.files_existing += 1,
                Ok(RestoreOutcome::Missing) => out.files_missing += 1,
                Ok(RestoreOutcome::Copied) => {
                    out.files_copied += 1;
                    out.bytes += file.size;
                    out.touched = true;
                }
                Ok(RestoreOutcome::Linked) => {
                    out.files_linked += 1;
                    out.bytes += file.size;
                    out.touched = true;
                }
                Err(err) => {
                    out.errors += 1;
                    out.fatal_errors += 1;
                    out.messages
                        .push(format!("restore: writing {}: {err:#}", dst.display()));
                }
            }
            continue;
        }
        let src = units.join(&entry.name).join(&file.path);
        let rel = Path::new(&entry.name).join(&file.path);
        #[cfg(unix)]
        {
            if let Err(err) = util::check_regular_chain(&units, &rel) {
                out.errors += 1;
                out.fatal_errors += 1;
                out.messages
                    .push(format!("restore: writing {}: {err:#}", dst.display()));
                continue;
            }
            match restore_file_at(
                view_root,
                &dest_rel,
                &src,
                entry.stamp,
                file,
                linkable,
                link,
            ) {
                Ok(RestoreOutcome::Existing) => {
                    out.files_existing += 1;
                }
                Ok(RestoreOutcome::Missing) => {
                    out.files_missing += 1;
                }
                Ok(RestoreOutcome::Linked) => {
                    out.files_linked += 1;
                    out.bytes += file.size;
                    out.touched = true;
                }
                Ok(RestoreOutcome::Copied) => {
                    out.files_copied += 1;
                    out.bytes += file.size;
                    out.touched = true;
                }
                Err(err) => {
                    out.errors += 1;
                    out.fatal_errors += 1;
                    out.messages
                        .push(format!("restore: writing {}: {err:#}", dst.display()));
                }
            }
            continue;
        }
        #[cfg(not(unix))]
        {
            match util::metadata_nofollow(&src) {
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    // Fail-open: a partial vault means Cargo rebuilds it.
                    out.files_missing += 1;
                    continue;
                }
                Err(err) => {
                    out.errors += 1;
                    out.messages
                        .push(format!("restore: inspecting {}: {err}", src.display()));
                    continue;
                }
            }
            let result = if shared && link.windows_link() {
                util::check_regular_chain(&units, &rel)
                    .and_then(|_| verify_store_file(&src, file, link.read_only))
                    .and_then(|_| match fs::hard_link(&src, &dst) {
                        Ok(()) => Ok(()),
                        // Cross-volume or a filesystem without links: a
                        // verified private copy is the fallback.
                        Err(_) => {
                            install_private_copy(&src, &dst, entry.stamp, file, link.read_only)
                        }
                    })
            } else {
                util::check_regular_chain(&units, &rel).and_then(|_| {
                    install_private_copy(&src, &dst, entry.stamp, file, link.read_only)
                })
            };
            match result {
                Ok(()) => {
                    if shared {
                        out.files_linked += 1;
                    } else {
                        out.files_copied += 1;
                    }
                    out.bytes += file.size;
                    out.touched = true;
                }
                Err(err) => {
                    out.errors += 1;
                    out.fatal_errors += 1;
                    out.messages
                        .push(format!("restore: writing {}: {err:#}", dst.display()));
                }
            }
        }
    }

    out
}

/// The store is a trust boundary: refuse a symlinked, foreign-owned, or
/// group/world-writable store. A root process must not consume a user-owned
/// vault (that is the hard-link privesc this fix closes).
/// Harvest is a signing step: only accept a real, local, non-shared build
/// root. A group/world-writable build dir is a shared trust domain, and every
/// unit found there would be signed into the vault.
fn validate_build_root(build_root: &Path) -> Result<PathBuf> {
    let build_root = util::validate_state_root(build_root, "build root")?;
    let meta = util::metadata_nofollow(&build_root)
        .with_context(|| format!("inspecting build root {}", build_root.display()))?;
    if !util::owned_by_us(&build_root, &meta) {
        anyhow::bail!(
            "build root {} is owned by another user — refusing to sign its units",
            build_root.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o022 != 0 {
            anyhow::bail!(
                "build root {} is group/world-writable (mode {:o}) — a shared build dir is a shared trust domain; use a private build dir",
                build_root.display(),
                meta.mode() & 0o777
            );
        }
    }
    #[cfg(windows)]
    require_private_windows_acl(&build_root, "build root")?;
    Ok(build_root)
}

pub(crate) fn check_store_trust(store_root: &Path) -> Result<()> {
    let meta = match util::metadata_nofollow(store_root) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            anyhow::bail!("store {} is not a real directory", store_root.display());
        }
        Err(err) => {
            return Err(err).with_context(|| format!("inspecting store {}", store_root.display()));
        }
    };
    if !meta.is_dir() {
        anyhow::bail!("store {} is not a real directory", store_root.display());
    }
    let read_only = store_is_read_only(store_root);
    // A reader may accept a foreign, read-only mount: the OS denies writes,
    // and the manifest signature is verified separately. A writable foreign
    // store is never a reader; it is one trust domain with its writer.
    if !read_only {
        util::ensure_windows_user_path(store_root, "store")?;
    }
    if !util::owned_by_us(store_root, &meta) && !read_only {
        anyhow::bail!(
            "store {} is owned by another user — refusing to execute its artifacts",
            store_root.display()
        );
    }
    #[cfg(windows)]
    if !read_only {
        require_private_windows_acl(store_root, "store")?;
    }
    // Read paths must not chmod an operator-selected directory. A store that
    // is ours but legacy-0755 stays readable; the writer marks and tightens
    // it in `ensure_store_root`.
    Ok(())
}

fn prepare_view_root(view_root: &Path) -> Result<()> {
    match util::metadata_nofollow(view_root) {
        Ok(meta) => {
            if !meta.is_dir() {
                anyhow::bail!("view {} is not a real directory", view_root.display());
            }
            if !util::owned_by_us(view_root, &meta) {
                anyhow::bail!(
                    "view {} is owned by another user — refusing to write into it",
                    view_root.display()
                );
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if meta.mode() & 0o022 != 0 {
                    anyhow::bail!(
                        "view {} is group/world-writable (mode {:o}) — refusing a shared restore target; use a 0700 dir",
                        view_root.display(),
                        meta.mode() & 0o777
                    );
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            anyhow::bail!("view {} is not a real directory", view_root.display());
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            util::create_private_dir_all(view_root)?;
        }
        Err(err) => {
            return Err(err).with_context(|| format!("inspecting view {}", view_root.display()));
        }
    }
    #[cfg(windows)]
    require_private_windows_acl(view_root, "view")?;
    // Do NOT chmod an explicitly supplied view root here: `restore --into /`
    // or `--into ~` must never change the mode of a system/home directory.
    // New view roots are created 0700; the default cache root is repaired by
    // `cmd_restore` (which knows it is the shared cache), and per-job work
    // dirs are created 0700 by `exec`.
    Ok(())
}

#[cfg(not(unix))]
fn verify_store_file(src: &Path, file: &FileEntry, allow_foreign: bool) -> Result<()> {
    let meta = match util::metadata_nofollow(src) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            anyhow::bail!("{} is not a regular file", src.display());
        }
        Err(err) => {
            return Err(err).with_context(|| format!("inspecting stored file {}", src.display()));
        }
    };
    if !meta.is_file() {
        anyhow::bail!("{} is not a regular file", src.display());
    }
    if !util::owned_by_us(src, &meta) && !allow_foreign {
        anyhow::bail!("{} is owned by another user", src.display());
    }
    if meta.len() != file.size {
        anyhow::bail!(
            "{} size drift (recorded {}, found {})",
            src.display(),
            file.size,
            meta.len()
        );
    }
    if file.sha256.is_empty() {
        anyhow::bail!("{} has no recorded SHA-256", src.display());
    }
    let found = util::sha256_file(src)?;
    if found != file.sha256 {
        anyhow::bail!("{} failed its SHA-256 check", src.display());
    }
    Ok(())
}

#[cfg(not(unix))]
fn install_private_copy(
    src: &Path,
    dst: &Path,
    stamp: u64,
    file: &FileEntry,
    allow_foreign: bool,
) -> Result<()> {
    // Create the destination directly (O_EXCL semantics). A temp file plus
    // hard_link fails on volumes/filesystems without links, including
    // cross-device and read-only vaults.
    let copy = if allow_foreign {
        util::copy_file_verified_unowned
    } else {
        util::copy_file_verified
    };
    copy(src, dst, file.size, &file.sha256)?;
    set_stamp(dst, stamp)?;
    // Private copies stay writable: rustc/cargo rewrite .rmeta and
    // fingerprint state in place. Only shared `deps/` artifacts are 0444.
    Ok(())
}

/// Read a small regular file without following a symlink.
fn read_small_regular(path: &Path) -> Option<String> {
    util::read_small_text(path, 4 * 1024 * 1024).ok()
}

// ── verify ──────────────────────────────────────────────────────────────────

/// Result of auditing one generation.
#[derive(Debug, Default)]
pub struct VerifyReport {
    pub parity: String,
    pub units: usize,
    pub files: usize,
    pub bytes: u64,
    /// Human lines: missing files, size/hash/stamp drift, orphan groups.
    pub problems: Vec<String>,
    /// Not a failure, but worth knowing (e.g. unknown files lying around).
    pub warnings: Vec<String>,
    /// Units older than one of their dependencies. Cargo recompiles exactly
    /// these after a restore ("the dependency `X` was rebuilt") — a quality
    /// fact, not an integrity failure.
    pub ordering: Vec<String>,
}

impl VerifyReport {
    pub fn is_clean(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Audit every generation in the vault: every manifest file present with the
/// recorded size, the canonical stamp, and — for memo files — the recorded
/// hash content; plus a count of unit groups the manifest doesn't know.
pub fn verify(store_root: &Path) -> Result<Vec<VerifyReport>> {
    let mut reports = Vec::new();
    for parity in generation_names(store_root)? {
        let mut report = VerifyReport {
            parity: parity.clone(),
            ..Default::default()
        };
        if let Err(err) = check_store_trust(store_root) {
            report
                .problems
                .push(format!("unsafe store: {err:#} — no artifact was read"));
            reports.push(report);
            continue;
        }
        let read_only = store_is_read_only(store_root);
        let Some(manifest) = load_manifest(store_root, &parity)? else {
            report.problems.push(format!(
                "generation {parity} has no readable manifest.json — it cannot be audited"
            ));
            reports.push(report);
            continue;
        };
        let units = units_dir(store_root, &parity);
        let generation_root = store_root.join(&parity);
        for entry in &manifest.units {
            for file in &entry.files {
                if let Some(object) = &file.object {
                    let blob = generation_root.join(object);
                    match util::metadata_nofollow(&blob) {
                        Ok(meta)
                            if meta.is_file() && (util::owned_by_us(&blob, &meta) || read_only) => {
                        }
                        Ok(_) => {
                            report
                                .problems
                                .push(format!("unsafe/missing blob: {object}"));
                            continue;
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                            report
                                .problems
                                .push(format!("unsafe/missing blob: {object}"));
                            continue;
                        }
                        Err(_) => {
                            report.problems.push(format!("missing blob: {object}"));
                            continue;
                        }
                    }
                    report.files += 1;
                    report.bytes += file.size;
                    match util::decompress_file_hashed(&blob, !read_only, file.size) {
                        Ok((size, hash)) if size == file.size && hash == file.sha256 => {}
                        Ok((size, hash)) => report.problems.push(format!(
                            "blob drift: {object} (recorded {} bytes/{}, found {} bytes/{})",
                            file.size,
                            &file.sha256[..file.sha256.len().min(12)],
                            size,
                            &hash[..hash.len().min(12)]
                        )),
                        Err(err) => report
                            .problems
                            .push(format!("blob unreadable: {object}: {err:#}")),
                    }
                    continue;
                }
                let path = units.join(&entry.name).join(&file.path);
                let rel = Path::new(&entry.name).join(&file.path);
                if let Err(err) = util::check_regular_chain(&units, &rel) {
                    report.problems.push(format!(
                        "unsafe path: {} ({err:#})",
                        display_join(&path, &units)
                    ));
                    continue;
                }
                let meta = match util::metadata_nofollow(&path) {
                    Ok(meta) => meta,
                    Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                        report.problems.push(format!(
                            "symlink/reparse in store (refused): {}",
                            display_join(&path, &units)
                        ));
                        continue;
                    }
                    Err(_) => {
                        report
                            .problems
                            .push(format!("missing: {}", display_join(&path, units.as_path())));
                        continue;
                    }
                };
                if !meta.is_file() {
                    report.problems.push(format!(
                        "not a regular file: {}",
                        display_join(&path, &units)
                    ));
                    continue;
                }
                if !util::owned_by_us(&path, &meta) && !read_only {
                    report.problems.push(format!(
                        "foreign-owned file: {}",
                        display_join(&path, &units)
                    ));
                }
                report.files += 1;
                report.bytes += meta.len();
                if meta.len() != file.size {
                    report.problems.push(format!(
                        "size drift: {} (recorded {}, found {})",
                        display_join(&path, &units),
                        file.size,
                        meta.len()
                    ));
                }
                let found_stamp = meta.modified().map(ceil_secs).unwrap_or(0);
                if found_stamp != entry.stamp {
                    report.problems.push(format!(
                        "stamp drift: {} (recorded {}, found {})",
                        display_join(&path, &units),
                        entry.stamp,
                        found_stamp
                    ));
                }
                if file.sha256.is_empty() {
                    report.problems.push(format!(
                        "no recorded SHA-256: {} (re-harvest this generation)",
                        display_join(&path, &units)
                    ));
                } else {
                    match util::sha256_file(&path) {
                        Ok(found) if found != file.sha256 => report.problems.push(format!(
                            "content drift: {} (recorded {}, found {})",
                            display_join(&path, &units),
                            &file.sha256[..file.sha256.len().min(12)],
                            &found[..found.len().min(12)]
                        )),
                        Ok(_) => {}
                        Err(err) => report.problems.push(format!(
                            "unreadable: {}: {err}",
                            display_join(&path, &units)
                        )),
                    }
                }
                if file.role == "memo" {
                    match read_small_regular(&path) {
                        Some(text) if file.path == entry.memo && text.trim() != entry.hash => {
                            let found = text.trim();
                            let detail = if crate::fingerprint::looks_like_hash(found) {
                                format!("found {found}")
                            } else {
                                "found non-hash content (not printed)".to_string()
                            };
                            report.problems.push(format!(
                                "hash drift: {} (recorded {}; {detail})",
                                display_join(&path, &units),
                                entry.hash
                            ));
                        }
                        Some(text)
                            if file.path != entry.memo
                                && !crate::fingerprint::looks_like_hash(text.trim()) =>
                        {
                            report.problems.push(format!(
                                "malformed memo file: {} (content is not a 16-hex hash)",
                                display_join(&path, &units)
                            ));
                        }
                        Some(_) => {}
                        None => report.problems.push(format!(
                            "unreadable/symlinked memo file: {}",
                            display_join(&path, &units)
                        )),
                    }
                }
            }
        }
        // Reject extra files in recorded unit dirs too: a manifest hash
        // list is only meaningful if the set of files is exact.
        for entry in &manifest.units {
            let unit_dir = units.join(&entry.name);
            let expected: std::collections::BTreeSet<String> =
                entry.files.iter().map(|file| file.path.clone()).collect();
            let walk = match WalkDir::new(&unit_dir)
                .min_depth(1)
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(walk) => walk,
                Err(err) => {
                    report
                        .problems
                        .push(format!("unreadable unit dir: units/{} ({err})", entry.name));
                    continue;
                }
            };
            for file in walk {
                if !file.file_type().is_file() {
                    continue;
                }
                let rel = file
                    .path()
                    .strip_prefix(&unit_dir)
                    .map(|rel| rel.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_default();
                if !expected.contains(&rel) {
                    report
                        .problems
                        .push(format!("unrecorded file: units/{}/{}", entry.name, rel));
                }
            }
        }

        // Ordering audit: a unit must be at least as new as its
        // dependencies, or cargo recompiles it after a restore ("the
        // dependency `X` was rebuilt"). Edges come from the stored
        // fingerprints; the join key is the dependency's memo hash — the
        // same value serde's `serde_core` edge (9416646317397223793) and
        // serde_core's memo file (71a9f323efa5ae82) share.
        let by_hash: std::collections::HashMap<&str, usize> = manifest
            .units
            .iter()
            .enumerate()
            .map(|(index, entry)| (entry.hash.as_str(), index))
            .collect();
        for entry in &manifest.units {
            let json = entry
                .files
                .iter()
                .find(|file| file.path.ends_with(".json"))
                .and_then(|file| read_small_regular(&units.join(&entry.name).join(&file.path)))
                .and_then(|text| crate::fingerprint::parse_fingerprint(&text));
            let Some(json) = json else { continue };
            for dep in &json.deps {
                let Some(dep_index) = dep
                    .memo_hash()
                    .and_then(|hash| by_hash.get(hash.as_str()))
                    .copied()
                else {
                    continue;
                };
                let dep_entry = &manifest.units[dep_index];
                if dep_entry.stamp > entry.stamp {
                    report.ordering.push(format!(
                        "{} is older than its dependency {} ({} older) — cargo recompiles it after a restore",
                        entry.name,
                        dep_entry.name,
                        crate::util::human_duration(Duration::from_secs(dep_entry.stamp - entry.stamp))
                    ));
                }
            }
        }
        report.units = manifest.units.len();

        // Unit groups on disk that the manifest doesn't record.
        match util::metadata_nofollow(&units) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                report.problems.push(format!(
                    "units directory {} is a symlink/reparse or not a directory",
                    units.display()
                ));
            }
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                report.problems.push(format!(
                    "units directory {} is a symlink/reparse or not a directory",
                    units.display()
                ));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => report.problems.push(format!(
                "unreadable units directory {}: {err}",
                units.display()
            )),
        }
        if units.is_dir() {
            let known: std::collections::BTreeSet<&str> = manifest
                .units
                .iter()
                .map(|unit| unit.name.as_str())
                .collect();
            for entry in fs::read_dir(&units)? {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') {
                    continue; // in-flight temp dirs of a crashed harvest
                }
                if !known.contains(name.as_str()) {
                    // An unrecorded group can be an orphan from a lost
                    // harvest or an injected file set. Treat it as a problem,
                    // not a cosmetic warning: `verify` must fail before a
                    // consumer trusts the generation.
                    report
                        .problems
                        .push(format!("unrecorded unit group: units/{name}"));
                }
            }
        }
        reports.push(report);
    }
    Ok(reports)
}

/// Path for humans: relative to `base` when possible.
fn display_join(path: &Path, base: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// One package/profile pool in the vault, used by the overlap report.
#[derive(Debug, Default)]
pub struct OverlapPackage {
    pub package: String,
    pub profile: String,
    pub units: usize,
    pub hashes: usize,
    pub bytes: u64,
    pub generations: usize,
}

/// Aggregated package/profile variants across every vault generation.
pub fn overlap(store_root: &Path) -> Result<Vec<OverlapPackage>> {
    if store_root.exists() {
        check_store_trust(store_root)?;
    }
    let mut pools: std::collections::BTreeMap<
        (String, String),
        (
            usize,
            u64,
            std::collections::BTreeSet<String>,
            std::collections::BTreeSet<String>,
        ),
    > = std::collections::BTreeMap::new();
    for generation in generation_names(store_root)? {
        let Some(manifest) = load_manifest(store_root, &generation)? else {
            continue;
        };
        for unit in &manifest.units {
            let package = unit_package(&unit.name)
                .unwrap_or(unit.name.as_str())
                .to_string();
            let entry = pools.entry((package, unit.profile.clone())).or_default();
            entry.0 += 1;
            entry.1 += unit.files.iter().map(|file| file.size).sum::<u64>();
            entry.2.insert(generation.clone());
            entry.3.insert(unit.hash.clone());
        }
    }
    let mut out: Vec<OverlapPackage> = pools
        .into_iter()
        .map(
            |((package, profile), (units, bytes, generations, hashes))| OverlapPackage {
                package,
                profile,
                units,
                hashes: hashes.len(),
                bytes,
                generations: generations.len(),
            },
        )
        .collect();
    out.sort_by(|a, b| {
        b.bytes
            .cmp(&a.bytes)
            .then_with(|| a.package.cmp(&b.package))
    });
    Ok(out)
}

// ── status ──────────────────────────────────────────────────────────────────

/// One generation as the `vault` command shows it.
#[derive(Debug, Default)]
pub struct GenerationInfo {
    pub parity: String,
    /// Matches the installed toolchain + flag environment.
    pub active: bool,
    pub units: usize,
    pub files: usize,
    /// Bytes as the store holds them; a file linked into views counts once.
    pub bytes: u64,
    /// Store files that are also linked elsewhere (`nlink > 1`).
    pub linked: usize,
    pub created: Option<u64>,
    pub updated: Option<u64>,
}

/// Summarize every generation of the vault.
pub fn generations(store_root: &Path) -> Result<Vec<GenerationInfo>> {
    let active = parity_key().ok();
    let mut out = Vec::new();
    let mut scanned = 0u64;
    for parity in generation_names(store_root)? {
        let mut info = GenerationInfo {
            parity: parity.clone(),
            active: active.as_deref() == Some(parity.as_str()),
            ..Default::default()
        };
        if let Some(manifest) = load_manifest(store_root, &parity)? {
            info.units = manifest.units.len();
            info.created = Some(manifest.created);
            info.updated = Some(manifest.updated);
        }
        let units = units_dir(store_root, &parity);
        if units.is_dir() {
            #[cfg(unix)]
            let mut seen_inodes = std::collections::HashSet::new();
            for entry in WalkDir::new(&units).min_depth(1) {
                let entry = entry?;
                scanned = scanned.saturating_add(1);
                if scanned > MAX_SCAN_FILES {
                    anyhow::bail!(
                        "store {} has more than {} files — refusing an unbounded scan",
                        store_root.display(),
                        MAX_SCAN_FILES
                    );
                }
                if !entry.file_type().is_file() {
                    continue;
                }
                let meta = entry.metadata()?;
                #[cfg(unix)]
                let unique = {
                    use std::os::unix::fs::MetadataExt;
                    seen_inodes.insert((meta.dev(), meta.ino()))
                };
                #[cfg(not(unix))]
                let unique = true;
                info.files += 1;
                if unique {
                    info.bytes += meta.len();
                }
                if link_count(&meta) > 1 {
                    info.linked += 1;
                }
            }
        }
        out.push(info);
    }
    Ok(out)
}

/// Hard links of one inode as the file system knows it (1 where unsupported).
pub(crate) fn link_count(meta: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.nlink()
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        1
    }
}

/// The vault's own matcher: package prefix or hash fragment of a group name.
fn unit_name_matches(name: &str, query: &str) -> bool {
    name.contains(query)
}

/// The package part of a unit dir name (`serde_core-b468be6fa8c1f936` →
/// `serde_core`); `None` for a name that does not end in a 16-hex hash.
fn unit_package(name: &str) -> Option<&str> {
    let (package, hash) = name.rsplit_once('-')?;
    (hash.len() == 16 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(package)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A build dir in the shapes real Cargo writes: a lib unit, a
    /// build-script compile unit, and a build-script run unit without
    /// dep-info — plus volatile files and wrapper internals that must be
    /// filtered out.
    fn synthetic_build_dir(root: &Path) -> Result<()> {
        let jsons = r#"{"rustc":12019306335353385202,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[]}"#;

        let lib = root.join("debug/.fingerprint/serde-102a33f055a8d229");
        fs::create_dir_all(&lib)?;
        fs::write(lib.join("lib-serde"), "5d82713a7f2d05e2")?;
        fs::write(lib.join("lib-serde.json"), jsons)?;
        fs::write(lib.join("dep-lib-serde"), [0u8; 24])?;
        fs::write(lib.join("invoked.timestamp"), "")?;
        fs::create_dir_all(root.join("debug/deps"))?;
        fs::write(
            root.join("debug/deps/libserde-102a33f055a8d229.rlib"),
            [7u8; 64],
        )?;
        fs::write(
            root.join("debug/deps/libserde-102a33f055a8d229.rmeta"),
            [6u8; 48],
        )?;
        fs::write(
            root.join("debug/deps/serde-102a33f055a8d229.d"),
            b"side file",
        )?;
        fs::write(
            root.join("debug/deps/libserde-102a33f055a8d229.kache-real"),
            b"wrapper",
        )?;

        let compile = root.join("debug/.fingerprint/x-1122334455667788");
        fs::create_dir_all(&compile)?;
        fs::write(
            compile.join("build-script-build-script-build"),
            "aaaabbbbccccdddd",
        )?;
        fs::write(compile.join("build-script-build-script-build.json"), jsons)?;
        fs::write(
            compile.join("dep-build-script-build-script-build"),
            [0u8; 8],
        )?;
        let compile_anchor = root.join("debug/build/x-1122334455667788");
        fs::create_dir_all(&compile_anchor)?;
        fs::write(
            compile_anchor.join("build_script_build-1122334455667788"),
            [3u8; 32],
        )?;
        fs::write(
            compile_anchor.join("build_script_build-1122334455667788.d"),
            b"dep",
        )?;
        fs::write(
            compile_anchor.join("build_script_build-1122334455667788.kache-real"),
            b"wrapper",
        )?;
        fs::write(compile_anchor.join("invoked.timestamp"), "")?;

        // The run unit has no dep-info at all (real Cargo layout).
        let run = root.join("debug/.fingerprint/x-aabbccddeeff0011");
        fs::create_dir_all(&run)?;
        fs::write(
            run.join("run-build-script-build-script-build"),
            "eeeeffff00001111",
        )?;
        fs::write(run.join("run-build-script-build-script-build.json"), jsons)?;
        let run_anchor = root.join("debug/build/x-aabbccddeeff0011");
        fs::create_dir_all(&run_anchor)?;
        fs::write(
            run_anchor.join("output"),
            b"cargo:rerun-if-changed=build.rs",
        )?;
        fs::write(run_anchor.join("stderr"), b"")?;
        fs::write(run_anchor.join("invoked.timestamp"), "")?;
        Ok(())
    }

    /// A build dir with one incomplete unit (memo file, but no artifacts).
    fn synthetic_husk(root: &Path) -> Result<()> {
        let unit = root.join("debug/.fingerprint/husk-aaaabbbbccccdddd");
        fs::create_dir_all(&unit)?;
        fs::write(unit.join("lib-husk"), "0000111122223333")?;
        Ok(())
    }

    #[test]
    fn parity_key_is_stable_and_shaped() -> Result<()> {
        let first = parity_key()?;
        let second = parity_key()?;
        assert_eq!(first, second);
        let tc = toolchain()?;
        assert!(first.starts_with(&format!("{}-{}", tc.release, tc.commit)));
        assert!(first.ends_with(&flags_digest(&tc.host)));
        Ok(())
    }

    #[test]
    fn harvest_stores_groups_with_one_canonical_stamp() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;

        let report = harvest(build.path(), store.path(), None, false)?;
        assert_eq!(report.stored, 3, "lib + build-script compile + run");
        assert_eq!(report.skipped_incomplete, 0);
        assert!(report.files >= 10, "got {}", report.files);
        assert!(report.bytes > 0);

        let parity = parity_key()?;
        let manifest = load_manifest(store.path(), &parity)?.expect("manifest written");
        assert_eq!(manifest.units.len(), 3);
        let lib_entry = manifest
            .units
            .iter()
            .find(|unit| unit.name == "serde-102a33f055a8d229")
            .expect("lib unit recorded");
        assert_eq!(lib_entry.hash, "5d82713a7f2d05e2");
        assert_eq!(lib_entry.profile, "debug");

        // Every stored file of the group carries the same stamp.
        let group = units_dir(store.path(), &parity).join(&lib_entry.name);
        for file in &lib_entry.files {
            let meta = fs::metadata(group.join(&file.path))?;
            assert_eq!(
                ceil_secs(meta.modified()?),
                lib_entry.stamp,
                "{}",
                file.path
            );
            assert_eq!(meta.len(), file.size);
        }

        // Volatile files and wrapper internals never enter the store.
        assert!(!group.join("invoked.timestamp").exists());
        for file in &lib_entry.files {
            assert!(!file.path.contains("kache"), "{}", file.path);
            assert!(!file.path.ends_with(".d"), "{}", file.path);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(group.join(&lib_entry.files[0].path))?;
            assert_eq!(
                meta.permissions().mode() & 0o777,
                0o444,
                "store is read-only"
            );
        }
        Ok(())
    }

    #[test]
    fn overlap_groups_units_by_package_and_profile() -> Result<()> {
        let store = tempfile::tempdir()?;
        let unit = |hash: &str, size: u64| UnitEntry {
            name: format!("demo-{hash}"),
            profile: "debug".into(),
            memo: "lib-demo".into(),
            hash: hash.into(),
            stamp: 1,
            layout: None,
            files: vec![FileEntry {
                path: "lib-demo".into(),
                dest: "deps/libdemo".into(),
                size,
                sha256: "0".repeat(64),
                role: "artifact".into(),
                object: None,
            }],
        };
        let manifest = Manifest {
            parity_key: "generation".into(),
            toolchain: "test".into(),
            created: 1,
            updated: 1,
            units: vec![unit("aaaaaaaaaaaaaaaa", 10), unit("bbbbbbbbbbbbbbbb", 20)],
            mac: String::new(),
            signature: String::new(),
        };
        save_manifest(store.path(), "generation", &manifest)?;
        let report = overlap(store.path())?;
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].package, "demo");
        assert_eq!(report[0].units, 2);
        assert_eq!(report[0].hashes, 2);
        assert_eq!(report[0].bytes, 30);
        Ok(())
    }

    #[test]
    fn harvest_skips_units_without_a_memo_hash() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;

        // A failed build-script compile: artifacts exist, but cargo left only
        // cached diagnostics where the memo hash belongs.
        let failed = build
            .path()
            .join("debug/.fingerprint/broken-0011223344556677");
        fs::create_dir_all(&failed)?;
        fs::write(
            failed.join("output-build-script-build-script-build"),
            r#"{"$message_type":"diagnostic","message":"linking with `clang` failed"}"#,
        )?;
        let anchor = build.path().join("debug/build/broken-0011223344556677");
        fs::create_dir_all(&anchor)?;
        fs::write(anchor.join("build_script_build-0011223344556677"), [1u8; 8])?;

        let report = harvest(build.path(), store.path(), None, false)?;
        assert_eq!(report.stored, 3, "the three valid units are stored");
        assert_eq!(report.skipped_incomplete, 1, "the failed unit is skipped");

        let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
        assert!(
            manifest
                .units
                .iter()
                .all(|unit| unit.name != "broken-0011223344556677"),
            "a diagnostic must never become a memo hash"
        );
        Ok(())
    }

    #[test]
    fn load_repairs_an_authentic_manifest_with_an_invalid_unit() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        let parity = parity_key()?;
        harvest(build.path(), store.path(), None, false)?;

        // Simulate an entry written before harvest validated the memo hash.
        let mut manifest = load_manifest(store.path(), &parity)?.expect("manifest");
        let bad = manifest.units[0].name.clone();
        manifest.units[0].hash = r#"{"$message_type":"diagnostic"}"#.into();
        // This fixture simulates an older HMAC-only manifest; the Ed25519
        // signature would no longer match after the field edit.
        manifest.signature.clear();
        manifest.mac = manifest_mac(&manifest)?;
        let path = manifest_path(store.path(), &parity);
        fs::write(&path, serde_json::to_string_pretty(&manifest)?)?;

        // A reader filters the invalid entry in memory but never rewrites the
        // store. The writer-only repair below is the only mutation.
        let read = load_manifest(store.path(), &parity)?.expect("manifest");
        assert!(
            read.units.iter().all(|unit| unit.name != bad),
            "the invalid entry is ignored"
        );
        assert_eq!(read.units.len(), 2, "the valid units survive");
        let raw = fs::read_to_string(&path)?;
        assert!(
            raw.contains("$message_type"),
            "the read path must not rewrite the manifest"
        );

        let repaired = load_manifest_at(store.path(), &parity, true)?.expect("manifest");
        assert!(
            repaired.units.iter().all(|unit| unit.name != bad),
            "the writer repair drops the invalid entry"
        );
        assert_eq!(repaired.units.len(), 2, "the valid units survive");
        let reread = load_manifest(store.path(), &parity)?.expect("manifest");
        assert_eq!(reread.units.len(), 2);
        Ok(())
    }

    #[test]
    fn harvest_rejects_a_fake_unit_without_a_cargo_fingerprint() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        let unit = build
            .path()
            .join("debug/.fingerprint/proc-1111222233334444");
        fs::create_dir_all(&unit)?;
        // A hand-written unit shape: a memo hash and an executable, no cargo JSON.
        fs::write(unit.join("lib-proc"), "0011223344556677")?;
        fs::create_dir_all(build.path().join("debug/deps"))?;
        fs::write(
            build.path().join("debug/deps/libproc-1111222233334444.so"),
            b"MALICIOUS-PROC-MACRO",
        )?;

        let report = harvest(build.path(), store.path(), None, false)?;
        assert_eq!(report.stored, 0, "hand-written unit must not be signed");
        assert_eq!(report.skipped_incomplete, 1);
        let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
        assert!(manifest.units.is_empty(), "{:?}", manifest.units);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn harvest_refuses_a_group_or_world_writable_build_root() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        fs::set_permissions(build.path(), fs::Permissions::from_mode(0o777))?;

        let err = harvest(build.path(), store.path(), None, false).unwrap_err();
        assert!(
            format!("{err:#}").contains("group/world-writable"),
            "{err:#}"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn restore_copies_from_a_shared_store_and_isolates_later_mutation() -> Result<()> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        let view = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        harvest(build.path(), store.path(), None, false)?;
        // A group/world-writable store is a shared trust domain: restore must
        // copy, never share an inode with the view.
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o777))?;

        let report = restore(view.path(), store.path(), None, None, false)?;
        assert_eq!(report.errors, 0);
        let parity = parity_key()?;
        let stored = units_dir(store.path(), &parity)
            .join("serde-102a33f055a8d229/deps/libserde-102a33f055a8d229.rlib");
        let linked = view
            .path()
            .join("debug/deps/libserde-102a33f055a8d229.rlib");
        assert_ne!(
            fs::metadata(&stored)?.ino(),
            fs::metadata(&linked)?.ino(),
            "shared store must not share inodes"
        );
        fs::set_permissions(&linked, fs::Permissions::from_mode(0o644))?;
        fs::write(&linked, b"MUTATED-VIA-VIEW")?;
        assert_ne!(
            fs::read(&stored)?,
            b"MUTATED-VIA-VIEW",
            "the store copy is isolated from the view"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn restore_falls_back_to_copy_across_filesystems() -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let Ok(shm) = tempfile::Builder::new()
            .prefix("epi-xdev-")
            .tempdir_in("/dev/shm")
        else {
            return Ok(()); // no separate filesystem in this environment
        };
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir_in(shm.path())?;
        let view = tempfile::tempdir()?;
        if fs::metadata(store.path())?.dev() == fs::metadata(view.path())?.dev() {
            return Ok(());
        }
        synthetic_build_dir(build.path())?;
        harvest(build.path(), store.path(), None, false)?;

        let report = restore(view.path(), store.path(), None, None, false)?;
        assert_eq!(report.errors, 0, "{:?}", report);
        let stored = units_dir(store.path(), &parity_key()?)
            .join("serde-102a33f055a8d229/deps/libserde-102a33f055a8d229.rlib");
        let copied = view
            .path()
            .join("debug/deps/libserde-102a33f055a8d229.rlib");
        assert_ne!(fs::metadata(&stored)?.ino(), fs::metadata(&copied)?.ino());
        assert_eq!(fs::read(&copied)?.len(), 64);
        Ok(())
    }

    #[test]
    fn harvest_is_idempotent_and_skips_incomplete_units() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        synthetic_husk(build.path())?;

        let first = harvest(build.path(), store.path(), None, false)?;
        assert_eq!(first.stored, 3);
        assert_eq!(first.skipped_incomplete, 1, "husk without artifacts");

        let second = harvest(build.path(), store.path(), None, false)?;
        assert_eq!(second.stored, 0);
        assert_eq!(second.unchanged, 3);
        assert_eq!(second.skipped_incomplete, 1);
        Ok(())
    }

    #[test]
    fn harvest_can_skip_compression_and_gc_blobs() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        let source = build
            .path()
            .join("debug/deps/libserde-102a33f055a8d229.rmeta");
        fs::write(&source, vec![7u8; 16 * 1024])?;

        let report = harvest_with(build.path(), store.path(), None, false, None, None, false)?;
        let manifest = load_manifest(store.path(), &report.parity)?.expect("manifest");
        let file = manifest
            .units
            .iter()
            .flat_map(|entry| entry.files.iter())
            .find(|file| file.path.ends_with(".rmeta"))
            .expect("rmeta");
        assert!(file.object.is_none(), "no-compress stores raw bytes");

        let store2 = tempfile::tempdir()?;
        harvest(build.path(), store2.path(), None, false)?;
        let report2 = harvest(build.path(), store2.path(), None, false)?;
        let manifest2 = load_manifest(store2.path(), &report2.parity)?.expect("manifest");
        let object = manifest2
            .units
            .iter()
            .flat_map(|entry| entry.files.iter())
            .find_map(|file| file.object.clone())
            .expect("compressed object");
        assert!(store2.path().join(&report2.parity).join(&object).is_file());
        drop_units(
            store2.path(),
            &report2.parity,
            &["serde-102a33f055a8d229".into()],
        )?;
        assert!(!store2.path().join(&report2.parity).join(object).exists());
        Ok(())
    }

    #[cfg(not(unix))]
    #[test]
    fn compressed_install_does_not_unlink_a_racing_destination() -> Result<()> {
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
        let entry = FileEntry {
            path: "deps/libx.rlib".into(),
            dest: "deps/libx.rlib".into(),
            size: 7,
            sha256: format!("{:x}", Sha256::digest(b"payload")),
            role: "artifact".into(),
            object: None,
        };

        match install_compressed_copy(&blob, &dst, 1_700_000_000, &entry)? {
            RestoreOutcome::Existing => {}
            _ => panic!("an existing destination must win the race"),
        }
        assert_eq!(fs::read(&dst)?, b"keep");
        assert!(
            !fs::read_dir(dir.path())?.any(|entry| entry
                .map(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".epicenter-tmp-"))
                .unwrap_or(false)),
            "the temporary file is removed"
        );
        Ok(())
    }

    #[test]
    fn harvest_compresses_artifacts_and_restores_into_a_fresh_view() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        let source = build
            .path()
            .join("debug/deps/libserde-102a33f055a8d229.rmeta");
        let data = vec![7u8; 16 * 1024];
        fs::write(&source, &data)?;

        harvest(build.path(), store.path(), None, false)?;
        let parity = parity_key()?;
        let manifest = load_manifest(store.path(), &parity)?.expect("manifest");
        let entry = manifest
            .units
            .iter()
            .find(|entry| entry.name == "serde-102a33f055a8d229")
            .expect("serde unit");
        let file = entry
            .files
            .iter()
            .find(|file| file.path.ends_with(".rmeta"))
            .expect("rmeta");
        let object = file.object.as_deref().expect("compressed object");
        assert!(store.path().join(&parity).join(object).is_file());

        // A view root that does not exist yet forces every profile/deps parent
        // to be created during restore, including the compressed-object path.
        let parent = tempfile::tempdir()?;
        let view = parent.path().join("fresh-view");
        restore(&view, store.path(), None, None, false)?;
        let restored = view.join("debug/deps/libserde-102a33f055a8d229.rmeta");
        assert_eq!(fs::read(&restored)?, data);
        let reports = verify(store.path())?;
        assert!(reports.iter().all(|report| report.is_clean()));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn harvest_copies_library_outputs_and_keeps_build_writable() -> Result<()> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        let report = harvest(build.path(), store.path(), None, false)?;

        let unit = format!("serde-102a33f055a8d229");
        let stored = units_dir(store.path(), &report.parity).join(&unit);
        let build_rlib = build
            .path()
            .join("debug/deps/libserde-102a33f055a8d229.rlib");
        let stored_rlib = stored.join("deps/libserde-102a33f055a8d229.rlib");
        let build_rmeta = build
            .path()
            .join("debug/deps/libserde-102a33f055a8d229.rmeta");
        let stored_rmeta = stored.join("deps/libserde-102a33f055a8d229.rmeta");

        // Never share an inode with the live build tree: the store stamps its
        // copy read-only, and a link would make the build output read-only
        // (and let either side mutate the other).
        assert_eq!(
            fs::metadata(&build_rlib)?.nlink(),
            1,
            "build keeps its inode"
        );
        assert_eq!(
            fs::metadata(&stored_rlib)?.nlink(),
            1,
            "store owns its inode"
        );
        assert_ne!(
            fs::metadata(&build_rlib)?.ino(),
            fs::metadata(&stored_rlib)?.ino()
        );
        assert_eq!(
            fs::metadata(&stored_rlib)?.permissions().mode() & 0o777,
            0o444
        );
        assert_ne!(
            fs::metadata(&build_rlib)?.permissions().mode() & 0o200,
            0,
            "the build output stays writable for cargo"
        );
        assert_eq!(fs::metadata(&build_rmeta)?.nlink(), 1, ".rmeta is a copy");
        assert_eq!(fs::metadata(&stored_rmeta)?.nlink(), 1, ".rmeta is a copy");
        Ok(())
    }

    #[test]
    fn repeat_harvest_does_not_rewrite_the_manifest() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;

        let first = harvest(build.path(), store.path(), None, false)?;
        let mut manifest = load_manifest(store.path(), &first.parity)?.expect("manifest");
        manifest.updated = 1;
        save_manifest(store.path(), &first.parity, &manifest)?;

        let second = harvest(build.path(), store.path(), None, false)?;
        assert_eq!(second.stored, 0);
        assert_eq!(second.unchanged, 3);
        let after = load_manifest(store.path(), &first.parity)?.expect("manifest");
        assert_eq!(after.updated, 1, "a no-op harvest must not rewrite it");
        Ok(())
    }

    #[test]
    fn harvest_refreshes_when_the_file_set_grows() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        harvest(build.path(), store.path(), Some("102a33f0"), false)?;

        fs::write(
            build.path().join("debug/deps/libserde-102a33f055a8d229.so"),
            [1u8; 16],
        )?;
        let report = harvest(build.path(), store.path(), Some("102a33f0"), false)?;
        assert_eq!(report.refreshed, 1);
        assert_eq!(report.stored, 0);

        let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
        let paths: Vec<&str> = manifest.units[0]
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect();
        assert!(
            paths.contains(&"deps/libserde-102a33f055a8d229.so"),
            "{paths:?}"
        );
        Ok(())
    }

    #[test]
    fn harvest_stores_all_memos_of_shared_dirs() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        let lib = build
            .path()
            .join("debug/.fingerprint/serde-102a33f055a8d229");
        fs::write(lib.join("bin-serde"), "1111222233334444")?;
        fs::write(
            lib.join("bin-serde.json"),
            r#"{"rustc":12019306335353385202,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[]}"#,
        )?;
        fs::write(lib.join("dep-bin-serde"), [0u8; 8])?;

        let report = harvest(build.path(), store.path(), Some("102a33f0"), false)?;
        assert_eq!(report.stored, 1);
        let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
        let entry = &manifest.units[0];
        let paths: Vec<&str> = entry.files.iter().map(|file| file.path.as_str()).collect();
        assert!(paths.contains(&"bin-serde"), "{paths:?}");
        assert!(paths.contains(&"dep-bin-serde"), "{paths:?}");

        let reports = verify(store.path())?;
        assert!(reports[0].is_clean(), "{:?}", reports[0].problems);
        Ok(())
    }

    #[test]
    fn harvest_dry_run_writes_nothing() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;

        let report = harvest(build.path(), store.path(), None, true)?;
        assert_eq!(report.stored, 3);
        assert_eq!(generation_names(store.path())?.len(), 0, "no generation");
        Ok(())
    }

    #[test]
    fn harvest_unit_filter_selects_one_group() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;

        let report = harvest(build.path(), store.path(), Some("102a33f0"), false)?;
        assert_eq!(report.stored, 1);
        let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
        assert_eq!(manifest.units.len(), 1);
        assert_eq!(manifest.units[0].name, "serde-102a33f055a8d229");
        Ok(())
    }

    #[test]
    fn restore_never_overwrites_existing_files() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        let view = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        harvest(build.path(), store.path(), None, false)?;

        // A pre-existing file must survive a restore untouched.
        let occupied = view
            .path()
            .join("debug/deps/libserde-102a33f055a8d229.rlib");
        fs::create_dir_all(occupied.parent().unwrap())?;
        fs::write(&occupied, b"live artifact")?;

        let report = restore(view.path(), store.path(), None, None, false)?;
        assert_eq!(report.units_linked, 3);
        assert_eq!(report.files_existing, 1, "the live artifact was skipped");
        assert_eq!(fs::read(&occupied)?, b"live artifact");
        // A writable store is copied from; the single deps artifact of this
        // fixture was the occupied one, so nothing was linked or copied.
        assert_eq!(report.files_linked, 0, "no other deps/ artifact");
        assert!(report.files_copied >= 12, "got {}", report.files_copied);

        // Memo file content and hash landed in the right place.
        let memo = view
            .path()
            .join("debug/.fingerprint/serde-102a33f055a8d229/lib-serde");
        assert_eq!(fs::read_to_string(&memo)?.trim(), "5d82713a7f2d05e2");
        assert!(
            view.path()
                .join("debug/build/x-aabbccddeeff0011/output")
                .is_file()
        );

        // Fingerprint state is a private writable copy: cargo rewrites it in
        // place after a rebuild, and a shared inode would EACCES on the
        // read-only store copy (or mutate the store).
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            use std::os::unix::fs::PermissionsExt;
            let parity = parity_key()?;
            let stored = units_dir(store.path(), &parity).join("serde-102a33f055a8d229/lib-serde");
            let view_meta = fs::metadata(&memo)?;
            assert_ne!(
                view_meta.ino(),
                fs::metadata(&stored)?.ino(),
                "state not shared"
            );
            assert_eq!(view_meta.nlink(), 1, "state owns its inode");
            assert_ne!(view_meta.permissions().mode() & 0o200, 0, "state writable");
        }

        // Second restore: everything already fresh.
        let again = restore(view.path(), store.path(), None, None, false)?;
        assert_eq!(again.units_already, 3);
        assert_eq!(again.files_linked, 0);
        assert_eq!(again.files_copied, 0);
        Ok(())
    }

    #[test]
    fn restore_into_missing_profile_dirs_creates_them() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        let view = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        harvest(build.path(), store.path(), None, false)?;

        let report = restore(view.path(), store.path(), None, None, false)?;
        assert_eq!(report.errors, 0);
        assert!(view.path().join("debug/.fingerprint").is_dir());
        Ok(())
    }

    #[test]
    fn restore_can_restrict_units_to_packages() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        let view = tempfile::tempdir()?;
        let now = now_secs();
        synthetic_edge_dir(build.path(), now - 3600, now)?;
        harvest(build.path(), store.path(), None, false)?;

        let mut packages = std::collections::HashSet::new();
        packages.insert("serde_core".to_string());
        let report = restore(view.path(), store.path(), None, Some(&packages), false)?;
        assert_eq!(report.errors, 0);
        assert!(
            view.path()
                .join("debug/.fingerprint/serde_core-b468be6fa8c1f936")
                .is_dir(),
            "a unit of a selected package is restored"
        );
        assert!(
            !view
                .path()
                .join("debug/.fingerprint/serde-746d173581f1a314")
                .exists(),
            "a unit of an unselected package is not restored"
        );
        Ok(())
    }

    #[test]
    fn harvest_and_restore_new_layout_units() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        let view = tempfile::tempdir()?;
        let unit = synthetic_new_layout_unit(build.path(), "anyhow", "9709d57b46b8d526")?;

        let report = harvest_with(
            build.path(),
            store.path(),
            None,
            false,
            None,
            Some(fingerprint::UnitLayout::New),
            true,
        )?;
        assert_eq!(report.stored, 1, "{report:?}");

        let parity = parity_key()?;
        let manifest = load_manifest(store.path(), &parity)?.expect("manifest");
        let entry = &manifest.units[0];
        assert_eq!(entry.layout(), fingerprint::UnitLayout::New);
        assert!(
            entry
                .files
                .iter()
                .any(|file| file.dest == "build/anyhow/9709d57b46b8d526/fingerprint/lib-anyhow")
        );
        assert!(
            entry.files.iter().any(|file| file.dest
                == "build/anyhow/9709d57b46b8d526/out/libanyhow-9709d57b46b8d526.rlib")
        );
        assert!(
            !entry.files.iter().any(|file| file.dest.ends_with(".d")),
            "rustc .d side files stay out of the vault"
        );

        let restored = restore_with(
            view.path(),
            store.path(),
            None,
            None,
            Some(fingerprint::UnitLayout::New),
            None,
            false,
            LinkPolicy::Copy,
        )?;
        assert_eq!(restored.errors, 0);
        let root = view.path().join("debug/build/anyhow/9709d57b46b8d526");
        assert!(root.join("fingerprint/lib-anyhow").is_file());
        assert!(root.join("out/libanyhow-9709d57b46b8d526.rlib").is_file());
        assert!(root.join("out/libanyhow-9709d57b46b8d526.rmeta").is_file());
        assert!(
            !view.path().join("debug/.fingerprint").exists(),
            "no classic paths for a new-layout unit"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let rlib = root.join("out/libanyhow-9709d57b46b8d526.rlib");
            let rmeta = root.join("out/libanyhow-9709d57b46b8d526.rmeta");
            assert_eq!(fs::metadata(&rlib)?.nlink(), 1, "rlib is a private copy");
            assert_eq!(fs::metadata(&rmeta)?.nlink(), 1, "rmeta is a copy");
        }
        // The fixture's source unit survives untouched.
        assert!(unit.join("out/libanyhow-9709d57b46b8d526.rlib").is_file());
        Ok(())
    }

    #[test]
    fn harvest_refreshes_when_only_the_layout_changes() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        harvest(build.path(), store.path(), Some("102a33f0"), false)?;

        let parity = parity_key()?;
        let before = load_manifest(store.path(), &parity)?.expect("manifest");
        assert_eq!(before.units[0].layout(), fingerprint::UnitLayout::Classic);
        let stamp = before.units[0].stamp;

        // Same package/hash/memo/json — only the destinations move to the
        // new layout. The "unchanged" check must notice the new dests.
        fs::remove_dir_all(build.path().join("debug/.fingerprint"))?;
        let unit = synthetic_new_layout_unit(build.path(), "serde", "102a33f055a8d229")?;
        fs::write(
            unit.join("fingerprint/lib-serde.json"),
            r#"{"rustc":12019306335353385202,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[]}"#,
        )?;
        for file in [
            unit.join("fingerprint/lib-serde"),
            unit.join("fingerprint/lib-serde.json"),
            unit.join("fingerprint/dep-lib-serde"),
            unit.join("out/libserde-102a33f055a8d229.rlib"),
            unit.join("out/libserde-102a33f055a8d229.rmeta"),
        ] {
            set_stamp(&file, stamp)?;
        }

        let report = harvest_with(
            build.path(),
            store.path(),
            Some("102a33f0"),
            false,
            None,
            Some(fingerprint::UnitLayout::New),
            true,
        )?;
        assert_eq!(report.refreshed, 1, "{report:?}");
        assert_eq!(report.stored, 0);

        let after = load_manifest(store.path(), &parity)?.expect("manifest");
        assert_eq!(
            after.units[0].layout(),
            fingerprint::UnitLayout::New,
            "the recorded layout follows the dests"
        );
        assert!(
            after.units[0]
                .files
                .iter()
                .any(|file| file.dest.starts_with("build/serde/102a33f055a8d229/"))
        );
        Ok(())
    }

    #[test]
    fn restore_can_filter_units_by_layout() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        let view = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        synthetic_new_layout_unit(build.path(), "anyhow", "9709d57b46b8d526")?;

        harvest_with(
            build.path(),
            store.path(),
            None,
            false,
            None,
            Some(fingerprint::UnitLayout::Classic),
            true,
        )?;
        harvest_with(
            build.path(),
            store.path(),
            None,
            false,
            None,
            Some(fingerprint::UnitLayout::New),
            true,
        )?;

        let report = restore_with(
            view.path(),
            store.path(),
            None,
            None,
            Some(fingerprint::UnitLayout::New),
            None,
            false,
            LinkPolicy::Copy,
        )?;
        assert_eq!(report.errors, 0);
        assert!(
            view.path()
                .join("debug/build/anyhow/9709d57b46b8d526/fingerprint/lib-anyhow")
                .is_file()
        );
        assert!(
            !view
                .path()
                .join("debug/.fingerprint/serde-102a33f055a8d229")
                .exists(),
            "a classic unit is not restored into a new-layout child"
        );
        Ok(())
    }

    #[test]
    fn restore_without_a_generation_reports_fail_open() -> Result<()> {
        let view = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        let report = restore(view.path(), store.path(), None, None, false)?;
        assert!(report.note.is_some());
        assert_eq!(report.files_linked, 0);
        Ok(())
    }

    #[test]
    fn verify_passes_clean_and_flags_drift() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        harvest(build.path(), store.path(), None, false)?;

        let reports = verify(store.path())?;
        assert_eq!(reports.len(), 1);
        assert!(reports[0].is_clean(), "{:?}", reports[0].problems);
        assert_eq!(reports[0].units, 3);

        // Damage one stored file: size + stamp drift must surface.
        let parity = parity_key()?;
        let victim = units_dir(store.path(), &parity).join("serde-102a33f055a8d229/dep-lib-serde");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&victim, fs::Permissions::from_mode(0o644))?;
        }
        fs::write(&victim, [9u8; 32])?;

        let reports = verify(store.path())?;
        assert!(!reports[0].is_clean());
        assert!(
            reports[0]
                .problems
                .iter()
                .any(|line| line.contains("size drift")),
            "{:?}",
            reports[0].problems
        );
        Ok(())
    }

    #[test]
    fn verify_reports_unrecorded_unit_groups() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        harvest(build.path(), store.path(), None, false)?;

        let stray = units_dir(store.path(), &parity_key()?).join("stray-0000000000000000");
        fs::create_dir_all(stray.join("deps"))?;
        fs::write(stray.join("deps/x.rlib"), [0u8; 4])?;

        let reports = verify(store.path())?;
        assert!(
            reports[0]
                .problems
                .iter()
                .any(|line| line.contains("stray-0000000000000000")),
            "{:?}",
            reports[0].problems
        );
        assert!(!reports[0].is_clean());
        Ok(())
    }

    #[test]
    fn generations_summary_counts_store_files() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        harvest(build.path(), store.path(), None, false)?;

        let generations = generations(store.path())?;
        assert_eq!(generations.len(), 1);
        assert!(generations[0].active, "current toolchain generation");
        assert_eq!(generations[0].units, 3);
        assert!(generations[0].files >= 10);
        assert!(generations[0].linked <= generations[0].files);
        Ok(())
    }

    #[test]
    fn cached_diagnostics_are_stored_as_extra_and_verify_clean() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        // Cargo's message cache lives in the fingerprint dir, next to the memo.
        fs::write(
            build
                .path()
                .join("debug/.fingerprint/serde-102a33f055a8d229/output-lib-serde"),
            r#"{"$message_type":"diagnostic","message":"warning: unused"}"#,
        )?;

        harvest(build.path(), store.path(), Some("102a33f0"), false)?;
        let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
        let output = manifest.units[0]
            .files
            .iter()
            .find(|file| file.path == "output-lib-serde")
            .expect("cached diagnostics are stored");
        assert_eq!(output.role, "extra");

        let reports = verify(store.path())?;
        assert!(reports[0].is_clean(), "{:?}", reports[0].problems);
        Ok(())
    }

    #[test]
    fn harvest_refreshes_when_a_role_drifted() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        harvest(build.path(), store.path(), Some("102a33f0"), false)?;

        // A manifest from before roles were content-based: the memo is
        // recorded as something else.
        let parity = parity_key()?;
        let mut manifest = load_manifest(store.path(), &parity)?.expect("manifest");
        let memo_index = manifest.units[0]
            .files
            .iter()
            .position(|file| file.path == manifest.units[0].memo)
            .expect("memo recorded");
        manifest.units[0].files[memo_index].role = "extra".to_string();
        save_manifest(store.path(), &parity, &manifest)?;

        let report = harvest(build.path(), store.path(), Some("102a33f0"), false)?;
        assert_eq!(report.refreshed, 1, "role drift forces a refresh");
        let manifest = load_manifest(store.path(), &parity)?.expect("manifest");
        let role = &manifest.units[0].files[memo_index].role;
        assert_eq!(role, "memo", "roles are rewritten");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn restore_auto_links_local_archives_and_copies_proc_macros() -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        let view = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        fs::write(
            build.path().join("debug/deps/libserde-102a33f055a8d229.so"),
            [9u8; 32],
        )?;
        harvest(build.path(), store.path(), None, false)?;

        let report = restore(view.path(), store.path(), None, None, false)?;
        assert_eq!(report.errors, 0);
        let rlib = view
            .path()
            .join("debug/deps/libserde-102a33f055a8d229.rlib");
        let so = view.path().join("debug/deps/libserde-102a33f055a8d229.so");
        assert!(
            fs::metadata(&rlib)?.nlink() >= 2,
            "auto links a local private store's archive output"
        );
        assert_eq!(
            fs::metadata(&so)?.nlink(),
            1,
            "proc-macro .so stays a writable private copy"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn restore_link_policy_forces_shared_inodes() -> Result<()> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        let view = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        fs::write(
            build.path().join("debug/deps/libserde-102a33f055a8d229.so"),
            [9u8; 32],
        )?;
        harvest(build.path(), store.path(), None, false)?;
        // Even a shared store is linked when the operator forces `link`.
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o777))?;

        let report = restore_policy(view.path(), store.path(), None, false, LinkPolicy::Link)?;
        assert_eq!(report.errors, 0);
        let rlib = view
            .path()
            .join("debug/deps/libserde-102a33f055a8d229.rlib");
        let so = view.path().join("debug/deps/libserde-102a33f055a8d229.so");
        assert_eq!(fs::metadata(&rlib)?.nlink(), 2, "rlib is linked");
        assert_eq!(fs::metadata(&so)?.nlink(), 2, "so is linked");
        Ok(())
    }

    #[test]
    fn restore_copy_policy_never_links() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        harvest(build.path(), store.path(), Some("102a33f0"), false)?;

        let view = tempfile::tempdir()?;
        restore_policy(
            view.path(),
            store.path(),
            Some("102a33f0"),
            false,
            LinkPolicy::Copy,
        )?;

        let state = view
            .path()
            .join("debug/.fingerprint/serde-102a33f055a8d229/lib-serde");
        let artifact = view
            .path()
            .join("debug/deps/libserde-102a33f055a8d229.rlib");
        let metadata = view
            .path()
            .join("debug/deps/libserde-102a33f055a8d229.rmeta");
        assert!(state.is_file() && artifact.is_file() && metadata.is_file());

        let parity = parity_key()?;
        let manifest = load_manifest(store.path(), &parity)?.expect("manifest");
        let entry = manifest
            .units
            .iter()
            .find(|entry| entry.name == "serde-102a33f055a8d229")
            .expect("stored unit");
        assert_eq!(ceil_secs(fs::metadata(&state)?.modified()?), entry.stamp);

        // Rewriting restored state must not reach the store (the exact
        // failure cargo hits when it stores a rebuilt fingerprint).
        fs::write(&state, "ffffffffffffffff")?;
        let stored = units_dir(store.path(), &parity)
            .join("serde-102a33f055a8d229")
            .join("lib-serde");
        assert_eq!(fs::read_to_string(&stored)?, "5d82713a7f2d05e2");

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                fs::metadata(&artifact)?.nlink(),
                1,
                "a writable store must not share its inode with the view"
            );
            assert_eq!(fs::metadata(&state)?.nlink(), 1, "state is a private copy");
            assert_eq!(
                fs::metadata(&metadata)?.nlink(),
                1,
                ".rmeta is a private copy (rustc opens it for write)"
            );
        }
        Ok(())
    }

    /// Two units with a resolved dependency edge: `serde` → `serde_core`.
    /// `dep_at`/`unit_at` are the stamps the files carry, so harvest stores
    /// exactly that ordering.
    /// A minimal new-layout unit: `debug/build/<pkg>/<hash>/{fingerprint,out}`.
    fn synthetic_new_layout_unit(root: &Path, package: &str, hash: &str) -> Result<PathBuf> {
        let unit = root.join("debug/build").join(package).join(hash);
        fs::create_dir_all(unit.join("fingerprint"))?;
        fs::create_dir_all(unit.join("out"))?;
        fs::write(
            unit.join("fingerprint").join(format!("lib-{package}")),
            "5d82713a7f2d05e2",
        )?;
        fs::write(
            unit.join("fingerprint").join(format!("dep-lib-{package}")),
            [0u8; 8],
        )?;
        fs::write(
            unit.join("fingerprint").join(format!("lib-{package}.json")),
            r#"{"rustc":12019306335353385202,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[]}"#,
        )?;
        fs::write(
            unit.join("out").join(format!("lib{package}-{hash}.rlib")),
            [7u8; 64],
        )?;
        fs::write(
            unit.join("out").join(format!("lib{package}-{hash}.rmeta")),
            [6u8; 48],
        )?;
        Ok(unit)
    }

    fn synthetic_edge_dir(root: &Path, dep_at: u64, unit_at: u64) -> Result<()> {
        fs::create_dir_all(root.join("debug/deps"))?;
        let core = root.join("debug/.fingerprint/serde_core-b468be6fa8c1f936");
        fs::create_dir_all(&core)?;
        fs::write(core.join("lib-serde_core"), "71a9f323efa5ae82")?;
        fs::write(
            core.join("lib-serde_core.json"),
            r#"{"rustc":5244445300240561903,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[]}"#,
        )?;
        fs::write(core.join("dep-lib-serde_core"), [0u8; 8])?;
        let core_rlib = root.join("debug/deps/libserde_core-b468be6fa8c1f936.rlib");
        fs::write(&core_rlib, [1u8; 32])?;

        let unit = root.join("debug/.fingerprint/serde-746d173581f1a314");
        fs::create_dir_all(&unit)?;
        fs::write(unit.join("lib-serde"), "5d82713a7f2d05e2")?;
        fs::write(
            unit.join("lib-serde.json"),
            r#"{"rustc":5244445300240561903,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[[11029742160753049355,"serde_core",false,9416646317397223793]]}"#,
        )?;
        fs::write(unit.join("dep-lib-serde"), [0u8; 8])?;
        let unit_rlib = root.join("debug/deps/libserde-746d173581f1a314.rlib");
        fs::write(&unit_rlib, [1u8; 32])?;

        set_stamp(&core.join("lib-serde_core"), dep_at)?;
        set_stamp(&core.join("dep-lib-serde_core"), dep_at)?;
        set_stamp(&core_rlib, dep_at)?;
        set_stamp(&unit.join("lib-serde"), unit_at)?;
        set_stamp(&unit.join("lib-serde.json"), unit_at)?;
        set_stamp(&unit.join("dep-lib-serde"), unit_at)?;
        set_stamp(&unit_rlib, unit_at)?;
        Ok(())
    }

    #[test]
    fn harvest_clamps_a_dependent_to_its_dependency() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        let now = now_secs();
        // The view itself is inverted (a fragmented cache: the dependency was
        // rebuilt after its dependent) — harvest must clamp the dependent up.
        synthetic_edge_dir(build.path(), now, now - 3600)?;
        harvest(build.path(), store.path(), None, false)?;

        let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
        let dependent = manifest
            .units
            .iter()
            .find(|entry| entry.name == "serde-746d173581f1a314")
            .expect("dependent stored");
        let dependency = manifest
            .units
            .iter()
            .find(|entry| entry.name == "serde_core-b468be6fa8c1f936")
            .expect("dependency stored");
        assert!(
            dependent.stamp >= dependency.stamp,
            "clamped: {} >= {}",
            dependent.stamp,
            dependency.stamp
        );

        let reports = verify(store.path())?;
        assert!(reports[0].is_clean(), "{:?}", reports[0].problems);
        assert!(reports[0].ordering.is_empty(), "{:?}", reports[0].ordering);
        Ok(())
    }

    #[test]
    fn harvest_stamps_groups_by_the_metadata_output() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        let now = now_secs();
        // Rustc writes `.rmeta` first and `.rlib` last: the consumable
        // moment — and therefore the stamp — is the metadata.
        set_stamp(
            &build
                .path()
                .join("debug/deps/libserde-102a33f055a8d229.rmeta"),
            now - 30,
        )?;
        set_stamp(
            &build
                .path()
                .join("debug/deps/libserde-102a33f055a8d229.rlib"),
            now,
        )?;
        harvest(build.path(), store.path(), Some("102a33f0"), false)?;

        let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
        assert_eq!(manifest.units[0].stamp, now - 30);
        Ok(())
    }

    #[test]
    fn harvest_stores_read_only_sources() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        // Wrappers (kache) and backup tools leave read-only files in the build
        // dir; `fs::copy` carries that attribute along, and stamping the copy
        // must not depend on the source's permissions (Windows: access denied).
        let source = build
            .path()
            .join("debug/.fingerprint/serde-102a33f055a8d229/dep-lib-serde");
        let mut perms = fs::metadata(&source)?.permissions();
        perms.set_readonly(true);
        fs::set_permissions(&source, perms)?;

        let report = harvest(build.path(), store.path(), Some("102a33f0"), false)?;
        assert_eq!(report.stored, 1);

        let parity = parity_key()?;
        let manifest = load_manifest(store.path(), &parity)?.expect("manifest");
        let stored = units_dir(store.path(), &parity)
            .join(&manifest.units[0].name)
            .join("dep-lib-serde");
        assert!(stored.is_file(), "the state file is stored");
        assert_eq!(
            ceil_secs(fs::metadata(&stored)?.modified()?),
            manifest.units[0].stamp,
            "the stored copy carries the canonical stamp"
        );
        Ok(())
    }

    /// Windows-only regression: `File::open` yields a GENERIC_READ handle and
    /// `SetFileTime` requires FILE_WRITE_ATTRIBUTES, so stamping failed with
    /// "Accesso negato" (os error 5) even when the copy itself was writable.
    #[cfg(windows)]
    #[test]
    fn set_stamp_sets_times_on_windows() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("dep-lib-x");
        fs::write(&file, b"x")?;

        set_stamp(&file, 1_700_000_000)?;
        assert_eq!(
            ceil_secs(fs::metadata(&file)?.modified()?),
            1_700_000_000,
            "a writable copy must be stampable"
        );

        // A copy that inherited a read-only source must be writable before
        // it can be stamped.
        let mut perms = fs::metadata(&file)?.permissions();
        perms.set_readonly(true);
        fs::set_permissions(&file, perms)?;
        let mut perms = fs::metadata(&file)?.permissions();
        perms.set_readonly(false);
        fs::set_permissions(&file, perms)?;
        set_stamp(&file, 1_700_000_100)?;
        assert_eq!(
            ceil_secs(fs::metadata(&file)?.modified()?),
            1_700_000_100,
            "a copy of a read-only source must be stampable"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_store_drops_its_staging_dir() -> Result<()> {
        use std::os::unix::fs::MetadataExt;

        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        if fs::metadata(build.path())?.uid() == 0 {
            return Ok(()); // root reads a 000 file anyway — nothing to inject
        }
        let artifact = build
            .path()
            .join("debug/deps/libserde-102a33f055a8d229.rlib");
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&artifact, fs::Permissions::from_mode(0o000))?;
        }

        let result = harvest(build.path(), store.path(), Some("102a33f0"), false);
        assert!(result.is_err(), "an unreadable artifact aborts the store");

        let units = units_dir(store.path(), &parity_key()?);
        if units.is_dir() {
            for entry in fs::read_dir(&units)? {
                let name = entry?.file_name().to_string_lossy().into_owned();
                assert!(!name.contains(".tmp-"), "staging leftover: {name}");
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn harvest_sweeps_stale_staging_dirs() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        let units = units_dir(store.path(), &parity_key()?);

        // A crashed store run from yesterday: dot-dir, read-only leftovers.
        let stale = units.join(".serde-102a33f055a8d229.tmp-99999");
        fs::create_dir_all(&stale)?;
        let leftover = stale.join("dep-lib-serde");
        fs::write(&leftover, b"x")?;
        fs::set_permissions(&leftover, fs::Permissions::from_mode(0o444))?;
        let dir = fs::File::open(&stale)?;
        dir.set_modified(UNIX_EPOCH + Duration::from_secs(now_secs() - 7200))?;

        // A concurrent harvest's staging dir must survive the sweep.
        let fresh = units.join(".serde-102a33f055a8d229.tmp-11111");
        fs::create_dir_all(&fresh)?;

        harvest(build.path(), store.path(), Some("102a33f0"), false)?;
        assert!(!stale.exists(), "stale staging dir swept");
        assert!(fresh.exists(), "fresh staging dir left alone");
        Ok(())
    }

    #[test]
    fn verify_flags_an_inverted_store_stamp() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        let now = now_secs();
        synthetic_edge_dir(build.path(), now - 3600, now)?;
        harvest(build.path(), store.path(), None, false)?;

        // Simulate a store written before the clamp existed: re-stamp the
        // dependent (files and manifest) older than its dependency.
        let parity = parity_key()?;
        let mut manifest = load_manifest(store.path(), &parity)?.expect("manifest");
        let units = units_dir(store.path(), &parity);
        let entry = manifest
            .units
            .iter_mut()
            .find(|entry| entry.name == "serde-746d173581f1a314")
            .expect("dependent stored");
        entry.stamp = now - 7200;
        for file in &entry.files {
            set_stamp(&units.join(&entry.name).join(&file.path), now - 7200)?;
        }
        save_manifest(store.path(), &parity, &manifest)?;

        let reports = verify(store.path())?;
        assert!(reports[0].is_clean(), "{:?}", reports[0].problems);
        assert_eq!(reports[0].ordering.len(), 1, "{:?}", reports[0].ordering);
        assert!(reports[0].ordering[0].contains("serde-746d173581f1a314"));
        assert!(reports[0].ordering[0].contains("serde_core-b468be6fa8c1f936"));
        Ok(())
    }

    #[test]
    fn manifest_validation_rejects_escapes() {
        let unit = |name: &str, profile: &str, path: &str, dest: &str| UnitEntry {
            name: name.into(),
            profile: profile.into(),
            memo: "lib-x".into(),
            hash: "0123456789abcdef".into(),
            stamp: 1,
            layout: None,
            files: vec![FileEntry {
                path: path.into(),
                dest: dest.into(),
                size: 1,
                sha256: String::new(),
                role: "artifact".into(),
                object: None,
            }],
        };
        let base = Manifest {
            parity_key: "p".into(),
            toolchain: "t".into(),
            created: 1,
            updated: 1,
            units: vec![],
            mac: String::new(),
            signature: String::new(),
        };
        for unit in [
            unit("../escape", "debug", "deps/x", "deps/x"),
            unit("ok", "/etc", "deps/x", "deps/x"),
            unit("ok", "debug", "/etc/passwd", "deps/x"),
            unit("ok", "debug", "deps/x", "/root/.ssh/authorized_keys"),
            unit("ok", "debug", "deps/../../x", "deps/x"),
            unit(".. ", "debug", "deps/x", "deps/x"),
            unit("...", "debug", "deps/x", "deps/x"),
            unit("CON.txt", "debug", "deps/x", "deps/x"),
        ] {
            let manifest = Manifest {
                units: vec![unit],
                ..base.clone()
            };
            assert!(manifest.validate().is_err(), "must reject {manifest:?}");
        }
    }

    #[test]
    fn harvest_records_sha256_and_verify_flags_content_drift() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        harvest(build.path(), store.path(), None, false)?;

        let parity = parity_key()?;
        let manifest = load_manifest(store.path(), &parity)?.expect("manifest");
        assert!(
            manifest
                .units
                .iter()
                .flat_map(|unit| &unit.files)
                .all(|file| !file.sha256.is_empty()),
            "every stored file must carry a hash"
        );

        let entry = manifest
            .units
            .iter()
            .find(|entry| entry.name == "serde-102a33f055a8d229")
            .expect("unit");
        let file = entry
            .files
            .iter()
            .find(|file| file.path == "deps/libserde-102a33f055a8d229.rlib")
            .expect("rlib");
        let path = units_dir(store.path(), &parity)
            .join(&entry.name)
            .join(&file.path);
        let mut bytes = fs::read(&path)?;
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01; // same size, different content
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        }
        fs::write(&path, &bytes)?;
        let stamp = UNIX_EPOCH + Duration::from_secs(entry.stamp);
        fs::OpenOptions::new()
            .write(true)
            .open(&path)?
            .set_modified(stamp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o444))?;
        }

        let reports = verify(store.path())?;
        assert!(
            reports[0]
                .problems
                .iter()
                .any(|problem| problem.contains("content drift")),
            "{:?}",
            reports[0].problems
        );

        let view = tempfile::tempdir()?;
        let report = restore(view.path(), store.path(), None, None, false)?;
        assert!(report.errors > 0, "tampered artifact must not install");
        assert!(
            !view.path().join(&file.dest).exists(),
            "tampered artifact must be absent from the view"
        );
        Ok(())
    }

    #[test]
    fn concurrent_harvest_keeps_every_unit() -> Result<()> {
        let store = tempfile::tempdir()?;
        let mut builds = Vec::new();
        for index in 0..6u32 {
            let build = tempfile::tempdir()?;
            let hex = format!("{:016x}", index + 1);
            let unit = build
                .path()
                .join("debug/.fingerprint")
                .join(format!("u{index}-{hex}"));
            fs::create_dir_all(&unit)?;
            fs::write(unit.join(format!("lib-u{index}")), "0123456789abcdef")?;
            fs::write(
                unit.join(format!("lib-u{index}.json")),
                r#"{"rustc":1,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[]}"#,
            )?;
            fs::write(unit.join(format!("dep-lib-u{index}")), [0u8; 8])?;
            fs::create_dir_all(build.path().join("debug/deps"))?;
            fs::write(
                build
                    .path()
                    .join("debug/deps")
                    .join(format!("libu{index}-{hex}.rlib")),
                [index as u8; 8],
            )?;
            builds.push(build);
        }
        std::thread::scope(|scope| {
            for build in &builds {
                scope.spawn(|| harvest(build.path(), store.path(), None, false));
            }
        });
        let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
        assert_eq!(manifest.units.len(), builds.len(), "{:?}", manifest.units);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn store_directories_are_private() -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        harvest(build.path(), store.path(), None, false)?;
        assert_eq!(
            fs::metadata(store.path())?.mode() & 0o077,
            0,
            "store root 0700"
        );
        let generation = store.path().join(parity_key()?);
        assert_eq!(
            fs::metadata(&generation)?.mode() & 0o077,
            0,
            "generation 0700"
        );
        Ok(())
    }

    #[test]
    fn manifest_has_an_ed25519_signature_and_readable_public_key() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        harvest(build.path(), store.path(), None, false)?;
        let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
        assert_eq!(manifest.signature.len(), 128);
        assert_eq!(manifest.mac.len(), 64);
        let pubkey = fs::read_to_string(store.path().join(PUBKEY_FILE))?;
        assert_eq!(pubkey.trim().len(), 64);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(store.path().join(PUBKEY_FILE))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o644
            );
        }
        Ok(())
    }

    #[test]
    fn manifest_signature_rejects_tampering() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        harvest(build.path(), store.path(), None, false)?;
        let parity = parity_key()?;
        let path = manifest_path(store.path(), &parity);
        let mut value: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path)?)?;
        value["toolchain"] = serde_json::Value::String("rustc forged".into());
        fs::write(&path, serde_json::to_string_pretty(&value)?)?;
        let err = load_manifest(store.path(), &parity).unwrap_err();
        assert!(format!("{err:#}").contains("signature check"), "{err:#}");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn harvest_rejects_a_symlinked_build_root() -> Result<()> {
        let victim = tempfile::tempdir()?;
        synthetic_build_dir(victim.path())?;
        let home = tempfile::tempdir()?;
        let build = home.path().join("build");
        std::os::unix::fs::symlink(victim.path(), &build)?;
        let store = tempfile::tempdir()?;
        let err = harvest(&build, store.path(), None, false).unwrap_err();
        assert!(format!("{err:#}").contains("symlink/reparse"), "{err:#}");
        Ok(())
    }

    #[test]
    fn verify_ordering_is_quiet_when_units_are_current() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        let now = now_secs();
        synthetic_edge_dir(build.path(), now - 3600, now)?;
        harvest(build.path(), store.path(), None, false)?;

        let reports = verify(store.path())?;
        assert!(reports[0].is_clean(), "{:?}", reports[0].problems);
        assert!(reports[0].ordering.is_empty(), "{:?}", reports[0].ordering);
        Ok(())
    }
}
