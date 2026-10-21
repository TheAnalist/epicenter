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
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::util::{self, FileLock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::fingerprint::{self, ArtifactInfo, Unit};

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

/// Parse `rustc -vV` (first line + `host:`).
pub fn toolchain() -> Result<Toolchain> {
    let mut command = util::command_for("rustc")?;
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
    let mut command = util::command_for("rustc").ok()?;
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
    let tc = toolchain()?;
    let key = format!(
        "{}-{}-{}-{}",
        tc.release,
        tc.commit,
        tc.host,
        flags_digest()
    );
    // The key becomes a directory name: never allow traversal via a fake
    // `rustc -vV` on PATH (e.g. release `../../x`).
    util::validate_component(&key, "parity key")?;
    Ok(key)
}

/// Digest of the flags that live outside the fingerprint: the flag
/// environment plus the flag-relevant keys of Cargo's global config.
fn flags_digest() -> String {
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
    build_root.parent().unwrap_or(build_root).join("store")
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

fn ensure_store_root(store_root: &Path) -> Result<()> {
    util::ensure_windows_user_path(store_root, "store")?;
    match fs::symlink_metadata(store_root) {
        Ok(meta) => {
            if !meta.is_dir() || meta.file_type().is_symlink() {
                anyhow::bail!(
                    "store root {} is not a real directory",
                    store_root.display()
                );
            }
            util::ensure_private_dir(store_root)?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            util::create_private_dir_all(store_root)?;
        }
        Err(err) => {
            return Err(err).with_context(|| format!("inspecting {}", store_root.display()));
        }
    }
    Ok(())
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
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mac: String,
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
    pub files: Vec<FileEntry>,
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
}

impl Manifest {
    /// Reject every path that could escape the store or the view. This runs
    /// before any consumer (restore/verify/evict) touches a manifest path.
    pub fn validate(&self) -> Result<()> {
        for unit in &self.units {
            util::validate_component(&unit.name, "unit name")?;
            util::validate_component(&unit.profile, "profile")?;
            util::validate_component(&unit.memo, "memo file")?;
            if !unit.hash.is_empty() && !fingerprint::looks_like_hash(&unit.hash) {
                anyhow::bail!("invalid memo hash {:?} in unit {}", unit.hash, unit.name);
            }
            for file in &unit.files {
                util::validate_rel(&file.path, "stored file path")?;
                util::validate_rel(&file.dest, "destination path")?;
                if !file.sha256.is_empty()
                    && (file.sha256.len() != 64
                        || !file.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()))
                {
                    anyhow::bail!("invalid SHA-256 for {} in unit {}", file.path, unit.name);
                }
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

fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
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
    if !util::owned_by_us(&meta) {
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

fn manifest_key() -> Result<Vec<u8>> {
    let path = manifest_key_path()?;
    if let Ok(key) = read_key_file(&path) {
        return Ok(key);
    }
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent", path.display()))?;
    util::create_private_dir_all(parent)?;
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|err| anyhow::anyhow!("generating vault key: {err}"))?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(&path) {
        Ok(mut file) => {
            file.write_all(&key)?;
            file.sync_all()?;
            Ok(key.to_vec())
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => read_key_file(&path),
        Err(err) => Err(err).with_context(|| format!("creating vault key {}", path.display())),
    }
}

fn manifest_mac(manifest: &Manifest) -> Result<String> {
    let mut unsigned = manifest.clone();
    unsigned.mac.clear();
    let body = serde_json::to_vec(&unsigned)?;
    Ok(hex32(&hmac_sha256(&manifest_key()?, &body)))
}

fn load_manifest(store_root: &Path, parity: &str) -> Result<Option<Manifest>> {
    let path = manifest_path(store_root, parity);
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("inspecting {}", path.display()));
        }
    };
    // The manifest is the list of files that will be executed/linked. Never
    // parse one that is a symlink, foreign-owned, or group/world-writable.
    if !meta.is_file() || meta.file_type().is_symlink() || util::is_reparse_point(&meta) {
        anyhow::bail!("{} is not a regular manifest file", path.display());
    }
    if !util::owned_by_us(&meta) {
        anyhow::bail!("{} is owned by another user", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o022 != 0 {
            anyhow::bail!(
                "{} is group/world-writable (mode {:o})",
                path.display(),
                meta.mode() & 0o777
            );
        }
    }
    let text = crate::util::read_trusted_config(&path, 16 * 1024 * 1024)
        .with_context(|| format!("reading {}", path.display()))?;
    let manifest: Manifest =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
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
    manifest
        .validate()
        .with_context(|| format!("validating {}", path.display()))?;
    Ok(Some(manifest))
}

pub(crate) fn save_manifest(store_root: &Path, parity: &str, manifest: &Manifest) -> Result<()> {
    util::validate_component(parity, "generation")?;
    let dir = store_root.join(parity);
    util::create_private_dir_all(&dir)?;
    let mut signed = manifest.clone();
    signed.mac.clear();
    signed.mac = manifest_mac(&signed)?;
    let what = serde_json::to_string_pretty(&signed)?;
    // O_EXCL + a symlink-free path: never write through a planted temp link.
    let mut tmp = None;
    for attempt in 0..100u32 {
        let candidate = dir.join(format!(
            "manifest.json.tmp-{}-{attempt}",
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
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with('.') {
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
    let dir_meta = fs::symlink_metadata(&unit.dir).ok()?;
    if !dir_meta.is_dir() || dir_meta.file_type().is_symlink() || util::is_reparse_point(&dir_meta)
    {
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
    let _lock = FileLock::acquire(&store_lock_path(store_root, generation))?;
    let Some(mut manifest) = load_manifest(store_root, generation)? else {
        return Ok(0);
    };
    let units = units_dir(store_root, generation);
    match fs::symlink_metadata(&units) {
        Ok(meta)
            if meta.is_dir()
                && !meta.file_type().is_symlink()
                && !util::is_reparse_point(&meta) => {}
        Ok(_) => {
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
        match fs::symlink_metadata(&dir) {
            Ok(meta) if meta.file_type().is_symlink() || util::is_reparse_point(&meta) => {
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
    if manifest.units.is_empty() {
        let _ = fs::remove_dir_all(store_root.join(generation));
    } else if dropped > 0 {
        manifest.updated = now_secs();
        save_manifest(store_root, generation, &manifest)?;
    }
    Ok(dropped)
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
    let tc = toolchain()?;
    let parity = parity_key()?;
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
        util::create_private_dir_all(&units_dir(store_root, &parity))?;
        let lock = FileLock::acquire(&store_lock_path(store_root, &parity))?;
        // Self-heal debris from a crashed or failed store run (dot-dirs whose
        // copies may have inherited read-only sources) before planning.
        sweep_staging(&units_dir(store_root, &parity));
        Some(lock)
    };

    let rows: Vec<(Unit, ArtifactInfo)> = fingerprint::read_units(build_root)?
        .into_iter()
        .map(|unit| {
            let arts = fingerprint::artifacts_for(build_root, &unit);
            (unit, arts)
        })
        .collect();

    // Freshness gate for the whole cache: nothing built since the toolchain
    // was installed means the cache belongs to an older generation.
    let newest_activity = rows.iter().filter_map(|(_, arts)| arts.newest).max();
    if let (Some(newest), Some(installed)) = (newest_activity, toolchain_install_time()) {
        if newest < installed {
            report.note = Some(format!(
                "the shared cache predates the installed toolchain ({}) — build once, then harvest",
                tc.version_line()
            ));
            return Ok(report);
        }
    }

    // Active generation = the rustc cohort of the most recently built unit
    // that carries a fingerprint JSON. Units without one can't be placed and
    // are harvested as-is (fail-open) rather than mislabeled.
    let active_gen = rows
        .iter()
        .filter(|(unit, _)| crate::who::rustc_of(unit) != "unknown")
        .max_by_key(|(_, arts)| arts.newest)
        .map(|(unit, _)| crate::who::rustc_of(unit))
        .unwrap_or_else(|| "unknown".into());

    let mut manifest = load_manifest(store_root, &parity)?.unwrap_or_else(|| Manifest {
        parity_key: parity.clone(),
        toolchain: tc.version_line(),
        created: now_secs(),
        updated: 0,
        units: Vec::new(),
        mac: String::new(),
    });

    // ── pass 1: collect the groups to store and their base stamps ──────────
    struct GroupPlan {
        unit: Unit,
        files: Vec<(PathBuf, String, String, String)>,
        memo: String,
        hash: String,
        base: u64,
    }
    let mut plans: Vec<GroupPlan> = Vec::new();

    for (unit, arts) in &rows {
        if let Some(query) = unit_filter {
            if !unit_name_matches(&unit.dir_name, query) {
                continue;
            }
        }
        let cohort = crate::who::rustc_of(unit);
        if cohort != "unknown" && active_gen != "unknown" && cohort != active_gen {
            report.skipped_stale += 1;
            continue;
        }

        let unit_dir = build_root
            .join(&unit.profile)
            .join(".fingerprint")
            .join(&unit.dir_name);
        let profile_dir = build_root.join(&unit.profile);
        let memo = unit.memo_file.clone();
        let mut files: Vec<(PathBuf, String, String, String)> = Vec::new();
        // (source, store path, destination relative to the profile dir, role)

        // The whole fingerprint dir except the volatile timestamp: hash
        // files, their serialized fingerprints, and dep-info. Shared dirs
        // (several memo files) are stored completely, so every mode of the
        // unit stays recognizable to Cargo.
        for entry in
            fs::read_dir(&unit_dir).with_context(|| format!("reading {}", unit_dir.display()))?
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
            } else if fs::read_to_string(entry.path())
                .map(|text| crate::fingerprint::looks_like_hash(text.trim()))
                .unwrap_or(false)
            {
                "memo"
            } else {
                // Cached diagnostics (`output-*`) and other cargo state.
                "extra"
            };
            files.push((
                entry.path(),
                name.clone(),
                format!(".fingerprint/{}/{name}", unit.dir_name),
                role.into(),
            ));
        }

        // Artifacts: `deps/…` and the `build/<anchor>/…` tree of build
        // scripts. Wrapper internals and rustc's `.d` side files stay out.
        let mut artifact_count = 0;
        for (path, _, _) in &arts.paths {
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
            if rel.starts_with("deps/") && rel.ends_with(".d") {
                continue;
            }
            let role = if rel.starts_with("build/") {
                "build-tree"
            } else {
                "artifact"
            };
            files.push((path.clone(), rel.clone(), rel, role.into()));
            artifact_count += 1;
        }
        if artifact_count == 0 {
            report.skipped_incomplete += 1;
            continue;
        }

        plans.push(GroupPlan {
            base: group_stamp(&files)?,
            memo,
            hash: unit.memo_hash.clone().unwrap_or_default(),
            files,
            unit: unit.clone(),
        });
    }

    // ── pass 2: enforce `T(unit) ≥ every dependency's T` (§11) ─────────────
    //
    // Base stamps restore the natural order inside one build view; a store
    // fed from several views can still invert edges (a dependency harvested
    // later than its dependent — e.g. a fragmented multi-project cache).
    // Resolve the edges (a dependency's memo hash → the unit that owns it)
    // and raise dependents until nothing is older than what it consumed.
    // `verify`'s ordering audit stays the guard for anything left over.
    let stored_stamps: std::collections::HashMap<String, u64> = manifest
        .units
        .iter()
        .map(|entry| (entry.hash.clone(), entry.stamp))
        .collect();
    let index: std::collections::HashMap<&str, usize> = plans
        .iter()
        .enumerate()
        .map(|(position, plan)| (plan.hash.as_str(), position))
        .collect();
    let mut plan_deps: Vec<Vec<usize>> = Vec::with_capacity(plans.len());
    let mut stamps: Vec<u64> = Vec::with_capacity(plans.len());
    for plan in &plans {
        let mut deps = Vec::new();
        let mut stamp = plan.base;
        for dep in plan
            .unit
            .json
            .as_ref()
            .map(|json| json.deps.as_slice())
            .unwrap_or(&[])
        {
            let Some(hash) = dep.memo_hash() else {
                continue;
            };
            if let Some(&at) = index.get(hash.as_str()) {
                deps.push(at);
            } else if let Some(known) = stored_stamps.get(hash.as_str()) {
                stamp = stamp.max(*known);
            }
        }
        plan_deps.push(deps);
        stamps.push(stamp);
    }
    // Dependencies before dependents; a cycle (never observed) keeps its base
    // order and the ordering audit reports whatever is left.
    let mut order: Vec<usize> = Vec::with_capacity(plans.len());
    let mut settled = vec![false; plans.len()];
    loop {
        let mut progressed = false;
        for at in 0..plans.len() {
            if settled[at] || !plan_deps[at].iter().all(|&dep| settled[dep]) {
                continue;
            }
            settled[at] = true;
            order.push(at);
            progressed = true;
        }
        if !progressed {
            break;
        }
    }
    for at in 0..plans.len() {
        if !settled[at] {
            order.push(at);
        }
    }
    for &at in &order {
        for dep in &plan_deps[at] {
            stamps[at] = stamps[at].max(stamps[*dep]);
        }
    }

    // ── pass 3: store (or refresh) one group at a time ─────────────────────
    for (at, plan) in plans.iter().enumerate() {
        let unit = &plan.unit;
        let files = &plan.files;
        let stamp = stamps[at];
        let group_dir = units_dir(store_root, &parity).join(&unit.dir_name);

        // Unchanged = same hash, profile and stamp, same (path, role) file
        // set, all present. Anything else is refreshed as a whole group.
        let mut new_entries: Vec<(&str, &str)> = files
            .iter()
            .map(|(_, path, _, role)| (path.as_str(), role.as_str()))
            .collect();
        new_entries.sort_unstable();
        let already = manifest
            .units
            .iter()
            .find(|entry| entry.name == unit.dir_name)
            .map(|entry| {
                let mut stored: Vec<(&str, &str)> = entry
                    .files
                    .iter()
                    .map(|file| (file.path.as_str(), file.role.as_str()))
                    .collect();
                stored.sort_unstable();
                entry.hash == plan.hash
                    && entry.profile == unit.profile
                    && entry.stamp == stamp
                    && stored == new_entries
                    && entry
                        .files
                        .iter()
                        .all(|file| !file.sha256.is_empty() && group_dir.join(&file.path).is_file())
            })
            .unwrap_or(false);
        if already {
            report.unchanged += 1;
            continue;
        }

        let bytes: u64 = files
            .iter()
            .filter_map(|(src, _, _, _)| fs::metadata(src).ok())
            .map(|meta| meta.len())
            .sum();
        if dry_run {
            report.stored += 1;
            report.files += files.len();
            report.bytes += bytes;
            continue;
        }

        let mut entries = Vec::with_capacity(files.len());
        store_group(
            store_root,
            &parity,
            &unit.dir_name,
            stamp,
            files,
            &mut entries,
        )
        .with_context(|| format!("storing unit {}", unit.dir_name))?;

        let entry = UnitEntry {
            name: unit.dir_name.clone(),
            profile: unit.profile.clone(),
            memo: plan.memo.clone(),
            hash: plan.hash.clone(),
            stamp,
            files: entries,
        };
        match manifest
            .units
            .iter_mut()
            .find(|existing| existing.name == entry.name)
        {
            Some(slot) => {
                *slot = entry;
                report.refreshed += 1;
            }
            None => {
                manifest.units.push(entry);
                report.stored += 1;
            }
        }
        report.files += files.len();
        report.bytes += bytes;
    }

    if !dry_run {
        manifest.units.sort_by(|a, b| {
            (a.profile.as_str(), a.name.as_str()).cmp(&(b.profile.as_str(), b.name.as_str()))
        });
        manifest.updated = now_secs();
        save_manifest(store_root, &parity, &manifest)?;
    }
    Ok(report)
}

/// Copy one unit group into its final place: a temporary directory next to
/// the target, stamped read-only files, then a swap that never leaves the
/// group half-written under its real name.
fn store_group(
    store_root: &Path,
    parity: &str,
    name: &str,
    stamp: u64,
    files: &[(PathBuf, String, String, String)],
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

    if let Err(err) = stage_group(&tmp, files, stamp, entries) {
        // Never leave a half-written staging dir behind: it would keep a
        // failed unit's bytes on disk and hide the failure from the next run.
        let _ = crate::util::force_remove_dir(&tmp);
        return Err(err);
    }

    let old = units.join(format!(".{name}.old-{}-{}", std::process::id(), now_secs()));
    match fs::symlink_metadata(&final_dir) {
        Ok(meta) if meta.file_type().is_symlink() || util::is_reparse_point(&meta) => {
            let _ = crate::util::force_remove_dir(&tmp);
            anyhow::bail!(
                "refusing symlinked/reparse store unit {}",
                final_dir.display()
            );
        }
        Ok(meta) if meta.is_dir() => fs::rename(&final_dir, &old)?,
        Ok(_) => {
            let _ = crate::util::force_remove_dir(&tmp);
            anyhow::bail!("store unit path {} is not a directory", final_dir.display());
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).context("inspecting store unit"),
    }
    fs::rename(&tmp, &final_dir)?;
    if fs::symlink_metadata(&old)
        .map(|meta| {
            meta.is_dir() && !meta.file_type().is_symlink() && !util::is_reparse_point(&meta)
        })
        .unwrap_or(false)
    {
        let _ = fs::remove_dir_all(&old);
    }
    Ok(())
}

/// Copy one unit group's files into its staging dir. Every file is made
/// writable before it is stamped and read-only again (on Unix) once the group
/// is in place.
///
/// `fs::copy` carries the source's attributes along. A read-only source — a
/// wrapper's hard-linked store file, a file restored from a backup — makes
/// `File::set_modified` fail with "access denied" on Windows even though the
/// copy lives in our own staging dir.
fn stage_group(
    tmp: &Path,
    files: &[(PathBuf, String, String, String)],
    stamp: u64,
    entries: &mut Vec<FileEntry>,
) -> Result<()> {
    for (src, path, dest, role) in files {
        let rel = util::validate_rel(path, "stored file path")?;
        let dst = tmp.join(&rel);
        if let Some(parent) = dst.parent() {
            util::create_private_dir_all(parent)?;
        }
        let (size, sha256) = util::copy_file_hashed(src, &dst)
            .with_context(|| format!("copying {} -> {}", src.display(), dst.display()))?;
        make_writable(&dst).with_context(|| format!("making {} writable", dst.display()))?;
        set_stamp(&dst, stamp)?;
        make_read_only(&dst)?;
        entries.push(FileEntry {
            path: path.clone(),
            dest: dest.clone(),
            size,
            sha256,
            role: role.clone(),
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
        let meta = match fs::symlink_metadata(entry.path()) {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        // Unlink a planted symlink itself; never traverse it.
        if meta.file_type().is_symlink() || util::is_reparse_point(&meta) {
            let _ = fs::remove_file(entry.path());
            continue;
        }
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

/// The canonical stamp of a group: the ceiling (whole seconds) of its
/// newest file, so every stored file is stamped at or after its true mtime
/// and cross-filesystem second-resolution round-trips cannot make an output
/// look newer than its own group.
fn group_stamp(files: &[(PathBuf, String, String, String)]) -> Result<u64> {
    let mut newest: Option<SystemTime> = None;
    let mut metadata: Option<SystemTime> = None;
    for (src, path, _, _) in files {
        let modified = fs::metadata(src)
            .and_then(|meta| meta.modified())
            .with_context(|| format!("reading mtime of {}", src.display()))?;
        if newest.map_or(true, |current| modified > current) {
            newest = Some(modified);
        }
        if path.ends_with(".rmeta") && metadata.map_or(true, |current| modified > current) {
            metadata = Some(modified);
        }
    }
    // The metadata output, when present, is the moment dependents can compile
    // against this unit: rustc writes `.rmeta` first and `.rlib` last, and a
    // dependent routinely finishes before its dependency's `.rlib` exists.
    // Stamping with the `.rlib` would make the group look newer than its own
    // dependents and force spurious rebuilds after a restore.
    Ok(match metadata.or(newest) {
        Some(time) => ceil_secs(time),
        None => now_secs(),
    })
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
        fs::OpenOptions::new()
            .access_mode(0x0100) // FILE_WRITE_ATTRIBUTES
            .open(path)
            .or_else(|_| fs::OpenOptions::new().write(true).open(path))
            .with_context(|| format!("opening {} to stamp it", path.display()))?
    };
    #[cfg(not(windows))]
    let file =
        fs::File::open(path).with_context(|| format!("opening {} to stamp it", path.display()))?;
    file.set_modified(time)
        .with_context(|| format!("stamping {}", path.display()))?;
    Ok(())
}

/// The store is read-only by contract; restored state must not be.
#[cfg(unix)]
fn make_writable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o644);
    fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn make_writable(path: &Path) -> std::io::Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_readonly(false);
    fs::set_permissions(path, perms)
}

/// On Unix the store is read-only (owner can still stamp and delete; only
/// content edits are refused). On Windows a read-only file blocks rename
/// and delete, so the store keeps normal permissions there.
fn make_read_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o444))?;
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

#[cfg(unix)]
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
fn restore_file_at(
    view_root: &Path,
    dest_rel: &Path,
    src: &Path,
    stamp: u64,
    file: &FileEntry,
    shared: bool,
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
    if !meta.is_file() || !util::owned_by_us(&meta) {
        anyhow::bail!("stored file {} is not a regular owned file", src.display());
    }
    if meta.len() != file.size {
        anyhow::bail!(
            "stored file {} size drift (recorded {}, found {})",
            src.display(),
            file.size,
            meta.len()
        );
    }
    if shared {
        if file.sha256.is_empty() {
            anyhow::bail!("{} has no recorded SHA-256", src.display());
        }
        let found = util::sha256_file_fd(&mut source)?;
        if found != file.sha256 {
            anyhow::bail!("{} failed its SHA-256 check", src.display());
        }
        parent.link_path(src, dst_name)?;
        Ok(RestoreOutcome::Linked)
    } else {
        // Write the private copy directly at the final name with O_EXCL. The
        // destination name is created once, at the held parent fd; on any
        // integrity/stamp failure the partial file is removed. No temp-path
        // lookup is needed, which keeps this portable on non-Linux Unix.
        let mut tmp = parent.create_excl(dst_name, 0o600)?;
        let result = util::copy_fd_verified(&mut source, &mut tmp, file.size, &file.sha256)
            .and_then(|_| util::set_stamp_fd(&tmp, stamp).map_err(anyhow::Error::from));
        if let Err(err) = result {
            let _ = parent.unlink(dst_name);
            return Err(err);
        }
        Ok(RestoreOutcome::Copied)
    }
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
pub fn restore(
    view_root: &Path,
    store_root: &Path,
    unit_filter: Option<&str>,
    dry_run: bool,
) -> Result<RestoreReport> {
    let parity = parity_key()?;
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
    for entry in &manifest.units {
        if let Some(query) = unit_filter {
            if !unit_name_matches(&entry.name, query) {
                continue;
            }
        }
        let fp_dir = view_root
            .join(&entry.profile)
            .join(".fingerprint")
            .join(&entry.name);
        if read_small_regular(&fp_dir.join(&entry.memo))
            .map(|text| text.trim() == entry.hash)
            .unwrap_or(false)
        {
            report.units_already += 1;
            continue;
        }

        let mut unit_touched = false;
        for file in &entry.files {
            // Both components were validated by Manifest::validate; keep the
            // join explicit and reject any symlink in the destination chain.
            let dest_rel = Path::new(&entry.profile).join(&file.dest);
            let dst = view_root.join(&dest_rel);
            match fs::symlink_metadata(&dst) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() || util::is_reparse_point(&meta) {
                        report.errors += 1;
                        report.fatal_errors += 1;
                        eprintln!(
                            "restore: refusing symlink/reparse destination {}",
                            dst.display()
                        );
                    } else {
                        report.files_existing += 1;
                    }
                    continue;
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    report.errors += 1;
                    eprintln!("restore: inspecting {}: {err}", dst.display());
                    continue;
                }
            }
            // Only `deps/` link outputs (`.rlib`, proc-macro `.so`) may share
            // the store inode — rustc replaces those atomically. `.rmeta` and
            // everything else are written in place by rustc, cargo or build
            // scripts: private verified copies only.
            let shared = file.path.starts_with("deps/") && !file.path.ends_with(".rmeta");
            if dry_run {
                unit_touched = true;
                if shared {
                    report.files_linked += 1;
                } else {
                    report.files_copied += 1;
                }
                report.bytes += file.size;
                continue;
            }
            let src = units.join(&entry.name).join(&file.path);
            let rel = Path::new(&entry.name).join(&file.path);
            #[cfg(unix)]
            {
                if let Err(err) = util::check_regular_chain(&units, &rel) {
                    report.errors += 1;
                    report.fatal_errors += 1;
                    eprintln!("restore: writing {}: {err:#}", dst.display());
                    continue;
                }
                match restore_file_at(view_root, &dest_rel, &src, entry.stamp, file, shared) {
                    Ok(RestoreOutcome::Existing) => {
                        report.files_existing += 1;
                    }
                    Ok(RestoreOutcome::Missing) => {
                        report.files_missing += 1;
                    }
                    Ok(RestoreOutcome::Linked) => {
                        report.files_linked += 1;
                        report.bytes += file.size;
                        unit_touched = true;
                    }
                    Ok(RestoreOutcome::Copied) => {
                        report.files_copied += 1;
                        report.bytes += file.size;
                        unit_touched = true;
                    }
                    Err(err) => {
                        report.errors += 1;
                        report.fatal_errors += 1;
                        eprintln!("restore: writing {}: {err:#}", dst.display());
                    }
                }
                continue;
            }
            #[cfg(not(unix))]
            {
                if let Some(parent) = dest_rel.parent() {
                    if let Err(err) = util::create_dir_chain_nofollow(view_root, parent) {
                        report.errors += 1;
                        report.fatal_errors += 1;
                        eprintln!("restore: creating {}: {err}", parent.display());
                        continue;
                    }
                }
                match fs::symlink_metadata(&src) {
                    Ok(_) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        // Fail-open: a partial vault means Cargo rebuilds it.
                        report.files_missing += 1;
                        continue;
                    }
                    Err(err) => {
                        report.errors += 1;
                        report.fatal_errors += 1;
                        eprintln!("restore: inspecting {}: {err}", src.display());
                        continue;
                    }
                }
                let result = if shared {
                    util::check_regular_chain(&units, &rel)
                        .and_then(|_| verify_store_file(&src, file))
                        .and_then(|_| fs::hard_link(&src, &dst).map_err(Into::into))
                } else {
                    util::check_regular_chain(&units, &rel)
                        .and_then(|_| install_private_copy(&src, &dst, entry.stamp, file))
                };
                match result {
                    Ok(()) => {
                        if shared {
                            report.files_linked += 1;
                        } else {
                            report.files_copied += 1;
                        }
                        report.bytes += file.size;
                        unit_touched = true;
                    }
                    Err(err) => {
                        report.errors += 1;
                        report.fatal_errors += 1;
                        eprintln!("restore: writing {}: {err:#}", dst.display());
                    }
                }
            }
        }
        if unit_touched {
            report.units_linked += 1;
        }
    }
    Ok(report)
}

/// The store is a trust boundary: refuse a symlinked, foreign-owned, or
/// group/world-writable store. A root process must not consume a user-owned
/// vault (that is the hard-link privesc this fix closes).
fn check_store_trust(store_root: &Path) -> Result<()> {
    util::ensure_windows_user_path(store_root, "store")?;
    let meta = fs::symlink_metadata(store_root)
        .with_context(|| format!("inspecting store {}", store_root.display()))?;
    if !meta.is_dir() || meta.file_type().is_symlink() || util::is_reparse_point(&meta) {
        anyhow::bail!("store {} is not a real directory", store_root.display());
    }
    if !util::owned_by_us(&meta) {
        anyhow::bail!(
            "store {} is owned by another user — refusing to execute its artifacts",
            store_root.display()
        );
    }
    // Repair the common pre-fix 0755 store instead of making every old vault
    // unusable; the directory is ours, so 0700 is always safe (and keeps
    // artifacts unreadable by other local users).
    util::ensure_private_dir(store_root)?;
    Ok(())
}

fn prepare_view_root(view_root: &Path) -> Result<()> {
    match fs::symlink_metadata(view_root) {
        Ok(meta) => {
            if !meta.is_dir() || meta.file_type().is_symlink() || util::is_reparse_point(&meta) {
                anyhow::bail!("view {} is not a real directory", view_root.display());
            }
            if !util::owned_by_us(&meta) {
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
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            util::create_private_dir_all(view_root)?;
        }
        Err(err) => {
            return Err(err).with_context(|| format!("inspecting view {}", view_root.display()));
        }
    }
    // Do NOT chmod an explicitly supplied view root here: `restore --into /`
    // or `--into ~` must never change the mode of a system/home directory.
    // New view roots are created 0700; the default cache root is repaired by
    // `cmd_restore` (which knows it is the shared cache), and per-job work
    // dirs are created 0700 by `exec`.
    Ok(())
}

#[cfg(not(unix))]
fn verify_store_file(src: &Path, file: &FileEntry) -> Result<()> {
    let meta = fs::symlink_metadata(src)
        .with_context(|| format!("inspecting stored file {}", src.display()))?;
    if !meta.file_type().is_file() || meta.file_type().is_symlink() || util::is_reparse_point(&meta)
    {
        anyhow::bail!("{} is not a regular file", src.display());
    }
    if !util::owned_by_us(&meta) {
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
fn install_private_copy(src: &Path, dst: &Path, stamp: u64, file: &FileEntry) -> Result<()> {
    let parent = dst
        .parent()
        .with_context(|| format!("destination {} has no parent", dst.display()))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let tmp = parent.join(format!(".epicenter-copy-{}-{nonce}", std::process::id()));
    util::copy_file_verified(src, &tmp, file.size, &file.sha256)?;
    make_writable(&tmp)?;
    set_stamp(&tmp, stamp)?;
    // Private copies stay writable: rustc/cargo rewrite .rmeta and
    // fingerprint state in place. Only shared `deps/` artifacts are 0444.
    // Link, never rename: this keeps "never overwrite an existing file".
    let installed = fs::hard_link(&tmp, dst);
    let _ = fs::remove_file(&tmp);
    installed.with_context(|| format!("installing {}", dst.display()))?;
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
        let Some(manifest) = load_manifest(store_root, &parity)? else {
            report.problems.push(format!(
                "generation {parity} has no readable manifest.json — it cannot be audited"
            ));
            reports.push(report);
            continue;
        };
        let units = units_dir(store_root, &parity);
        for entry in &manifest.units {
            for file in &entry.files {
                let path = units.join(&entry.name).join(&file.path);
                let rel = Path::new(&entry.name).join(&file.path);
                if let Err(err) = util::check_regular_chain(&units, &rel) {
                    report.problems.push(format!(
                        "unsafe path: {} ({err:#})",
                        display_join(&path, &units)
                    ));
                    continue;
                }
                let meta = match fs::symlink_metadata(&path) {
                    Ok(meta) => meta,
                    Err(_) => {
                        report
                            .problems
                            .push(format!("missing: {}", display_join(&path, units.as_path())));
                        continue;
                    }
                };
                if meta.file_type().is_symlink() || util::is_reparse_point(&meta) {
                    report.problems.push(format!(
                        "symlink/reparse in store (refused): {}",
                        display_join(&path, &units)
                    ));
                    continue;
                }
                if !meta.is_file() {
                    report.problems.push(format!(
                        "not a regular file: {}",
                        display_join(&path, &units)
                    ));
                    continue;
                }
                if !util::owned_by_us(&meta) {
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
        match fs::symlink_metadata(&units) {
            Ok(meta)
                if meta.is_dir()
                    && !meta.file_type().is_symlink()
                    && !util::is_reparse_point(&meta) => {}
            Ok(_) => {
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
            for entry in WalkDir::new(&units).min_depth(1) {
                let entry = entry?;
                if !entry.file_type().is_file() {
                    continue;
                }
                let meta = entry.metadata()?;
                info.files += 1;
                info.bytes += meta.len();
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A build dir in the shapes real Cargo writes: a lib unit, a
    /// build-script compile unit, and a build-script run unit without
    /// dep-info — plus volatile files and wrapper internals that must be
    /// filtered out.
    fn synthetic_build_dir(root: &Path) -> Result<()> {
        let jsons =
            r#"{"rustc":12019306335353385202,"features":"[]","declared_features":"[]","deps":[]}"#;

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
        assert!(first.ends_with(&flags_digest()));
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
    fn restore_links_hardlinks_and_never_overwrites() -> Result<()> {
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

        let report = restore(view.path(), store.path(), None, false)?;
        assert_eq!(report.units_linked, 3);
        assert_eq!(report.files_existing, 1, "the live artifact was skipped");
        assert_eq!(fs::read(&occupied)?, b"live artifact");
        // Only `deps/` artifacts are hard-linked; state and build trees are
        // private copies (cargo writes both in place). The single deps/
        // artifact of this fixture was the occupied one, so nothing linked.
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
        let again = restore(view.path(), store.path(), None, false)?;
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

        let report = restore(view.path(), store.path(), None, false)?;
        assert_eq!(report.errors, 0);
        assert!(view.path().join("debug/.fingerprint").is_dir());
        Ok(())
    }

    #[test]
    fn restore_without_a_generation_reports_fail_open() -> Result<()> {
        let view = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        let report = restore(view.path(), store.path(), None, false)?;
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

    #[test]
    fn restore_shares_artifacts_but_copies_state_writable() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        harvest(build.path(), store.path(), Some("102a33f0"), false)?;

        let view = tempfile::tempdir()?;
        restore(view.path(), store.path(), Some("102a33f0"), false)?;

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
            assert!(
                fs::metadata(&artifact)?.nlink() >= 2,
                "artifact shares the store inode"
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
    fn synthetic_edge_dir(root: &Path, dep_at: u64, unit_at: u64) -> Result<()> {
        fs::create_dir_all(root.join("debug/deps"))?;
        let core = root.join("debug/.fingerprint/serde_core-b468be6fa8c1f936");
        fs::create_dir_all(&core)?;
        fs::write(core.join("lib-serde_core"), "71a9f323efa5ae82")?;
        fs::write(core.join("dep-lib-serde_core"), [0u8; 8])?;
        let core_rlib = root.join("debug/deps/libserde_core-b468be6fa8c1f936.rlib");
        fs::write(&core_rlib, [1u8; 32])?;

        let unit = root.join("debug/.fingerprint/serde-746d173581f1a314");
        fs::create_dir_all(&unit)?;
        fs::write(unit.join("lib-serde"), "5d82713a7f2d05e2")?;
        fs::write(
            unit.join("lib-serde.json"),
            r#"{"rustc":5244445300240561903,"features":"[]","declared_features":"[]","deps":[[11029742160753049355,"serde_core",false,9416646317397223793]]}"#,
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

        // The exact `stage_group` order for a copy that inherited a read-only
        // source (kache hardlinks): make it writable, then stamp it.
        let mut perms = fs::metadata(&file)?.permissions();
        perms.set_readonly(true);
        fs::set_permissions(&file, perms)?;
        make_writable(&file)?;
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
        set_stamp(&stale, now_secs() - 7200)?;

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
            files: vec![FileEntry {
                path: path.into(),
                dest: dest.into(),
                size: 1,
                sha256: String::new(),
                role: "artifact".into(),
            }],
        };
        let base = Manifest {
            parity_key: "p".into(),
            toolchain: "t".into(),
            created: 1,
            updated: 1,
            units: vec![],
            mac: String::new(),
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
        let report = restore(view.path(), store.path(), None, false)?;
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
                r#"{"rustc":1,"features":"[]","declared_features":"[]","deps":[]}"#,
            )?;
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
