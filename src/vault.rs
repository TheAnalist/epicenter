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
//! (`stamp`), chosen at harvest as the ceiling of the group's newest file.
//! Restore never stamps: hard-linked files share the store's inode, and a
//! `touch` on a restored file would rewrite the store itself.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::fingerprint::{self, ArtifactInfo, Unit};

/// Seed for the flag digest, versioned: bumping it retires old generations.
const PARITY_SEED: &str = "epicenter-parity-v1";

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
    let output = Command::new("rustc")
        .arg("-vV")
        .output()
        .context("running `rustc -vV`")?;
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
    let output = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .ok()?;
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
    Ok(format!(
        "{}-{}-{}-{}",
        tc.release,
        tc.commit,
        tc.host,
        flags_digest()
    ))
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
    ] {
        input.push('\0');
        input.push_str(name);
        input.push('=');
        input.push_str(&std::env::var(name).unwrap_or_default());
    }
    if let Ok(path) = crate::config::cargo_config_path() {
        if let Ok(text) = fs::read_to_string(path) {
            for key in ["rustflags", "rustdocflags", "target"] {
                if let Some(value) = crate::config::read_table_key(&text, "build", key) {
                    input.push('\0');
                    input.push_str(key);
                    input.push('=');
                    input.push_str(&value);
                }
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
    build_root
        .parent()
        .unwrap_or(build_root)
        .join("store")
}

/// `store/<parity-key>/units`.
pub fn units_dir(store_root: &Path, parity: &str) -> PathBuf {
    store_root.join(parity).join("units")
}

fn manifest_path(store_root: &Path, parity: &str) -> PathBuf {
    store_root.join(parity).join("manifest.json")
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
    /// `memo` | `fingerprint` | `dep-info` | `artifact` | `build-tree`.
    pub role: String,
}

fn load_manifest(store_root: &Path, parity: &str) -> Result<Option<Manifest>> {
    let path = manifest_path(store_root, parity);
    if !path.is_file() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?;
    let manifest = serde_json::from_str(&text)
        .with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(manifest))
}

fn save_manifest(store_root: &Path, parity: &str, manifest: &Manifest) -> Result<()> {
    let dir = store_root.join(parity);
    fs::create_dir_all(&dir)?;
    let what = serde_json::to_string_pretty(manifest)?;
    let tmp = dir.join(format!("manifest.json.tmp-{}", std::process::id()));
    fs::write(&tmp, what + "\n")?;
    fs::rename(&tmp, manifest_path(store_root, parity))?;
    Ok(())
}

/// Names of the store generations (directories under `store/`).
pub fn generation_names(store_root: &Path) -> Result<Vec<String>> {
    if !store_root.is_dir() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(store_root)
        .with_context(|| format!("reading {}", store_root.display()))?
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
    let text = fs::read_to_string(unit.dir.join(format!("{}.json", unit.entry.memo))).ok()?;
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
    let Some(mut manifest) = load_manifest(store_root, generation)? else {
        return Ok(0);
    };
    let units = units_dir(store_root, generation);
    let mut dropped = 0;
    manifest.units.retain(|entry| {
        if !names.contains(&entry.name) {
            return true;
        }
        match fs::remove_dir_all(units.join(&entry.name)) {
            Ok(()) => {
                dropped += 1;
                false
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                dropped += 1;
                false
            }
            Err(err) => {
                eprintln!("could not remove {}: {err}", units.join(&entry.name).display());
                true
            }
        }
    });
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
    });

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
        for entry in fs::read_dir(&unit_dir)
            .with_context(|| format!("reading {}", unit_dir.display()))?
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

        let stamp = group_stamp(&files)?;
        let hash = unit.memo_hash.clone().unwrap_or_default();
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
                entry.hash == hash
                    && entry.profile == unit.profile
                    && entry.stamp == stamp
                    && stored == new_entries
                    && entry
                        .files
                        .iter()
                        .all(|file| group_dir.join(&file.path).is_file())
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
        store_group(store_root, &parity, &unit.dir_name, stamp, &files, &mut entries)
            .with_context(|| format!("storing unit {}", unit.dir_name))?;

        let entry = UnitEntry {
            name: unit.dir_name.clone(),
            profile: unit.profile.clone(),
            memo,
            hash,
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
    let units = units_dir(store_root, parity);
    let final_dir = units.join(name);
    let tmp = units.join(format!(".{name}.tmp-{}", std::process::id()));
    if tmp.is_dir() {
        fs::remove_dir_all(&tmp)?;
    }
    fs::create_dir_all(&tmp)?;

    for (src, path, dest, role) in files {
        let dst = tmp.join(path);
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(src, &dst)
            .with_context(|| format!("copying {} -> {}", src.display(), dst.display()))?;
        set_stamp(&dst, stamp)?;
        make_read_only(&dst)?;
        let size = fs::metadata(&dst).map(|meta| meta.len()).unwrap_or(0);
        entries.push(FileEntry {
            path: path.clone(),
            dest: dest.clone(),
            size,
            role: role.clone(),
        });
    }

    let old = units.join(format!(".{name}.old-{}", std::process::id()));
    if final_dir.is_dir() {
        fs::rename(&final_dir, &old)?;
    }
    fs::rename(&tmp, &final_dir)?;
    if old.is_dir() {
        let _ = fs::remove_dir_all(&old);
    }
    Ok(())
}

/// The canonical stamp of a group: the ceiling (whole seconds) of its
/// newest file, so every stored file is stamped at or after its true mtime
/// and cross-filesystem second-resolution round-trips cannot make an output
/// look newer than its own group.
fn group_stamp(files: &[(PathBuf, String, String, String)]) -> Result<u64> {
    let mut newest: Option<SystemTime> = None;
    for (src, _, _, _) in files {
        let modified = fs::metadata(src)
            .and_then(|meta| meta.modified())
            .with_context(|| format!("reading mtime of {}", src.display()))?;
        if newest.map_or(true, |current| modified > current) {
            newest = Some(modified);
        }
    }
    Ok(match newest {
        Some(time) => ceil_secs(time),
        None => now_secs(),
    })
}

/// Round a timestamp up to whole seconds.
fn ceil_secs(time: SystemTime) -> u64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs();
            if duration.subsec_nanos() > 0 { secs + 1 } else { secs }
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
    let file = fs::File::open(path)
        .with_context(|| format!("opening {} to stamp it", path.display()))?;
    file.set_modified(time)
        .with_context(|| format!("stamping {}", path.display()))?;
    Ok(())
}

/// Copy a file into a view as a **private** inode: writable, and stamped
/// with the canonical group time. Required for everything cargo writes in
/// place (`O_TRUNC`) — a shared inode would either hit the read-only store
/// file (EACCES) or mutate the store.
fn copy_private(src: &Path, dst: &Path, stamp: u64) -> std::io::Result<()> {
    fs::copy(src, dst)?;
    make_writable(dst)?;
    let _ = set_stamp(dst, stamp);
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
    pub bytes: u64,
    pub errors: usize,
    pub note: Option<String>,
}

/// Link matching unit groups from the vault into a working dir.
///
/// `deps/` artifacts are hard-linked — rustc only ever replaces them
/// atomically. Fingerprint state and build-script trees become private
/// writable copies, because cargo and build scripts write those *in place*:
/// a shared inode would either hit the read-only store file (EACCES) or
/// mutate the store. Hard links share the store's canonical stamp;
/// private copies are stamped after copying. Never overwrites a file that
/// already exists, never touches sources, and a partial vault is fine:
/// Cargo recompiles whatever is missing.
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
    let Some(manifest) = load_manifest(store_root, &parity)? else {
        report.note = Some(
            "the vault holds no units for this generation yet — run `epicenter harvest` after a build"
                .into(),
        );
        return Ok(report);
    };

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
        if fs::read_to_string(fp_dir.join(&entry.memo))
            .map(|text| text.trim() == entry.hash)
            .unwrap_or(false)
        {
            report.units_already += 1;
            continue;
        }

        let mut unit_touched = false;
        for file in &entry.files {
            let dst = view_root.join(&entry.profile).join(&file.dest);
            if dst.exists() {
                report.files_existing += 1;
                continue;
            }
            // Only `deps/` artifacts may share the store inode (rustc
            // replaces them atomically). Everything else is written in
            // place by cargo or by build scripts: private copies only.
            let shared = file.path.starts_with("deps/");
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
            if let Some(parent) = dst.parent() {
                if let Err(err) = fs::create_dir_all(parent) {
                    report.errors += 1;
                    eprintln!("restore: creating {}: {err}", parent.display());
                    continue;
                }
            }
            let linked = shared && fs::hard_link(&src, &dst).is_ok();
            let result = if linked {
                Ok(())
            } else {
                copy_private(&src, &dst, entry.stamp)
            };
            match result {
                Ok(()) => {
                    if linked {
                        report.files_linked += 1;
                    } else {
                        report.files_copied += 1;
                    }
                    unit_touched = true;
                }
                Err(err) => {
                    report.errors += 1;
                    eprintln!("restore: writing {}: {err}", dst.display());
                    continue;
                }
            }
            report.bytes += file.size;
        }
        if unit_touched {
            report.units_linked += 1;
        }
    }
    Ok(report)
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
                let meta = match fs::metadata(&path) {
                    Ok(meta) => meta,
                    Err(_) => {
                        report
                            .problems
                            .push(format!("missing: {}", display_join(&path, units.as_path())));
                        continue;
                    }
                };
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
                if file.role == "memo" {
                    match fs::read_to_string(&path) {
                        Ok(text) if file.path == entry.memo && text.trim() != entry.hash => {
                            report.problems.push(format!(
                                "hash drift: {} (recorded {}, found {})",
                                display_join(&path, &units),
                                entry.hash,
                                text.trim()
                            ));
                        }
                        Ok(text)
                            if file.path != entry.memo
                                && !crate::fingerprint::looks_like_hash(text.trim()) =>
                        {
                            report.problems.push(format!(
                                "malformed memo file: {} ({:?})",
                                display_join(&path, &units),
                                text.trim()
                            ));
                        }
                        Ok(_) => {}
                        Err(err) => report.problems.push(format!(
                            "unreadable memo file {}: {err}",
                            display_join(&path, &units)
                        )),
                    }
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
                .and_then(|file| {
                    fs::read_to_string(units.join(&entry.name).join(&file.path)).ok()
                })
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
        if units.is_dir() {
            let known: std::collections::BTreeSet<&str> =
                manifest.units.iter().map(|unit| unit.name.as_str()).collect();
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
                    report
                        .warnings
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
        let jsons = r#"{"rustc":12019306335353385202,"features":"[]","declared_features":"[]","deps":[]}"#;

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
        fs::write(
            compile.join("build-script-build-script-build.json"),
            jsons,
        )?;
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
        fs::write(
            run.join("run-build-script-build-script-build.json"),
            jsons,
        )?;
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
            assert_eq!(ceil_secs(meta.modified()?), lib_entry.stamp, "{}", file.path);
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
            assert_eq!(meta.permissions().mode() & 0o777, 0o444, "store is read-only");
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
            build
                .path()
                .join("debug/deps/libserde-102a33f055a8d229.rmeta"),
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
            paths.contains(&"deps/libserde-102a33f055a8d229.rmeta"),
            "{paths:?}"
        );
        Ok(())
    }

    #[test]
    fn harvest_stores_all_memos_of_shared_dirs() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_build_dir(build.path())?;
        let lib = build.path().join("debug/.fingerprint/serde-102a33f055a8d229");
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
        let occupied = view.path().join("debug/deps/libserde-102a33f055a8d229.rlib");
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
            let stored =
                units_dir(store.path(), &parity).join("serde-102a33f055a8d229/lib-serde");
            let view_meta = fs::metadata(&memo)?;
            assert_ne!(view_meta.ino(), fs::metadata(&stored)?.ino(), "state not shared");
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
        let victim =
            units_dir(store.path(), &parity).join("serde-102a33f055a8d229/dep-lib-serde");
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
                .warnings
                .iter()
                .any(|line| line.contains("stray-0000000000000000")),
            "{:?}",
            reports[0].warnings
        );
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
        assert!(state.is_file() && artifact.is_file());

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
            assert!(fs::metadata(&artifact)?.nlink() >= 2, "artifact shares the store inode");
            assert_eq!(fs::metadata(&state)?.nlink(), 1, "state is a private copy");
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
    fn verify_flags_units_older_than_a_dependency() -> Result<()> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        let now = now_secs();
        synthetic_edge_dir(build.path(), now, now - 3600)?;
        harvest(build.path(), store.path(), None, false)?;

        let reports = verify(store.path())?;
        assert!(reports[0].is_clean(), "{:?}", reports[0].problems);
        assert_eq!(reports[0].ordering.len(), 1, "{:?}", reports[0].ordering);
        assert!(reports[0].ordering[0].contains("serde-746d173581f1a314"));
        assert!(reports[0].ordering[0].contains("serde_core-b468be6fa8c1f936"));
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
