//! Read-only parser for cargo's `.fingerprint/` state: parses each unit
//! directory into a [`Unit`] (kind, hashes, fingerprint JSON, dep-info) and
//! attaches the artifacts that belong to it.
//!
//! Directory layout as written by cargo:
//! ```text
//! <build>/<profile>/.fingerprint/<package>-<16hex>/
//!   <memo-file>            ← TEXT, 16 hex chars = the authoritative memo hash
//!   <memo-file>.json       ← serialized Fingerprint (schema below)
//!   dep-<memo-file>        ← binary EncodedDepInfo (not parsed here)
//!   invoked.timestamp      ← optional, ignorable
//! ```
//! `<memo-file>` names the target kind: `lib-serde` (lib),
//! `build-script-build` (compile build script), `run-build-script-build`
//! (run build script), or the bin name.
//!
//! Cargo's new build-dir layout (nightly 1.99+ with `-Zbuild-dir-new-layout`,
//! on by default there; stable 1.100+) writes one directory per unit instead:
//! ```text
//! <build>/<profile>/build/<package>/<16hex>/
//!   fingerprint/   ← the same files as the classic `.fingerprint/<pkg>-<hex>/`
//!   out/           ← the artifacts the classic layout kept in `<profile>/deps/`
//!   run/           ← run-build-script state (classic `build/<anchor>/`)
//! ```
//! Both layouts can coexist in one build dir (a stable and a nightly build
//! sharing the cache), so [`read_units`] discovers units by shape. The
//! [`layout_for_cargo`] helper decides which layout a child build will write,
//! which `exec` uses to seed the matching units.
//!
//! JSON schema — mostly opaque HASH NUMBERS plus two human facts:
//! `{rustc, features, declared_features, target, profile, path, deps,
//!  local, rustflags, config, compile_kind}` where `features` /
//! `declared_features` are STRINGS containing serialized JSON arrays.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitKind {
    Lib,
    BuildScriptCompile,
    BuildScriptRun,
    Other,
}

impl UnitKind {
    pub fn label(self) -> &'static str {
        match self {
            UnitKind::Lib => "lib",
            UnitKind::BuildScriptCompile => "build.rs",
            UnitKind::BuildScriptRun => "build-run",
            UnitKind::Other => "other",
        }
    }
}

/// Which build-dir layout produced a unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnitLayout {
    /// Cargo 1.91–1.99 stable: `<profile>/.fingerprint/<pkg>-<hash>/` +
    /// `<profile>/deps/`.
    Classic,
    /// Cargo nightly 1.99+ / stable 1.100+:
    /// `<profile>/build/<pkg>/<hash>/{fingerprint,out}/`.
    New,
}

impl UnitLayout {
    pub fn label(self) -> &'static str {
        match self {
            UnitLayout::Classic => "classic",
            UnitLayout::New => "new",
        }
    }
}

/// The per-unit directory of the new build-dir layout:
/// ```text
/// <build-dir>/<profile>/build/<package>/<hash>/
///    fingerprint/   ↔ the classic `.fingerprint/<package>-<hash>/` contents
///    out/           ↔ the artifacts classic kept in `deps/`
/// ```
/// `<hash>` is the unit hash — the classic fingerprint-dir suffix.
#[derive(Debug, Clone)]
pub struct NewUnitLayout {
    /// `debug` / `release` …
    profile: String,
    /// `anyhow`, `serde_core`, …
    package: String,
    /// `9709d57b46b8d526`
    hash: String,
}

impl NewUnitLayout {
    pub fn new(profile: &str, package: &str, hash: &str) -> Self {
        Self {
            profile: profile.to_string(),
            package: package.to_string(),
            hash: hash.to_string(),
        }
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn package(&self) -> &str {
        &self.package
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// `<build>/<profile>/build/<package>/<hash>`
    pub fn unit_dir(&self, build_root: &Path) -> PathBuf {
        build_root
            .join(&self.profile)
            .join("build")
            .join(&self.package)
            .join(&self.hash)
    }

    /// `<build>/<profile>/build/<package>/<hash>/fingerprint`
    pub fn fingerprint_dir(&self, build_root: &Path) -> PathBuf {
        self.unit_dir(build_root).join("fingerprint")
    }

    /// `<build>/<profile>/build/<package>/<hash>/out`
    pub fn out_dir(&self, build_root: &Path) -> PathBuf {
        self.unit_dir(build_root).join("out")
    }
}

/// Which layout a cargo of this version writes. `version` is the output of
/// `cargo --version` (e.g. `cargo 1.99.0-nightly (7c83d4cc0 …)`); `args` is
/// the child argv, scanned for `-Zbuild-dir-new-layout`.
///
/// Rules (the feature is nightly-first):
/// - stable/beta ≥ 1.100 → new (the new layout ships in 1.100);
/// - nightly ≥ 1.99 → new (nightly 1.99 enables the flag by default);
/// - nightly < 1.99 with `-Zbuild-dir-new-layout` → new;
/// - everything else → classic (covers 1.91 … 1.99 stable).
pub fn layout_for_cargo(version: &str, args: &[String]) -> UnitLayout {
    let Some((major, minor)) = parse_cargo_version(version) else {
        return UnitLayout::Classic;
    };
    let nightly = version.contains("-nightly");
    if major > 1 || (major == 1 && minor >= 100) {
        return UnitLayout::New;
    }
    if nightly && minor >= 99 {
        return UnitLayout::New;
    }
    if nightly && has_new_layout_flag(args) {
        return UnitLayout::New;
    }
    UnitLayout::Classic
}

/// `cargo 1.99.0-nightly (7c83d4cc0 …)` → `(1, 99)`.
pub fn parse_cargo_version(text: &str) -> Option<(u64, u64)> {
    let token = text
        .split_whitespace()
        .find(|part| part.chars().next().is_some_and(|c| c.is_ascii_digit()))?;
    let mut parts = token.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// `-Zbuild-dir-new-layout` or `-Z build-dir-new-layout` in an argv.
pub fn has_new_layout_flag(args: &[String]) -> bool {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            break;
        }
        if arg == "-Z" {
            if let Some(next) = iter.next() {
                if next == "build-dir-new-layout" || next.starts_with("build-dir-new-layout=") {
                    return true;
                }
            }
        } else if let Some(rest) = arg.strip_prefix("-Z") {
            if rest == "build-dir-new-layout" || rest.starts_with("build-dir-new-layout=") {
                return true;
            }
        }
    }
    false
}

/// One parsed unit directory, in either build-dir layout.
#[derive(Debug, Clone)]
pub struct Unit {
    /// `serde-102a33f055a8d229`
    pub dir_name: String,
    /// `serde` (dir name minus the 16-hex suffix)
    pub package: String,
    /// `102a33f055a8d229` — == the deps/ filename suffix
    pub dir_suffix: String,
    /// `debug` / `release` …
    pub profile: String,
    pub kind: UnitKind,
    /// Which build-dir layout this unit came from.
    pub layout: UnitLayout,
    /// Directory holding the memo/json/dep files:
    /// classic `.fingerprint/<pkg>-<hash>`, new `build/<pkg>/<hash>/fingerprint`.
    pub fingerprint_dir: PathBuf,
    /// New-layout unit root (`<profile>/build/<pkg>/<hash>`); equal to
    /// `fingerprint_dir` in the classic layout.
    pub unit_dir: PathBuf,
    /// Name of the memo file (`lib-serde`, `build-script-build`, …)
    pub memo_file: String,
    /// Content of the memo file — the authoritative hash
    pub memo_hash: Option<String>,
    pub json: Option<FingerprintJson>,
    pub dep_info: Option<PathBuf>,
    /// Files inside the unit dir (for forensics completeness).
    pub extra_files: Vec<String>,
}

impl Unit {
    /// View-relative directory that holds this unit's fingerprint state.
    pub fn fingerprint_rel(&self) -> String {
        match self.layout {
            UnitLayout::Classic => format!(".fingerprint/{}", self.dir_name),
            UnitLayout::New => {
                format!("build/{}/{}/fingerprint", self.package, self.dir_suffix)
            }
        }
    }
}

/// Typed view of the serialized Fingerprint schema.
#[derive(Debug, Clone, Default)]
pub struct FingerprintJson {
    /// Toolchain identity — the #1 cache-key invalidator.
    pub rustc: String,
    pub features: Vec<String>,
    pub declared_features: Vec<String>,
    /// `[dep-id, dep-name, flag, unit-hash]` triples, simplified.
    pub deps: Vec<DepRef>,
    /// Opaque hashes (reported as-is).
    pub target: String,
    pub profile: String,
    pub path: String,
    pub config: String,
    pub compile_kind: String,
    pub rustflags: Vec<String>,
    /// `local[].CheckDepInfo.dep_info` paths (relative to the build dir).
    pub dep_info_paths: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DepRef {
    pub name: String,
    pub unit_hash: String,
}

impl DepRef {
    /// The dependency's **memo hash** — the join key between a dependency
    /// edge and the unit that owns it.
    ///
    /// Cargo stores a dependency's fingerprint hash as a u64 in the
    /// fingerprint JSON, and writes the same value into the dependency's
    /// memo file as hex of its **little-endian** bytes (cargo's `to_hex`).
    /// Example: serde's `serde_core` entry `9416646317397223793`
    /// resolves to `serde_core-…/lib-serde_core` = `71a9f323efa5ae82`
    /// (the same number, in opposite byte order).
    pub fn memo_hash(&self) -> Option<String> {
        let value: u64 = self.unit_hash.parse().ok()?;
        let mut out = String::with_capacity(16);
        for byte in value.to_le_bytes() {
            out.push_str(&format!("{byte:02x}"));
        }
        Some(out)
    }
}

/// Parse `<package>-<16hex>` into (package, hex).
fn split_dir_name(dir_name: &str) -> Option<(String, String)> {
    let (pkg, hex) = dir_name.rsplit_once('-')?;
    Some((pkg.to_string(), hex.to_string()))
}

/// The target kind a memo file name implies (`lib-serde`, `build-script-build`, …).
pub fn classify_kind(memo_file: &str) -> UnitKind {
    if memo_file.starts_with("lib") {
        UnitKind::Lib
    } else if memo_file.starts_with("run") {
        UnitKind::BuildScriptRun
    } else if memo_file.contains("build-script") || memo_file.starts_with("build") {
        UnitKind::BuildScriptCompile
    } else {
        UnitKind::Other
    }
}

/// `features`/`declared_features` are strings holding a JSON array — unwrap.
fn parse_string_array(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Value::String(text) => serde_json::from_str::<Vec<String>>(text)
            .unwrap_or_else(|_| text.split_whitespace().map(str::to_string).collect()),
        _ => Vec::new(),
    }
}

fn parse_u64_field(json: &Value, key: &str) -> String {
    match json.get(key) {
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(other) if !other.is_null() => other.to_string(),
        _ => String::new(),
    }
}

fn parse_fingerprint_json(json: &Value) -> FingerprintJson {
    let deps = json
        .get("deps")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let arr = item.as_array()?;
                    let unit_hash = match arr.get(3)? {
                        Value::Number(number) => number.to_string(),
                        Value::String(text) => text.clone(),
                        _ => return None,
                    };
                    Some(DepRef {
                        name: arr.get(1)?.as_str()?.to_string(),
                        unit_hash,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let dep_info_paths = json
        .get("local")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    item.get("CheckDepInfo")?
                        .get("dep_info")?
                        .as_str()
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default();

    FingerprintJson {
        rustc: parse_u64_field(json, "rustc"),
        features: json
            .get("features")
            .map(parse_string_array)
            .unwrap_or_default(),
        declared_features: json
            .get("declared_features")
            .map(parse_string_array)
            .unwrap_or_default(),
        deps,
        target: parse_u64_field(json, "target"),
        profile: parse_u64_field(json, "profile"),
        path: parse_u64_field(json, "path"),
        config: parse_u64_field(json, "config"),
        compile_kind: parse_u64_field(json, "compile_kind"),
        rustflags: json
            .get("rustflags")
            .map(parse_string_array)
            .unwrap_or_default(),
        dep_info_paths,
    }
}

/// Parse a serialized `<memo>.json` fingerprint — from a build dir or from
/// the vault's stored copy; both hold the same cargo-written bytes.
pub fn parse_fingerprint(text: &str) -> Option<FingerprintJson> {
    serde_json::from_str::<Value>(text)
        .ok()
        .map(|value| parse_fingerprint_json(&value))
}

/// Read every unit directory in both build-dir layouts:
/// `<profile>/.fingerprint/<pkg>-<hash>/` (classic) and
/// `<profile>/build/<pkg>/<hash>/fingerprint/` (new). Both may coexist in
/// one build dir, so this is shape-based rather than a single global mode.
pub fn read_units(build_root: &Path) -> Result<Vec<Unit>> {
    let mut units = Vec::new();
    for profile_entry in fs::read_dir(build_root)
        .with_context(|| format!("reading build dir {}", build_root.display()))?
    {
        let profile_entry = profile_entry?;
        if !profile_entry.file_type()?.is_dir() {
            continue;
        }
        let profile = profile_entry.file_name().to_string_lossy().into_owned();
        let profile_dir = profile_entry.path();

        // Classic layout: <profile>/.fingerprint/<pkg>-<hash>/
        let fp_root = profile_dir.join(".fingerprint");
        if is_real_dir(&fp_root) {
            for unit_entry in
                fs::read_dir(&fp_root).with_context(|| format!("reading {}", fp_root.display()))?
            {
                let unit_entry = unit_entry?;
                if !unit_entry.file_type()?.is_dir() {
                    continue;
                }
                if let Some(unit) = read_classic_unit(&profile, &unit_entry.path()) {
                    units.push(unit);
                }
            }
        }

        // New layout: <profile>/build/<pkg>/<hash>/fingerprint/
        let build_dir = profile_dir.join("build");
        if is_real_dir(&build_dir) {
            for package_entry in fs::read_dir(&build_dir)
                .with_context(|| format!("reading {}", build_dir.display()))?
            {
                let package_entry = package_entry?;
                if !package_entry.file_type()?.is_dir() {
                    continue;
                }
                let package = package_entry.file_name().to_string_lossy().into_owned();
                for hash_entry in fs::read_dir(package_entry.path())
                    .with_context(|| format!("reading {}", package_entry.path().display()))?
                {
                    let hash_entry = hash_entry?;
                    if !hash_entry.file_type()?.is_dir() {
                        continue;
                    }
                    let hash = hash_entry.file_name().to_string_lossy().into_owned();
                    if !looks_like_hash(&hash) {
                        continue;
                    }
                    if !is_real_dir(&hash_entry.path().join("fingerprint")) {
                        continue;
                    }
                    if let Some(unit) = read_new_unit(build_root, &profile, &package, &hash) {
                        units.push(unit);
                    }
                }
            }
        }
    }
    Ok(units)
}

/// Memo hash → index of the unit that owns it. First wins on duplicates.
pub fn memo_index(units: &[Unit]) -> HashMap<String, usize> {
    let mut index = HashMap::new();
    for (position, unit) in units.iter().enumerate() {
        if let Some(hash) = unit.memo_hash.as_deref() {
            index.entry(hash.to_string()).or_insert(position);
        }
    }
    index
}

/// Resolve one dependency edge against a memo index.
pub fn resolve_dep(index: &HashMap<String, usize>, dep: &DepRef) -> Option<usize> {
    index.get(dep.memo_hash()?.as_str()).copied()
}

/// Every unit's dependency edges, resolved to indices in `units`.
///
/// Unresolved edges — a dependency absent from this view, or one recorded
/// against a secondary memo file of a shared dir — are dropped: a partial
/// graph is useful, a wrong edge would be worse than a missing one.
pub fn dep_edges(units: &[Unit]) -> Vec<Vec<usize>> {
    let index = memo_index(units);
    units
        .iter()
        .map(|unit| {
            unit.json
                .as_ref()
                .map(|json| {
                    json.deps
                        .iter()
                        .filter_map(|dep| resolve_dep(&index, dep))
                        .collect()
                })
                .unwrap_or_default()
        })
        .collect()
}

/// A directory we may read: real, not a symlink or a Windows reparse point.
fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|meta| {
            meta.is_dir() && !meta.file_type().is_symlink() && !crate::util::is_reparse_point(&meta)
        })
        .unwrap_or(false)
}

fn read_classic_unit(profile: &str, unit_dir: &Path) -> Option<Unit> {
    let dir_name = unit_dir.file_name()?.to_string_lossy().into_owned();
    let (package, dir_suffix) = split_dir_name(&dir_name)?;
    let parsed = parse_unit_files(unit_dir)?;
    Some(Unit {
        dir_name,
        package,
        dir_suffix,
        profile: profile.to_string(),
        kind: parsed.kind,
        layout: UnitLayout::Classic,
        fingerprint_dir: unit_dir.to_path_buf(),
        unit_dir: unit_dir.to_path_buf(),
        memo_file: parsed.memo_file,
        memo_hash: Some(parsed.memo_hash),
        json: parsed.json,
        dep_info: parsed.dep_info,
        extra_files: parsed.extra_files,
    })
}

fn read_new_unit(build_root: &Path, profile: &str, package: &str, hash: &str) -> Option<Unit> {
    let layout = NewUnitLayout::new(profile, package, hash);
    let fingerprint_dir = layout.fingerprint_dir(build_root);
    let parsed = parse_unit_files(&fingerprint_dir)?;
    Some(Unit {
        dir_name: format!("{package}-{hash}"),
        package: package.to_string(),
        dir_suffix: hash.to_string(),
        profile: profile.to_string(),
        kind: parsed.kind,
        layout: UnitLayout::New,
        unit_dir: layout.unit_dir(build_root),
        fingerprint_dir,
        memo_file: parsed.memo_file,
        memo_hash: Some(parsed.memo_hash),
        json: parsed.json,
        dep_info: parsed.dep_info,
        extra_files: parsed.extra_files,
    })
}

struct ParsedUnit {
    kind: UnitKind,
    memo_file: String,
    memo_hash: String,
    json: Option<FingerprintJson>,
    dep_info: Option<PathBuf>,
    extra_files: Vec<String>,
}

/// Parse the contents of a fingerprint directory — identical in both layouts.
fn parse_unit_files(unit_dir: &Path) -> Option<ParsedUnit> {
    let mut candidates: Vec<(String, String)> = Vec::new(); // (name, content)
    let mut dep_info: Option<PathBuf> = None;
    let mut json_path: Option<PathBuf> = None;

    for entry in fs::read_dir(unit_dir).ok()? {
        let entry = entry.ok()?;
        // Only regular files: never read a FIFO/device/symlink planted by a
        // build script (harvest would otherwise hang or copy a secret).
        let entry_meta = fs::symlink_metadata(entry.path()).ok()?;
        if !entry_meta.is_file()
            || entry_meta.file_type().is_symlink()
            || crate::util::is_reparse_point(&entry_meta)
        {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("dep-") {
            dep_info = Some(entry.path());
            continue;
        }
        if name.ends_with(".json") {
            json_path = Some(entry.path());
            continue;
        }
        if name == "invoked.timestamp" {
            continue;
        }
        if entry
            .metadata()
            .map(|meta| meta.len() > 4 * 1024 * 1024)
            .unwrap_or(true)
        {
            continue;
        }
        let content = crate::util::read_small_text(&entry.path(), 4 * 1024 * 1024)
            .ok()?
            .trim()
            .to_string();
        candidates.push((name, content));
    }

    let ((memo_file, memo_hash), extra_files) = pick_memo(candidates)?;
    let kind = classify_kind(&memo_file);
    let json = json_path
        .and_then(|path| crate::util::read_small_text(&path, 4 * 1024 * 1024).ok())
        .and_then(|text| parse_fingerprint(&text));
    Some(ParsedUnit {
        kind,
        memo_file,
        memo_hash,
        json,
        dep_info,
        extra_files,
    })
}

/// Choose the memo file among a unit dir's remaining files: the one whose
/// content is a 16-hex hash. Cargo also keeps cached diagnostics in the same
/// directory (`output-*`) — those are state, not fingerprints. When nothing
/// looks like a hash the first candidate is used anyway, so a corrupted unit
/// still shows up in forensics instead of disappearing.
fn pick_memo(mut candidates: Vec<(String, String)>) -> Option<((String, String), Vec<String>)> {
    if candidates.is_empty() {
        return None;
    }
    let index = candidates
        .iter()
        .position(|(_, content)| looks_like_hash(content))
        .unwrap_or(0);
    let (name, hash) = candidates.remove(index);
    let extras = candidates.into_iter().map(|(name, _)| name).collect();
    Some(((name, hash), extras))
}

/// A fingerprint memo file holds exactly 16 hex characters.
pub(crate) fn looks_like_hash(text: &str) -> bool {
    text.len() == 16 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Directories that back a unit's artifacts (shared by the reader and by
/// `evict`): classic `build/<package>-<hex>/` anchors (dash/underscore and
/// bare-hash candidates), or the new per-unit root `build/<pkg>/<hash>/`.
pub(crate) fn build_anchor_dirs(build_root: &Path, unit: &Unit) -> Vec<PathBuf> {
    if unit.layout == UnitLayout::New {
        return vec![unit.unit_dir.clone()];
    }
    let build_dir = build_root.join(&unit.profile).join("build");
    let pkg_plain = &unit.package;
    let pkg_underscored = unit.package.replace('-', "_");
    let mut candidates = Vec::new();
    candidates.push(build_dir.join(format!("{pkg_underscored}-{}", unit.dir_suffix)));
    if pkg_plain != &pkg_underscored {
        candidates.push(build_dir.join(format!("{pkg_plain}-{}", unit.dir_suffix)));
    }
    candidates.push(build_dir.join(&unit.dir_suffix));
    candidates
}

/// Artifacts that belong to a unit, found by suffix (fingerprint dir hash
/// == deps filename suffix) — `deps/*-{hex}.rlib|rmeta|so…` and, for build
/// script units, the whole `build/{hex}/` subtree. Registry and workspace
/// units look identical here.
pub struct ArtifactInfo {
    pub paths: Vec<(PathBuf, u64, Option<SystemTime>)>,
    pub bytes: u64,
    pub newest: Option<SystemTime>,
}

pub fn artifacts_for(build_root: &Path, unit: &Unit) -> ArtifactInfo {
    let mut paths = Vec::new();
    match unit.layout {
        UnitLayout::Classic => collect_classic_artifacts(build_root, unit, &mut paths),
        UnitLayout::New => collect_new_artifacts(unit, &mut paths),
    }

    let mut bytes = 0;
    let mut newest: Option<SystemTime> = None;
    for (_, size, mtime) in &paths {
        bytes += size;
        if let Some(m) = mtime {
            if newest.map_or(true, |n| *m > n) {
                newest = Some(*m);
            }
        }
    }
    ArtifactInfo {
        paths,
        bytes,
        newest,
    }
}

fn collect_classic_artifacts(
    build_root: &Path,
    unit: &Unit,
    paths: &mut Vec<(PathBuf, u64, Option<SystemTime>)>,
) {
    let profile_dir = build_root.join(&unit.profile);
    let deps_dir = profile_dir.join("deps");
    if is_real_dir(&deps_dir) {
        let suffix = format!("-{}", unit.dir_suffix);
        if let Ok(entries) = fs::read_dir(&deps_dir) {
            for entry in entries.flatten() {
                // Regular files only; a symlink/FIFO here must not be copied.
                if !entry
                    .file_type()
                    .map(|kind| kind.is_file())
                    .unwrap_or(false)
                {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                // Compare on the STEM so extensions don't hide the match:
                // `libserde-102a….rlib` → stem `libserde-102a…` ends with `-102a…`.
                let stem = Path::new(&name)
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or(name.clone());
                if !stem.ends_with(&suffix) {
                    continue;
                }
                if let Ok(meta) = entry.metadata() {
                    paths.push((entry.path(), meta.len(), meta.modified().ok()));
                }
            }
        }
    }

    if unit.kind != UnitKind::Lib {
        for candidate in build_anchor_dirs(build_root, unit) {
            if !is_real_dir(&candidate) {
                continue;
            }
            for entry in WalkDir::new(&candidate).min_depth(1) {
                let Ok(entry) = entry else { continue };
                if !entry.file_type().is_file() {
                    continue;
                }
                if let Ok(meta) = entry.metadata() {
                    paths.push((entry.path().to_path_buf(), meta.len(), meta.modified().ok()));
                }
            }
        }
    }
}

/// New layout: artifacts live in the unit's `out/` (rustc link outputs,
/// build-script binaries), `run/` (run-build-script state) and at the unit
/// root (`output`, `stderr`, `stdout`, `root-output`, …). `fingerprint/` is
/// handled separately by the vault.
fn collect_new_artifacts(unit: &Unit, paths: &mut Vec<(PathBuf, u64, Option<SystemTime>)>) {
    for sub in ["out", "run"] {
        let dir = unit.unit_dir.join(sub);
        if !is_real_dir(&dir) {
            continue;
        }
        for entry in WalkDir::new(&dir).min_depth(1) {
            let Ok(entry) = entry else { continue };
            if !entry.file_type().is_file() {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                paths.push((entry.path().to_path_buf(), meta.len(), meta.modified().ok()));
            }
        }
    }
    let Ok(entries) = fs::read_dir(&unit.unit_dir) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry
            .file_type()
            .map(|kind| kind.is_file())
            .unwrap_or(false)
        {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            paths.push((entry.path(), meta.len(), meta.modified().ok()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim sample from the live shared cache (1.97.1 generation).
    const SAMPLE_JSON: &str = r#"{"rustc":12019306335353385202,"features":"[\"default\", \"derive\", \"serde_derive\", \"std\"]","declared_features":"[\"alloc\", \"default\", \"derive\", \"rc\", \"serde_derive\", \"std\", \"unstable\"]","target":11327258112168116673,"profile":15657897354478470176,"path":14081935628356765094,"deps":[[6557439603276904804,"build_script_build",false,14091436140065671243],[11029742160753049355,"serde_core",false,8824494307375987869],[13312204359551525516,"serde_derive",false,16721730783038555939]],"local":[{"CheckDepInfo":{"dep_info":"debug\\.fingerprint\\serde-102a33f055a8d229\\dep-lib-serde","checksum":false}}],"rustflags":[],"config":9396254390672932401,"compile_kind":0}"#;

    #[test]
    fn reads_and_parses_synthetic_unit() -> Result<()> {
        let root = tempfile::tempdir()?;
        let unit_dir = root
            .path()
            .join("debug/.fingerprint/serde-102a33f055a8d229");
        fs::create_dir_all(&unit_dir)?;
        // memo file: 16 hex chars, no trailing newline (verbatim format)
        fs::write(unit_dir.join("lib-serde"), "5d82713a7f2d05e2")?;
        fs::write(unit_dir.join("lib-serde.json"), SAMPLE_JSON)?;
        fs::write(unit_dir.join("dep-lib-serde"), [0u8; 69])?;
        fs::write(unit_dir.join("invoked.timestamp"), "")?;
        fs::create_dir_all(root.path().join("debug/deps"))?;
        fs::write(
            root.path()
                .join("debug/deps/libserde-102a33f055a8d229.rlib"),
            [0u8; 10],
        )?;

        let units = read_units(root.path())?;
        assert_eq!(units.len(), 1);

        let unit = &units[0];
        assert_eq!(unit.package, "serde");
        assert_eq!(unit.dir_suffix, "102a33f055a8d229");
        assert_eq!(unit.profile, "debug");
        assert_eq!(unit.kind, UnitKind::Lib);
        assert_eq!(unit.memo_hash.as_deref(), Some("5d82713a7f2d05e2"));
        assert!(unit.dep_info.is_some());

        let json = unit.json.as_ref().expect("sample json must parse");
        assert_eq!(json.rustc, "12019306335353385202");
        assert!(json.features.contains(&"derive".to_string()));
        assert!(json.declared_features.contains(&"unstable".to_string()));
        assert_eq!(json.deps.len(), 3);
        assert_eq!(json.deps[1].name, "serde_core");
        assert_eq!(json.dep_info_paths.len(), 1);

        // Suffix-matching artifact attach.
        let arts = artifacts_for(root.path(), unit);
        assert_eq!(arts.paths.len(), 1);
        assert_eq!(arts.bytes, 10);
        assert!(arts.newest.is_some());
        Ok(())
    }

    #[test]
    fn reads_new_layout_units() -> Result<()> {
        let root = tempfile::tempdir()?;
        let unit_dir = root.path().join("debug/build/anyhow/9709d57b46b8d526");
        fs::create_dir_all(unit_dir.join("fingerprint"))?;
        fs::create_dir_all(unit_dir.join("out"))?;
        fs::write(unit_dir.join("fingerprint/lib-anyhow"), "5d82713a7f2d05e2")?;
        fs::write(unit_dir.join("fingerprint/lib-anyhow.json"), SAMPLE_JSON)?;
        fs::write(unit_dir.join("fingerprint/dep-lib-anyhow"), [0u8; 69])?;
        fs::write(unit_dir.join("fingerprint/invoked.timestamp"), "")?;
        fs::write(
            unit_dir.join("out/libanyhow-9709d57b46b8d526.rlib"),
            [0u8; 10],
        )?;
        fs::write(
            unit_dir.join("out/libanyhow-9709d57b46b8d526.rmeta"),
            [0u8; 5],
        )?;
        fs::write(unit_dir.join("out/anyhow-9709d57b46b8d526.d"), [0u8; 3])?;

        let units = read_units(root.path())?;
        assert_eq!(units.len(), 1);
        let unit = &units[0];
        assert_eq!(unit.layout, UnitLayout::New);
        assert_eq!(unit.package, "anyhow");
        assert_eq!(unit.dir_suffix, "9709d57b46b8d526");
        assert_eq!(unit.dir_name, "anyhow-9709d57b46b8d526");
        assert_eq!(unit.memo_hash.as_deref(), Some("5d82713a7f2d05e2"));
        assert_eq!(unit.fingerprint_dir, unit_dir.join("fingerprint"));
        assert_eq!(unit.unit_dir, unit_dir);
        assert_eq!(
            unit.fingerprint_rel(),
            "build/anyhow/9709d57b46b8d526/fingerprint"
        );

        let arts = artifacts_for(root.path(), unit);
        assert_eq!(arts.paths.len(), 3, "rlib + rmeta + d");
        assert_eq!(arts.bytes, 18);
        Ok(())
    }

    #[test]
    fn reads_mixed_layouts_in_one_build_dir() -> Result<()> {
        let root = tempfile::tempdir()?;
        let classic = root
            .path()
            .join("debug/.fingerprint/serde-102a33f055a8d229");
        fs::create_dir_all(&classic)?;
        fs::write(classic.join("lib-serde"), "5d82713a7f2d05e2")?;
        fs::create_dir_all(root.path().join("debug/deps"))?;
        fs::write(
            root.path()
                .join("debug/deps/libserde-102a33f055a8d229.rlib"),
            [0u8; 4],
        )?;

        let new = root.path().join("release/build/anyhow/9709d57b46b8d526");
        fs::create_dir_all(new.join("fingerprint"))?;
        fs::create_dir_all(new.join("out"))?;
        fs::write(new.join("fingerprint/lib-anyhow"), "aaaaaaaaaaaaaaaa")?;
        fs::write(new.join("out/libanyhow-9709d57b46b8d526.rlib"), [0u8; 4])?;

        let units = read_units(root.path())?;
        assert_eq!(units.len(), 2);
        assert!(
            units
                .iter()
                .any(|unit| unit.layout == UnitLayout::Classic && unit.profile == "debug")
        );
        assert!(
            units
                .iter()
                .any(|unit| unit.layout == UnitLayout::New && unit.profile == "release")
        );
        Ok(())
    }

    #[test]
    fn layout_decision_follows_cargo_version_and_flags() {
        let none: Vec<String> = Vec::new();
        let new_flag = vec!["-Zbuild-dir-new-layout".to_string()];
        let split_flag = vec!["-Z".to_string(), "build-dir-new-layout".to_string()];

        assert_eq!(
            layout_for_cargo("cargo 1.91.0 (000000000 2026-01-01)", &none),
            UnitLayout::Classic
        );
        assert_eq!(
            layout_for_cargo("cargo 1.99.0 (000000000 2026-01-01)", &none),
            UnitLayout::Classic
        );
        assert_eq!(
            layout_for_cargo("cargo 1.99.0-nightly (7c83d4cc0 2026-07-29)", &none),
            UnitLayout::New
        );
        assert_eq!(
            layout_for_cargo("cargo 1.98.0-nightly (000000000 2026-01-01)", &none),
            UnitLayout::Classic
        );
        assert_eq!(
            layout_for_cargo("cargo 1.98.0-nightly (000000000 2026-01-01)", &new_flag),
            UnitLayout::New
        );
        assert_eq!(
            layout_for_cargo("cargo 1.98.0-nightly (000000000 2026-01-01)", &split_flag),
            UnitLayout::New
        );
        assert_eq!(
            layout_for_cargo("cargo 1.100.0 (000000000 2026-01-01)", &none),
            UnitLayout::New
        );
        assert_eq!(layout_for_cargo("garbage", &none), UnitLayout::Classic);
    }

    #[test]
    fn run_units_attach_their_build_tree() -> Result<()> {
        let root = tempfile::tempdir()?;
        let unit_dir = root.path().join("debug/.fingerprint/x-1122334455667788");
        fs::create_dir_all(&unit_dir)?;
        fs::write(unit_dir.join("build-script-build"), "aaaabbbbccccdddd")?;
        fs::create_dir_all(root.path().join("debug/build/1122334455667788"))?;
        fs::write(
            root.path().join("debug/build/1122334455667788/output"),
            [0u8; 4],
        )?;
        fs::write(
            root.path().join("debug/build/1122334455667788/stderr"),
            [0u8; 6],
        )?;

        let units = read_units(root.path())?;
        assert_eq!(units.len(), 1);
        let unit = &units[0];
        assert_eq!(unit.kind, UnitKind::BuildScriptCompile);
        let arts = artifacts_for(root.path(), unit);
        assert_eq!(arts.paths.len(), 2, "output + stderr attached");
        assert_eq!(arts.bytes, 10);
        assert!(arts.newest.is_some());
        Ok(())
    }

    #[test]
    fn cached_diagnostics_are_not_mistaken_for_the_memo() -> Result<()> {
        let root = tempfile::tempdir()?;
        let unit_dir = root
            .path()
            .join("debug/.fingerprint/serde-102a33f055a8d229");
        fs::create_dir_all(&unit_dir)?;
        fs::write(unit_dir.join("lib-serde"), "5d82713a7f2d05e2")?;
        fs::write(unit_dir.join("dep-lib-serde"), [0u8; 8])?;
        // Cargo's message cache: rendered diagnostics live in the same dir.
        fs::write(
            unit_dir.join("output-lib-serde"),
            r#"{"$message_type":"diagnostic","message":"unused import"}"#,
        )?;

        let units = read_units(root.path())?;
        assert_eq!(units.len(), 1);
        let unit = &units[0];
        assert_eq!(unit.memo_file, "lib-serde", "the hash file wins");
        assert_eq!(unit.memo_hash.as_deref(), Some("5d82713a7f2d05e2"));
        assert_eq!(unit.extra_files, vec!["output-lib-serde".to_string()]);
        Ok(())
    }

    #[test]
    fn dep_hashes_resolve_to_memo_hashes_little_endian() {
        // Example: serde's fingerprint lists serde_core as 9416646317397223793,
        // and serde_core-b468be6fa8c1f936/lib-serde_core contains 71a9f323efa5ae82.
        let dep = DepRef {
            name: "serde_core".into(),
            unit_hash: "9416646317397223793".into(),
        };
        assert_eq!(dep.memo_hash().as_deref(), Some("71a9f323efa5ae82"));

        let junk = DepRef {
            name: "x".into(),
            unit_hash: "not-a-number".into(),
        };
        assert!(junk.memo_hash().is_none());
    }

    #[test]
    fn dep_edges_join_the_graph_by_memo_hash() -> Result<()> {
        let root = tempfile::tempdir()?;
        let core = root
            .path()
            .join("debug/.fingerprint/serde_core-b468be6fa8c1f936");
        fs::create_dir_all(&core)?;
        fs::write(core.join("lib-serde_core"), "71a9f323efa5ae82")?;
        fs::create_dir_all(root.path().join("debug/deps"))?;
        fs::write(
            root.path()
                .join("debug/deps/libserde_core-b468be6fa8c1f936.rlib"),
            [0u8; 4],
        )?;

        let serde = root
            .path()
            .join("debug/.fingerprint/serde-746d173581f1a314");
        fs::create_dir_all(&serde)?;
        fs::write(serde.join("lib-serde"), "5d82713a7f2d05e2")?;
        fs::write(
            serde.join("lib-serde.json"),
            r#"{"deps":[[11029742160753049355,"serde_core",false,9416646317397223793]]}"#,
        )?;
        fs::write(
            root.path()
                .join("debug/deps/libserde-746d173581f1a314.rlib"),
            [0u8; 4],
        )?;

        let units = read_units(root.path())?;
        assert_eq!(units.len(), 2);
        let edges = dep_edges(&units);
        let serde_at = units.iter().position(|u| u.package == "serde").unwrap();
        let core_at = units
            .iter()
            .position(|u| u.package == "serde_core")
            .unwrap();
        assert_eq!(edges[serde_at], vec![core_at]);
        assert!(edges[core_at].is_empty());
        Ok(())
    }

    #[test]
    fn pick_memo_prefers_hash_content_and_falls_back() {
        let candidates = vec![
            (
                "output-lib-x".to_string(),
                r#"{"message":"warning"}"#.to_string(),
            ),
            ("lib-x".to_string(), "5d82713a7f2d05e2".to_string()),
        ];
        let ((name, hash), extras) = pick_memo(candidates).expect("a memo exists");
        assert_eq!(name, "lib-x");
        assert_eq!(hash, "5d82713a7f2d05e2");
        assert_eq!(extras, vec!["output-lib-x".to_string()]);

        // Nothing hash-shaped: the first candidate is the fallback, so a
        // corrupted unit still shows up in forensics instead of vanishing.
        let candidates = vec![("weird".to_string(), "not a hash".to_string())];
        let ((name, _), extras) = pick_memo(candidates).expect("fallback");
        assert_eq!(name, "weird");
        assert!(extras.is_empty());

        assert!(pick_memo(Vec::new()).is_none());
    }
}
