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
//! JSON schema — mostly opaque HASH NUMBERS plus two human facts:
//! `{rustc, features, declared_features, target, profile, path, deps,
//!  local, rustflags, config, compile_kind}` where `features` /
//! `declared_features` are STRINGS containing serialized JSON arrays.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
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

/// One parsed `.fingerprint/<package>-<16hex>/` directory.
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
    /// Name of the memo file (`lib-serde`, `build-script-build`, …)
    pub memo_file: String,
    /// Content of the memo file — the authoritative hash
    pub memo_hash: Option<String>,
    pub json: Option<FingerprintJson>,
    pub dep_info: Option<PathBuf>,
    /// Files inside the unit dir (for forensics completeness).
    pub extra_files: Vec<String>,
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

/// Read every unit directory under all `.fingerprint/` roots inside the build dir.
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
        let fp_root = build_root.join(&profile).join(".fingerprint");
        let fp_meta = match fs::symlink_metadata(&fp_root) {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        if !fp_meta.is_dir()
            || fp_meta.file_type().is_symlink()
            || crate::util::is_reparse_point(&fp_meta)
        {
            continue; // finals (CACHEDIR.TAG …), locks, symlinks — no fingerprints here
        }
        for unit_entry in
            fs::read_dir(&fp_root).with_context(|| format!("reading {}", fp_root.display()))?
        {
            let unit_entry = unit_entry?;
            // `file_type()` does not follow symlinks: a unit dir must be real.
            if !unit_entry.file_type()?.is_dir() {
                continue;
            }
            let unit_dir = unit_entry.path();
            if let Some(unit) = read_unit_dir(&profile, &unit_dir) {
                units.push(unit);
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

fn read_unit_dir(profile: &str, unit_dir: &Path) -> Option<Unit> {
    let dir_name = unit_dir.file_name()?.to_string_lossy().into_owned();
    let (package, dir_suffix) = split_dir_name(&dir_name)?;

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

    let ((memo_file_name, memo_hash), extra_files) = pick_memo(candidates)?;
    let kind = classify_kind(&memo_file_name);

    let json = json_path
        .and_then(|path| crate::util::read_small_text(&path, 4 * 1024 * 1024).ok())
        .and_then(|text| parse_fingerprint(&text));

    Some(Unit {
        dir_name,
        package,
        dir_suffix,
        profile: profile.to_string(),
        kind,
        memo_file: memo_file_name,
        memo_hash: Some(memo_hash),
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

/// Candidate `build/<package>-<hex>` anchor dirs for a build-script unit
/// (dashes may be underscore-normalized in artifact paths — check both
/// plus the bare-hash fallback). Shared by the reader and by `evict`.
pub(crate) fn build_anchor_dirs(build_root: &Path, unit: &Unit) -> Vec<PathBuf> {
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
    let profile_dir = build_root.join(&unit.profile);
    let mut paths = Vec::new();

    let deps_dir = profile_dir.join("deps");
    let deps_real = fs::symlink_metadata(&deps_dir)
        .map(|meta| {
            meta.is_dir() && !meta.file_type().is_symlink() && !crate::util::is_reparse_point(&meta)
        })
        .unwrap_or(false);
    if let Ok(entries) = fs::read_dir(&deps_dir) {
        if !deps_real {
            return ArtifactInfo {
                paths: Vec::new(),
                bytes: 0,
                newest: None,
            };
        }
        let suffix = format!("-{}", unit.dir_suffix);
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

    if unit.kind != UnitKind::Lib {
        for candidate in build_anchor_dirs(build_root, unit) {
            let is_real_dir = fs::symlink_metadata(&candidate)
                .map(|meta| {
                    meta.is_dir()
                        && !meta.file_type().is_symlink()
                        && !crate::util::is_reparse_point(&meta)
                })
                .unwrap_or(false);
            if !is_real_dir {
                continue;
            }
            for entry in WalkDir::new(&candidate).min_depth(1) {
                let Ok(entry) = entry else { continue };
                if !entry.file_type().is_file() {
                    continue;
                }
                if let Ok(meta) = entry.metadata() {
                    paths.push((entry.path().into(), meta.len(), meta.modified().ok()));
                }
            }
        }
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
