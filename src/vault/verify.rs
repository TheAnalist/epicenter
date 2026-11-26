//! Verify: audit a vault generation against its manifest.

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use rayon::prelude::*;

use crate::util::{self, metadata_nofollow};

use super::harvest::ceil_secs;
use super::layout::{check_store_trust, generation_names, store_is_read_only, units_dir};
use super::manifest::{Manifest, UnitEntry, load_manifest};
use super::restore::read_small_regular;

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
    let mut budget = util::ScanBudget::new("verify");
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
        // One no-follow probe decides every `units/` traversal below: a
        // symlinked or missing directory is never followed, and the audit
        // reports it instead of reading whatever it points at.
        let units_traversable = match util::metadata_nofollow(&units) {
            Ok(meta) if meta.is_dir() => true,
            Ok(_) => {
                report.problems.push(format!(
                    "units directory {} is a symlink/reparse or not a directory",
                    units.display()
                ));
                false
            }
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                report.problems.push(format!(
                    "units directory {} is a symlink/reparse or not a directory",
                    units.display()
                ));
                false
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
            Err(err) => {
                report.problems.push(format!(
                    "unreadable units directory {}: {err}",
                    units.display()
                ));
                false
            }
        };

        // Content-addressed blobs are shared between units. Verify each
        // object once (decode cap = the largest recorded size) and compare
        // that result against every reference below.
        let blobs = unique_blobs(&manifest);
        let checks: std::collections::BTreeMap<&str, BlobCheck> = crate::settings::scan_pool()
            .install(|| {
                blobs
                    .par_iter()
                    .map(|(object, max_size)| {
                        (
                            *object,
                            check_blob(&generation_root, object, *max_size, read_only),
                        )
                    })
                    .collect()
            });

        let ctx = AuditCtx {
            units: &units,
            read_only,
        };
        let audits: Vec<UnitAudit> = if manifest.units.len() > 1 {
            crate::settings::scan_pool().install(|| {
                manifest
                    .units
                    .par_iter()
                    .map(|entry| ctx.audit(entry, &checks))
                    .collect()
            })
        } else {
            manifest
                .units
                .iter()
                .map(|entry| ctx.audit(entry, &checks))
                .collect()
        };
        for audit in audits {
            report.files = report.files.saturating_add(audit.files);
            report.bytes = report.bytes.saturating_add(audit.bytes);
            report.problems.extend(audit.problems);
        }

        // Reject extra files in recorded unit dirs too: a manifest hash
        // list is only meaningful if the set of files is exact.
        if units_traversable {
            for entry in &manifest.units {
                let unit_dir = units.join(&entry.name);
                let expected: std::collections::BTreeSet<String> =
                    entry.files.iter().map(|file| file.path.clone()).collect();
                let mut walk = util::SafeWalk::new(&unit_dir).walk_with(&mut budget);
                for file in walk.by_ref() {
                    let file = match file {
                        Ok(file) => file,
                        Err(err) => {
                            report
                                .problems
                                .push(format!("unreadable unit dir: units/{} ({err})", entry.name));
                            continue;
                        }
                    };
                    let rel = file
                        .path()
                        .strip_prefix(&unit_dir)
                        .map(|rel| rel.to_string_lossy().replace('\\', "/"))
                        .unwrap_or_default();
                    match metadata_nofollow(file.path()) {
                        Ok(meta) if !meta.is_file() => continue,
                        Ok(_) => (),
                        Err(err) => {
                            // An entry we cannot stat is still a candidate
                            // extra file: never drop it from the audit.
                            report.problems.push(format!(
                                "unreadable entry in units/{}/{}: {err}",
                                entry.name, rel
                            ));
                            continue;
                        }
                    }
                    if !expected.contains(&rel) {
                        report
                            .problems
                            .push(format!("unrecorded file: units/{}/{}", entry.name, rel));
                    }
                }
                if walk.truncated() {
                    report
                        .problems
                        .push("scan budget exceeded — extra-file audit truncated".to_string());
                    break;
                }
            }
        }

        // Ordering audit: a unit must be at least as new as its
        // dependencies, or cargo recompiles it after a restore ("the
        // dependency `X` was rebuilt"). Edges come from the stored
        // fingerprints; the join key is the dependency's memo hash — the
        // same value serde's `serde_core` edge (9416646317397223793) and
        // serde_core's memo file (71a9f323efa5ae82) share.
        if units_traversable {
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
        }
        report.units = manifest.units.len();

        // Unit groups on disk that the manifest doesn't record.
        if units_traversable {
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

/// One generation's read-only view of the store, used by the parallel audit.
pub(crate) struct AuditCtx<'a> {
    pub(crate) units: &'a Path,
    pub(crate) read_only: bool,
}

#[derive(Default)]
pub(crate) struct UnitAudit {
    pub(crate) problems: Vec<String>,
    pub(crate) files: usize,
    pub(crate) bytes: u64,
}

/// The verified content of one blob, or why it could not be read.
pub(crate) enum BlobCheck {
    Verified { size: u64, hash: String },
    Unsafe,
    Missing,
    Unreadable(String),
}

/// Every distinct blob object in the manifest, with the largest recorded
/// decoded size (the decode cap for its one verification).
pub(crate) fn unique_blobs(manifest: &Manifest) -> std::collections::BTreeMap<&str, u64> {
    let mut blobs: std::collections::BTreeMap<&str, u64> = std::collections::BTreeMap::new();
    for entry in &manifest.units {
        for file in &entry.files {
            if let Some(object) = file.object.as_deref() {
                let slot = blobs.entry(object).or_insert(0);
                *slot = (*slot).max(file.size);
            }
        }
    }
    blobs
}

/// Probe and hash one blob without following links or trusting foreign bytes.
fn check_blob(generation_root: &Path, object: &str, max_size: u64, read_only: bool) -> BlobCheck {
    let blob = generation_root.join(object);
    match util::metadata_nofollow(&blob) {
        Ok(meta) if meta.is_file() && (util::owned_by_us(&blob, &meta) || read_only) => {}
        Ok(_) => return BlobCheck::Unsafe,
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            return BlobCheck::Unsafe;
        }
        Err(_) => return BlobCheck::Missing,
    }
    match util::decompress_file_hashed(&blob, !read_only, max_size) {
        Ok((size, hash)) => BlobCheck::Verified { size, hash },
        Err(err) => BlobCheck::Unreadable(format!("{err:#}")),
    }
}

impl AuditCtx<'_> {
    /// Audit one unit group. Pure reads: safe to run on a worker, and every
    /// message it produces is merged in manifest order by the caller.
    pub(crate) fn audit(
        &self,
        entry: &UnitEntry,
        blobs: &std::collections::BTreeMap<&str, BlobCheck>,
    ) -> UnitAudit {
        let units = self.units;
        let read_only = self.read_only;
        let mut out = UnitAudit::default();
        for file in &entry.files {
            if let Some(object) = &file.object {
                match blobs.get(object.as_str()) {
                    Some(BlobCheck::Unsafe) => {
                        out.problems.push(format!("unsafe/missing blob: {object}"))
                    }
                    Some(BlobCheck::Missing) | None => {
                        out.problems.push(format!("missing blob: {object}"))
                    }
                    // The blob exists and is ours: it counts as a stored file
                    // even if its bytes cannot be decoded.
                    Some(check) => {
                        out.files = out.files.saturating_add(1);
                        out.bytes = out.bytes.saturating_add(file.size);
                        match check {
                            BlobCheck::Verified { size, hash }
                                if *size != file.size || hash != &file.sha256 =>
                            {
                                out.problems.push(format!(
                                    "blob drift: {object} (recorded {} bytes/{}, found {size} bytes/{})",
                                    file.size,
                                    &file.sha256[..file.sha256.len().min(12)],
                                    &hash[..hash.len().min(12)]
                                ));
                            }
                            BlobCheck::Unreadable(err) => out
                                .problems
                                .push(format!("blob unreadable: {object}: {err}")),
                            _ => {}
                        }
                    }
                }
                continue;
            }
            let path = units.join(&entry.name).join(&file.path);
            let rel = Path::new(&entry.name).join(&file.path);
            if let Err(err) = util::check_regular_chain(units, &rel) {
                out.problems.push(format!(
                    "unsafe path: {} ({err:#})",
                    display_join(&path, units)
                ));
                continue;
            }
            let meta = match util::metadata_nofollow(&path) {
                Ok(meta) => meta,
                Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                    out.problems.push(format!(
                        "symlink/reparse in store (refused): {}",
                        display_join(&path, units)
                    ));
                    continue;
                }
                Err(_) => {
                    out.problems
                        .push(format!("missing: {}", display_join(&path, units)));
                    continue;
                }
            };
            if !meta.is_file() {
                out.problems.push(format!(
                    "not a regular file: {}",
                    display_join(&path, units)
                ));
                continue;
            }
            if !util::owned_by_us(&path, &meta) && !read_only {
                out.problems.push(format!(
                    "foreign-owned file: {}",
                    display_join(&path, units)
                ));
            }
            out.files = out.files.saturating_add(1);
            out.bytes = out.bytes.saturating_add(meta.len());
            if meta.len() != file.size {
                out.problems.push(format!(
                    "size drift: {} (recorded {}, found {})",
                    display_join(&path, units),
                    file.size,
                    meta.len()
                ));
            }
            let found_stamp = meta.modified().map(ceil_secs).unwrap_or(0);
            if found_stamp != entry.stamp {
                out.problems.push(format!(
                    "stamp drift: {} (recorded {}, found {})",
                    display_join(&path, units),
                    entry.stamp,
                    found_stamp
                ));
            }
            if file.sha256.is_empty() {
                out.problems.push(format!(
                    "no recorded SHA-256: {} (re-harvest this generation)",
                    display_join(&path, units)
                ));
            } else {
                match util::sha256_file(&path) {
                    Ok(found) if found != file.sha256 => out.problems.push(format!(
                        "content drift: {} (recorded {}, found {})",
                        display_join(&path, units),
                        &file.sha256[..file.sha256.len().min(12)],
                        &found[..found.len().min(12)]
                    )),
                    Ok(_) => {}
                    Err(err) => out
                        .problems
                        .push(format!("unreadable: {}: {err}", display_join(&path, units))),
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
                        out.problems.push(format!(
                            "hash drift: {} (recorded {}; {detail})",
                            display_join(&path, units),
                            entry.hash
                        ));
                    }
                    Some(text)
                        if file.path != entry.memo
                            && !crate::fingerprint::looks_like_hash(text.trim()) =>
                    {
                        out.problems.push(format!(
                            "malformed memo file: {} (content is not a 16-hex hash)",
                            display_join(&path, units)
                        ));
                    }
                    Some(_) => {}
                    None => out.problems.push(format!(
                        "unreadable/symlinked memo file: {}",
                        display_join(&path, units)
                    )),
                }
            }
        }
        out
    }
}

/// Path for humans: relative to `base` when possible.
fn display_join(path: &Path, base: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
