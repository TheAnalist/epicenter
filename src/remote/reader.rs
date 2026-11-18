//! Reader orchestration: verify a signed index, select compatible units,
//! fetch only their blobs, and import them into the local vault.

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::{
    BlobRef, Compression, IndexPointer, LocalEnvironment, RemoteSource, RemoteUnit, SignedIndex,
    SourceKind, cache, state, verify_body, verify_index,
};
use crate::fingerprint::UnitLayout;
use crate::lockfile::{LockIndex, LockSource};
use crate::settings::{RemotePolicy, RemoteTier};
use crate::vault::{self, ImportFile, ImportSource, ImportUnit};

/// Everything one fetch/import needs. Tests inject `local`, `generation` and
/// `state_root`; production derives them from the child toolchain.
pub struct FetchRequest<'a> {
    pub remote: &'a RemotePolicy,
    pub source: &'a dyn RemoteSource,
    pub store_root: &'a Path,
    pub state_root: Option<&'a Path>,
    pub packages: Option<&'a LockIndex>,
    pub selector: Option<&'a str>,
    pub layout: Option<UnitLayout>,
    pub profile: Option<&'a str>,
    pub unit_filter: Option<&'a str>,
    pub local: Option<&'a LocalEnvironment>,
    pub generation: Option<&'a str>,
    pub now: u64,
    pub dry_run: bool,
}

/// The outcome of one reader pass. A remote miss is data, not an error: `exec`
/// falls back to a local build and `store fetch` turns `fallback` into an
/// exit status.
#[derive(Debug, Default)]
pub struct FetchReport {
    pub disabled: bool,
    pub sequence: u64,
    pub key_id: String,
    pub tier: String,
    pub candidates: usize,
    pub imported: usize,
    pub skipped: usize,
    pub files: usize,
    pub bytes: u64,
    pub cache_store: Option<PathBuf>,
    pub fallback: Option<String>,
    pub warning: Option<String>,
    pub offline: bool,
}

pub fn fetch_and_import(request: &FetchRequest<'_>) -> Result<FetchReport> {
    let mut report = FetchReport {
        tier: request.remote.tier.as_str().to_string(),
        ..Default::default()
    };
    if !request.remote.enabled {
        report.disabled = true;
        return Ok(report);
    }
    // The cache and its store are local write targets. Reject a symlinked or
    // reparse root before reading a manifest or creating a staging dir.
    cache::validate_layout(request.remote)?;
    let cache_root = cache::endpoint_root(request.remote)?;
    let cache_store_root = cache::store_root(request.remote)?;
    if overlaps(request.store_root, &cache_root) || overlaps(request.store_root, &cache_store_root)
    {
        return Ok(fallback(
            report,
            "remote cache overlaps the configured store; choose a separate cache work root",
        ));
    }
    if request.store_root.exists()
        && let Err(err) = vault::check_store_trust(request.store_root)
    {
        return Ok(fallback(report, format!("{err:#}")));
    }

    let (cache, _cache_lock) = if request.dry_run {
        (cache::Cache::open_reader(request.remote)?, None)
    } else {
        let (cache, lock) = cache::Cache::open_writer(request.remote)?;
        (cache, Some(lock))
    };

    let pointer_bytes = match request.source.fetch_pointer() {
        Ok(bytes) => bytes,
        Err(err) => {
            report.offline = true;
            match cache.read_pointer()? {
                Some(bytes) => bytes,
                None => return Ok(fallback(report, format!("offline: {err}"))),
            }
        }
    };
    let pointer: IndexPointer = match serde_json::from_slice(&pointer_bytes) {
        Ok(pointer) => pointer,
        Err(err) => {
            if report.offline && !request.dry_run {
                let _ = cache.remove_pointer();
            }
            return Ok(tampered(
                report,
                format!("remote index pointer is malformed: {err}"),
            ));
        }
    };
    let pinned = request
        .remote
        .publisher_key
        .as_deref()
        .context("remote is enabled without a pinned publisher key")?;
    if let Err(err) = pointer.verify(pinned, request.now) {
        return Ok(tampered(report, format!("{err:#}")));
    }
    report.sequence = pointer.sequence;
    report.key_id = pointer.key_id.clone();

    let state_root = match request.state_root {
        Some(root) => root.to_path_buf(),
        None => crate::paths::state_dir()?,
    };
    if let Err(err) = state::check_pointer_at(&state_root, request.remote, &pointer) {
        return Ok(fallback(report, format!("{err:#}")));
    }

    let mut cached_body = None;
    if let Some(bytes) = cache.read_body(&pointer.body_sha256)? {
        if verify_body(&pointer, &bytes, request.now).is_ok() {
            cached_body = Some(bytes);
        } else if !request.dry_run {
            // A damaged cache entry must not pin the reader to a fallback.
            cache.remove_body(&pointer.body_sha256)?;
        }
    }
    let body_bytes = match cached_body {
        Some(bytes) => bytes,
        None => {
            if report.offline {
                return Ok(fallback(
                    report,
                    "offline and the accepted index body is not cached",
                ));
            }
            let bytes = match request
                .source
                .fetch_body(&pointer.body_sha256, super::MAX_INDEX_BODY_BYTES)
            {
                Ok(bytes) => bytes,
                Err(err) => return Ok(fallback(report, format!("fetching index body: {err:#}"))),
            };
            if !request.dry_run
                && let Err(err) = cache.install_body(&pointer.body_sha256, &bytes)
            {
                return Ok(fallback(report, format!("caching index body: {err:#}")));
            }
            bytes
        }
    };

    let index = match verify_index(
        &pointer_bytes,
        &body_bytes,
        pinned,
        request.remote.tier,
        request.now,
    ) {
        Ok(index) => index,
        Err(err) => return Ok(tampered(report, format!("{err:#}"))),
    };

    if !request.dry_run
        && let Err(err) = cache.install_pointer(&pointer_bytes)
    {
        return Ok(fallback(report, format!("caching index pointer: {err:#}")));
    }

    let local = match request.local {
        Some(local) => local.clone(),
        None => LocalEnvironment::gather_for(request.selector)?,
    };
    if let Err(err) = index.body().validate_for_local(request.remote.tier, &local) {
        return Ok(fallback(report, format!("{err:#}")));
    }

    let candidates: Vec<&RemoteUnit> = index
        .body()
        .units
        .iter()
        .filter(|unit| selected(unit, request))
        .collect();
    report.candidates = candidates.len();
    for unit in &candidates {
        report.files += unit.files.len();
        report.bytes = report
            .bytes
            .saturating_add(unit.files.iter().map(|file| file.size).sum::<u64>());
    }

    if request.dry_run {
        return Ok(report);
    }
    if candidates.is_empty() {
        finish_state(
            &state_root,
            request.remote,
            &index,
            request.now,
            &mut report,
        );
        return Ok(report);
    }

    let generation = match request.generation {
        Some(generation) => generation.to_string(),
        None => vault::parity_key_of(request.selector)?,
    };
    let toolchain = format!("rustc {} ({})", local.rustc.release, local.rustc.commit);
    let all_imports = build_imports(&candidates, &cache)?;

    let main_writable = vault::store_accepts_imports(request.store_root);
    let mut used_cache = !main_writable;
    let target = if used_cache {
        &cache_store_root
    } else {
        request.store_root
    };
    let missing = vault::missing_import_units(target, &generation, &all_imports)?;
    if used_cache {
        report.cache_store = Some(cache_store_root.clone());
    }
    if missing.is_empty() {
        // Every candidate is already in the target generation (or conflicts
        // with a local unit, which import would preserve). Do not touch the
        // blob cache at all.
        report.skipped += all_imports.len();
        report.files = 0;
        report.bytes = 0;
        finish_state(
            &state_root,
            request.remote,
            &index,
            request.now,
            &mut report,
        );
        return Ok(report);
    }
    if used_cache && !vault::store_accepts_imports(&cache_store_root) {
        report.fallback = Some(if cache_store_root.exists() {
            "store is read-only and the cache store is read-only; missing units were not imported"
                .to_string()
        } else {
            "store is read-only and the cache store is not writable".to_string()
        });
        finish_state(
            &state_root,
            request.remote,
            &index,
            request.now,
            &mut report,
        );
        return Ok(report);
    }

    let selected: Vec<&RemoteUnit> = missing.iter().map(|&at| candidates[at]).collect();
    report.skipped += candidates.len().saturating_sub(selected.len());
    let mut blobs: BTreeMap<&str, BlobRef> = BTreeMap::new();
    for unit in &selected {
        for file in &unit.files {
            blobs.entry(file.blob.as_str()).or_insert_with(|| BlobRef {
                blob: file.blob.clone(),
                blob_size: file.blob_size,
                sha256: file.sha256.clone(),
                size: file.size,
                compression: file.compression,
            });
        }
    }
    for blob in blobs.values() {
        if let Err(err) = cache.install_blob(request.source, blob) {
            return Ok(fallback(
                report,
                format!(
                    "fetching blob {}: {err:#}",
                    &blob.blob[..12.min(blob.blob.len())]
                ),
            ));
        }
    }
    let imports = build_imports(&selected, &cache)?;

    let imported = match vault::import_units(target, &generation, &toolchain, &imports) {
        Ok(imported) => Some(imported),
        Err(err) if !used_cache && vault::store_accepts_imports(&cache_store_root) => {
            // A writable-looking store can still reject a write (ACL, mount
            // remount, disk policy). Use the local cache store rather than
            // failing the build.
            match vault::import_units(&cache_store_root, &generation, &toolchain, &imports) {
                Ok(imported) => {
                    used_cache = true;
                    report.warning = Some(format!("store import failed, used cache: {err:#}"));
                    Some(imported)
                }
                Err(cache_err) => {
                    return Ok(fallback(
                        report,
                        format!("import failed ({err:#}); cache import failed ({cache_err:#})"),
                    ));
                }
            }
        }
        Err(err) => return Ok(fallback(report, format!("import failed: {err:#}"))),
    };
    if let Some(imported) = imported {
        report.imported = imported.stored;
        report.skipped += imported.skipped;
        report.files = imported.files;
        report.bytes = imported.bytes;
    }
    if used_cache {
        report.cache_store = Some(cache_store_root);
    }
    finish_state(
        &state_root,
        request.remote,
        &index,
        request.now,
        &mut report,
    );
    if let Err(err) = cache.sweep(&index) {
        report.warning = Some(format!("cache sweep failed: {err:#}"));
    }
    Ok(report)
}

fn selected(unit: &RemoteUnit, request: &FetchRequest<'_>) -> bool {
    if !unit.importable_for(request.remote.tier) {
        return false;
    }
    if let Some(profile) = request.profile
        && unit.profile != profile
    {
        return false;
    }
    if let Some(layout) = request.layout
        && unit.layout != layout
    {
        return false;
    }
    if let Some(query) = request.unit_filter
        && !unit.name.contains(query)
    {
        return false;
    }
    if let Some(lock) = request.packages
        && !lock_matches(unit, lock)
    {
        return false;
    }
    true
}

fn lock_matches(unit: &RemoteUnit, lock: &LockIndex) -> bool {
    match lock.resolve(&unit.package, unit.version.as_deref()) {
        Ok(Some(LockSource::Registry { index, checksum })) => {
            unit.source.kind == SourceKind::Registry
                && unit.source.id == index
                && unit
                    .source
                    .checksum
                    .as_deref()
                    .is_some_and(|found| found.eq_ignore_ascii_case(&checksum))
        }
        Ok(Some(LockSource::Git { id })) => {
            unit.source.kind == SourceKind::Git && unit.source.id == id
        }
        _ => false,
    }
}

fn build_imports(candidates: &[&RemoteUnit], cache: &cache::Cache) -> Result<Vec<ImportUnit>> {
    let mut out = Vec::with_capacity(candidates.len());
    for unit in candidates {
        let mut files = Vec::with_capacity(unit.files.len());
        for file in &unit.files {
            let blob = cache.blob_path(&file.blob)?;
            files.push(ImportFile {
                path: file.path.clone(),
                dest: file.dest.clone(),
                size: file.size,
                sha256: file.sha256.clone(),
                role: file.role.as_str().to_string(),
                source: match file.compression {
                    Compression::Raw => ImportSource::Raw(blob),
                    Compression::Gzip => ImportSource::Gzip(blob),
                },
            });
        }
        out.push(ImportUnit {
            name: unit.name.clone(),
            profile: unit.profile.clone(),
            memo: unit.memo.clone(),
            hash: unit.hash.clone(),
            version: unit.version.clone(),
            stamp: unit.stamp,
            layout: unit.layout,
            files,
        });
    }
    Ok(out)
}

fn finish_state(
    root: &Path,
    remote: &RemotePolicy,
    index: &SignedIndex,
    now: u64,
    report: &mut FetchReport,
) {
    if let Err(err) = state::record_state_at(root, remote, index, now) {
        report.warning = Some(format!("recording remote state: {err:#}"));
    }
}

fn fallback(mut report: FetchReport, reason: impl Into<String>) -> FetchReport {
    report.fallback = Some(reason.into());
    report
}

fn tampered(mut report: FetchReport, reason: impl Into<String>) -> FetchReport {
    report.warning = Some(reason.into());
    report.fallback = Some("remote content failed verification".to_string());
    report
}

fn overlaps(left: &Path, right: &Path) -> bool {
    let left = std::fs::canonicalize(left).unwrap_or_else(|_| left.to_path_buf());
    let right = std::fs::canonicalize(right).unwrap_or_else(|_| right.to_path_buf());
    left == right || left.starts_with(&right) || right.starts_with(&left)
}

/// Read a fetched index without importing. Used by diagnostics.
pub fn preview(index: &SignedIndex, reader: RemoteTier) -> Result<usize> {
    let body = index.body();
    body.validate_for(reader)?;
    Ok(body
        .units
        .iter()
        .filter(|unit| unit.importable_for(reader))
        .count())
}
