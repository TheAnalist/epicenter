//! Compact: hard-link identical store files.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::util;

use super::generations::stored_units;
use super::layout::{check_store_trust, ensure_writable_store, generation_names, lock_generation};

struct CompactFile {
    path: PathBuf,
    size: u64,
    hash: String,
    id: Option<(u64, u64)>,
    /// Canonical unit stamp when this path is a raw manifest file. `None`
    /// means the file is a blob/compressed path whose mtime `verify` ignores.
    stamp: Option<u64>,
}

#[derive(Clone, Copy)]
enum StampConstraint {
    Unstamped,
    Stamped(u64),
    Ambiguous,
}

/// Summary of one `store compact` run.
#[derive(Debug, Default)]
pub struct CompactReport {
    pub dry_run: bool,
    pub generations: usize,
    pub groups: usize,
    pub linked: usize,
    pub bytes_saved: u64,
    pub already_shared: usize,
    pub skipped: usize,
}

/// Hard-link identical regular files under the chosen generations' `units/`
/// and `blobs/` trees. Manifests are never touched: paths, sizes and hashes
/// stay exactly the same, only the inode is shared.
pub fn compact(
    store_root: &Path,
    generation: Option<&str>,
    dry_run: bool,
) -> Result<CompactReport> {
    let mut report = CompactReport {
        dry_run,
        ..Default::default()
    };
    if !dry_run {
        ensure_writable_store(store_root, "compact")?;
    }
    let mut generations = generation_names(store_root)?;
    if let Some(query) = generation {
        generations.retain(|name| name.contains(query));
        anyhow::ensure!(
            !generations.is_empty(),
            "no vault generation matches {query:?}"
        );
    }
    report.generations = generations.len();
    if generations.is_empty() {
        return Ok(report);
    }
    if dry_run {
        check_store_trust(store_root)?;
    }
    // A dry run is a pure audit: no lock files, no temp cleanup. The real run
    // holds every touched generation so harvest/evict cannot swap a unit.
    let mut locks = Vec::new();
    if !dry_run {
        locks.reserve(generations.len());
        for generation in &generations {
            locks.push(lock_generation(store_root, generation)?);
        }
    }

    // `verify` requires every raw manifest file's mtime to equal its unit
    // stamp. A hard link shares the inode mtime, so raw files may only be
    // grouped when their stamps match. Compressed unit paths and blobs are
    // not mtime-checked (`verify` follows `object`), so they are unstamped.
    let selected: std::collections::HashSet<&str> =
        generations.iter().map(String::as_str).collect();
    let mut raw_stamps: std::collections::HashMap<PathBuf, u64> = std::collections::HashMap::new();
    for stored in stored_units(store_root)? {
        if !selected.contains(stored.generation.as_str()) {
            continue;
        }
        for file in &stored.entry.files {
            if file.object.is_none() {
                raw_stamps.insert(stored.dir.join(&file.path), stored.entry.stamp);
            }
        }
    }

    let mut budget = util::ScanBudget::new("compact");
    let mut hashes: std::collections::HashMap<(u64, u64), (u64, String)> =
        std::collections::HashMap::new();
    let mut files: Vec<CompactFile> = Vec::new();

    for generation in &generations {
        for dir in ["units", "blobs"] {
            let base = store_root.join(generation).join(dir);
            if util::probe(&base, "compact root")?.is_none() {
                continue;
            }
            let walker = util::SafeWalk::new(&base).walk();
            for entry in walker {
                budget.spend()?;
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => {
                        report.skipped += 1;
                        continue;
                    }
                };
                let path = entry.path();
                let name = path.file_name().map(|name| name.to_string_lossy());
                if name.as_deref().is_some_and(|name| name.starts_with('.')) {
                    if !dry_run
                        && name
                            .as_deref()
                            .is_some_and(|name| name.starts_with(".compact-"))
                    {
                        let _ = fs::remove_file(path);
                    }
                    continue;
                }
                let meta = match util::metadata_nofollow(path) {
                    Ok(meta) => meta,
                    Err(_) => {
                        report.skipped += 1;
                        continue;
                    }
                };
                if !meta.is_file() {
                    continue;
                }
                let id = util::file_identity(path, &meta);
                let (size, hash) = if let Some(id) = id
                    && let Some(cached) = hashes.get(&id)
                {
                    cached.clone()
                } else {
                    let hash = match util::sha256_file(path) {
                        Ok(hash) => hash,
                        Err(_) => {
                            report.skipped += 1;
                            continue;
                        }
                    };
                    let key = (meta.len(), hash);
                    if let Some(id) = id {
                        hashes.insert(id, key.clone());
                    }
                    key
                };
                files.push(CompactFile {
                    path: path.to_path_buf(),
                    size,
                    hash,
                    id,
                    stamp: raw_stamps.get(path).copied(),
                });
            }
        }
    }

    // One inode has one mtime. If aliases disagree about their raw stamp, the
    // manifest itself is inconsistent; leave that inode alone.
    let mut constraints: std::collections::HashMap<(u64, u64), StampConstraint> =
        std::collections::HashMap::new();
    for file in &files {
        let Some(id) = file.id else {
            continue;
        };
        let entry = constraints.entry(id).or_insert(StampConstraint::Unstamped);
        match (file.stamp, *entry) {
            (Some(stamp), StampConstraint::Unstamped) => {
                *entry = StampConstraint::Stamped(stamp);
            }
            (Some(stamp), StampConstraint::Stamped(existing)) if existing != stamp => {
                *entry = StampConstraint::Ambiguous;
            }
            _ => {}
        }
    }

    let mut groups: std::collections::HashMap<(u64, String, Option<u64>), Vec<PathBuf>> =
        std::collections::HashMap::new();
    for file in files {
        let stamp = match file.id {
            Some(id) => match constraints.get(&id) {
                Some(StampConstraint::Ambiguous) => {
                    report.skipped += 1;
                    continue;
                }
                Some(StampConstraint::Stamped(stamp)) => Some(*stamp),
                Some(StampConstraint::Unstamped) | None => None,
            },
            None => file.stamp,
        };
        groups
            .entry((file.size, file.hash, stamp))
            .or_default()
            .push(file.path);
    }

    for (_, mut paths) in groups {
        if paths.len() < 2 {
            continue;
        }
        paths.sort_by(|a, b| {
            let a_blob = is_blob_path(a);
            let b_blob = is_blob_path(b);
            b_blob.cmp(&a_blob).then_with(|| a.cmp(b))
        });
        let canonical = paths.remove(0);
        let canonical_meta = match fs::metadata(&canonical) {
            Ok(meta) => meta,
            Err(_) => {
                report.skipped += 1;
                continue;
            }
        };
        let canonical_id = util::file_identity(&canonical, &canonical_meta);
        let mut counted = false;
        for duplicate in paths {
            let dup_meta = match util::metadata_nofollow(&duplicate) {
                Ok(meta) => meta,
                Err(_) => {
                    report.skipped += 1;
                    continue;
                }
            };
            if !dup_meta.is_file() {
                report.skipped += 1;
                continue;
            }
            if let (Some(canonical_id), Some(dup_id)) =
                (canonical_id, util::file_identity(&duplicate, &dup_meta))
                && canonical_id == dup_id
            {
                report.already_shared += 1;
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if canonical_meta.mode() & 0o777 != dup_meta.mode() & 0o777 {
                    report.skipped += 1;
                    continue;
                }
            }
            if !counted {
                report.groups += 1;
                counted = true;
            }
            if dry_run {
                report.linked += 1;
                report.bytes_saved = report.bytes_saved.saturating_add(dup_meta.len());
                continue;
            }
            match link_replace(&canonical, &duplicate) {
                Ok(()) => {
                    report.linked += 1;
                    report.bytes_saved = report.bytes_saved.saturating_add(dup_meta.len());
                }
                Err(err) => {
                    report.skipped += 1;
                    eprintln!("  could not compact {}: {err:#}", duplicate.display());
                }
            }
        }
    }

    drop(locks);
    Ok(report)
}

fn is_blob_path(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "blobs")
}

fn link_replace(canonical: &Path, duplicate: &Path) -> Result<()> {
    let parent = duplicate
        .parent()
        .with_context(|| format!("{} has no parent", duplicate.display()))?;
    let temp = util::link_temp(canonical, parent, "compact")?;
    match util::replace_file(&temp, duplicate) {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = fs::remove_file(&temp);
            Err(err).with_context(|| {
                format!("linking {} -> {}", canonical.display(), duplicate.display())
            })
        }
    }
}
