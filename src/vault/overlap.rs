//! Package/profile overlap report across generations.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::util;

use super::generations::stored_units;
use super::layout::unit_package;

/// One unit in a package/profile pool.
#[derive(Debug, Default)]
pub struct OverlapUnit {
    pub name: String,
    pub hash: String,
    pub generation: String,
    pub stamp: u64,
    pub bytes: u64,
    pub active: bool,
}

#[derive(Default)]
struct OverlapPool {
    units: usize,
    bytes: u64,
    files: Vec<PathBuf>,
    hashes: std::collections::BTreeSet<String>,
    generations: std::collections::BTreeSet<String>,
    active: usize,
    rows: Vec<OverlapUnit>,
}

/// One package/profile pool in the vault, used by the overlap report.
#[derive(Debug, Default)]
pub struct OverlapPackage {
    pub package: String,
    pub profile: String,
    pub units: usize,
    pub hashes: usize,
    /// Units that share a memo hash with another unit. This is a hint, not
    /// proof of byte identity; `store compact` checks the actual file bytes.
    pub identical: usize,
    pub active: usize,
    /// Recorded decoded bytes (the old `bytes` field).
    pub bytes: u64,
    /// Actual on-disk bytes, with hard links counted once.
    pub unique_bytes: u64,
    pub generations: usize,
    pub unit_rows: Vec<OverlapUnit>,
}

/// Aggregated package/profile variants across every vault generation.
/// `active` names are the unit dirs currently present in the shared build
/// view; they are used to distinguish live variants from evictable ones.
pub fn overlap(
    store_root: &Path,
    active: &std::collections::HashSet<String>,
) -> Result<Vec<OverlapPackage>> {
    let mut pools: std::collections::BTreeMap<(String, String), OverlapPool> =
        std::collections::BTreeMap::new();
    for stored in stored_units(store_root)? {
        let package = unit_package(&stored.entry.name)
            .unwrap_or(stored.entry.name.as_str())
            .to_string();
        let profile = stored.entry.profile.clone();
        let mut bytes = 0u64;
        let mut paths = Vec::with_capacity(stored.entry.files.len());
        for file in &stored.entry.files {
            bytes = bytes.saturating_add(file.size);
            paths.push(stored.dir.join(&file.path));
        }
        let is_active = active.contains(&stored.entry.name);
        let row = OverlapUnit {
            name: stored.entry.name.clone(),
            hash: stored.entry.hash.clone(),
            generation: stored.generation.clone(),
            stamp: stored.entry.stamp,
            bytes,
            active: is_active,
        };
        let entry = pools.entry((package, profile)).or_default();
        entry.units += 1;
        entry.bytes = entry.bytes.saturating_add(bytes);
        entry.files.extend(paths);
        entry.hashes.insert(stored.entry.hash);
        entry.generations.insert(stored.generation);
        entry.active += usize::from(is_active);
        entry.rows.push(row);
    }

    let mut out = Vec::with_capacity(pools.len());
    for ((package, profile), mut pool) in pools {
        pool.rows.sort_by(|left, right| {
            right
                .bytes
                .cmp(&left.bytes)
                .then_with(|| left.name.cmp(&right.name))
        });
        out.push(OverlapPackage {
            package,
            profile,
            units: pool.units,
            hashes: pool.hashes.len(),
            identical: pool.units.saturating_sub(pool.hashes.len()),
            active: pool.active,
            bytes: pool.bytes,
            unique_bytes: util::account_files(&pool.files).0,
            generations: pool.generations.len(),
            unit_rows: pool.rows,
        });
    }
    out.sort_by(|a, b| {
        b.bytes
            .cmp(&a.bytes)
            .then_with(|| a.package.cmp(&b.package))
    });
    Ok(out)
}
