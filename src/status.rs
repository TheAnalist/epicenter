//! Read-only inspection of the shared cache: total size, per-directory
//! buckets, oldest entry, and the largest build units.

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Result;
use walkdir::WalkDir;

use crate::prune;

/// Size/count of one top-level bucket (usually a profile dir: `debug`, `release`).
pub struct DirStat {
    pub name: String,
    pub bytes: u64,
    pub files: u64,
}

pub struct CacheSummary {
    pub root: PathBuf,
    pub total_bytes: u64,
    pub total_files: u64,
    /// Per top-level directory, largest first.
    pub dirs: Vec<DirStat>,
    /// Oldest file mtime = how long ago the cache was first used.
    pub oldest: Option<SystemTime>,
    /// The 10 largest build units, largest first.
    pub top_units: Vec<(String, u64)>,
}

/// Gather statistics about the cache at `root`.
///
/// Note the two failure postures on purpose: scanning stops at the first
/// *unreadable entry* silently (status must never fail because one file is
/// locked), but a failing `prune::scan` uses `?` (a cache that can't be
/// classified is interesting and loudly reported).
pub fn summarize(root: &Path) -> Result<CacheSummary> {
    let mut summary = CacheSummary {
        root: root.to_path_buf(),
        total_bytes: 0,
        total_files: 0,
        dirs: Vec::new(),
        oldest: None,
        top_units: Vec::new(),
    };

    // Per top-level bucket (profile dirs like `debug`/`release`, usually).
    let mut buckets: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for entry in WalkDir::new(root).min_depth(1) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue, // locked/unreadable: skip, never crash status
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };

        summary.total_bytes += meta.len();
        summary.total_files += 1;
        if let Ok(mtime) = meta.modified() {
            if summary.oldest.map_or(true, |oldest| mtime < oldest) {
                summary.oldest = Some(mtime);
            }
        }

        // Bucket by the FIRST component under the cache root; files that
        // live directly IN the root have no directory component and go to
        // the synthetic "(cache root)" bucket.
        let rel: Vec<String> = entry
            .path()
            .strip_prefix(root)
            .ok()
            .map(|rel| {
                rel.components()
                    .map(|comp| comp.as_os_str().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        let bucket = if rel.len() > 1 {
            rel[0].clone()
        } else {
            "(cache root)".to_string()
        };
        let bucket = buckets.entry(bucket).or_insert((0, 0));
        bucket.0 += meta.len();
        bucket.1 += 1;
    }

    summary.dirs = buckets
        .into_iter()
        .map(|(name, (bytes, files))| DirStat { name, bytes, files })
        .collect();
    summary.dirs.sort_by_key(|dir| Reverse(dir.bytes));

    summary.top_units = prune::scan(root)?
        .into_values()
        .map(|group| (group.key, group.bytes))
        .collect();
    summary
        .top_units
        .sort_by_key(|(_, bytes)| Reverse(*bytes));
    summary.top_units.truncate(10);

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn summarizes_sizes_and_buckets() -> Result<()> {
        let root = tempfile::tempdir()?;
        let debug = root.path().join("debug");
        fs::create_dir_all(debug.join("deps"))?;
        fs::write(debug.join("deps/liba-abc.rlib"), [0u8; 10])?;
        fs::write(debug.join("a.d"), [0u8; 3])?;
        fs::write(root.path().join("top.txt"), [0u8; 2])?;

        let summary = summarize(root.path())?;
        assert_eq!(summary.total_bytes, 15);
        assert_eq!(summary.total_files, 3);

        let debug_bucket = summary.dirs.iter().find(|d| d.name == "debug").unwrap();
        assert_eq!(debug_bucket.bytes, 13);
        assert_eq!(debug_bucket.files, 2);

        let root_bucket = summary.dirs.iter().find(|d| d.name == "(cache root)").unwrap();
        assert_eq!(root_bucket.bytes, 2);

        // Only `liba-abc.rlib` is classifiable into a unit.
        assert_eq!(summary.top_units.len(), 1);
        Ok(())
    }
}
