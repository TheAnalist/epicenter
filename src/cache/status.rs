//! Read-only inspection of the shared cache: total size, per-directory
//! buckets, oldest entry, and the largest build units.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Result;

use crate::prune;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// Size/count of one top-level bucket (usually a profile dir: `debug`, `release`).
pub struct DirStat {
    pub name: String,
    pub bytes: u64,
    pub files: u64,
}

pub struct CacheSummary {
    pub root: PathBuf,
    /// Unique inode bytes in the tree; hard-linked paths count once.
    pub total_bytes: u64,
    /// Path count, including hard links.
    pub total_files: u64,
    /// Paths whose inode has more than one link.
    pub linked_files: u64,
    /// Per top-level directory, largest first.
    pub dirs: Vec<DirStat>,
    /// Oldest file mtime = how long ago the cache was first used.
    pub oldest: Option<SystemTime>,
    /// The 10 largest build units, largest first.
    pub top_units: Vec<(String, u64)>,
}

/// One snapshot of a path's size, link count, and stable identity. On Windows
/// all three come from the same `GetFileInformationByHandle` call, so a file
/// that changes during the walk cannot contribute mismatched facts.
fn observe(path: &Path, meta: &std::fs::Metadata) -> (Option<(u64, u64)>, u64, u64) {
    #[cfg(unix)]
    {
        let _ = path;
        (Some((meta.dev(), meta.ino())), meta.len(), meta.nlink())
    }
    #[cfg(windows)]
    {
        match crate::util::windows_file_identity(path) {
            Some((volume, index, links, size)) => {
                (Some((u64::from(volume), index)), size, u64::from(links))
            }
            None => (None, meta.len(), 1),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        (None, meta.len(), 1)
    }
}

/// The bucket name for a path: its first component under the root, or the
/// synthetic `(cache root)` for files directly in the root.
fn bucket_name(root: &Path, path: &Path) -> String {
    let Ok(rel) = path.strip_prefix(root) else {
        return "(cache root)".to_string();
    };
    let mut components = rel.components();
    match (components.next(), components.next()) {
        (Some(first), Some(_)) => first.as_os_str().to_string_lossy().into_owned(),
        _ => "(cache root)".to_string(),
    }
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
        linked_files: 0,
        dirs: Vec::new(),
        oldest: None,
        top_units: Vec::new(),
    };

    // Per top-level bucket (profile dirs like `debug`/`release`, usually).
    let mut buckets: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    // Per inode: its size and the lexicographically smallest bucket that holds
    // a link. Charging the bytes to the smallest bucket makes bucket totals
    // independent of the order the walk happens to visit hard links in.
    let mut inodes: HashMap<(u64, u64), (u64, String)> = HashMap::new();
    let groups = prune::scan_with(root, "status", |path, meta| {
        let (identity, size, links) = observe(path, meta);
        summary.total_files = summary.total_files.saturating_add(1);
        if links > 1 {
            summary.linked_files = summary.linked_files.saturating_add(1);
        }
        if let Ok(mtime) = meta.modified()
            && summary.oldest.is_none_or(|oldest| mtime < oldest)
        {
            summary.oldest = Some(mtime);
        }

        let bucket = bucket_name(root, path);
        let entry = buckets.entry(bucket.clone()).or_insert((0, 0));
        entry.1 = entry.1.saturating_add(1);

        match identity {
            Some(inode) => {
                inodes
                    .entry(inode)
                    .and_modify(|(stored, smallest)| {
                        *stored = (*stored).max(size);
                        if bucket < *smallest {
                            *smallest = bucket.clone();
                        }
                    })
                    .or_insert((size, bucket));
            }
            // No stable identity: count the path on its own.
            None => {
                entry.0 = entry.0.saturating_add(size);
                summary.total_bytes = summary.total_bytes.saturating_add(size);
            }
        }
    })?;

    // Unique inode bytes go to the smallest bucket that holds a link.
    for (size, bucket) in inodes.into_values() {
        summary.total_bytes = summary.total_bytes.saturating_add(size);
        if let Some(entry) = buckets.get_mut(&bucket) {
            entry.0 = entry.0.saturating_add(size);
        }
    }

    summary.dirs = buckets
        .into_iter()
        .map(|(name, (bytes, files))| DirStat { name, bytes, files })
        .collect();
    summary.dirs.sort_by_key(|dir| Reverse(dir.bytes));

    summary.top_units = groups
        .into_values()
        .map(|group| (group.key, group.bytes))
        .collect();
    summary.top_units.sort_by_key(|(_, bytes)| Reverse(*bytes));
    summary.top_units.truncate(10);

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[cfg(unix)]
    #[test]
    fn hard_links_count_once() -> Result<()> {
        let root = tempfile::tempdir()?;
        let debug = root.path().join("debug");
        fs::create_dir_all(&debug)?;
        let first = debug.join("liba.rlib");
        let second = debug.join("libb.rlib");
        fs::write(&first, [0u8; 10])?;
        fs::hard_link(&first, &second)?;

        let summary = summarize(root.path())?;
        assert_eq!(summary.total_bytes, 10);
        assert_eq!(summary.total_files, 2);
        assert_eq!(summary.linked_files, 2);
        let bucket = summary.dirs.iter().find(|d| d.name == "debug").unwrap();
        assert_eq!(bucket.bytes, 10);
        assert_eq!(bucket.files, 2);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn hard_links_across_buckets_are_order_independent() -> Result<()> {
        fn build(first: &str, second: &str) -> Result<CacheSummary> {
            let root = tempfile::tempdir()?;
            for bucket in [first, second] {
                fs::create_dir_all(root.path().join(bucket))?;
            }
            let a = root.path().join(first).join("liba.rlib");
            fs::write(&a, [0u8; 10])?;
            fs::hard_link(&a, root.path().join(second).join("shared.rlib"))?;
            summarize(root.path())
        }

        let left = build("debug", "release")?;
        let right = build("release", "debug")?;
        // The inode's bytes land in the same bucket regardless of walk order.
        let debug = |summary: &CacheSummary| {
            summary
                .dirs
                .iter()
                .find(|dir| dir.name == "debug")
                .map(|dir| dir.bytes)
                .unwrap_or(0)
        };
        let release = |summary: &CacheSummary| {
            summary
                .dirs
                .iter()
                .find(|dir| dir.name == "release")
                .map(|dir| dir.bytes)
                .unwrap_or(0)
        };
        assert_eq!(left.total_bytes, 10);
        assert_eq!(right.total_bytes, 10);
        assert_eq!(debug(&left), debug(&right));
        assert_eq!(release(&left), release(&right));
        assert_eq!(debug(&left) + release(&left), left.total_bytes);
        assert_eq!(left.total_files, 2);
        assert_eq!(left.linked_files, 2);
        Ok(())
    }

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

        let root_bucket = summary
            .dirs
            .iter()
            .find(|d| d.name == "(cache root)")
            .unwrap();
        assert_eq!(root_bucket.bytes, 2);

        // Only `liba-abc.rlib` is classifiable into a unit.
        assert_eq!(summary.top_units.len(), 1);
        Ok(())
    }
}
