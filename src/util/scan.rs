// ── scan: bounded, junction-safe directory walks ──

use std::path::{Component, Path};

use anyhow::Result;
use walkdir::WalkDir;

use super::platform::metadata_nofollow;

/// Upper bound for one stored artifact. This is a disk-fill guard, not a
/// performance target: rustc artifacts are normally far smaller.
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Bound one tree scan so a hostile tree cannot burn CPU/IO indefinitely.
pub(crate) const MAX_SCAN_FILES: u64 = 2_000_000;

/// Bound the depth of a recursive scan; deeper trees are truncated.
pub(crate) const MAX_SCAN_DEPTH: usize = 64;

/// A shared entry budget for a tree walk. `spend` is for fallible scans that
/// should report the hostile tree; `take` is for infallible summaries that
/// truncate instead (a partial listing is safer than unbounded work).
pub(crate) struct ScanBudget {
    remaining: u64,
    limit: u64,
    what: &'static str,
}

impl ScanBudget {
    pub(crate) fn new(what: &'static str) -> Self {
        Self {
            remaining: MAX_SCAN_FILES,
            limit: MAX_SCAN_FILES,
            what,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_limit(limit: u64, what: &'static str) -> Self {
        Self {
            remaining: limit,
            limit,
            what,
        }
    }

    pub(crate) fn spend(&mut self) -> Result<()> {
        if self.take() {
            Ok(())
        } else {
            anyhow::bail!(
                "{} scan exceeded {} entries — refusing a hostile tree",
                self.what,
                self.limit
            )
        }
    }

    pub(crate) fn take(&mut self) -> bool {
        if self.remaining == 0 {
            false
        } else {
            self.remaining -= 1;
            true
        }
    }
}

/// Does any component from `base` to `target` resolve through a symlink or
/// reparse point? The check includes `base` and the final component. A target
/// outside `base` also returns `true`, so callers can use this as a
/// `WalkDir::filter_entry` predicate and skip an entire junction subtree.
pub(crate) fn has_reparse_component(base: &Path, target: &Path) -> bool {
    if metadata_nofollow(base).is_err() {
        return true;
    }
    let Ok(rel) = target.strip_prefix(base) else {
        return true;
    };
    let mut current = base.to_path_buf();
    for component in rel.components() {
        match component {
            Component::Normal(name) => current.push(name),
            Component::CurDir => continue,
            _ => return true,
        }
        if metadata_nofollow(&current).is_err() {
            return true;
        }
    }
    false
}

/// `WalkDir::filter_entry` predicate: regular files pass; a symlink is
/// rejected; a directory is accepted only when it is not itself a reparse
/// point. Ancestors were already vetted when they were yielded (the walker
/// prunes a rejected subtree), so this is one entry check instead of a
/// component walk per entry.
///
/// The walker must also use `follow_links(false)` and
/// `follow_root_links(false)`: WalkDir follows a symlinked **root** by default
/// even when `follow_links(false)` is set, and the root entry is not yielded
/// when `min_depth(1)` is used, so this predicate never sees it.
pub(crate) fn walk_entry_is_safe(entry: &walkdir::DirEntry) -> bool {
    let kind = entry.file_type();
    if kind.is_symlink() {
        return false;
    }
    if !kind.is_dir() {
        return true;
    }
    // On Windows, Rust reports a name-surrogate reparse tag (symlink or
    // junction) as `is_symlink`, so those are already rejected. Other reparse
    // directory tags (cloud/dedup/NFS) report `is_dir` without `is_symlink`;
    // only a no-follow stat exposes the reparse attribute. On Unix a directory
    // entry is real.
    #[cfg(windows)]
    {
        metadata_nofollow(entry.path()).is_ok()
    }
    #[cfg(not(windows))]
    {
        true
    }
}

/// `WalkDir::filter_entry` predicate that prunes only reparse **directories**.
/// Use for scans that must still see symlinked files (a planted lock file must
/// be rejected, not hidden) but must never descend through a junction.
pub(crate) fn walk_dir_is_safe(entry: &walkdir::DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return true;
    }
    #[cfg(windows)]
    {
        metadata_nofollow(entry.path()).is_ok()
    }
    #[cfg(not(windows))]
    {
        true
    }
}

/// A bounded, junction-safe tree walk. The safety predicate is part of the
/// constructor so every scan skips a reparse subtree instead of traversing it.
/// Directory pruning requires top-down order; collect first, then sort by depth
/// when a removal has to happen children-first.
pub(crate) struct SafeWalk<'a> {
    base: &'a Path,
    depth: usize,
    keep_links: bool,
}

impl<'a> SafeWalk<'a> {
    pub(crate) fn new(base: &'a Path) -> Self {
        Self {
            base,
            depth: MAX_SCAN_DEPTH,
            keep_links: false,
        }
    }

    pub(crate) fn depth(mut self, depth: usize) -> Self {
        debug_assert!(depth >= 1, "max_depth is clamped up to min_depth(1)");
        self.depth = depth;
        self
    }

    /// Yield symlinked files while still pruning reparse directories.
    pub(crate) fn keep_links(mut self) -> Self {
        self.keep_links = true;
        self
    }

    pub(crate) fn walk(self) -> impl Iterator<Item = walkdir::Result<walkdir::DirEntry>> + 'a {
        // `follow_root_links(false)` stops a symlinked root. A Windows junction
        // is not a symlink for older platforms and non-surrogate reparse
        // directories are not either, so reject any reparse root explicitly.
        // (Do not encode "yield nothing" as `max_depth(0)`: walkdir clamps it
        // up to `min_depth(1)` and would yield the target's direct children.)
        let reject_root = matches!(
            metadata_nofollow(self.base),
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput
        );
        let filter: fn(&walkdir::DirEntry) -> bool = if self.keep_links {
            walk_dir_is_safe
        } else {
            walk_entry_is_safe
        };
        WalkDir::new(self.base)
            .min_depth(1)
            .max_depth(self.depth)
            .follow_links(false)
            .follow_root_links(false)
            .into_iter()
            .filter_entry(filter)
            .take(if reject_root { 0 } else { usize::MAX })
    }
}
