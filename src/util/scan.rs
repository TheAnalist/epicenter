// ── scan: bounded, junction-safe directory walks ──

use std::path::{Component, Path};

use anyhow::Result;
use walkdir::WalkDir;

use super::platform::metadata_nofollow;

/// Upper bound for one stored artifact. This is a disk-fill guard, not a
/// performance target: rustc artifacts are normally far smaller.
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Refuse a copy whose running byte count passes [`MAX_FILE_BYTES`]. A metadata
/// check alone cannot stop a file that grows after it was inspected, so every
/// copy loop passes each chunk through this cap.
pub(crate) fn check_copied_size(size: u64) -> Result<()> {
    anyhow::ensure!(
        size <= MAX_FILE_BYTES,
        "copy exceeds the {MAX_FILE_BYTES} byte cap"
    );
    Ok(())
}

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
        let (walker, filter, reject_root) = self.into_parts();
        walker
            .filter_entry(filter)
            .take(if reject_root { 0 } else { usize::MAX })
    }

    /// [`walk`](Self::walk) with every visited entry charged to `budget`
    /// **before** the safety predicate runs: a hostile tree of rejected
    /// symlinks/reparse points cannot buy free traversal. Iteration stops when
    /// the budget runs out; [`BudgetedWalk::truncated`] reports that it did.
    pub(crate) fn walk_with(self, budget: &mut ScanBudget) -> BudgetedWalk<'_> {
        let (walker, filter, reject_root) = self.into_parts();
        BudgetedWalk {
            walker,
            budget,
            filter,
            reject_root,
            stopped: false,
        }
    }

    fn into_parts(self) -> (walkdir::IntoIter, fn(&walkdir::DirEntry) -> bool, bool) {
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
        let walker = WalkDir::new(self.base)
            .min_depth(1)
            .max_depth(self.depth)
            .follow_links(false)
            .follow_root_links(false)
            .into_iter();
        (walker, filter, reject_root)
    }
}

/// A [`SafeWalk`] that charges a [`ScanBudget`] for every entry the walker
/// visits — including entries the safety predicate then rejects.
pub(crate) struct BudgetedWalk<'b> {
    walker: walkdir::IntoIter,
    budget: &'b mut ScanBudget,
    filter: fn(&walkdir::DirEntry) -> bool,
    reject_root: bool,
    stopped: bool,
}

impl BudgetedWalk<'_> {
    /// Did iteration stop because the budget ran out? A caller whose deletion
    /// depends on a complete walk must treat `true` as fail-closed.
    pub(crate) fn truncated(&self) -> bool {
        self.stopped
    }
}

impl Iterator for BudgetedWalk<'_> {
    type Item = walkdir::Result<walkdir::DirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reject_root {
            return None;
        }
        loop {
            let item = self.walker.next()?;
            if !self.budget.take() {
                self.stopped = true;
                return None;
            }
            match item {
                Ok(entry) => {
                    if !(self.filter)(&entry) {
                        if entry.file_type().is_dir() {
                            self.walker.skip_current_dir();
                        }
                        continue;
                    }
                    return Some(Ok(entry));
                }
                Err(err) => return Some(Err(err)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copied_size_cap_rejects_an_oversized_stream() {
        assert!(check_copied_size(MAX_FILE_BYTES).is_ok());
        assert!(check_copied_size(MAX_FILE_BYTES + 1).is_err());
    }

    #[test]
    fn budgeted_walk_stops_at_the_limit() -> Result<()> {
        let root = tempfile::tempdir()?;
        for index in 0..8 {
            std::fs::write(root.path().join(format!("file{index}")), b"x")?;
        }
        let mut budget = ScanBudget::with_limit(3, "test");
        let mut walk = SafeWalk::new(root.path()).walk_with(&mut budget);
        let visited = walk.by_ref().filter_map(Result::ok).count();
        assert_eq!(visited, 3, "the walk yields at most the budget");
        assert!(walk.truncated(), "the walk reports the truncation");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejected_entries_consume_the_budget() -> Result<()> {
        let root = tempfile::tempdir()?;
        let victim = tempfile::tempdir()?;
        for index in 0..3 {
            std::os::unix::fs::symlink(victim.path(), root.path().join(format!("link{index}")))?;
        }
        let mut budget = ScanBudget::with_limit(2, "test");
        let mut walk = SafeWalk::new(root.path()).walk_with(&mut budget);
        let visited = walk.by_ref().filter_map(Result::ok).count();
        assert_eq!(visited, 0, "symlinks are rejected, not visited");
        assert!(
            walk.truncated(),
            "entries rejected by the safety filter still charge the budget"
        );
        Ok(())
    }
}
