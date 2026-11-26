//! Garbage collection for the shared cache.
//!
//! The key idea: every artifact in the cache belongs to a build "unit"
//! identified by a `name-hash` key (Cargo appends a metadata hash to
//! filenames). Deleting a *whole unit* keeps Cargo's bookkeeping consistent;
//! and if anything still needed got deleted, Cargo simply rebuilds it —
//! pruning is safe by design.
//!

use std::collections::{BTreeMap, HashMap};
#[cfg(test)]
use std::fs;
use std::fs::Metadata;
use std::path::Component;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::util;
use anyhow::Result;

/// One build unit: all files in the cache sharing a `name-hash` key.
pub struct Group {
    /// e.g. `serde-deadbeef`
    pub key: String,
    /// Every file belonging to the unit (may span `deps/` and `.fingerprint/`).
    pub files: Vec<PathBuf>,
    /// For `build/`, `incremental/`, `.fingerprint/` units: the directory that
    /// backs the whole unit, deleted as a whole when stale.
    pub anchor: Option<PathBuf>,
    /// Newest mtime seen among the files ("last used").
    pub newest: Option<SystemTime>,
    /// Total size of all files.
    pub bytes: u64,
    /// Retention family: incremental, deps, build, or fingerprint.
    pub kind: String,
    /// True for `incremental/` and wrapper `incremental.*` state.
    pub incremental: bool,
}

/// Extract `name-hash` from a Cargo artifact name.
fn name_hash(name: &str, strip_ext: bool) -> Option<String> {
    // Final component only (survives both `path\to\name` and `path/to/name`).
    let file = name.replace('\\', "/");
    let file = file.split('/').next_back()?;

    let stem = if strip_ext {
        Path::new(file).file_stem()?.to_str()?
    } else {
        file
    };

    // Split at the LAST `-`; no dash or an empty hash is unhashable.
    let (name, hash) = stem.rsplit_once('-')?;
    if hash.is_empty() {
        return None;
    }

    // `.fingerprint/.../<dir>` anchors have no `lib` prefix — dep files do.
    let name = if strip_ext {
        name.strip_prefix("lib").unwrap_or(name)
    } else {
        name
    };

    // Normalize dashes to underscores in the name part so that
    // `deps/libtokio_util-abc.rlib` and `.fingerprint/tokio-util-abc/`
    // land on the SAME key and get deleted together.
    Some(format!("{}-{}", name.replace('-', "_"), hash))
}

/// Classify a file inside the cache into its build unit.
pub fn artifact_key(root: &Path, path: &Path) -> Option<String> {
    if !path.starts_with(root) {
        return None;
    }
    // Only the components RELATIVE to the root are scanned — otherwise the
    // root's own name can trigger keywords (the cache root is literally
    // named `.../epicenter/build`, which would classify every file as
    // an `anchor` unit and silently empty the whole scan!).
    let components: Vec<&str> = path
        .strip_prefix(root)
        .ok()?
        .components()
        .filter(|c| !matches!(c, Component::RootDir))
        .filter_map(|c| c.as_os_str().to_str())
        .collect();

    if components.len() < 2 || components.iter().any(|c| *c == ".cargo-lock") {
        return None;
    }

    for (i, comp) in components.iter().enumerate() {
        match *comp {
            // deps/<libname-hash>.rlib|.rmeta|.d ... — key from the file name
            "deps" => {
                let file = components.last()?;
                return name_hash(file, true);
            }
            // New layout: build/<package>/<16hex>/… — one directory per unit.
            "build" => {
                let first = components.get(i + 1)?;
                if let Some(hash) = components
                    .get(i + 2)
                    .filter(|hash| crate::fingerprint::looks_like_hash(hash))
                {
                    return Some(format!("{}-{}", first.replace('-', "_"), hash));
                }
                // Classic: build/<package>-<hash>/…
                return name_hash(first, false);
            }
            // incremental/<crate-hash>/, .fingerprint/<crate-hash>/
            "incremental" => {
                let anchor_dir = components.get(i + 1)?;
                return name_hash(anchor_dir, false);
            }
            // Wrapper state: incremental.kache-auto/... is one reclaimable
            // family; its internal v1/<hash>/session layout is opaque.
            comp if comp.starts_with("incremental") => {
                return Some((*comp).to_string());
            }
            ".fingerprint" => {
                let anchor_dir = components.get(i + 1)?;
                return name_hash(anchor_dir, false);
            }
            _ => {}
        }
    }
    None
}

/// For `build/`, `incremental/` and `.fingerprint/` units: the directory
/// backing the unit (everything up to and including the component AFTER the
/// keyword, joined onto `root`).
fn anchor_for(root: &Path, path: &Path) -> Option<PathBuf> {
    let rel = path.strip_prefix(root).ok()?;
    let comps: Vec<Component> = rel.components().collect();
    for (i, comp) in comps.iter().enumerate() {
        let name = comp.as_os_str().to_str()?;
        match name {
            "build" => {
                // New layout: build/<pkg>/<16hex> (do NOT collapse to
                // build/<pkg> — that would delete sibling units).
                let new_layout = comps
                    .get(i + 2)
                    .and_then(|c| c.as_os_str().to_str())
                    .map(crate::fingerprint::looks_like_hash)
                    .unwrap_or(false);
                let take = if new_layout { i + 3 } else { i + 2 };
                let anchor: PathBuf = comps.iter().take(take).collect();
                return Some(root.join(anchor));
            }
            "incremental" => {
                let anchor: PathBuf = comps.iter().take(i + 2).collect();
                return Some(root.join(anchor));
            }
            name if name.starts_with("incremental") => {
                let anchor: PathBuf = comps.iter().take(i + 1).collect();
                return Some(root.join(anchor));
            }
            ".fingerprint" => {
                let anchor: PathBuf = comps.iter().take(i + 2).collect();
                return Some(root.join(anchor));
            }
            _ => {}
        }
    }
    None
}

/// Is this path incremental state? Only the `incremental` directory under a
/// profile and the `incremental.*` wrapper families qualify. A package or
/// build directory whose *name* merely starts with `incremental` is ordinary
/// output, so stop at the same keywords `artifact_key` classifies first.
fn is_incremental_path(root: &Path, path: &Path) -> bool {
    let Ok(rel) = path.strip_prefix(root) else {
        return false;
    };
    let mut components = rel.components();
    // The first component is the profile: state lives below it.
    components.next();
    for component in components {
        let name = component.as_os_str().to_string_lossy();
        if name == "incremental" || name.starts_with("incremental.") {
            return true;
        }
        if matches!(name.as_ref(), "build" | ".fingerprint" | "deps") {
            return false;
        }
    }
    false
}

/// Walk `root` and group every file into units.
pub fn scan(root: &Path) -> Result<BTreeMap<String, Group>> {
    scan_with(root, "prune", |_, _| {})
}

/// Scan once and let the caller visit every regular file. `status` uses this
/// to collect totals from the same walk that classifies prune groups.
pub(crate) fn scan_with(
    root: &Path,
    budget_name: &'static str,
    mut visit: impl FnMut(&Path, &Metadata),
) -> Result<BTreeMap<String, Group>> {
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();
    let mut budget = util::ScanBudget::new(budget_name);
    let mut walk = util::SafeWalk::new(root).walk_with(&mut budget);
    for entry in walk.by_ref() {
        // Unreadable entries are skipped rather than failing the whole scan.
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let meta: Metadata = match util::metadata_nofollow(&entry.path()) {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        if !meta.is_file() {
            continue;
        }
        visit(entry.path(), &meta);
        // `artifact_key` -> None means "never touch" (locks, root files...).
        let Some(key) = artifact_key(root, entry.path()) else {
            continue;
        };
        let incremental = is_incremental_path(root, entry.path());
        let kind = if incremental {
            "incremental"
        } else if entry
            .path()
            .components()
            .any(|component| component.as_os_str() == "deps")
        {
            "deps"
        } else if entry
            .path()
            .components()
            .any(|component| component.as_os_str() == "build")
        {
            "build"
        } else {
            "fingerprint"
        };
        let group = groups.entry(key.clone()).or_insert_with(|| Group {
            key,
            files: Vec::new(),
            anchor: None,
            newest: None,
            bytes: 0,
            kind: kind.to_string(),
            incremental,
        });
        group.incremental |= incremental;
        group.bytes = group.bytes.saturating_add(meta.len());
        group.files.push(entry.into_path());
        if let Ok(mtime) = meta.modified() {
            if group.newest.map_or(false, |n| mtime > n) || group.newest.is_none() {
                group.newest = Some(mtime);
            }
        }
    }
    if walk.truncated() {
        budget.spend()?;
    }
    for group in groups.values_mut() {
        group.anchor = group.files.iter().find_map(|f| anchor_for(root, f));
    }
    Ok(groups)
}

#[derive(Debug, Default)]
pub struct PruneReport {
    pub removed_groups: u64,
    pub kept_groups: u64,
    pub files_freed: u64,
    pub bytes_freed: u64,
    pub bytes_released: u64,
    pub errors: u64,
}

/// Retention options for [`prune_with`].
#[derive(Debug, Default)]
pub struct Options {
    /// Keep the newest N groups per package/kind and remove older duplicates.
    /// When set, the age cutoff is ignored.
    pub keep_latest: Option<usize>,
    /// Only consider incremental state (`incremental/` and `incremental.*`).
    pub incremental: bool,
}

/// The garbage collector with default age retention.
pub fn prune(root: &Path, cutoff: SystemTime, delete: bool) -> Result<PruneReport> {
    prune_with(root, cutoff, delete, &Options::default())
}

fn package_key(key: &str) -> &str {
    key.rsplit_once('-')
        .filter(|(_, hash)| crate::fingerprint::looks_like_hash(hash))
        .map(|(package, _)| package)
        .unwrap_or(key)
}

/// One pre-deletion observation of a file that a removal will touch.
struct ObservedFile {
    path: PathBuf,
    size: u64,
    links: u64,
    identity: Option<(u64, u64)>,
}

fn observed_file(path: &Path) -> Option<ObservedFile> {
    let meta = util::metadata_nofollow(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    Some(ObservedFile {
        path: path.to_path_buf(),
        size: meta.len(),
        links: crate::vault::link_count(path, &meta),
        identity: crate::util::file_identity(path, &meta),
    })
}

/// Every regular file removing this group touches: its classified files plus
/// the whole anchor tree, which also removes entries the scan skipped (a
/// nested lock file, an unreadable artifact).
fn removal_paths(group: &Group) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(anchor) = &group.anchor {
        let mut budget = util::ScanBudget::new("removal tree");
        let mut walk = util::SafeWalk::new(anchor).walk_with(&mut budget);
        if let Ok(entries) = walk.by_ref().collect::<Result<Vec<_>, _>>() {
            for entry in entries {
                if util::metadata_nofollow(entry.path()).is_ok_and(|meta| meta.is_file()) {
                    paths.push(entry.into_path());
                }
            }
        }
    }
    paths.extend(group.files.iter().cloned());
    paths.sort();
    paths.dedup();
    paths
}

/// Bytes actually reclaimed by removing `observed`: a file frees its bytes
/// only when every link it had is gone, and an inode is counted once.
fn account_removed(observed: &[ObservedFile]) -> (u64, u64, u64) {
    let mut per_inode: HashMap<(u64, u64), (u64, u64, u64)> = HashMap::new();
    let mut unknown_freed = 0u64;
    let mut freed_count = 0u64;
    for file in observed {
        // A path that survived a failed removal is not reclaimed.
        if file.path.symlink_metadata().is_ok() {
            continue;
        }
        freed_count = freed_count.saturating_add(1);
        match file.identity {
            Some(inode) => {
                let entry = per_inode.entry(inode).or_insert((file.size, file.links, 0));
                entry.0 = entry.0.max(file.size);
                entry.2 = entry.2.saturating_add(1);
            }
            None => unknown_freed = unknown_freed.saturating_add(file.size),
        }
    }
    let mut nominal = unknown_freed;
    let mut freed = unknown_freed;
    for (size, links, removed) in per_inode.values() {
        nominal = nominal.saturating_add(*size);
        if *removed >= *links {
            freed = freed.saturating_add(*size);
        }
    }
    (freed_count, freed, nominal.saturating_sub(freed))
}

/// The garbage collector.
pub fn prune_with(
    root: &Path,
    cutoff: SystemTime,
    delete: bool,
    opts: &Options,
) -> Result<PruneReport> {
    // Hold Cargo's build locks through the whole scan/delete. A check that
    // drops them lets a build start before the removals and lose artifacts.
    let mut build_locks = if delete {
        match crate::job::cargo_lock_set(root)? {
            Some(locks) => Some(locks),
            None => anyhow::bail!(
                "build dir {} is in use by a live build — prune skipped",
                root.display()
            ),
        }
    } else {
        None
    };
    let groups = scan(root)?;
    // A profile can appear while the scan runs. Discover it now and hold its
    // lock too, before any deletion, so a build starting there is fenced.
    if let Some(locks) = build_locks.as_mut()
        && !locks.refresh(root)?
    {
        anyhow::bail!(
            "build dir {} is in use by a live build — prune skipped",
            root.display()
        );
    }
    let mut report = PruneReport::default();
    let mut selected = Vec::new();
    let mut candidates: Vec<Group> = groups
        .into_values()
        .filter(|group| !opts.incremental || group.incremental)
        .collect();

    if let Some(keep) = opts.keep_latest {
        candidates.sort_by(|a, b| b.newest.cmp(&a.newest).then_with(|| a.key.cmp(&b.key)));
        let mut kept: std::collections::HashMap<(String, String), usize> =
            std::collections::HashMap::new();
        for group in candidates {
            let bucket = (package_key(&group.key).to_string(), group.kind.clone());
            let count = kept.entry(bucket).or_default();
            if *count < keep {
                *count += 1;
                report.kept_groups += 1;
            } else {
                selected.push(group);
            }
        }
    } else {
        for group in candidates {
            // No usable mtime -> keep (conservative).
            let Some(newest) = group.newest else {
                report.kept_groups += 1;
                continue;
            };
            if newest >= cutoff {
                report.kept_groups += 1;
                continue;
            }
            selected.push(group);
        }
    }

    if opts.incremental {
        // A unit key can be shared by incremental state and an ordinary deps
        // artifact. Prune only the incremental paths and never the compiled
        // build output that happens to share the key.
        selected.retain_mut(|group| {
            group.files.retain(|file| is_incremental_path(root, file));
            group.anchor = group.files.iter().find_map(|file| anchor_for(root, file));
            !group.files.is_empty()
        });
    }

    report.removed_groups = selected.len() as u64;
    // The anchor delete removes the whole tree, including entries the scan
    // skipped (a nested lock file), so account those paths too.
    let mut targets = Vec::new();
    for group in &selected {
        targets.extend(removal_paths(group));
    }
    targets.sort();
    targets.dedup();

    if !delete {
        let (_, freed, released, count) = crate::util::account_files(&targets);
        report.files_freed = count;
        report.bytes_freed = freed;
        report.bytes_released = released;
        return Ok(report);
    }

    let observed: Vec<ObservedFile> = targets
        .iter()
        .filter_map(|path| observed_file(path))
        .collect();

    for group in selected {
        match &group.anchor {
            Some(anchor) => {
                if let Err(err) = crate::util::remove_tree(root, anchor) {
                    report.errors += 1;
                    eprintln!("could not remove {}: {err:#}", anchor.display());
                }
                // One unit can span both `.fingerprint/<dir>` and `deps/`: the
                // anchor covers the first family; files outside it go individually.
                for file in &group.files {
                    if file.starts_with(anchor) {
                        continue;
                    }
                    if let Err(err) = crate::util::remove_file(root, file) {
                        report.errors += 1;
                        eprintln!("could not remove {}: {err:#}", file.display());
                    }
                }
            }
            None => {
                for file in &group.files {
                    if let Err(err) = crate::util::remove_file(root, file) {
                        report.errors += 1;
                        eprintln!("could not remove {}: {err:#}", file.display());
                    }
                }
            }
        }
    }
    // Report what the filesystem actually let go, not what the selection
    // planned: a failed removal or a file that vanished keeps its bytes.
    let (count, freed, released) = account_removed(&observed);
    report.files_freed = count;
    report.bytes_freed = freed;
    report.bytes_released = released;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_hash_strips_and_normalizes() {
        assert_eq!(
            name_hash(".fingerprints\\libserde-deadbeef.rlib", true),
            Some("serde-deadbeef".into())
        );
        assert_eq!(
            name_hash("sada/libtokio_util-abc123.rmeta", true),
            Some("tokio_util-abc123".into())
        );
        assert_eq!(
            name_hash("mybin-abc123.d", true),
            Some("mybin-abc123".into())
        );
        // Anchor dirs never have the `lib` prefix, but dashes -> underscores applies.
        assert_eq!(
            name_hash("tokio-util-abc123", false),
            Some("tokio_util-abc123".into())
        );
        assert_eq!(
            name_hash("serde-deadbeef", false),
            Some("serde-deadbeef".into())
        );
    }

    #[test]
    fn name_hash_rejects_unhashable_names() {
        assert_eq!(name_hash("nometa", false), None);
        assert_eq!(name_hash("weird", false), None);
    }

    #[test]
    fn keys_deps_and_fingerprints_together() {
        let root = Path::new("/cache");
        assert_eq!(
            artifact_key(root, Path::new("/cache/debug/deps/libserde-deadbeef.rlib")),
            Some("serde-deadbeef".into()),
        );
        assert_eq!(
            artifact_key(
                root,
                Path::new("/cache/debug/.fingerprint/serde-deadbeef/root-output")
            ),
            Some("serde-deadbeef".into()),
            "same unit must share one key so they get deleted together",
        );
    }

    #[test]
    fn keys_build_and_incremental_by_anchor_dir() {
        let root = Path::new("/cache");
        assert_eq!(
            artifact_key(
                root,
                Path::new("/cache/debug/build/tokio-util-abc/out/main.rs")
            ),
            Some("tokio_util-abc".into()),
        );
        assert_eq!(
            artifact_key(
                root,
                Path::new("/cache/debug/incremental/myproj-1a2b/s-gx/cache.bin")
            ),
            Some("myproj-1a2b".into()),
        );
    }

    #[test]
    fn leaves_protected_files_alone() {
        let root = Path::new("/cache");
        assert_eq!(artifact_key(root, Path::new("/cache/.cargo-lock")), None);
        assert_eq!(
            artifact_key(root, Path::new("/cache/.rustc_info.json")),
            None
        );
        assert_eq!(artifact_key(root, Path::new("/cache/debug/mybin.d")), None);
        assert_eq!(artifact_key(root, Path::new("/elsewhere/x")), None);
    }

    #[test]
    fn scans_units_and_anchors() -> Result<()> {
        let root = tempfile::tempdir()?;
        let deps = root.path().join("debug/deps");
        let fingerprint = root.path().join("debug/.fingerprint/anyhow-abc");
        fs::create_dir_all(&deps)?;
        fs::create_dir_all(&fingerprint)?;
        fs::write(deps.join("libanyhow-abc.rlib"), [0u8; 10])?;
        fs::write(deps.join("libanyhow-abc.rmeta"), [0u8; 5])?;
        fs::write(fingerprint.join("root-output"), [0u8; 1])?;
        fs::write(root.path().join("debug/.cargo-lock"), [0u8; 2])?;

        let groups = scan(root.path())?;
        assert_eq!(
            groups.len(),
            1,
            "lock file is not a unit; got {:?}",
            groups.keys()
        );
        let group = &groups["anyhow-abc"];
        assert_eq!(group.files.len(), 3);
        assert_eq!(group.bytes, 16);
        assert_eq!(group.anchor.as_deref(), Some(fingerprint.as_path()));
        Ok(())
    }

    #[test]
    fn scans_new_layout_units_per_unit_dir() -> Result<()> {
        let root = tempfile::tempdir()?;
        let one = root.path().join("debug/build/anyhow/9709d57b46b8d526");
        let two = root.path().join("debug/build/anyhow/6d5788609cdad9a4");
        for unit in [&one, &two] {
            fs::create_dir_all(unit.join("fingerprint"))?;
            fs::create_dir_all(unit.join("out"))?;
            fs::write(unit.join("fingerprint/lib-anyhow"), "aaaaaaaabbbbbbbb")?;
            fs::write(unit.join("out/libanyhow-9709d57b46b8d526.rlib"), [0u8; 10])?;
        }

        let groups = scan(root.path())?;
        assert_eq!(
            groups.len(),
            2,
            "two units of one package: {:?}",
            groups.keys()
        );
        assert!(groups.keys().all(|key| key.starts_with("anyhow-")));
        for (key, group) in &groups {
            let unit = if key.ends_with("9709d57b46b8d526") {
                &one
            } else {
                &two
            };
            assert_eq!(
                group.anchor.as_deref(),
                Some(unit.as_path()),
                "anchor must stop at the unit dir, never build/<pkg>"
            );
        }
        Ok(())
    }

    #[test]
    fn classifies_wrapper_incremental_state() {
        let root = Path::new("/cache");
        let file = root
            .join("debug/incremental.kache-auto/v1/0123456789abcdef/rustc/foo-abc/session/file");
        assert_eq!(
            artifact_key(root, &file).as_deref(),
            Some("incremental.kache-auto")
        );
        assert_eq!(
            anchor_for(root, &file).as_deref(),
            Some(root.join("debug/incremental.kache-auto").as_path())
        );
    }

    #[test]
    fn keep_latest_retains_the_newest_groups() -> Result<()> {
        let root = tempfile::tempdir()?;
        let deps = root.path().join("debug/deps");
        fs::create_dir_all(&deps)?;
        let now = SystemTime::now();
        let hashes = ["1111111111111111", "2222222222222222", "3333333333333333"];
        for (index, hash) in hashes.iter().enumerate() {
            let file = deps.join(format!("libsame-{hash}.rlib"));
            fs::write(&file, vec![index as u8; 10])?;
            let modified = now - std::time::Duration::from_secs((3 - index) as u64 * 60);
            fs::File::options()
                .write(true)
                .open(&file)?
                .set_modified(modified)?;
        }

        let opts = Options {
            keep_latest: Some(2),
            incremental: false,
        };
        let report = prune_with(root.path(), now, false, &opts)?;
        assert_eq!(report.removed_groups, 1);
        assert_eq!(report.kept_groups, 2);
        assert_eq!(report.bytes_freed, 10);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn prune_reports_only_actually_freed_bytes() -> Result<()> {
        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let deps = root.path().join("debug/deps");
        let fingerprint = root.path().join("debug/.fingerprint/x-abc");
        fs::create_dir_all(&deps)?;
        fs::create_dir_all(&fingerprint)?;
        let artifact = deps.join("libx-abc.rlib");
        fs::write(&artifact, [0u8; 7])?;
        fs::write(fingerprint.join("root-output"), [0u8; 2])?;
        fs::hard_link(&artifact, outside.path().join("kept.rlib"))?;

        let cutoff = SystemTime::now() + std::time::Duration::from_secs(3_600);
        let report = prune(root.path(), cutoff, false)?;
        assert_eq!(report.files_freed, 2);
        assert_eq!(report.bytes_freed, 2, "only the private fingerprint frees");
        assert_eq!(report.bytes_released, 7, "the rlib keeps its outside link");
        Ok(())
    }

    #[test]
    fn delete_refuses_a_live_cargo_build_lock() -> Result<()> {
        let root = tempfile::tempdir()?;
        let deps = root.path().join("debug/deps");
        let lock_dir = root.path().join("debug");
        fs::create_dir_all(&deps)?;
        fs::write(deps.join("libx-abc.rlib"), [0u8; 7])?;
        let lock_path = lock_dir.join(".cargo-build-lock");
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&lock_path)?;
        lock.lock()?;
        let cutoff = SystemTime::now() + std::time::Duration::from_secs(3_600);
        let err = prune(root.path(), cutoff, true).unwrap_err();
        assert!(err.to_string().contains("in use"), "{err}");
        assert!(deps.join("libx-abc.rlib").exists());
        Ok(())
    }

    #[test]
    fn incremental_only_prune_keeps_compiled_units() -> Result<()> {
        let root = tempfile::tempdir()?;
        let incremental = root.path().join("debug/incremental.kache-auto");
        let deps = root.path().join("debug/deps");
        fs::create_dir_all(&incremental)?;
        fs::create_dir_all(&deps)?;
        fs::write(incremental.join("session.bin"), b"scratch")?;
        let artifact = deps.join("libdemo-aaaaaaaaaaaaaaaa.rlib");
        fs::write(&artifact, b"compiled")?;

        let report = prune_with(
            root.path(),
            SystemTime::now(),
            true,
            &Options {
                keep_latest: Some(0),
                incremental: true,
            },
        )?;
        assert_eq!(report.removed_groups, 1);
        assert_eq!(report.errors, 0);
        assert!(!incremental.exists());
        assert_eq!(fs::read(artifact)?, b"compiled");
        Ok(())
    }

    #[test]
    fn prune_reports_then_deletes_stale_units() -> Result<()> {
        let root = tempfile::tempdir()?;
        let deps = root.path().join("debug/deps");
        let fingerprint = root.path().join("debug/.fingerprint/x-abc");
        fs::create_dir_all(&deps)?;
        fs::create_dir_all(&fingerprint)?;
        fs::write(deps.join("libx-abc.rlib"), [0u8; 7])?;
        fs::write(fingerprint.join("root-output"), [0u8; 2])?;

        // Cutoff in the future makes everything look stale — deterministic.
        let cutoff = SystemTime::now() + std::time::Duration::from_secs(3_600);

        // Dry run: full report, but nothing actually deleted.
        let report = prune(root.path(), cutoff, false)?;
        assert_eq!(report.removed_groups, 1);
        assert_eq!(report.files_freed, 2);
        assert_eq!(report.bytes_freed, 9);
        assert!(
            deps.join("libx-abc.rlib").exists(),
            "dry run must not delete"
        );

        // Real run: files AND the .fingerprint dir are gone.
        let report = prune(root.path(), cutoff, true)?;
        assert_eq!(report.bytes_freed, 9);
        assert!(!deps.join("libx-abc.rlib").exists());
        assert!(!fingerprint.exists());
        Ok(())
    }

    #[test]
    fn incremental_prune_ignores_names_that_merely_start_with_incremental() -> Result<()> {
        let base = tempfile::tempdir()?;
        // The cache root and a build package both carry an `incremental*` name;
        // neither is incremental state.
        let root = base.path().join("incremental-cache");
        let deps = root.join("debug/deps");
        let build = root.join("debug/build/incremental-tool/9709d57b46b8d526/out");
        fs::create_dir_all(&deps)?;
        fs::create_dir_all(&build)?;
        let dep = deps.join("libdemo-aaaaaaaaaaaaaaaa.rlib");
        let output = build.join("libincremental_tool-9709d57b46b8d526.rlib");
        fs::write(&dep, b"compiled")?;
        fs::write(&output, b"output")?;

        let report = prune_with(
            &root,
            SystemTime::now(),
            true,
            &Options {
                keep_latest: Some(0),
                incremental: true,
            },
        )?;
        assert_eq!(report.removed_groups, 0);
        assert_eq!(report.errors, 0);
        assert_eq!(fs::read(&dep)?, b"compiled");
        assert_eq!(fs::read(&output)?, b"output");
        Ok(())
    }

    #[test]
    fn incremental_prune_keeps_output_sharing_a_unit_key() -> Result<()> {
        let root = tempfile::tempdir()?;
        let deps = root.path().join("debug/deps");
        let state = root.path().join("debug/incremental/demo-aaaaaaaaaaaaaaaa");
        fs::create_dir_all(&deps)?;
        fs::create_dir_all(&state)?;
        let artifact = deps.join("libdemo-aaaaaaaaaaaaaaaa.rlib");
        fs::write(&artifact, b"compiled")?;
        fs::write(state.join("session.bin"), b"scratch")?;

        let report = prune_with(
            root.path(),
            SystemTime::now(),
            true,
            &Options {
                keep_latest: Some(0),
                incremental: true,
            },
        )?;
        assert_eq!(report.removed_groups, 1);
        assert_eq!(report.errors, 0);
        assert!(!state.exists(), "incremental state is reclaimed");
        assert_eq!(
            fs::read(&artifact)?,
            b"compiled",
            "compiled output shares the key but must survive"
        );
        Ok(())
    }

    #[test]
    fn prune_reports_the_anchor_tree_it_actually_removed() -> Result<()> {
        let root = tempfile::tempdir()?;
        let state = root.path().join("debug/incremental/demo-aaaaaaaaaaaaaaaa");
        fs::create_dir_all(&state)?;
        fs::write(state.join("session.bin"), [0u8; 3])?;
        // A nested lock is not classifiable, so a plan of the classified files
        // alone misses it; deleting the anchor tree still reclaims its bytes.
        fs::write(state.join(".cargo-lock"), [0u8; 4])?;

        let cutoff = SystemTime::now() + std::time::Duration::from_secs(3_600);
        let dry = prune(root.path(), cutoff, false)?;
        assert_eq!(dry.files_freed, 2);
        assert_eq!(dry.bytes_freed, 7);

        let report = prune(root.path(), cutoff, true)?;
        assert_eq!(report.removed_groups, 1);
        assert_eq!(report.errors, 0);
        assert_eq!(report.files_freed, 2);
        assert_eq!(report.bytes_freed, 7);
        assert!(!state.exists());
        Ok(())
    }
}
