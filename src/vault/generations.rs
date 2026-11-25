//! The contents of one generation: unit names, stored units and status.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::util::{self, FileLock, now_secs};

use super::identity::parity_key;
use super::layout::{
    check_store_trust, ensure_writable_store, generation_names, remove_generation_lock,
    store_chain_has_reparse, store_lock_path, units_dir,
};
use super::manifest::{Manifest, UnitEntry, load_manifest, load_manifest_at, save_manifest};

/// Unit dir names of one generation: the manifest when readable, else the
/// `units/` directory (so an orphan generation can still be fully deleted).
pub fn generation_unit_names(store_root: &Path, parity: &str) -> Result<Vec<String>> {
    util::validate_component(parity, "generation")?;
    match util::probe(store_root, "store")? {
        Some(meta) if meta.is_dir() => {}
        Some(_) | None => return Ok(Vec::new()),
    }
    let generation = store_root.join(parity);
    if store_chain_has_reparse(store_root, &generation)? {
        anyhow::bail!(
            "generation {} is a symlink/reparse point",
            generation.display()
        );
    }
    if let Ok(Some(manifest)) = load_manifest(store_root, parity) {
        return Ok(manifest
            .units
            .iter()
            .map(|entry| entry.name.clone())
            .collect());
    }
    let units = units_dir(store_root, parity);
    if store_chain_has_reparse(store_root, &units)? {
        anyhow::bail!("units dir {} is a symlink/reparse point", units.display());
    }
    let mut names = Vec::new();
    if let Ok(entries) = fs::read_dir(&units) {
        for entry in entries.flatten() {
            if !entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if util::validate_component(&name, "unit name").is_ok() {
                names.push(name);
            }
        }
    }
    names.sort();
    Ok(names)
}

// ── stored units (read / remove) ─────────────────────────────────────────────

/// One unit as the vault holds it.
#[derive(Debug, Clone)]
pub struct StoredUnit {
    /// The generation directory the unit lives in (the parity key).
    pub generation: String,
    /// The manifest entry: name, profile, hash, stamp, files.
    pub entry: UnitEntry,
    /// `store/<generation>/units/<name>`.
    pub dir: PathBuf,
    /// Store root this unit was enumerated from. Kept so readers can
    /// revalidate the whole chain before opening a unit file.
    pub store_root: PathBuf,
}

/// Every stored unit across all generations, manifest-driven.
pub fn stored_units(store_root: &Path) -> Result<Vec<StoredUnit>> {
    match util::probe(store_root, "store")? {
        Some(meta) if meta.is_dir() => check_store_trust(store_root)?,
        Some(_) => anyhow::bail!("store {} is not a real directory", store_root.display()),
        None => return Ok(Vec::new()),
    }
    let mut out = Vec::new();
    for generation in generation_names(store_root)? {
        let Some(manifest) = load_manifest(store_root, &generation)? else {
            continue;
        };
        let units = units_dir(store_root, &generation);
        if store_chain_has_reparse(store_root, &units)? {
            anyhow::bail!("units dir {} is a symlink/reparse point", units.display());
        }
        for entry in manifest.units {
            let dir = units.join(&entry.name);
            util::probe(&dir, "unit")?;
            out.push(StoredUnit {
                generation: generation.clone(),
                entry,
                dir,
                store_root: store_root.to_path_buf(),
            });
        }
    }
    Ok(out)
}

/// The `rustc` identity recorded in a stored unit's Fingerprint JSON.
pub fn stored_unit_rustc(unit: &StoredUnit) -> Option<String> {
    let rel = Path::new(&unit.generation)
        .join("units")
        .join(&unit.entry.name)
        .join(format!("{}.json", unit.entry.memo));
    util::check_regular_chain(&unit.store_root, &rel).ok()?;
    let text = fs::read_to_string(unit.store_root.join(&rel)).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    match value.get("rustc") {
        Some(serde_json::Value::Number(number)) => Some(number.to_string()),
        Some(serde_json::Value::String(text)) => Some(text.clone()),
        _ => None,
    }
}

/// Remove stored unit groups: their directories go, the manifest is pruned,
/// and a generation left without units disappears entirely. Returns how many
/// groups were dropped; groups that could not be removed stay recorded.
pub fn drop_units(store_root: &Path, generation: &str, names: &[String]) -> Result<usize> {
    util::validate_component(generation, "generation")?;
    ensure_writable_store(store_root, "removing units")?;
    let lock = FileLock::acquire(&store_lock_path(store_root, generation))?;
    let generation_dir = store_root.join(generation);
    match util::probe(&generation_dir, "generation")? {
        Some(meta) if meta.is_dir() => {}
        Some(_) => anyhow::bail!("generation {} is not a directory", generation_dir.display()),
        None => {
            drop(lock);
            remove_generation_lock(store_root, generation);
            return Ok(0);
        }
    }
    let Some(mut manifest) = load_manifest_at(store_root, generation, true)? else {
        return Ok(0);
    };
    let units = units_dir(store_root, generation);
    match util::probe(&units, "units dir")? {
        Some(meta) if meta.is_dir() => {}
        Some(_) => {
            anyhow::bail!(
                "units dir {} is a symlink/reparse or not a directory",
                units.display()
            );
        }
        None => {
            // Nothing to remove; the manifest may still be pruned.
        }
    }
    let mut kept = Vec::with_capacity(manifest.units.len());
    let mut dropped = 0;
    for entry in manifest.units.drain(..) {
        if !names.contains(&entry.name) {
            kept.push(entry);
            continue;
        }
        util::validate_component(&entry.name, "unit name")?;
        let dir = units.join(&entry.name);
        match util::metadata_nofollow(&dir) {
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                eprintln!(
                    "could not remove symlinked/reparse unit {}: refused",
                    dir.display()
                );
                kept.push(entry);
            }
            Ok(meta) if meta.is_dir() => {
                // Delete relative to the store root, walking every component
                // with no-follow. The old canonicalize-then-remove_dir_all
                // sequence was a check/use race.
                match util::remove_tree(store_root, &dir) {
                    Ok(()) => {
                        // A path swap during deletion is skipped safely. Do
                        // not prune the manifest entry if the unit is still
                        // there.
                        if util::metadata_nofollow(&dir).is_ok_and(|meta| meta.is_dir()) {
                            eprintln!(
                                "could not remove {}: path changed or is not a real directory",
                                dir.display()
                            );
                            kept.push(entry);
                        } else {
                            dropped += 1;
                        }
                    }
                    Err(err) => {
                        eprintln!("could not remove {}: {err:#}", dir.display());
                        kept.push(entry);
                    }
                }
            }
            Ok(_) => {
                eprintln!("could not remove {}: not a directory", dir.display());
                kept.push(entry);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                dropped += 1;
            }
            Err(err) => {
                eprintln!("could not remove {}: {err}", dir.display());
                kept.push(entry);
            }
        }
    }
    manifest.units = kept;
    let empty = manifest.units.is_empty();
    if empty {
        let _ = util::remove_tree(store_root, &generation_dir);
    } else if dropped > 0 {
        manifest.updated = now_secs();
        save_manifest(store_root, generation, &manifest)?;
        sweep_blobs(store_root, generation, &manifest);
    }
    drop(lock);
    if empty {
        // The parity-key store is gone; its outside lock file is debris.
        remove_generation_lock(store_root, generation);
    }
    Ok(dropped)
}
/// Remove gzip blobs no longer referenced by the surviving manifest.
fn sweep_blobs(store_root: &Path, generation: &str, manifest: &Manifest) {
    let referenced: std::collections::HashSet<&str> = manifest
        .units
        .iter()
        .flat_map(|unit| unit.files.iter())
        .filter_map(|file| file.object.as_deref())
        .collect();
    let blobs = store_root.join(generation).join("blobs");
    let generation_root = store_root.join(generation);
    let mut budget = util::ScanBudget::new("blob sweep");
    // Collect top-down so `filter_entry` can prune a reparse subtree, then
    // delete deepest-first (each directory after its children). A contents-first
    // walk would traverse the subtree before filtering it: walkdir applies the
    // predicate only after descending.
    let mut entries = Vec::new();
    for entry in util::SafeWalk::new(&blobs).walk() {
        if !budget.take() {
            break;
        }
        if let Ok(entry) = entry {
            entries.push(entry);
        }
    }
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.depth()));
    for entry in entries {
        let path = entry.path();
        if entry.file_type().is_file() {
            let rel = path
                .strip_prefix(&generation_root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            if !referenced.contains(rel.as_str()) {
                let _ = util::remove_file(store_root, path);
            }
        } else if entry.file_type().is_dir() {
            let _ = util::remove_empty_dir(store_root, path);
        }
    }
}

// ── status ──────────────────────────────────────────────────────────────────

/// One generation as the `vault` command shows it.
#[derive(Debug, Default)]
pub struct GenerationInfo {
    pub parity: String,
    /// Matches the installed toolchain + flag environment.
    pub active: bool,
    pub units: usize,
    pub files: usize,
    /// Bytes as the store holds them; a file linked into views counts once.
    pub bytes: u64,
    /// Store files that are also linked elsewhere (`nlink > 1`).
    pub linked: usize,
    pub created: Option<u64>,
    pub updated: Option<u64>,
}

/// Summarize every generation of the vault.
pub fn generations(store_root: &Path) -> Result<Vec<GenerationInfo>> {
    if store_root.exists() {
        check_store_trust(store_root)?;
    }
    let active = parity_key().ok();
    let mut out = Vec::new();
    let mut scanned = 0u64;
    for parity in generation_names(store_root)? {
        let mut info = GenerationInfo {
            parity: parity.clone(),
            active: active.as_deref() == Some(parity.as_str()),
            ..Default::default()
        };
        if let Some(manifest) = load_manifest(store_root, &parity)? {
            info.units = manifest.units.len();
            info.created = Some(manifest.created);
            info.updated = Some(manifest.updated);
        }
        let units = units_dir(store_root, &parity);
        if !util::has_reparse_component(store_root, &units) && units.is_dir() {
            #[cfg(any(unix, windows))]
            let mut seen_inodes = std::collections::HashSet::new();
            let walker = util::SafeWalk::new(&units).walk();
            for entry in walker {
                let entry = entry?;
                scanned = scanned.saturating_add(1);
                if scanned > util::MAX_SCAN_FILES {
                    anyhow::bail!(
                        "store {} has more than {} files — refusing an unbounded scan",
                        store_root.display(),
                        util::MAX_SCAN_FILES
                    );
                }
                if !entry.file_type().is_file() {
                    continue;
                }
                let meta = entry.metadata()?;
                #[cfg(unix)]
                let unique = {
                    use std::os::unix::fs::MetadataExt;
                    seen_inodes.insert((meta.dev(), meta.ino()))
                };
                #[cfg(windows)]
                let unique = crate::util::windows_file_identity(entry.path())
                    .map(|(volume, index, _, _)| seen_inodes.insert((u64::from(volume), index)))
                    .unwrap_or(true);
                #[cfg(not(any(unix, windows)))]
                let unique = true;
                info.files = info.files.saturating_add(1);
                if unique {
                    info.bytes = info.bytes.saturating_add(meta.len());
                }
                if link_count(entry.path(), &meta) > 1 {
                    info.linked += 1;
                }
            }
        }
        out.push(info);
    }
    Ok(out)
}

/// Hard links of one inode as the file system knows it (1 where unsupported).
pub(crate) fn link_count(path: &Path, meta: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = path;
        meta.nlink()
    }
    #[cfg(windows)]
    {
        let _ = meta;
        crate::util::windows_file_identity(path)
            .map(|(_, _, links, _)| u64::from(links))
            .unwrap_or(1)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, meta);
        1
    }
}
