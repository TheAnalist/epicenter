//! Harvest: sign the unit groups of a build dir into the vault.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rayon::prelude::*;

use crate::fingerprint::{self, ArtifactInfo, Unit};
use crate::util::{self, FileLock, metadata_nofollow, now_secs};

use super::identity::{parity_key_with, toolchain_install_time_of, toolchain_of};
#[cfg(windows)]
use super::layout::require_private_windows_acl;
use super::layout::{
    GENERATION_MARKER, ensure_store_root, store_is_shared_mount, store_lock_path,
    unit_name_matches, units_dir, write_marker,
};
use super::manifest::{FileEntry, Manifest, UnitEntry, load_manifest_at, save_manifest};

// ── harvest ─────────────────────────────────────────────────────────────────

/// What one harvest did.
#[derive(Debug, Default)]
pub struct HarvestReport {
    pub parity: String,
    pub toolchain: String,
    pub stored: usize,
    pub refreshed: usize,
    pub unchanged: usize,
    pub skipped_stale: usize,
    pub skipped_incomplete: usize,
    pub files: usize,
    pub bytes: u64,
    pub note: Option<String>,
    /// Set when the caller bypassed the exec-record gate (`--trusted`).
    pub trusted: Option<String>,
}

/// Who vouches for a build root at harvest time.
///
/// Harvest is a signing step: the vault manifest is authenticated, so whatever
/// is signed becomes indistinguishable from a build this host trusts. A build
/// dir is untrusted input, so the default is [`Recorded`](Self::Recorded).
#[derive(Debug, Clone, Copy)]
pub enum HarvestTrust<'a> {
    /// Sign only a build this host ran: a job dir needs the `exec` record
    /// written next to it, and a shared build dir must be local and private.
    Recorded,
    /// Explicit trusted-builder mode (`--trusted`): the caller asserts that
    /// every writer of this build root is in the same trust domain.
    Trusted(&'a str),
}

/// Store unit groups from a build dir into the vault.
///
/// Only units built by the installed toolchain are stored: the newest unit's
/// rustc cohort marks the active generation, and a cache that as a whole
/// predates the installed toolchain produces a note instead of stale copies
/// filed under the current parity key.
pub fn harvest(
    build_root: &Path,
    store_root: &Path,
    unit_filter: Option<&str>,
    dry_run: bool,
) -> Result<HarvestReport> {
    harvest_with_trust(
        build_root,
        store_root,
        unit_filter,
        dry_run,
        None,
        None,
        true,
        HarvestTrust::Recorded,
    )
}

/// Harvest for a specific toolchain and/or layout (`exec` with a `+toolchain`
/// child). The plain [`harvest`] uses the default toolchain and derives the
/// layout from `cargo --version`.
pub fn harvest_with(
    build_root: &Path,
    store_root: &Path,
    unit_filter: Option<&str>,
    dry_run: bool,
    selector: Option<&str>,
    layout: Option<fingerprint::UnitLayout>,
    compress: bool,
) -> Result<HarvestReport> {
    harvest_with_trust(
        build_root,
        store_root,
        unit_filter,
        dry_run,
        selector,
        layout,
        compress,
        HarvestTrust::Recorded,
    )
}

/// [`harvest_with`] with an explicit trust decision.
pub fn harvest_with_trust(
    build_root: &Path,
    store_root: &Path,
    unit_filter: Option<&str>,
    dry_run: bool,
    selector: Option<&str>,
    layout: Option<fingerprint::UnitLayout>,
    compress: bool,
    trust: HarvestTrust<'_>,
) -> Result<HarvestReport> {
    let build_root = validate_build_root(build_root)?;
    authorize_harvest(&build_root, trust)?;
    // Fence the writer against a live Cargo build. A lock check that drops the
    // handles races the build that starts one instruction later.
    let tc = toolchain_of(selector)?;
    let parity = parity_key_with(&tc)?;
    let mut report = HarvestReport {
        parity: parity.clone(),
        toolchain: tc.version_line(),
        trusted: match trust {
            HarvestTrust::Trusted(reason) => Some(reason.to_string()),
            HarvestTrust::Recorded => None,
        },
        ..Default::default()
    };

    // Serialize every manifest read-modify-write. Parallel `exec --harvest`
    // jobs otherwise lose each other's units (last writer wins).
    let _lock = if dry_run {
        None
    } else {
        ensure_store_root(store_root)?;
        util::create_private_dir_all(&store_root.join(&parity))?;
        write_marker(&store_root.join(&parity).join(GENERATION_MARKER))?;
        util::create_private_dir_all(&units_dir(store_root, &parity))?;
        let lock = FileLock::acquire(&store_lock_path(store_root, &parity))?;
        // Self-heal debris from a crashed or failed store run (dot-dirs whose
        // copies may have inherited read-only sources) before planning.
        sweep_staging(&units_dir(store_root, &parity))?;
        Some(lock)
    };
    let generation_root = store_root.join(&parity);
    match util::probe(&generation_root, "generation")? {
        Some(meta) if meta.is_dir() => {}
        // A dry run does not create the generation directory.
        Some(_) => anyhow::bail!(
            "generation {} is not a directory",
            generation_root.display()
        ),
        None => {}
    }
    let blobs = if compress && !dry_run {
        Some(generation_root.clone())
    } else {
        None
    };
    if let Some(root) = &blobs {
        util::create_private_dir_all(&root.join("blobs"))?;
    }

    let pool = (crate::settings::copy_workers() > 1).then(crate::settings::copy_pool);

    // Fence the writer against a live Cargo build. Acquire after the
    // toolchain probe: a forked/exec'd child must not inherit the lock fd.
    let _build_locks = match crate::job::cargo_locks(&build_root)? {
        Some(locks) => Some(locks),
        None => anyhow::bail!(
            "build dir {} is in use by a live build — harvest skipped",
            build_root.display()
        ),
    };
    let mut rows = fingerprint::read_rows(&build_root, pool)?;

    // A view that mixes both layouts is ambiguous: keep the layout of the
    // harvest toolchain (stable classic vs nightly new) and drop the other.
    let mut has_classic = false;
    let mut has_new = false;
    for (unit, _) in &rows {
        has_classic |= unit.layout == fingerprint::UnitLayout::Classic;
        has_new |= unit.layout == fingerprint::UnitLayout::New;
    }
    let expected_layout = layout.or_else(|| {
        (has_classic && has_new).then(|| fingerprint::layout_for_cargo(&tc.release, &[]))
    });
    if let Some(wanted) = expected_layout {
        let before = rows.len();
        rows.retain(|(unit, _)| unit.layout == wanted);
        report.skipped_stale += before - rows.len();
    }

    // Freshness gate for the whole cache and the active rustc cohort. Both
    // read the same newest-artifact information, so keep it in one pass.
    let mut newest_activity: Option<SystemTime> = None;
    let mut active_gen = String::from("unknown");
    let mut active_newest: Option<SystemTime> = None;
    for (unit, arts) in &rows {
        if let Some(time) = arts.newest {
            newest_activity = Some(newest_activity.map_or(time, |current| current.max(time)));
        }
        if crate::fingerprint::rustc_of(unit) != "unknown"
            && active_newest.map_or(true, |current| arts.newest >= Some(current))
        {
            active_newest = arts.newest;
            active_gen = crate::fingerprint::rustc_of(unit);
        }
    }
    if let (Some(newest), Some(installed)) = (newest_activity, toolchain_install_time_of(selector))
    {
        if newest < installed {
            report.note = Some(format!(
                "the shared cache predates the installed toolchain ({}) — build once, then harvest",
                tc.version_line()
            ));
            return Ok(report);
        }
    }

    let loaded = load_manifest_at(store_root, &parity, !dry_run)?;
    let had_manifest = loaded.is_some();
    let mut manifest = loaded.unwrap_or_else(|| Manifest {
        parity_key: parity.clone(),
        toolchain: tc.version_line(),
        created: now_secs(),
        updated: 0,
        units: Vec::new(),
        mac: String::new(),
        signature: String::new(),
    });

    let mut manifest_index: std::collections::HashMap<String, usize> =
        std::collections::HashMap::with_capacity(manifest.units.len());
    for (index, entry) in manifest.units.iter().enumerate() {
        manifest_index.entry(entry.name.clone()).or_insert(index);
    }

    let mut plans = Vec::with_capacity(rows.len());
    for (unit, arts) in rows {
        if let Some(query) = unit_filter {
            if !unit_name_matches(&unit.dir_name, query) {
                continue;
            }
        }
        let cohort = crate::fingerprint::rustc_of(&unit);
        if cohort != "unknown" && active_gen != "unknown" && cohort != active_gen {
            report.skipped_stale += 1;
            continue;
        }
        // A unit already stored with a version keeps it: no second `.d` read
        // on a warm harvest.
        let known = manifest_index
            .get(&unit.dir_name)
            .and_then(|&index| manifest.units[index].version.as_deref());
        match plan_unit(unit, &arts, &build_root, known)? {
            Some(plan) => plans.push(plan),
            None => report.skipped_incomplete += 1,
        }
    }

    resolve_plan_graph(&mut plans, &manifest);

    // Select work once: compare the planned file set with the manifest, then
    // keep only the plans that need a copy.
    let mut pending: Vec<usize> = Vec::new();
    let mut version_changed = false;
    for (at, plan) in plans.iter().enumerate() {
        let unit = &plan.unit;
        let group_dir = units_dir(store_root, &parity).join(&unit.dir_name);
        let mut new_entries: Vec<(&str, &str, &str)> = plan
            .files
            .iter()
            .map(|file| (file.path.as_str(), file.dest.as_str(), file.role))
            .collect();
        new_entries.sort_unstable();
        let already = manifest_index
            .get(&unit.dir_name)
            .and_then(|&index| manifest.units.get(index))
            .map(|entry| {
                let mut stored: Vec<(&str, &str, &str)> = entry
                    .files
                    .iter()
                    .map(|file| (file.path.as_str(), file.dest.as_str(), file.role.as_str()))
                    .collect();
                stored.sort_unstable();
                entry.hash == plan.hash
                    && entry.profile == unit.profile
                    && entry.stamp == plan.stamp
                    && stored == new_entries
                    && entry.files.iter().all(|file| {
                        if file.sha256.is_empty() || !group_dir.join(&file.path).is_file() {
                            return false;
                        }
                        file.object
                            .as_ref()
                            .map(|object| generation_root.join(object).is_file())
                            .unwrap_or(true)
                    })
            })
            .unwrap_or(false);
        if already {
            // An older manifest has no version. Learn it in place instead of
            // re-copying unchanged files just to add one field.
            if let Some(&slot) = manifest_index.get(&unit.dir_name) {
                if manifest.units[slot].version != plan.version {
                    manifest.units[slot].version = plan.version.clone();
                    version_changed = true;
                }
            }
            report.unchanged += 1;
            continue;
        }
        if dry_run {
            report.stored += 1;
            report.files = report.files.saturating_add(plan.files.len());
            report.bytes = report.bytes.saturating_add(plan.bytes);
            continue;
        }
        pending.push(at);
    }

    let changed = !pending.is_empty();
    if changed {
        let store_one = |at: usize| -> Result<Vec<FileEntry>> {
            let plan = &plans[at];
            let mut entries = Vec::with_capacity(plan.files.len());
            store_group(
                store_root,
                &parity,
                &plan.unit.dir_name,
                plan.stamp,
                &plan.files,
                blobs.as_deref(),
                &mut entries,
            )
            .with_context(|| format!("storing unit {}", plan.unit.dir_name))?;
            Ok(entries)
        };
        let stored: Vec<Result<Vec<FileEntry>>> = match pool {
            Some(pool) if pending.len() > 1 => {
                pool.install(|| pending.par_iter().map(|&at| store_one(at)).collect())
            }
            _ => pending.iter().map(|&at| store_one(at)).collect(),
        };

        for (at, entries) in pending.into_iter().zip(stored) {
            let entries = entries?;
            let plan = &plans[at];
            let entry = UnitEntry {
                name: plan.unit.dir_name.clone(),
                profile: plan.unit.profile.clone(),
                memo: plan.memo.clone(),
                hash: plan.hash.clone(),
                version: plan.version.clone(),
                stamp: plan.stamp,
                layout: Some(plan.unit.layout),
                files: entries,
            };
            match manifest_index.get(&entry.name).copied() {
                Some(slot) => {
                    manifest.units[slot] = entry;
                    report.refreshed += 1;
                }
                None => {
                    manifest_index.insert(entry.name.clone(), manifest.units.len());
                    manifest.units.push(entry);
                    report.stored += 1;
                }
            }
            report.files = report.files.saturating_add(plan.files.len());
            report.bytes = report.bytes.saturating_add(plan.bytes);
        }
    }

    if !dry_run && (changed || version_changed || !had_manifest || manifest.units.is_empty()) {
        manifest.units.sort_by(|a, b| {
            (a.profile.as_str(), a.name.as_str()).cmp(&(b.profile.as_str(), b.name.as_str()))
        });
        manifest.updated = now_secs();
        save_manifest(store_root, &parity, &manifest)?;
    }
    Ok(report)
}

struct PlannedFile {
    src: PathBuf,
    path: String,
    dest: String,
    role: &'static str,
    size: u64,
    modified: SystemTime,
}

struct UnitPlan {
    unit: Unit,
    files: Vec<PlannedFile>,
    memo: String,
    hash: String,
    version: Option<String>,
    base: u64,
    bytes: u64,
    deps: Vec<usize>,
    stamp: u64,
}

/// Package version from rustc's dep-info side file.
///
/// Registry crates live at `…/registry/src/<index>/<name>-<version>/…` and
/// rustc's `.d` file lists that path. One bounded read per planned unit; a
/// missing or non-registry source yields `None`, which keeps the name-only
/// match at restore instead of dropping the unit.
fn unit_version(arts: &ArtifactInfo, package: &str) -> Option<String> {
    let dep = arts
        .paths
        .iter()
        .map(|(path, _, _)| path)
        .find(|path| path.extension().is_some_and(|ext| ext == "d"))?;
    let text = util::read_text_prefix(dep, 64 * 1024).ok()?;
    let (_, sources) = text.lines().next()?.split_once(": ")?;
    for token in sources.split_whitespace() {
        let normalized = token.replace("\\ ", " ").replace('\\', "/");
        if !normalized.contains("/registry/src/") && !normalized.contains("/git/checkouts/") {
            continue;
        }
        for component in Path::new(&normalized).components().rev() {
            let name = component.as_os_str().to_string_lossy();
            let Some((crate_name, version)) = name.rsplit_once('-') else {
                continue;
            };
            if crate_name == package && looks_like_version(version) {
                return Some(version.to_string());
            }
        }
    }
    None
}

fn looks_like_version(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text.starts_with(|ch: char| ch.is_ascii_digit())
        && text.contains('.')
        && text
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '+'))
}

/// Turn one discovered unit into a copy plan. File size and mtime are read
/// once here, so later phases never walk the same files again.
fn plan_unit(
    unit: Unit,
    arts: &ArtifactInfo,
    build_root: &Path,
    known_version: Option<&str>,
) -> Result<Option<UnitPlan>> {
    let unit_dir = &unit.fingerprint_dir;
    let profile_dir = build_root.join(&unit.profile);
    let memo = unit.memo_file.clone();
    let hash = unit.memo_hash.clone().unwrap_or_default();
    // A fingerprint dir without a memo hash is an incomplete build (cargo
    // may leave only `output-*` diagnostics when compilation or linking
    // failed). There is nothing to restore, and recording the diagnostic
    // text as a hash would poison the manifest.
    if !fingerprint::looks_like_hash(&hash) {
        return Ok(None);
    }
    // Provenance gate: harvest is a signing step, so only a complete Cargo
    // fingerprint may enter the vault. A hand-written shape (memo + .so) has
    // no `<memo>.json`, no dep-info and no unit hashes; it is not a unit.
    let Some(json) = unit.json.as_ref() else {
        return Ok(None);
    };
    if json.rustc.is_empty()
        || json.target.is_empty()
        || json.profile.is_empty()
        || json.path.is_empty()
    {
        return Ok(None);
    }
    if unit.kind != fingerprint::UnitKind::BuildScriptRun && unit.dep_info.is_none() {
        return Ok(None);
    }
    let memo_json = unit
        .fingerprint_dir
        .join(format!("{}.json", unit.memo_file));
    match util::metadata_nofollow(&memo_json) {
        Ok(meta) if meta.is_file() => {}
        _ => return Ok(None),
    }
    let mut files: Vec<PlannedFile> = Vec::new();

    // The parser already read this directory once; reuse its names, roles and
    // metadata instead of re-reading and re-classifying every file.
    for seen in &unit.files_seen {
        if is_volatile(&seen.name) {
            continue;
        }
        let src = unit_dir.join(&seen.name);
        let modified = seen
            .modified
            .with_context(|| format!("reading mtime of {}", src.display()))?;
        files.push(PlannedFile {
            src,
            path: seen.name.clone(),
            dest: format!("{}/{}", unit.fingerprint_rel(), seen.name),
            role: seen.role,
            size: seen.size,
            modified,
        });
    }

    // Artifacts: `deps/…` and the `build/<anchor>/…` tree of build scripts.
    // Wrapper internals and rustc's `.d` side files stay out.
    let mut artifact_count = 0;
    for (path, size, modified) in &arts.paths {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if is_volatile(&name) {
            continue;
        }
        let Ok(rel) = path.strip_prefix(&profile_dir) else {
            continue;
        };
        let rel = rel.to_string_lossy().replace('\\', "/");
        if rel.ends_with(".d")
            && (rel.starts_with("deps/") || unit.layout == fingerprint::UnitLayout::New)
        {
            continue;
        }
        let role = if rel.starts_with("deps/") || rel.contains("/out/") {
            "artifact"
        } else if rel.starts_with("build/") {
            "build-tree"
        } else {
            "artifact"
        };
        let modified = match modified {
            Some(modified) => *modified,
            None => fs::metadata(path)
                .and_then(|meta| meta.modified())
                .with_context(|| format!("reading mtime of {}", path.display()))?,
        };
        files.push(PlannedFile {
            src: path.clone(),
            path: rel.clone(),
            dest: rel,
            role,
            size: *size,
            modified,
        });
        artifact_count += 1;
    }
    if artifact_count == 0 {
        return Ok(None);
    }

    let bytes = files.iter().map(|file| file.size).sum();
    let base = group_base(&files);
    let version = known_version
        .map(str::to_string)
        .or_else(|| unit_version(arts, &unit.package));
    Ok(Some(UnitPlan {
        unit,
        files,
        memo,
        hash,
        version,
        base,
        bytes,
        deps: Vec::new(),
        stamp: base,
    }))
}

/// Resolve dependency edges and raise each unit's stamp to every stored or
/// planned dependency. Kahn's queue replaces the repeated full-array scan;
/// the final walk keeps the same one-pass behavior for an unexpected cycle.
fn resolve_plan_graph(plans: &mut [UnitPlan], manifest: &Manifest) {
    let stored_stamps: std::collections::HashMap<String, u64> = manifest
        .units
        .iter()
        .map(|entry| (entry.hash.clone(), entry.stamp))
        .collect();
    let index: std::collections::HashMap<String, usize> = plans
        .iter()
        .enumerate()
        .map(|(position, plan)| (plan.hash.clone(), position))
        .collect();

    for plan in plans.iter_mut() {
        let (deps, stamp) = {
            let mut deps = Vec::new();
            let mut stamp = plan.base;
            if let Some(json) = plan.unit.json.as_ref() {
                for dep in &json.deps {
                    let Some(hash) = dep.memo_hash() else {
                        continue;
                    };
                    if let Some(&at) = index.get(hash.as_str()) {
                        deps.push(at);
                    } else if let Some(known) = stored_stamps.get(hash.as_str()) {
                        stamp = stamp.max(*known);
                    }
                }
            }
            (deps, stamp)
        };
        plan.deps = deps;
        plan.stamp = stamp;
    }

    let count = plans.len();
    let mut indegree = vec![0usize; count];
    let mut followers: Vec<Vec<usize>> = vec![Vec::new(); count];
    for (at, plan) in plans.iter().enumerate() {
        for &dep in &plan.deps {
            if dep == at {
                continue;
            }
            indegree[at] += 1;
            followers[dep].push(at);
        }
    }
    let mut queue: std::collections::VecDeque<usize> =
        (0..count).filter(|&at| indegree[at] == 0).collect();
    let mut order = Vec::with_capacity(count);
    while let Some(at) = queue.pop_front() {
        order.push(at);
        for &next in &followers[at] {
            indegree[next] -= 1;
            if indegree[next] == 0 {
                queue.push_back(next);
            }
        }
    }
    if order.len() < count {
        let mut ordered = vec![false; count];
        for &at in &order {
            ordered[at] = true;
        }
        for at in 0..count {
            if !ordered[at] {
                order.push(at);
            }
        }
    }
    for &at in &order {
        let mut stamp = plans[at].stamp;
        for &dep in &plans[at].deps {
            stamp = stamp.max(plans[dep].stamp);
        }
        plans[at].stamp = stamp;
    }
}

/// The canonical stamp: the ceiling of the newest `.rmeta` when present,
/// otherwise of the newest file.
fn group_base(files: &[PlannedFile]) -> u64 {
    let mut newest: Option<SystemTime> = None;
    let mut metadata: Option<SystemTime> = None;
    for file in files {
        if newest.map_or(true, |current| file.modified > current) {
            newest = Some(file.modified);
        }
        if file.path.ends_with(".rmeta") && metadata.map_or(true, |current| file.modified > current)
        {
            metadata = Some(file.modified);
        }
    }
    match metadata.or(newest) {
        Some(time) => ceil_secs(time),
        None => now_secs(),
    }
}

/// Copy one unit group into its final place: a temporary directory next to
/// the target, stamped read-only files, then a swap that never leaves the
/// group half-written under its real name.
fn store_group(
    store_root: &Path,
    parity: &str,
    name: &str,
    stamp: u64,
    files: &[PlannedFile],
    blobs: Option<&Path>,
    entries: &mut Vec<FileEntry>,
) -> Result<()> {
    util::validate_component(name, "unit name")?;
    let units = units_dir(store_root, parity);
    let final_dir = units.join(name);
    // Unique staging names + O_EXCL directory creation: a pre-planted symlink
    // or temp dir can never be followed/truncated.
    let tmp = util::create_temp_dir(&units, &format!("{name}.tmp"))?;

    if let Err(err) = stage_group(&tmp, files, stamp, blobs, entries) {
        // Never leave a half-written staging dir behind: it would keep a
        // failed unit's bytes on disk and hide the failure from the next run.
        let _ = util::remove_tree(&units, &tmp);
        return Err(err);
    }

    let old = units.join(format!(".{name}.old-{}-{}", std::process::id(), now_secs()));
    match util::metadata_nofollow(&final_dir) {
        Ok(meta) if meta.is_dir() => fs::rename(&final_dir, &old)?,
        Ok(_) => {
            let _ = util::remove_tree(&units, &tmp);
            anyhow::bail!("store unit path {} is not a directory", final_dir.display());
        }
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            let _ = util::remove_tree(&units, &tmp);
            anyhow::bail!(
                "refusing symlinked/reparse store unit {}",
                final_dir.display()
            );
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).context("inspecting store unit"),
    }
    fs::rename(&tmp, &final_dir)?;
    if util::metadata_nofollow(&old).is_ok_and(|meta| meta.is_dir()) {
        let _ = util::remove_tree(&units, &old);
    }
    Ok(())
}

/// Library outputs bypass gzip (rustc reads them directly at restore time);
/// all other artifacts are compressed when it wins.
#[cfg(unix)]
fn is_library_output(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let extension = name.rsplit_once('.').map(|(_, extension)| extension);
    if path.starts_with("deps/") {
        matches!(extension, Some("rlib" | "so" | "dylib" | "a"))
    } else if path.contains("/out/") {
        matches!(extension, Some("rlib" | "so"))
    } else {
        false
    }
}

/// Copy one staged file. Never hard-link the live build tree into the store:
/// the store stamps files read-only and the build tree stays writable, so a
/// shared inode can be rewritten through either path (and Cargo cannot
/// replace a read-only output in place). Reflink is attempted by
/// `copy_file_hashed`; otherwise this is a verified copy.
fn materialize_file(file: &PlannedFile, dst: &Path) -> Result<(u64, String)> {
    util::copy_file_hashed(&file.src, dst)
}

/// Copy or link one unit group's files into its staging dir. `materialize_file`
/// leaves every destination writable; stamping and the read-only store mode
/// happen after that.
fn stage_group(
    tmp: &Path,
    files: &[PlannedFile],
    stamp: u64,
    blobs: Option<&Path>,
    entries: &mut Vec<FileEntry>,
) -> Result<()> {
    for file in files {
        let rel = util::validate_rel(&file.path, "stored file path")?;
        let dst = tmp.join(&rel);
        if let Some(parent) = dst.parent() {
            util::create_private_dir_all(parent)?;
        }
        #[cfg(unix)]
        let library = is_library_output(&file.path);
        #[cfg(not(unix))]
        let library = false;
        if let Some(root) = blobs {
            if !library && matches!(file.role, "artifact" | "build-tree") {
                if let Some((size, sha256, object)) = util::compress_file_hashed(&file.src, root)
                    .with_context(|| format!("compressing {}", file.src.display()))?
                {
                    let blob = root.join(&object);
                    fs::hard_link(&blob, &dst).with_context(|| {
                        format!("linking {} -> {}", blob.display(), dst.display())
                    })?;
                    entries.push(FileEntry {
                        path: file.path.clone(),
                        dest: file.dest.clone(),
                        size,
                        sha256,
                        role: file.role.to_string(),
                        object: Some(object),
                    });
                    continue;
                }
            }
        }
        let (size, sha256) = materialize_file(file, &dst)
            .with_context(|| format!("storing {} -> {}", file.src.display(), dst.display()))?;
        set_stamp(&dst, stamp)?;
        make_read_only(&dst)?;
        entries.push(FileEntry {
            path: file.path.clone(),
            dest: file.dest.clone(),
            size,
            sha256,
            role: file.role.to_string(),
            object: None,
        });
    }
    Ok(())
}

/// Remove staging leftovers (`.{unit}.tmp-{pid}`, `.{unit}.old-{pid}`) that a
/// crashed or failed run left in the units dir. Fresh dirs are left alone: a
/// concurrent harvest may be filling them right now.
pub(crate) fn sweep_staging(units: &Path) -> Result<()> {
    metadata_nofollow(units)?;
    let entries = fs::read_dir(units)?;
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !(name.contains(".tmp-") || name.contains(".old-")) {
            continue;
        }
        let meta = match util::metadata_nofollow(&entry.path()) {
            Ok(meta) => meta,
            // Unlink a planted symlink/reparse name itself; never traverse it.
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                let _ = util::remove_file(units, &entry.path());
                continue;
            }
            Err(_) => continue,
        };
        if !meta.is_dir() {
            continue;
        }
        let stale = meta
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age > Duration::from_secs(600));
        if stale {
            let _ = util::remove_tree(units, &entry.path());
        }
    }
    Ok(())
}

/// Round a timestamp up to whole seconds.
pub(crate) fn ceil_secs(time: SystemTime) -> u64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs();
            if duration.subsec_nanos() > 0 {
                secs + 1
            } else {
                secs
            }
        }
        Err(_) => 0,
    }
}

pub(crate) fn set_stamp(path: &Path, stamp: u64) -> Result<()> {
    let time = UNIX_EPOCH + Duration::from_secs(stamp);
    // Unix allows futimens on a read-only fd owned by us; Windows requires a
    // handle with FILE_WRITE_ATTRIBUTES (GENERIC_READ's set_modified is
    // denied). A 0444 store file must still be stampable on Windows.
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let file = fs::OpenOptions::new()
            .access_mode(0x0100) // FILE_WRITE_ATTRIBUTES
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .or_else(|_| {
                fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(path)
            })
            .with_context(|| format!("opening {} to stamp it", path.display()))?;
        let meta = file.metadata()?;
        if meta.file_type().is_symlink() || util::is_reparse_point(&meta) {
            anyhow::bail!("refusing symlink/reparse stamp target {}", path.display());
        }
        file
    };
    #[cfg(unix)]
    let file = util::open_file_nofollow(path)
        .with_context(|| format!("opening {} to stamp it", path.display()))?;
    #[cfg(not(any(unix, windows)))]
    let file =
        fs::File::open(path).with_context(|| format!("opening {} to stamp it", path.display()))?;
    file.set_modified(time)
        .with_context(|| format!("stamping {}", path.display()))?;
    Ok(())
}

/// On Unix the store is read-only (owner can still stamp and delete; only
/// content edits are refused). On Windows a read-only file blocks rename
/// and delete, so the store keeps normal permissions there.
pub(crate) fn make_read_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file = util::open_file_nofollow(path)
            .with_context(|| format!("opening {} to mark it read-only", path.display()))?;
        file.set_permissions(fs::Permissions::from_mode(0o444))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Files that never enter the store: the volatile invocation timestamp,
/// and wrapper bookkeeping (`*.kache-*`, `.kache*`) that lives in the build
/// dir but is no part of Cargo's state.
#[inline]
fn is_volatile(name: &str) -> bool {
    name == "invoked.timestamp" || name.contains(".kache")
}

/// Harvest is a signing step: only accept a real, local, non-shared build
/// root. A group/world-writable build dir is a shared trust domain, and every
/// unit found there would be signed into the vault.
/// Refuse to sign a build root this host cannot vouch for.
///
/// The ownership/mode check in [`validate_build_root`] is not enough: a job
/// dir or a shared build dir can still be written by another process between
/// the check and the copy. The job marker decides which proof applies.
fn authorize_harvest(build_root: &Path, trust: HarvestTrust<'_>) -> Result<()> {
    if let HarvestTrust::Trusted(_) = trust {
        return Ok(());
    }
    // A network mount is a second trust domain: the writer may be a different
    // machine entirely, so nothing inside the dir is a provenance signal.
    if store_is_shared_mount(build_root) {
        anyhow::bail!(
            "build dir {} is a network/shared mount — refusing to sign it; pass --trusted only if every writer is in this trust domain",
            build_root.display()
        );
    }
    if let Some(token) = crate::job::job_marker_token(build_root)? {
        match crate::job::record_covers(build_root, &token)? {
            crate::job::RecordCoverage::Matching => {}
            crate::job::RecordCoverage::Absent => anyhow::bail!(
                "job dir {} has no exec record on this host — refusing to sign it; harvest it from the `epicenter exec --harvest` run that built it",
                build_root.display()
            ),
            crate::job::RecordCoverage::Mismatch => anyhow::bail!(
                "job dir {} has an exec record for a different build (token or path mismatch) — refusing to sign it",
                build_root.display()
            ),
            crate::job::RecordCoverage::Untrusted => anyhow::bail!(
                "job dir {} has an exec record this host does not trust (symlink, foreign owner, or permissive mode) — refusing to sign it",
                build_root.display()
            ),
        }
    }
    Ok(())
}

fn validate_build_root(build_root: &Path) -> Result<PathBuf> {
    let build_root = util::validate_state_root(build_root, "build root")?;
    let meta = util::metadata_nofollow(&build_root)
        .with_context(|| format!("inspecting build root {}", build_root.display()))?;
    if !util::owned_by_us(&build_root, &meta) {
        anyhow::bail!(
            "build root {} is owned by another user — refusing to sign its units",
            build_root.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o022 != 0 {
            anyhow::bail!(
                "build root {} is group/world-writable (mode {:o}) — a shared build dir is a shared trust domain; use a private build dir",
                build_root.display(),
                meta.mode() & 0o777
            );
        }
    }
    #[cfg(windows)]
    require_private_windows_acl(&build_root, "build root")?;
    Ok(build_root)
}
