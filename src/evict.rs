//! `epicenter evict` — deliberate, user-invoked removal of units.
//! Eviction is never automatic: the caller must select units explicitly.
//!
//! Safety shape (mirrors `prune`):
//! - **dry run by default** — pass `--yes` to actually delete;
//! - **current toolchain generation is protected** unless `--force`:
//!   removing it would force a rebuild of units cargo may be using right now;
//! - at least one selector is required — there is no "evict everything".

use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use walkdir::WalkDir;

use crate::fingerprint::{self, ArtifactInfo, Unit};
use crate::util::{self, human_age, human_bytes, parse_duration};
use crate::who;

/// What the user asked to evict.
pub struct Options<'a> {
    /// Unit query: dir name, dir hash fragment, or package name.
    pub unit: Option<&'a str>,
    /// Every unit on a stale toolchain generation (the bulk selector).
    pub stale: bool,
    /// Exact (or prefix) rustc fingerprint identity.
    pub rustc_key: Option<&'a str>,
    /// Units whose artifacts are already missing (fingerprint husks).
    pub husks: bool,
    /// Units untouched for longer than this (e.g. `30d`).
    pub older_than: Option<&'a str>,
    /// The per-job working-dir tier: collect `work/<job-id>/` views
    /// (its own selector; default age 7 days).
    pub work_dirs: bool,
    /// Remove ONE job dir now (name, `work/<id>`, or a path under `work/`):
    /// explicit choices bypass the GC age window; a locked dir is refused.
    pub work_dir: Option<&'a str>,
    /// Surgical view operation: unlink units from ONE view only (`build`,
    /// a `work/<id>` job dir, or a path). Never touches the vault.
    pub work: Option<&'a str>,
    /// Package selector for `--work` (dashes and underscores both match).
    pub crate_name: Option<&'a str>,
    /// Which tier an eviction touches: the store, the views, or both.
    pub tier: Tier,
    /// Also allow evicting current-generation units.
    pub force: bool,
    /// Actually delete (without this it is a dry run).
    pub delete: bool,
}

/// What an eviction touches. The vault ("store") is the user's storage —
/// trimming it never breaks a build, only the next one compiles more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Tier {
    /// The store and every known view (default).
    All,
    /// The vault only — views keep their hard links.
    Store,
    /// The shared build dir and every job dir — the vault is untouched.
    View,
}

impl Tier {
    fn touches_store(self) -> bool {
        matches!(self, Tier::All | Tier::Store)
    }

    fn touches_view(self) -> bool {
        matches!(self, Tier::All | Tier::View)
    }
}

/// Default max age of a per-job working dir before `--work-dirs` collects it.
pub const DEFAULT_WORK_MAX_AGE: &str = "7d";

/// `epicenter evict [unit] [--stale|--rustc-key|--husks|--older-than|--work-dirs|--work <view>] [--tier <t>] [--force] [--yes]`
pub fn run(build_root: &Path, opts: &Options<'_>) -> Result<()> {
    // An empty selector is a wildcard (`contains("")`) — never delete by it.
    for (name, value) in [
        ("--unit", opts.unit),
        ("--rustc-key", opts.rustc_key),
        ("--crate", opts.crate_name),
    ] {
        if value.is_some_and(|value| value.is_empty()) {
            bail!("{name} must not be empty — use an explicit selector or a dry run");
        }
    }
    if let Some(target) = opts.work_dir {
        if opts.work_dirs || opts.work.is_some() {
            bail!(
                "one operation at a time — --work-dir removes ONE job dir:\n\
                 --work-dirs collects the whole tier by age, --work unlinks units inside a view"
            );
        }
        if opts.unit.is_some()
            || opts.crate_name.is_some()
            || opts.stale
            || opts.rustc_key.is_some()
            || opts.husks
            || opts.older_than.is_some()
        {
            bail!(
                "--work-dir removes exactly the named job dir and takes no selectors:\n\
                 e.g. `epicenter evict --work-dir ci-1` (dry run) then --yes"
            );
        }
        if opts.tier != Tier::All {
            bail!("--tier does not apply to --work-dir — a job dir is one view, removed whole");
        }
        return evict_work_dir(build_root, target, opts.delete);
    }

    if opts.work_dirs {
        if opts.work.is_some()
            || opts.unit.is_some()
            || opts.stale
            || opts.rustc_key.is_some()
            || opts.husks
        {
            bail!(
                "--work-dirs collects whole stale job dirs — it takes no unit selectors:\n\
                 run `epicenter evict --work-dirs` on its own, or drop --work-dirs"
            );
        }
        evict_work_dirs(build_root, opts.older_than, opts.delete)?;
        return Ok(());
    }

    if let Some(work) = opts.work {
        if opts.stale || opts.rustc_key.is_some() || opts.husks || opts.older_than.is_some() {
            bail!(
                "--work unlinks units from ONE view — only --crate / --unit apply:\n\
                 for bulk view work use `--tier view`, for whole job dirs use --work-dirs"
            );
        }
        if opts.unit.is_none() && opts.crate_name.is_none() {
            bail!(
                "nothing selected — --work needs --crate <name> or --unit <hash>:\n\
                 e.g. `epicenter evict --work ci-1 --crate serde` (dry run unless --yes)"
            );
        }
        if opts.tier != Tier::All {
            bail!(
                "--tier does not apply to --work — that operation is always view-only:\n\
                 the vault is never touched by it"
            );
        }
        return evict_from_view(build_root, opts, work);
    }

    if opts.unit.is_none()
        && !opts.stale
        && opts.rustc_key.is_none()
        && !opts.husks
        && opts.older_than.is_none()
    {
        bail!(
            "nothing selected — pass one selector:\n\
             --unit <hash|package>   a specific unit\n\
             --stale                 every unit from an older toolchain\n\
             --rustc-key <hash>      units matching a toolchain identity\n\
             --husks                 units whose artifacts are already gone\n\
             --older-than <age>      units untouched for longer (e.g. 90d)\n\
             --work-dirs             stale per-job working dirs (default 7d)\n\
             dry run unless you pass --yes — full help: `epicenter evict --help`"
        );
    }

    let store_root = crate::vault::store_root(build_root);
    let active = crate::vault::parity_key().ok();
    let age_limit = opts
        .older_than
        .map(parse_duration)
        .transpose()
        .context("invalid value for --older-than")?;
    let now = SystemTime::now();

    let mut candidates: BTreeMap<String, Candidate> = BTreeMap::new();
    let mut view_labels: Vec<String> = Vec::new();
    let mut skipped_views: Vec<String> = Vec::new();

    // Store pass: the vault is the user's storage — trimming it costs compile
    // time at most, so the selectors apply here exactly as they do to views.
    if opts.tier.touches_store() {
        for stored in crate::vault::stored_units(&store_root)? {
            if !store_selectors_hit(opts, &stored, active.as_deref(), age_limit, now) {
                continue;
            }
            let mut files = Vec::new();
            collect_tree_files(&stored.dir, &mut files);
            let current = active.as_deref() == Some(stored.generation.as_str());
            let candidate = candidate_for(&mut candidates, &stored.entry.name);
            candidate.kind = fingerprint::classify_kind(&stored.entry.memo)
                .label()
                .to_string();
            candidate.current |= current;
            candidate.newest = max_time(candidate.newest, stamp_time(stored.entry.stamp));
            push_place(
                candidate,
                Place::Store {
                    generation: stored.generation.clone(),
                    files,
                },
            );
        }
    }

    // View passes: the shared build dir plus every job dir, minus locked ones.
    if opts.tier.touches_view() {
        for (label, root) in known_views(build_root) {
            if crate::exec::dir_locked(&root) {
                skipped_views.push(label);
                continue;
            }
            let rows = who::collect(&root).with_context(|| format!("reading view {label}"))?;
            let current = active_cohort(&rows);
            for (unit, arts) in rows {
                if !view_selectors_hit(opts, &unit, &arts, &current, age_limit, now) {
                    continue;
                }
                if !view_labels.contains(&label) {
                    view_labels.push(label.clone());
                }
                let files = view_unit_files(&root, &unit, &arts);
                let artifacts: Vec<PathBuf> =
                    arts.paths.iter().map(|(path, _, _)| path.clone()).collect();
                let candidate = candidate_for(&mut candidates, &unit.dir_name);
                candidate.kind = unit.kind.label().to_string();
                candidate.current |= !current.is_empty() && who::rustc_of(&unit) == current;
                candidate.newest = max_time(candidate.newest, arts.newest);
                push_place(
                    candidate,
                    Place::View {
                        label: label.clone(),
                        unit_dir: root
                            .join(&unit.profile)
                            .join(".fingerprint")
                            .join(&unit.dir_name),
                        anchors: fingerprint::build_anchor_dirs(&root, &unit),
                        artifacts,
                        files,
                    },
                );
            }
        }
    }

    if opts.delete {
        println!("{}", util::heading("epicenter evict — removing"));
    } else {
        println!(
            "{}",
            util::heading("epicenter evict — DRY RUN (nothing is removed; pass --yes to delete)")
        );
    }

    let mut protected = 0usize;
    let mut chosen: Vec<Candidate> = Vec::new();
    for (_, candidate) in candidates {
        // Current-generation units are protected whenever a view is involved;
        // `--tier store` is explicitly the vault-trimming mode.
        if candidate.current && !opts.force && opts.tier.touches_view() {
            protected += 1;
            continue;
        }
        chosen.push(candidate);
    }
    chosen.sort_by_key(|candidate| std::cmp::Reverse(candidate.bytes));

    if chosen.is_empty() {
        println!("  nothing matches the given selectors");
        if protected > 0 {
            println!(
                "  {} {protected} current-generation unit(s) matched but are protected — use --force to include them",
                util::warn(util::GLYPH_WARN)
            );
        }
        return Ok(());
    }

    for candidate in &chosen {
        let mut labels: Vec<&str> = candidate.places.iter().map(Place::label).collect();
        labels.sort_unstable();
        labels.dedup();
        println!(
            "  {} {:<38} {:<9} {:>9}  {:>10} old  {}{}",
            util::green(util::GLYPH_PASS),
            candidate.name,
            candidate.kind,
            human_bytes(candidate.bytes),
            candidate
                .newest
                .map(human_age)
                .unwrap_or_else(|| "?".into()),
            labels.join(" + "),
            if candidate.current && opts.force {
                util::dim("  (current — forced)")
            } else if candidate.current {
                util::dim("  (current)")
            } else {
                String::new()
            },
        );
    }

    let all_files: Vec<PathBuf> = chosen
        .iter()
        .flat_map(|candidate| candidate.places.iter())
        .flat_map(|place| place.files().iter().cloned())
        .collect();
    let (nominal, freed, released, count) = account_files(&all_files);
    let places: usize = chosen.iter().map(|candidate| candidate.places.len()).sum();

    println!();
    println!(
        "  {} {} unit(s) · {} place(s) · {} file(s) · {} nominal",
        util::dim("selection:"),
        chosen.len(),
        places,
        count,
        util::green(&human_bytes(nominal))
    );
    println!(
        "  {} {} actually freed · {} links released",
        util::dim("result:   "),
        human_bytes(freed),
        human_bytes(released)
    );
    println!(
        "  {} {}",
        util::dim("tier:     "),
        tier_summary(opts.tier, &view_labels)
    );
    if protected > 0 {
        println!(
            "  {} {protected} current-generation unit(s) skipped — use --force to include them",
            util::warn(util::GLYPH_WARN)
        );
    }
    for label in &skipped_views {
        println!(
            "  {} view {label} is in use by a live build — skipped",
            util::warn(util::GLYPH_WARN)
        );
    }
    if !opts.delete {
        println!(
            "  {}",
            util::dim("run again with -y or --yes to remove them")
        );
        return Ok(());
    }

    // ── delete ──────────────────────────────────────────────────────────────
    let mut errors = 0u64;

    let mut per_generation: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for candidate in &chosen {
        for place in &candidate.places {
            if let Place::Store { generation, .. } = place {
                per_generation
                    .entry(generation.clone())
                    .or_default()
                    .push(candidate.name.clone());
            }
        }
    }
    let mut store_dropped = 0usize;
    for (generation, names) in &per_generation {
        match crate::vault::drop_units(&store_root, generation, names) {
            Ok(dropped) => store_dropped += dropped,
            Err(err) => {
                errors += 1;
                eprintln!("could not prune the vault: {err}");
            }
        }
    }

    let mut view_counts: BTreeMap<String, usize> = BTreeMap::new();
    for candidate in &chosen {
        for place in &candidate.places {
            if let Place::View {
                label,
                unit_dir,
                anchors,
                artifacts,
                ..
            } = place
            {
                remove_dir(unit_dir, &mut errors);
                for anchor in anchors {
                    if anchor.is_dir() {
                        remove_dir(anchor, &mut errors);
                    }
                }
                for artifact in artifacts {
                    remove_file(artifact, &mut errors);
                }
                *view_counts.entry(label.clone()).or_default() += 1;
            }
        }
    }

    println!();
    println!(
        "  {} {} unit(s) evicted · {} actually freed · {} links released",
        util::green(util::GLYPH_PASS),
        chosen.len(),
        human_bytes(freed),
        human_bytes(released)
    );
    if store_dropped > 0 {
        println!(
            "  {:<11} {} unit(s) dropped · manifest updated",
            util::dim("store"),
            store_dropped
        );
    }
    for (label, count) in &view_counts {
        println!("  {:<11} {} unit(s) unlinked", util::dim(label), count);
    }
    if errors > 0 {
        println!(
            "  {} {} (see messages above)",
            util::fail(util::GLYPH_FAIL),
            errors
        );
    }
    println!(
        "  {}",
        util::dim("`epicenter vault` shows what the store holds now")
    );
    Ok(())
}

/// What one `--work-dirs` pass found and did.
#[derive(Debug, Default)]
pub struct WorkReport {
    /// Job dirs seen under `work/`.
    pub scanned: usize,
    /// Collectible (old enough, not locked).
    pub eligible: usize,
    /// Younger than the age limit.
    pub young: usize,
    /// A live build holds the dir's lock.
    pub in_use: usize,
    /// Directories actually removed.
    pub removed: usize,
    /// Sum of sizes of the collected dirs (each file counts once per path).
    pub nominal_bytes: u64,
    /// Bytes whose last link lived in those dirs — actually freed.
    pub unique_bytes: u64,
    /// Bytes still linked from the store or another view.
    pub shared_bytes: u64,
    pub errors: u64,
}

/// One `work/<job-id>/` view.
struct WorkDir {
    name: String,
    path: PathBuf,
    newest: Option<SystemTime>,
    locked: bool,
    old_enough: bool,
    bytes: u64,
    unique: u64,
    shared: u64,
    files: u64,
}

/// `epicenter evict --work-dir <id|path>` — remove ONE job dir now. An
/// explicit choice is reason enough: the 7-day (or `--older-than`) window is a
/// GC policy for bulk collection, not a gate on deliberate removals. The same
/// guards apply: a dir a live build has locked is refused, and the shared
/// build dir can never be a target.
fn evict_work_dir(build_root: &Path, target: &str, delete: bool) -> Result<()> {
    let work_root = crate::exec::work_root(build_root);
    let path = resolve_work_dir(&work_root, target)?;
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let job_lock =
        match crate::util::FileLock::try_acquire(&crate::exec::job_lock_path(&work_root, &name))? {
            Some(lock) => lock,
            None => bail!(
                "job dir {} is in use by an epicenter process — remove it when it finishes",
                path.display()
            ),
        };
    if crate::exec::dir_locked(&path) {
        bail!(
            "job dir {} is in use by a live build — remove it when it finishes",
            path.display()
        );
    }
    let newest = dir_newest(&path);
    let (bytes, unique, shared, files) = dir_accounting(&path);

    if delete {
        println!(
            "{}",
            util::heading(&format!("epicenter evict --work-dir {name} — removing"))
        );
    } else {
        println!(
            "{}",
            util::heading(&format!(
                "epicenter evict --work-dir {name} — DRY RUN (nothing is removed; pass --yes)"
            ))
        );
    }
    println!(
        "  {} {}",
        util::dim(&format!("{:<11}", "job dir")),
        path.display()
    );
    println!(
        "  {} {:<40} {:>9} · {:>4} file(s)  {:>10} old  {}",
        util::green(util::GLYPH_PASS),
        name,
        human_bytes(bytes),
        files,
        newest.map(human_age).unwrap_or_else(|| "?".into()),
        util::dim("explicitly selected — age policy not applied")
    );
    println!();
    println!(
        "  {} {} nominal — {} actually freed · {} links released",
        util::dim("result:   "),
        human_bytes(bytes),
        human_bytes(unique),
        human_bytes(shared)
    );
    if !delete {
        println!("  {}", util::dim("run again with -y or --yes to remove it"));
        return Ok(());
    }
    // Rename out of the way first: a hidden tombstone is not a job dir any
    // later GC/exec can guess, and a build that races the check fails rather
    // than writing into a directory being deleted.
    let tombstone = work_root.join(format!(".{name}.deleting-{}", std::process::id()));
    if fs::symlink_metadata(&tombstone).is_ok() {
        let _ = crate::util::force_remove_dir(&tombstone);
    }
    fs::rename(&path, &tombstone).with_context(|| format!("isolating {}", path.display()))?;
    if let Err(err) = fs::remove_dir_all(&tombstone) {
        let _ = fs::rename(&tombstone, &path);
        drop(job_lock);
        return Err(err).with_context(|| format!("removing {}", path.display()));
    }
    drop(job_lock);
    println!();
    println!(
        "  {} {name} removed · {} actually freed · {} links released",
        util::green(util::GLYPH_PASS),
        human_bytes(unique),
        human_bytes(shared)
    );
    println!(
        "  {}",
        util::dim("the vault is untouched — a job dir is a view")
    );
    Ok(())
}

/// `--work-dir` targets: a job id (plain or `work/<id>`), or a path that is a
/// direct child of the work root. `build` and anything outside are refused.
fn resolve_work_dir(work_root: &Path, target: &str) -> Result<PathBuf> {
    if target == "build" {
        bail!(
            "the shared build dir is never removed — it is the core asset:\n\
             to work inside it use `epicenter evict --work build --crate <name>`"
        );
    }
    let candidate = work_root.join(target.trim_start_matches("work/"));
    let candidate = if candidate.is_dir() {
        candidate
    } else {
        PathBuf::from(target)
    };
    if !candidate.is_dir() {
        bail!("no job dir named {target:?} — `epicenter vault` shows the work tier");
    }
    let inside = candidate
        .canonicalize()
        .ok()
        .zip(work_root.canonicalize().ok())
        .map(|(child, root)| child.parent() == Some(root.as_path()))
        .unwrap_or(false);
    if !inside {
        bail!(
            "{} is not a job dir under {} — --work-dir removes the work tier only",
            candidate.display(),
            work_root.display()
        );
    }
    Ok(candidate)
}

/// The working-dir tier: `work/<job-id>/` views are disposable, so a job dir
/// whose newest activity is older than the limit is collectible. A directory
/// that a live build has locked is never touched, and the vault is never
/// touched at all — removing a view only unlinks hard links.
fn evict_work_dirs(
    build_root: &Path,
    older_than: Option<&str>,
    delete: bool,
) -> Result<WorkReport> {
    let work_root = crate::exec::work_root(build_root);
    let age_text = older_than.unwrap_or(DEFAULT_WORK_MAX_AGE);
    let limit = parse_duration(age_text).context("invalid value for --older-than")?;

    if delete {
        println!(
            "{}",
            util::heading("epicenter evict --work-dirs — removing")
        );
    } else {
        println!(
            "{}",
            util::heading(
                "epicenter evict --work-dirs — DRY RUN (nothing is removed; pass --yes to delete)"
            )
        );
    }
    let mut report = WorkReport::default();
    if !work_root.is_dir() {
        println!("  no working dirs at {}", work_root.display());
        return Ok(report);
    }

    let now = SystemTime::now();
    let mut rows: Vec<WorkDir> = Vec::new();
    for entry in
        fs::read_dir(&work_root).with_context(|| format!("reading {}", work_root.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        let newest = dir_newest(&path);
        let locked = crate::exec::dir_locked(&path);
        let (bytes, unique, shared, files) = dir_accounting(&path);
        let old_enough = newest
            .map(|m| now.duration_since(m).map_or(true, |age| age > limit))
            .unwrap_or(true);
        rows.push(WorkDir {
            name,
            path,
            newest,
            locked,
            old_enough,
            bytes,
            unique,
            shared,
            files,
        });
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    if rows.is_empty() {
        println!(
            "  no working dirs at {} — nothing to collect",
            work_root.display()
        );
        return Ok(report);
    }

    for row in &rows {
        report.scanned += 1;
        let (icon, note) = if row.locked {
            report.in_use += 1;
            (
                util::warn(util::GLYPH_WARN),
                util::warn("in use by a live build — never collected").to_string(),
            )
        } else if row.old_enough {
            report.eligible += 1;
            (
                util::green(util::GLYPH_PASS),
                util::green("collectible").to_string(),
            )
        } else {
            report.young += 1;
            (
                util::info(util::GLYPH_INFO),
                util::dim(&format!("younger than {age_text}")).to_string(),
            )
        };
        println!(
            "  {icon} {:<40} {:>9} · {:>4} file(s)  {:>10} old  {note}",
            row.name,
            human_bytes(row.bytes),
            row.files,
            row.newest.map(human_age).unwrap_or_else(|| "?".into()),
        );
    }

    for row in rows.iter().filter(|row| row.old_enough && !row.locked) {
        report.nominal_bytes += row.bytes;
        report.unique_bytes += row.unique;
        report.shared_bytes += row.shared;
    }
    println!();
    if report.eligible == 0 {
        println!(
            "  {} nothing older than {age_text} to collect",
            util::dim("selection:")
        );
    } else {
        println!(
            "  {} {} dir(s) · {} nominal · {} unique to the jobs (freed), {} still shared with the store",
            util::dim("selection:"),
            report.eligible,
            util::green(&human_bytes(report.nominal_bytes)),
            util::green(&human_bytes(report.unique_bytes)),
            util::dim(&human_bytes(report.shared_bytes)),
        );
    }
    if report.in_use > 0 {
        println!(
            "  {} {} dir(s) in use by a live build — left alone",
            util::warn(util::GLYPH_WARN),
            report.in_use
        );
    }
    if report.young > 0 {
        println!(
            "  {} {} dir(s) younger than {age_text} — kept",
            util::info(util::GLYPH_INFO),
            report.young
        );
    }
    if report.eligible == 0 {
        return Ok(report);
    }
    if !delete {
        println!(
            "  {}",
            util::dim("run again with -y or --yes to remove the selected dirs")
        );
        return Ok(report);
    }

    let mut freed_unique = 0u64;
    let mut freed_shared = 0u64;
    for row in rows.iter().filter(|row| row.old_enough && !row.locked) {
        let _job_lock = match crate::util::FileLock::try_acquire(&crate::exec::job_lock_path(
            &work_root, &row.name,
        ))? {
            Some(lock) => lock,
            None => {
                report.in_use += 1;
                continue;
            }
        };
        if crate::exec::dir_locked(&row.path) {
            report.in_use += 1;
            continue;
        }
        match fs::remove_dir_all(&row.path) {
            Ok(()) => {
                report.removed += 1;
                freed_unique += row.unique;
                freed_shared += row.shared;
            }
            Err(e) => {
                report.errors += 1;
                eprintln!("could not remove {}: {e}", row.path.display());
            }
        }
    }
    println!();
    println!(
        "  {} {} dir(s) evicted · {} actually freed · {} link(s) released (other links, e.g. the vault, still hold those bytes)",
        util::green(util::GLYPH_PASS),
        report.removed,
        human_bytes(freed_unique),
        util::dim(&human_bytes(freed_shared)),
    );
    if report.errors > 0 {
        println!(
            "  {} {} (see messages above)",
            util::fail(util::GLYPH_FAIL),
            report.errors
        );
    }
    println!(
        "  {}",
        util::dim("the vault is untouched — `epicenter vault` shows what remains")
    );
    Ok(report)
}

/// Newest file mtime in the tree — a job is as fresh as its last file write
/// (directory mtimes only move when entries are added or removed).
fn dir_newest(dir: &Path) -> Option<SystemTime> {
    let mut newest = None;
    for entry in WalkDir::new(dir).min_depth(1).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        if let Some(modified) = entry.metadata().ok().and_then(|meta| meta.modified().ok()) {
            if newest.map_or(true, |current| modified > current) {
                newest = Some(modified);
            }
        }
    }
    newest
}

/// (nominal bytes, unique bytes, shared bytes, file count) of one view.
fn dir_accounting(dir: &Path) -> (u64, u64, u64, u64) {
    let mut bytes = 0u64;
    let mut unique = 0u64;
    let mut shared = 0u64;
    let mut files = 0u64;
    for entry in WalkDir::new(dir).min_depth(1).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let size = meta.len();
        bytes += size;
        files += 1;
        if crate::vault::link_count(&meta) > 1 {
            shared += size;
        } else {
            unique += size;
        }
    }
    (bytes, unique, shared, files)
}

/// Resolve `--work`: `build` = the shared view; a job id (with or without
/// the `work/` prefix) = that job dir; anything else = a directory path.
fn resolve_view(build_root: &Path, work: &str) -> Result<PathBuf> {
    if work == "build" {
        return Ok(build_root.to_path_buf());
    }
    let work_root = crate::exec::work_root(build_root);
    let job = work_root.join(work.trim_start_matches("work/"));
    if fs::symlink_metadata(&job)
        .map(|meta| meta.is_dir() && !meta.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Ok(job);
    }
    let path = PathBuf::from(work);
    if fs::symlink_metadata(&path)
        .map(|meta| meta.is_dir() && !meta.file_type().is_symlink())
        .unwrap_or(false)
    {
        let canonical = path.canonicalize()?;
        let work_root_canonical = work_root.canonicalize().ok();
        let build_canonical = build_root.canonicalize().ok();
        let allowed = work_root_canonical
            .iter()
            .chain(build_canonical.iter())
            .any(|root| canonical.starts_with(root));
        if allowed {
            return Ok(path);
        }
        bail!(
            "view {} is outside {} and {} — refusing to delete outside the cache",
            path.display(),
            work_root.display(),
            build_root.display()
        );
    }
    bail!(
        "no view named {work:?} — expected `build`, a job id under {}, or a directory under it",
        work_root.display()
    );
}

/// `--crate` selector: package name; dashes and underscores are interchangeable.
fn crate_matches(unit: &Unit, name: &str) -> bool {
    unit.package == name || unit.package.replace('-', "_") == name.replace('-', "_")
}

/// Selector for one view's unit (`--work` mode).
fn surgery_unit_matches(unit: &Unit, opts: &Options<'_>) -> bool {
    let mut hit = false;
    if let Some(query) = opts.unit {
        hit |= who::unit_matches(unit, query);
    }
    if let Some(name) = opts.crate_name {
        hit |= crate_matches(unit, name);
    }
    hit
}

/// Files a view-unit removal would unlink (for honest accounting).
fn view_unit_files(root: &Path, unit: &Unit, arts: &ArtifactInfo) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_tree_files(
        &root
            .join(&unit.profile)
            .join(".fingerprint")
            .join(&unit.dir_name),
        &mut files,
    );
    // `arts.paths` already covers the `build/<anchor>/` files.
    for (path, _, _) in &arts.paths {
        files.push(path.clone());
    }
    files
}

fn collect_tree_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in WalkDir::new(dir).min_depth(1).into_iter().flatten() {
        if entry.file_type().is_file() {
            out.push(entry.path().to_path_buf());
        }
    }
}

/// Remove one unit from one view: fingerprint dir, build anchors, artifacts.
fn remove_view_unit(root: &Path, unit: &Unit, arts: &ArtifactInfo, errors: &mut u64) {
    let fingerprint_dir = root
        .join(&unit.profile)
        .join(".fingerprint")
        .join(&unit.dir_name);
    remove_dir(&fingerprint_dir, errors);
    for anchor in fingerprint::build_anchor_dirs(root, unit) {
        if anchor.is_dir() {
            remove_dir(&anchor, errors);
        }
    }
    for (path, _, _) in &arts.paths {
        remove_file(path, errors);
    }
}

/// (nominal, actually freed, released, file count) of a set of paths about to
/// be unlinked. A file frees its bytes only when every one of its links is in
/// the set; inodes are counted once, so hard links never inflate the total.
fn account_files(files: &[PathBuf]) -> (u64, u64, u64, u64) {
    #[cfg(unix)]
    {
        use std::collections::{HashMap, HashSet};
        use std::os::unix::fs::MetadataExt;

        let mut per_inode: HashMap<(u64, u64), (u64, u64, u64)> = HashMap::new();
        let mut seen: HashSet<&Path> = HashSet::new();
        let mut count = 0u64;
        for path in files {
            if !seen.insert(path.as_path()) {
                continue;
            }
            let Ok(meta) = fs::metadata(path) else {
                continue;
            };
            count += 1;
            let entry =
                per_inode
                    .entry((meta.dev(), meta.ino()))
                    .or_insert((meta.len(), meta.nlink(), 0));
            entry.2 += 1;
        }
        let mut nominal = 0u64;
        let mut freed = 0u64;
        for (size, links, planned) in per_inode.values() {
            nominal += size;
            if planned >= links {
                freed += size;
            }
        }
        (nominal, freed, nominal - freed, count)
    }
    #[cfg(not(unix))]
    {
        // No link counts here: report the paths as freed (single-link ceiling).
        let mut seen: std::collections::HashSet<&Path> = std::collections::HashSet::new();
        let mut nominal = 0u64;
        let mut count = 0u64;
        for path in files {
            if !seen.insert(path.as_path()) {
                continue;
            }
            if let Ok(meta) = fs::metadata(path) {
                nominal += meta.len();
                count += 1;
            }
        }
        (nominal, nominal, 0, count)
    }
}

/// One unit that matches the selectors, with every place it would be removed
/// from (a vault generation and/or the views that hold a hard link).
struct Candidate {
    name: String,
    kind: String,
    bytes: u64,
    newest: Option<SystemTime>,
    current: bool,
    places: Vec<Place>,
}

/// One place a candidate lives.
enum Place {
    Store {
        generation: String,
        files: Vec<PathBuf>,
    },
    View {
        label: String,
        unit_dir: PathBuf,
        anchors: Vec<PathBuf>,
        artifacts: Vec<PathBuf>,
        files: Vec<PathBuf>,
    },
}

impl Place {
    fn label(&self) -> &str {
        match self {
            Place::Store { .. } => "store",
            Place::View { label, .. } => label,
        }
    }

    fn files(&self) -> &[PathBuf] {
        match self {
            Place::Store { files, .. } | Place::View { files, .. } => files,
        }
    }
}

fn candidate_for<'a>(
    candidates: &'a mut BTreeMap<String, Candidate>,
    name: &str,
) -> &'a mut Candidate {
    candidates
        .entry(name.to_string())
        .or_insert_with(|| Candidate {
            name: name.to_string(),
            kind: "?".to_string(),
            bytes: 0,
            newest: None,
            current: false,
            places: Vec::new(),
        })
}

fn push_place(candidate: &mut Candidate, place: Place) {
    candidate.bytes += place
        .files()
        .iter()
        .filter_map(|path| fs::metadata(path).ok())
        .map(|meta| meta.len())
        .sum::<u64>();
    candidate.places.push(place);
}

fn stamp_time(stamp: u64) -> Option<SystemTime> {
    (stamp > 0).then(|| std::time::UNIX_EPOCH + Duration::from_secs(stamp))
}

fn max_time(left: Option<SystemTime>, right: Option<SystemTime>) -> Option<SystemTime> {
    match (left, right) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (left, None) => left,
        (None, right) => right,
    }
}

/// Every view epicenter knows about: the shared build dir, then each job dir.
fn known_views(build_root: &Path) -> Vec<(String, PathBuf)> {
    let mut views = vec![("build".to_string(), build_root.to_path_buf())];
    let work_root = crate::exec::work_root(build_root);
    if let Ok(entries) = fs::read_dir(&work_root) {
        for entry in entries.flatten() {
            if !entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            views.push((format!("work/{name}"), entry.path()));
        }
    }
    views
}

/// The largest rustc cohort of a view marks the generation its working code
/// belongs to (the heuristic `who`/`evict` have always used).
fn active_cohort(rows: &[(Unit, ArtifactInfo)]) -> String {
    who::rustc_cohorts(rows)
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(id, _)| id)
        .unwrap_or_default()
}

/// Selector for one stored unit. `--stale` means "not the installed
/// toolchain's generation"; the other selectors mirror the view semantics.
fn store_selectors_hit(
    opts: &Options<'_>,
    stored: &crate::vault::StoredUnit,
    active: Option<&str>,
    limit: Option<Duration>,
    now: SystemTime,
) -> bool {
    let mut hit = false;
    if let Some(query) = opts.unit {
        hit |= stored.entry.name.contains(query);
    }
    if opts.stale {
        hit |= active.map(|key| stored.generation != key).unwrap_or(false);
    }
    if let Some(key) = opts.rustc_key {
        hit |= crate::vault::stored_unit_rustc(stored)
            .map(|id| id.starts_with(key))
            .unwrap_or(false);
    }
    if let Some(limit) = limit {
        hit |= stamp_time(stored.entry.stamp)
            .map(|stamp| now.duration_since(stamp).map_or(true, |age| age > limit))
            .unwrap_or(false);
    }
    if opts.husks {
        hit |= stored
            .entry
            .files
            .iter()
            .any(|file| !stored.dir.join(&file.path).is_file());
    }
    hit
}

/// Selector for one view's unit.
fn view_selectors_hit(
    opts: &Options<'_>,
    unit: &Unit,
    arts: &ArtifactInfo,
    current: &str,
    limit: Option<Duration>,
    now: SystemTime,
) -> bool {
    let mut hit = false;
    if let Some(query) = opts.unit {
        hit |= who::unit_matches(unit, query);
    }
    if opts.stale {
        hit |= !current.is_empty() && who::rustc_of(unit) != current;
    }
    if let Some(key) = opts.rustc_key {
        hit |= who::rustc_of(unit).starts_with(key);
    }
    if opts.husks {
        hit |= arts.paths.is_empty();
    }
    if let Some(limit) = limit {
        hit |= arts
            .newest
            .map(|newest| now.duration_since(newest).map_or(true, |age| age > limit))
            .unwrap_or(false);
    }
    hit
}

/// The `tier:` line of the selection report.
fn tier_summary(tier: Tier, views: &[String]) -> String {
    match tier {
        Tier::Store => "store — the vault only (views keep their links)".to_string(),
        Tier::View => format!("view — {} (the vault is untouched)", view_list(views)),
        Tier::All => format!("all — the vault + {}", view_list(views)),
    }
}

fn view_list(views: &[String]) -> String {
    if views.is_empty() {
        return "no views".to_string();
    }
    let mut text = views.iter().take(4).cloned().collect::<Vec<_>>().join(", ");
    if views.len() > 4 {
        text.push_str(&format!(", … (+{} more)", views.len() - 4));
    }
    text
}

/// `epicenter evict --work <view> --crate/--unit …` — unlink matching units
/// from ONE view. A freshness operation: the vault is never touched, and the
/// honest numbers say what was freed (units this view owned alone) versus
/// what was merely released (units the vault still holds).
fn evict_from_view(build_root: &Path, opts: &Options<'_>, work: &str) -> Result<()> {
    let root = resolve_view(build_root, work)?;
    if crate::exec::dir_locked(&root) {
        bail!(
            "view {} is in use by a live build — unlink when it finishes",
            root.display()
        );
    }
    let vaulted: std::collections::BTreeSet<String> =
        crate::vault::stored_units(&crate::vault::store_root(build_root))?
            .into_iter()
            .map(|unit| unit.entry.name)
            .collect();

    let rows = who::collect(&root).context("reading the view")?;
    let chosen: Vec<&(Unit, ArtifactInfo)> = rows
        .iter()
        .filter(|(unit, _)| surgery_unit_matches(unit, opts))
        .collect();

    if opts.delete {
        println!(
            "{}",
            util::heading(&format!("epicenter evict --work {work} — unlinking"))
        );
    } else {
        println!(
            "{}",
            util::heading(&format!(
                "epicenter evict --work {work} — DRY RUN (nothing is unlinked; pass --yes)"
            ))
        );
    }
    println!(
        "  {} {}",
        util::dim(&format!("{:<11}", "view")),
        root.display()
    );
    if chosen.is_empty() {
        println!("  nothing in this view matches — check `epicenter who --unit <q>`");
        return Ok(());
    }

    let mut files = Vec::new();
    for (unit, arts) in &chosen {
        files.extend(view_unit_files(&root, unit, arts));
    }
    let (nominal, freed, released, count) = account_files(&files);

    for (unit, arts) in &chosen {
        println!(
            "  {} {:<40} {:<9} {:>9}  {}",
            util::green(util::GLYPH_PASS),
            unit.dir_name,
            unit.kind.label(),
            human_bytes(arts.bytes),
            if vaulted.contains(&unit.dir_name) {
                util::dim("in the vault — Cargo will rebuild it here")
            } else {
                util::warn("only in this view — its bytes go")
            }
        );
    }
    println!();
    println!(
        "  {} {} unit(s) · {} file(s) · {} nominal",
        util::dim("selection:"),
        chosen.len(),
        count,
        util::green(&human_bytes(nominal))
    );
    println!(
        "  {} {} actually freed · {} links released (still held elsewhere, e.g. the vault)",
        util::dim("result:   "),
        human_bytes(freed),
        human_bytes(released)
    );
    if !opts.delete {
        println!(
            "  {}",
            util::dim("run again with -y or --yes to unlink these units from this view")
        );
        return Ok(());
    }

    let mut errors = 0u64;
    for (unit, arts) in &chosen {
        remove_view_unit(&root, unit, arts, &mut errors);
    }
    println!();
    println!(
        "  {} {} unit(s) unlinked from {work} · {} actually freed · {} links released",
        util::green(util::GLYPH_PASS),
        chosen.len(),
        human_bytes(freed),
        human_bytes(released)
    );
    if errors > 0 {
        println!(
            "  {} {} (see messages above)",
            util::fail(util::GLYPH_FAIL),
            errors
        );
    }
    println!(
        "  {}",
        util::dim("Cargo will rebuild these units here; the vault is untouched")
    );
    Ok(())
}

fn remove_dir(path: &Path, errors: &mut u64) {
    if let Err(e) = fs::remove_dir_all(path) {
        if e.kind() != ErrorKind::NotFound {
            *errors += 1;
            eprintln!("could not remove {}: {e}", path.display());
        }
    }
}

fn remove_file(path: &Path, errors: &mut u64) {
    if let Err(e) = fs::remove_file(path) {
        if e.kind() != ErrorKind::NotFound {
            *errors += 1;
            eprintln!("could not remove {}: {e}", path.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One unit (`pkg-1122334455667788`) + its rlib in a build-dir shape.
    fn write_synthetic_unit(root: &Path) -> Result<()> {
        let unit_dir = root.join("debug/.fingerprint/pkg-1122334455667788");
        fs::create_dir_all(&unit_dir)?;
        fs::write(unit_dir.join("lib-pkg"), "0011223344556677")?;
        fs::write(unit_dir.join("dep-lib-pkg"), [0u8; 8])?;
        fs::create_dir_all(root.join("debug/deps"))?;
        fs::write(
            root.join("debug/deps/libpkg-1122334455667788.rlib"),
            [0u8; 16],
        )?;
        Ok(())
    }

    /// `{home}/build` with one unit — hermetic, so the store sits in
    /// `{home}/store` and never touches anything outside the tempdir.
    fn synthetic_home() -> Result<(tempfile::TempDir, PathBuf)> {
        let home = tempfile::tempdir()?;
        let build = home.path().join("build");
        fs::create_dir_all(&build)?;
        write_synthetic_unit(&build)?;
        Ok((home, build))
    }

    fn no_selectors() -> Options<'static> {
        Options {
            unit: None,
            stale: false,
            rustc_key: None,
            husks: false,
            older_than: None,
            work_dirs: false,
            work_dir: None,
            work: None,
            crate_name: None,
            tier: Tier::All,
            force: false,
            delete: false,
        }
    }

    #[test]
    fn requires_at_least_one_selector() -> Result<()> {
        let (_home, build) = synthetic_home()?;
        assert!(run(&build, &no_selectors()).is_err());
        Ok(())
    }

    #[test]
    fn stale_selector_skips_current_generation() -> Result<()> {
        let (_home, build) = synthetic_home()?;
        let opts = Options {
            stale: true,
            ..no_selectors()
        };
        // A single unit IS the current cohort → stale selects nothing.
        run(&build, &opts)?;
        assert!(
            build
                .join("debug/.fingerprint/pkg-1122334455667788")
                .exists()
        );
        Ok(())
    }

    #[test]
    fn evicts_fingerprint_and_artifacts_with_force() -> Result<()> {
        let (_home, build) = synthetic_home()?;
        let opts = Options {
            unit: Some("pkg-1122334455667788"),
            force: true,
            delete: true,
            ..no_selectors()
        };
        run(&build, &opts)?;
        assert!(
            !build
                .join("debug/.fingerprint/pkg-1122334455667788")
                .exists(),
            "fingerprint dir must be gone"
        );
        assert!(
            !build
                .join("debug/deps/libpkg-1122334455667788.rlib")
                .exists(),
            "artifact must be gone"
        );
        Ok(())
    }

    use std::time::Duration;

    /// `{home}/build` + `{home}/work` — the sibling layout of a real cache.
    fn tier_home() -> Result<tempfile::TempDir> {
        let home = tempfile::tempdir()?;
        fs::create_dir_all(home.path().join("build"))?;
        fs::create_dir_all(home.path().join("work"))?;
        Ok(home)
    }

    /// One job dir: `work/<name>/debug/libjob.rlib`, aged by `age_days`.
    fn aged_job(home: &Path, name: &str, age_days: u64) -> Result<PathBuf> {
        let debug = home.join("work").join(name).join("debug");
        fs::create_dir_all(&debug)?;
        let artifact = debug.join("libjob.rlib");
        fs::write(&artifact, [0u8; 64])?;
        if age_days > 0 {
            let when = SystemTime::now() - Duration::from_secs(age_days * 86_400);
            fs::File::open(&artifact)?.set_modified(when)?;
        }
        Ok(home.join("work").join(name))
    }

    #[test]
    fn work_dirs_collect_by_age_and_keep_young_ones() -> Result<()> {
        let home = tier_home()?;
        let build = home.path().join("build");
        let old_job = aged_job(home.path(), "old-job", 30)?;
        let fresh_job = aged_job(home.path(), "fresh-job", 0)?;

        let dry = evict_work_dirs(&build, None, false)?;
        assert_eq!((dry.scanned, dry.eligible, dry.young), (2, 1, 1));
        assert!(
            old_job.exists() && fresh_job.exists(),
            "dry run touches nothing"
        );

        let done = evict_work_dirs(&build, None, true)?;
        assert_eq!(done.removed, 1);
        assert_eq!(done.unique_bytes, 64, "unique bytes are actually freed");
        assert!(!old_job.exists(), "aged job dir collected");
        assert!(fresh_job.exists(), "young job dir kept");
        Ok(())
    }

    #[test]
    fn work_dirs_never_collect_locked_jobs() -> Result<()> {
        let home = tier_home()?;
        let build = home.path().join("build");
        let job = aged_job(home.path(), "locked-job", 30)?;
        let lock_path = job.join("debug/.cargo-build-lock");
        fs::write(&lock_path, b"")?;
        // The lock file was also written a month ago, so age alone would collect it.
        let when = SystemTime::now() - Duration::from_secs(30 * 86_400);
        fs::File::open(&lock_path)?.set_modified(when)?;

        let held = fs::OpenOptions::new().write(true).open(&lock_path)?;
        held.try_lock().context("test holds the lock")?;

        let report = evict_work_dirs(&build, None, true)?;
        assert_eq!((report.in_use, report.removed), (1, 0));
        assert!(job.exists(), "a locked job dir is never touched");

        held.unlock()?;
        drop(held);
        let report = evict_work_dirs(&build, None, true)?;
        assert_eq!(report.removed, 1);
        assert!(!job.exists());
        Ok(())
    }

    #[test]
    fn work_dirs_cannot_be_combined_with_unit_selectors() -> Result<()> {
        let home = tier_home()?;
        let opts = Options {
            work_dirs: true,
            stale: true,
            ..no_selectors()
        };
        assert!(run(&home.path().join("build"), &opts).is_err());
        Ok(())
    }

    #[test]
    fn work_dir_accounting_separates_unique_and_shared_bytes() -> Result<()> {
        let home = tier_home()?;
        let debug = home.path().join("work/aged-job/debug");
        fs::create_dir_all(&debug)?;
        let unique = debug.join("unique.rlib");
        let shared = debug.join("shared.rlib");
        fs::write(&unique, [0u8; 100])?;
        fs::write(&shared, [0u8; 200])?;
        // One artifact also lives in the store → its bytes are not freed here.
        fs::hard_link(&shared, home.path().join("store-copy.rlib"))?;
        let when = SystemTime::now() - Duration::from_secs(30 * 86_400);
        fs::File::open(&unique)?.set_modified(when)?;
        fs::File::open(&shared)?.set_modified(when)?;

        let report = evict_work_dirs(&home.path().join("build"), None, false)?;
        assert_eq!(report.unique_bytes, 100);
        assert_eq!(report.shared_bytes, 200);
        assert_eq!(report.nominal_bytes, 300);
        Ok(())
    }

    #[test]
    fn work_dir_removal_ignores_the_age_window() -> Result<()> {
        let home = tier_home()?;
        let build = home.path().join("build");
        let job = aged_job(home.path(), "fresh-job", 0)?;
        let opts = Options {
            work_dir: Some("fresh-job"),
            delete: true,
            ..no_selectors()
        };
        run(&build, &opts)?;
        assert!(
            !job.exists(),
            "an explicitly selected dir goes regardless of age"
        );
        Ok(())
    }

    #[test]
    fn work_dir_refuses_locked_and_unknown_targets() -> Result<()> {
        let home = tier_home()?;
        let build = home.path().join("build");
        let job = aged_job(home.path(), "locked-job", 0)?;
        let lock_path = job.join("debug/.cargo-build-lock");
        fs::write(&lock_path, b"")?;
        let held = fs::OpenOptions::new().write(true).open(&lock_path)?;
        held.try_lock().context("test holds the lock")?;

        let opts = Options {
            work_dir: Some("locked-job"),
            delete: true,
            ..no_selectors()
        };
        let err = run(&build, &opts).unwrap_err();
        assert!(err.to_string().contains("in use"), "{err}");
        assert!(job.exists(), "a locked job dir survives");
        drop(held);

        let unknown = Options {
            work_dir: Some("nope"),
            ..no_selectors()
        };
        assert!(run(&build, &unknown).is_err());
        Ok(())
    }

    #[test]
    fn work_dir_never_targets_the_shared_build_or_outside_paths() -> Result<()> {
        let home = tier_home()?;
        let build = home.path().join("build");
        let shared = Options {
            work_dir: Some("build"),
            ..no_selectors()
        };
        let err = run(&build, &shared).unwrap_err();
        assert!(err.to_string().contains("never removed"), "{err}");

        let outside = Options {
            work_dir: Some("/tmp"),
            ..no_selectors()
        };
        assert!(
            run(&build, &outside).is_err(),
            "only job dirs under work/ — /tmp is refused"
        );
        Ok(())
    }

    #[test]
    fn work_dir_rejects_selectors_and_sibling_modes() -> Result<()> {
        let home = tier_home()?;
        let build = home.path().join("build");
        let with_age = Options {
            work_dir: Some("x"),
            older_than: Some("30d"),
            ..no_selectors()
        };
        assert!(run(&build, &with_age).is_err());

        let with_dirs = Options {
            work_dir: Some("x"),
            work_dirs: true,
            ..no_selectors()
        };
        let err = run(&build, &with_dirs).unwrap_err();
        assert!(err.to_string().contains("one operation"), "{err}");
        Ok(())
    }

    /// `{home}/build` with one unit + `{home}/work/ci-1` with the same unit.
    fn tiered_views() -> Result<(tempfile::TempDir, PathBuf)> {
        let home = tempfile::tempdir()?;
        fs::create_dir_all(home.path().join("build"))?;
        fs::create_dir_all(home.path().join("work"))?;
        write_synthetic_unit(&home.path().join("build"))?;
        let job = home.path().join("work/ci-1");
        write_synthetic_unit(&job)?;
        Ok((home, job))
    }

    #[test]
    fn work_surgery_unlinks_only_the_named_view() -> Result<()> {
        let (home, job) = tiered_views()?;
        let build = home.path().join("build");
        let opts = Options {
            work: Some("ci-1"),
            crate_name: Some("pkg"),
            delete: true,
            ..no_selectors()
        };
        run(&build, &opts)?;
        assert!(
            !job.join("debug/.fingerprint/pkg-1122334455667788").exists(),
            "job fingerprint unlinked"
        );
        assert!(
            !job.join("debug/deps/libpkg-1122334455667788.rlib").exists(),
            "job artifact unlinked"
        );
        assert!(
            build
                .join("debug/.fingerprint/pkg-1122334455667788")
                .exists(),
            "build view untouched"
        );
        assert!(
            build
                .join("debug/deps/libpkg-1122334455667788.rlib")
                .exists(),
            "build artifact untouched"
        );
        assert!(!home.path().join("store").exists(), "no store was touched");
        Ok(())
    }

    #[test]
    fn work_surgery_accepts_the_shared_build_view() -> Result<()> {
        let (home, job) = tiered_views()?;
        let build = home.path().join("build");
        let opts = Options {
            work: Some("build"),
            unit: Some("pkg"),
            delete: true,
            ..no_selectors()
        };
        run(&build, &opts)?;
        assert!(
            !build
                .join("debug/.fingerprint/pkg-1122334455667788")
                .exists()
        );
        assert!(job.join("debug/.fingerprint/pkg-1122334455667788").exists());
        Ok(())
    }

    #[test]
    fn work_surgery_refuses_a_locked_view() -> Result<()> {
        let (home, job) = tiered_views()?;
        let build = home.path().join("build");
        let lock_path = job.join("debug/.cargo-build-lock");
        fs::write(&lock_path, b"")?;
        let held = fs::OpenOptions::new().write(true).open(&lock_path)?;
        held.try_lock().context("test holds the lock")?;
        let opts = Options {
            work: Some("ci-1"),
            crate_name: Some("pkg"),
            delete: true,
            ..no_selectors()
        };
        let err = run(&build, &opts).unwrap_err();
        assert!(err.to_string().contains("in use"), "{err}");
        assert!(job.join("debug/.fingerprint/pkg-1122334455667788").exists());
        Ok(())
    }

    #[test]
    fn work_surgery_requires_a_selector_and_rejects_bulk_ones() -> Result<()> {
        let (home, _job) = tiered_views()?;
        let build = home.path().join("build");
        let bare = Options {
            work: Some("ci-1"),
            ..no_selectors()
        };
        assert!(run(&build, &bare).is_err(), "needs --crate/--unit");
        let bulk = Options {
            work: Some("ci-1"),
            stale: true,
            ..no_selectors()
        };
        let err = run(&build, &bulk).unwrap_err();
        assert!(err.to_string().contains("--crate"), "{err}");
        Ok(())
    }

    #[test]
    fn work_surgery_unknown_view_errors() -> Result<()> {
        let (home, _job) = tiered_views()?;
        let build = home.path().join("build");
        let opts = Options {
            work: Some("nope"),
            crate_name: Some("pkg"),
            ..no_selectors()
        };
        assert!(run(&build, &opts).is_err());
        Ok(())
    }

    /// A home where the unit is both harvested into the store and present in
    /// the build view — the state a real `harvest` leaves behind.
    fn harvested_home() -> Result<(tempfile::TempDir, PathBuf)> {
        let (home, build) = synthetic_home()?;
        crate::vault::harvest(&build, &home.path().join("store"), None, false)?;
        Ok((home, build))
    }

    #[test]
    fn store_tier_drops_groups_and_prunes_the_manifest() -> Result<()> {
        let (home, build) = harvested_home()?;
        let store = home.path().join("store");
        assert_eq!(crate::vault::stored_units(&store)?.len(), 1, "harvested");

        // No --force: with --tier store the vault is the user's to trim.
        let opts = Options {
            unit: Some("pkg"),
            tier: Tier::Store,
            delete: true,
            ..no_selectors()
        };
        run(&build, &opts)?;
        assert_eq!(
            crate::vault::stored_units(&store)?.len(),
            0,
            "store record gone"
        );
        assert!(
            build
                .join("debug/.fingerprint/pkg-1122334455667788")
                .exists(),
            "the view keeps its links"
        );
        assert!(
            build
                .join("debug/deps/libpkg-1122334455667788.rlib")
                .exists(),
            "the view keeps its artifact"
        );
        Ok(())
    }

    #[test]
    fn view_tier_leaves_the_store_alone() -> Result<()> {
        let (home, build) = harvested_home()?;
        let store = home.path().join("store");
        let opts = Options {
            unit: Some("pkg"),
            tier: Tier::View,
            force: true,
            delete: true,
            ..no_selectors()
        };
        run(&build, &opts)?;
        assert!(
            !build
                .join("debug/.fingerprint/pkg-1122334455667788")
                .exists()
        );
        assert_eq!(
            crate::vault::stored_units(&store)?.len(),
            1,
            "store record stays"
        );
        Ok(())
    }

    #[test]
    fn default_tier_removes_store_and_view_together() -> Result<()> {
        let (home, build) = harvested_home()?;
        let store = home.path().join("store");
        let opts = Options {
            unit: Some("pkg"),
            force: true,
            delete: true,
            ..no_selectors()
        };
        run(&build, &opts)?;
        assert_eq!(crate::vault::stored_units(&store)?.len(), 0);
        assert!(
            !build
                .join("debug/.fingerprint/pkg-1122334455667788")
                .exists()
        );
        assert!(
            !build
                .join("debug/deps/libpkg-1122334455667788.rlib")
                .exists()
        );
        Ok(())
    }

    #[test]
    fn current_generation_is_protected_for_views() -> Result<()> {
        let (home, build) = harvested_home()?;
        let store = home.path().join("store");
        let opts = Options {
            unit: Some("pkg"),
            delete: true,
            ..no_selectors()
        };
        run(&build, &opts)?;
        assert!(
            build
                .join("debug/.fingerprint/pkg-1122334455667788")
                .exists(),
            "current unit protected without --force"
        );
        assert_eq!(crate::vault::stored_units(&store)?.len(), 1);
        Ok(())
    }

    #[test]
    fn stale_drops_non_active_generations_from_the_store() -> Result<()> {
        let (home, build) = harvested_home()?;
        let store = home.path().join("store");
        let old = store.join("0.0.0-deadbeef-x86_64-unknown-linux-gnu-00000000");
        let unit = old.join("units/oldpkg-0000111122223333");
        fs::create_dir_all(&unit)?;
        fs::write(unit.join("lib-old"), "aaaaaaaabbbbbbbb")?;
        fs::write(
            old.join("manifest.json"),
            r#"{"parity_key":"0.0.0-deadbeef-x86_64-unknown-linux-gnu-00000000","toolchain":"rustc 0.0.0","created":1,"updated":1,"units":[{"name":"oldpkg-0000111122223333","profile":"debug","memo":"lib-old","hash":"aaaaaaaabbbbbbbb","stamp":1,"files":[{"path":"lib-old","dest":".fingerprint/oldpkg-0000111122223333/lib-old","size":16,"role":"memo"}]}]}"#,
        )?;

        let opts = Options {
            stale: true,
            tier: Tier::Store,
            delete: true,
            ..no_selectors()
        };
        run(&build, &opts)?;
        assert!(!old.exists(), "the old generation is gone");
        assert_eq!(
            crate::vault::stored_units(&store)?.len(),
            1,
            "the active generation survives"
        );
        Ok(())
    }

    #[test]
    fn accounting_frees_only_inodes_whose_last_link_goes() -> Result<()> {
        let home = tempfile::tempdir()?;
        let a = home.path().join("a.bin");
        let b = home.path().join("b.bin");
        let store_copy = home.path().join("store-copy.bin");
        fs::write(&a, [0u8; 100])?;
        fs::write(&b, [0u8; 200])?;
        fs::hard_link(&b, &store_copy)?;

        // Both links of `b` are in the plan → its bytes are actually freed.
        let (nominal, freed, released, count) =
            account_files(&[a.clone(), b.clone(), store_copy.clone()]);
        assert_eq!((nominal, freed, released, count), (300, 300, 0, 3));

        // Only the view's links are removed → `b` is released, not freed.
        let (nominal, freed, released, count) = account_files(&[a, b]);
        assert_eq!((nominal, freed, released, count), (300, 100, 200, 2));
        Ok(())
    }
}
