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
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};

use crate::fingerprint::{self, ArtifactInfo, Unit};
use crate::util::{self, human_age, human_bytes, metadata_nofollow, parse_duration};
use crate::who;

/// What the user asked to evict.
pub struct Options<'a> {
    /// Unit query: dir name, dir hash fragment, or package name.
    pub unit: Option<&'a str>,
    /// Every unit on a stale toolchain generation (the bulk selector).
    pub stale: bool,
    /// Exact (or prefix) rustc fingerprint identity.
    pub rustc_key: Option<&'a str>,
    /// Delete whole parity-key generations (exact key or substring).
    pub generation: Option<&'a str>,
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
    let build_root = if build_root.exists() {
        crate::util::validate_state_root(build_root, "build root")?
    } else {
        build_root.to_path_buf()
    };
    let build_root = build_root.as_path();
    let work_root = crate::exec::work_root(build_root);
    let store_root = crate::vault::store_root(build_root);
    if work_root.exists() {
        crate::util::check_private_dir(&work_root, crate::util::Privacy::Repair)?;
    }
    if work_root.starts_with(&store_root) || store_root.starts_with(&work_root) {
        bail!(
            "work root {} overlaps the vault {} — refusing to collect job dirs",
            work_root.display(),
            store_root.display()
        );
    }
    if let (Ok(canonical_work), Ok(canonical_store)) =
        (work_root.canonicalize(), store_root.canonicalize())
    {
        if canonical_work.starts_with(&canonical_store)
            || canonical_store.starts_with(&canonical_work)
        {
            bail!(
                "work root {} resolves inside the vault {} — refusing to collect job dirs",
                work_root.display(),
                store_root.display()
            );
        }
    }
    #[cfg(windows)]
    crate::util::ensure_windows_user_path(&work_root, "work root")?;
    // An empty selector is a wildcard (`contains("")`) — never delete by it.
    for (name, value) in [
        ("--unit", opts.unit),
        ("--rustc-key", opts.rustc_key),
        ("--generation", opts.generation),
        ("--crate", opts.crate_name),
    ] {
        if value.is_some_and(|value| value.is_empty()) {
            bail!("{name} must not be empty — use an explicit selector or a dry run");
        }
    }
    if let Some(query) = opts.generation {
        if opts.unit.is_some()
            || opts.stale
            || opts.rustc_key.is_some()
            || opts.husks
            || opts.older_than.is_some()
            || opts.work_dirs
            || opts.work_dir.is_some()
            || opts.work.is_some()
            || opts.crate_name.is_some()
        {
            bail!(
                "--generation deletes whole parity-key generations — it takes no unit selectors:\n\
                 e.g. `epicenter evict --generation 1.97.1` (dry run unless --yes)"
            );
        }
        if opts.tier == Tier::View {
            bail!(
                "--generation is a vault operation — use --tier store, or the default all to also unlink matching view units"
            );
        }
        return evict_generations(build_root, opts, query);
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
    crate::util::probe(&store_root, "store")?;

    if opts.delete && opts.tier.touches_store() && !crate::vault::store_accepts_imports(&store_root)
    {
        bail!(
            "store {} is read-only or not writable — cannot evict the store tier; \
             run with `--tier view` to clean views, or omit `--yes` for a dry run",
            store_root.display()
        );
    }

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
                let files = view_unit_files(&unit, &arts);
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
                        root: root.clone(),
                        unit_dir: unit.fingerprint_dir.clone(),
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

    // A lone `--unit` names exactly what the user wants — deliberate, like
    // `--tier store` and `--work-dir`. Bulk selectors keep the guard.
    let explicit_unit = opts.unit.is_some()
        && !opts.stale
        && opts.rustc_key.is_none()
        && !opts.husks
        && opts.older_than.is_none();

    let mut protected = 0usize;
    let mut chosen: Vec<Candidate> = Vec::new();
    for (_, candidate) in candidates {
        // Current-generation units are protected whenever a view is involved;
        // `--tier store` is explicitly the vault-trimming mode.
        if candidate.current && !opts.force && opts.tier.touches_view() && !explicit_unit {
            protected += 1;
            continue;
        }
        chosen.push(candidate);
    }
    chosen.sort_by_key(|candidate| std::cmp::Reverse(candidate.bytes));

    if chosen.is_empty() {
        if protected > 0 {
            println!(
                "  {} {protected} current-generation unit(s) match but are protected — use --force to include them",
                util::warn(util::GLYPH_WARN)
            );
            println!(
                "  {}",
                util::dim("nothing else matches the given selectors")
            );
        } else {
            println!("  nothing matches the given selectors");
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
    let (nominal, freed, released, count) = util::account_files(&all_files);
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
    if opts.delete && opts.tier.touches_store() {
        // Empty generations and orphan locks are removed with their units.
        crate::vault::sweep_store_debris(&store_root);
    }

    let mut view_counts: BTreeMap<String, usize> = BTreeMap::new();
    for candidate in &chosen {
        for place in &candidate.places {
            if let Place::View {
                label,
                root,
                unit_dir,
                anchors,
                artifacts,
                ..
            } = place
            {
                // The scan happened earlier; a build may have started since.
                // Re-check the live lock and take the per-job epicenter lock.
                let _job_lock = match label.strip_prefix("work/") {
                    Some(name) => match crate::util::FileLock::try_acquire(
                        &crate::exec::job_lock_path(
                            &crate::exec::work_root(&crate::vault::store_root(
                                &crate::config::trusted_cache_root()?,
                            )),
                            name,
                        ),
                    ) {
                        Ok(Some(lock)) => Some(lock),
                        Ok(None) => {
                            errors += 1;
                            eprintln!("view {label} is in use by an epicenter process — skipped");
                            continue;
                        }
                        Err(err) => {
                            errors += 1;
                            eprintln!("view {label} lock failed: {err:#} — skipped");
                            continue;
                        }
                    },
                    None => None,
                };
                let Some(_cargo_locks) = crate::job::cargo_locks(root)? else {
                    errors += 1;
                    eprintln!("view {label} is in use by a live build — skipped");
                    continue;
                };
                remove_dir(root, unit_dir, &mut errors);
                for anchor in anchors {
                    remove_dir(root, anchor, &mut errors);
                }
                for artifact in artifacts {
                    remove_file(root, artifact, &mut errors);
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
    // Windows locks the current directory of every process: a shell sitting
    // inside the job dir makes rename/remove fail with "access denied".
    if cwd_is_within(&path) {
        bail!(
            "the current directory is inside {} — `cd` out of the job dir and retry; \
             Windows cannot rename or remove a directory a process is working in",
            path.display()
        );
    }
    let job_lock =
        match crate::util::FileLock::try_acquire(&crate::exec::job_lock_path(&work_root, &name))? {
            Some(lock) => lock,
            None => bail!(
                "job dir {} is in use by an epicenter process — remove it when it finishes",
                path.display()
            ),
        };
    // Hold Cargo's own lock files through the rename/delete. A boolean check
    // here would release the locks immediately and let a build start in the
    // window before `rename`.
    let cargo_locks = match crate::job::cargo_locks(&path)? {
        Some(locks) => locks,
        None => bail!(
            "job dir {} is in use by a live build — remove it when it finishes",
            path.display()
        ),
    };
    let stats = tree_stats(&path);

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
        human_bytes(stats.bytes),
        stats.files,
        stats.newest.map(human_age).unwrap_or_else(|| "?".into()),
        util::dim("explicitly selected — age policy not applied")
    );
    println!();
    if !delete {
        println!(
            "  {} {} nominal — {} would be freed · {} links released",
            util::dim("result:   "),
            human_bytes(stats.bytes),
            human_bytes(stats.unique),
            human_bytes(stats.shared)
        );
        println!("  {}", util::dim("run again with -y or --yes to remove it"));
        return Ok(());
    }
    // Rename out of the way first: a hidden tombstone is not a job dir any
    // later GC/exec can guess, and a build that races the check fails rather
    // than writing into a directory being deleted.
    let tombstone = work_root.join(format!(".{name}.deleting-{}", std::process::id()));
    match crate::util::probe_kind(&tombstone)? {
        crate::util::Probed::Real(_) => {
            crate::util::remove_tree(&work_root, &tombstone)
                .with_context(|| format!("clearing stale tombstone {}", tombstone.display()))?;
        }
        // No stale tombstone to clear. A link is not a tombstone we created;
        // do not follow it. The later rename fails safely if it still occupies
        // the name.
        crate::util::Probed::Missing | crate::util::Probed::Reparse => {}
    }
    // Windows refuses to rename a directory while a handle inside it is open,
    // including Cargo's lock files. Drop our guards right before the rename;
    // the job lock (outside the dir) still keeps other epicenter jobs out.
    #[cfg(windows)]
    drop(cargo_locks);
    #[cfg(not(windows))]
    let _cargo_locks = cargo_locks;
    isolate_dir(&path, &tombstone).with_context(|| {
        format!(
            "isolating {} — a process still holds this job dir open (a build, editor/rust-analyzer, \
             or a shell inside it); close it and retry",
            path.display()
        )
    })?;
    if let Err(err) = crate::util::remove_tree(&work_root, &tombstone) {
        let _ = fs::rename(&tombstone, &path);
        drop(job_lock);
        return Err(err).with_context(|| format!("removing {}", path.display()));
    }
    drop(job_lock);
    crate::exec::remove_job_lock(&work_root, &name);
    crate::exec::sweep_job_locks(&work_root);
    println!(
        "  {} {} nominal — {} actually freed · {} links released",
        util::dim("result:   "),
        human_bytes(stats.bytes),
        human_bytes(stats.unique),
        human_bytes(stats.shared)
    );
    println!();
    println!("  {} {name} removed", util::green(util::GLYPH_PASS));
    println!(
        "  {}",
        util::dim("the vault is untouched — a job dir is a view")
    );
    Ok(())
}

/// Rename into the tombstone, retrying the transient access-denied Windows
/// returns while antivirus/indexers briefly inspect the tree. Other platforms
/// rename once: a permission error there is an ACL problem, not a race.
fn isolate_dir(path: &Path, tombstone: &Path) -> std::io::Result<()> {
    let attempts = if cfg!(windows) { 4 } else { 1 };
    let mut last: Option<std::io::Error> = None;
    for attempt in 0..attempts {
        match fs::rename(path, tombstone) {
            Ok(()) => return Ok(()),
            Err(err)
                if attempt + 1 < attempts && err.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                last = Some(err);
                std::thread::sleep(std::time::Duration::from_millis(150 * (attempt + 1)));
            }
            Err(err) => return Err(err),
        }
    }
    Err(last.expect("a failed attempt records its error"))
}

/// Is the process working directory inside `path`? Canonical paths compare
/// the same way for a plain dir and one reached through a junction.
fn cwd_is_within(path: &Path) -> bool {
    let Ok(cwd) = std::env::current_dir() else {
        return false;
    };
    let (Ok(cwd), Ok(target)) = (cwd.canonicalize(), path.canonicalize()) else {
        return false;
    };
    path_is_within(&cwd, &target)
}

fn path_is_within(cwd: &Path, target: &Path) -> bool {
    cwd == target || cwd.starts_with(target)
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
    let Some(candidate_meta) = crate::util::probe(&candidate, "job dir")? else {
        bail!("no job dir named {target:?} — `epicenter vault` shows the work tier")
    };
    if !candidate_meta.is_dir() {
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
        let meta = match metadata_nofollow(&path) {
            Ok(meta) => meta,
            // The entry vanished or became a link while we scanned it.
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
                ) =>
            {
                continue;
            }
            // One unreadable job dir must not block collection of the rest.
            Err(_) => continue,
        };
        if !meta.is_dir() {
            continue;
        }
        let locked = crate::exec::dir_locked(&path);
        let stats = tree_stats(&path);
        let newest = stats.newest;
        // A filtered/reparse subtree can hide every regular file. Treat a
        // non-empty dir without a visible file as fresh, never as infinitely
        // old: bulk collection must not delete a job it could not inspect.
        let empty = fs::read_dir(&path)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(false);
        let old_enough = match newest {
            Some(modified) => now.duration_since(modified).map_or(true, |age| age > limit),
            None => empty,
        };
        rows.push(WorkDir {
            name,
            path,
            newest,
            locked,
            old_enough,
            bytes: stats.bytes,
            unique: stats.unique,
            shared: stats.shared,
            files: stats.files,
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
            util::safe_display(std::ffi::OsStr::new(&row.name)),
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
        let job_lock = match crate::util::FileLock::try_acquire(&crate::exec::job_lock_path(
            &work_root, &row.name,
        ))? {
            Some(lock) => lock,
            None => {
                report.in_use += 1;
                continue;
            }
        };
        let cargo_locks = match crate::job::cargo_locks(&row.path)? {
            Some(locks) => locks,
            None => {
                report.in_use += 1;
                continue;
            }
        };
        // Same Windows rule as `--work-dir`: an open handle inside the tree
        // blocks the directory removal.
        #[cfg(windows)]
        drop(cargo_locks);
        #[cfg(not(windows))]
        let _cargo_locks = cargo_locks;
        match crate::util::remove_tree(&work_root, &row.path) {
            Ok(()) => {
                report.removed += 1;
                freed_unique += row.unique;
                freed_shared += row.shared;
                drop(job_lock);
                crate::exec::remove_job_lock(&work_root, &row.name);
            }
            Err(e) => {
                report.errors += 1;
                eprintln!("could not remove {}: {e}", row.path.display());
            }
        }
    }
    crate::exec::sweep_job_locks(&work_root);
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

/// Summary of one job/view tree: newest file mtime plus link-aware
/// accounting. A job is as fresh as its last file write (directory mtimes only
/// move when entries are added or removed), and one walk feeds both the age
/// policy and the size report.
#[derive(Debug, Default)]
struct TreeStats {
    newest: Option<SystemTime>,
    bytes: u64,
    unique: u64,
    shared: u64,
    files: u64,
}

fn tree_stats(dir: &Path) -> TreeStats {
    let mut stats = TreeStats::default();
    let mut budget = crate::util::ScanBudget::new("work dir tree");
    for entry in crate::util::SafeWalk::new(dir).walk().flatten() {
        if !budget.take() {
            break;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let size = meta.len();
        stats.bytes = stats.bytes.saturating_add(size);
        stats.files = stats.files.saturating_add(1);
        if let Ok(modified) = meta.modified() {
            if stats.newest.map_or(true, |current| modified > current) {
                stats.newest = Some(modified);
            }
        }
        if crate::vault::link_count(entry.path(), &meta) > 1 {
            stats.shared = stats.shared.saturating_add(size);
        } else {
            stats.unique = stats.unique.saturating_add(size);
        }
    }
    stats
}

/// Resolve `--work`: `build` = the shared view; a job id (with or without
/// the `work/` prefix) = that job dir; anything else = a directory path.
fn resolve_view(build_root: &Path, work: &str) -> Result<PathBuf> {
    if work == "build" {
        return crate::util::validate_state_root(build_root, "build view");
    }
    let work_root = crate::exec::work_root(build_root);
    // Only a plain job id (or `work/<id>`) may use the join shortcut. An
    // absolute path or `../x` would replace the base in `Path::join` and
    // bypass the containment check below.
    let job_id = work.strip_prefix("work/").unwrap_or(work);
    if crate::util::validate_component(job_id, "job id").is_ok() {
        let job = work_root.join(job_id);
        if let Ok(meta) = metadata_nofollow(&job) {
            if meta.is_dir() {
                // Apply containment to the join shortcut too: a junction
                // inside work/ must not point outside the work root.
                if let (Ok(root), Ok(canon)) = (work_root.canonicalize(), job.canonicalize()) {
                    if canon != root && canon.starts_with(&root) {
                        return Ok(job);
                    }
                }
            }
        }
    }
    let path = PathBuf::from(work);
    if metadata_nofollow(&path)
        .map(|meta| meta.is_dir())
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
fn view_unit_files(unit: &Unit, arts: &ArtifactInfo) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_tree_files(&unit.fingerprint_dir, &mut files);
    // `arts.paths` already covers the `build/<anchor>/` files.
    for (path, _, _) in &arts.paths {
        files.push(path.clone());
    }
    files
}

fn collect_tree_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut budget = crate::util::ScanBudget::new("store tree");
    for entry in crate::util::SafeWalk::new(dir).walk().flatten() {
        if !budget.take() {
            return;
        }
        if entry.file_type().is_file() {
            out.push(entry.path().to_path_buf());
        }
    }
}

/// Remove one unit from one view: fingerprint dir, build anchors, artifacts.
fn remove_view_unit(root: &Path, unit: &Unit, arts: &ArtifactInfo, errors: &mut u64) {
    // Artifacts first: in the new layout they live inside the unit root, and
    // removing that root first would make the later file removals fail.
    for (path, _, _) in &arts.paths {
        remove_file(root, path, errors);
    }
    remove_dir(root, &unit.fingerprint_dir, errors);
    for anchor in fingerprint::build_anchor_dirs(root, unit) {
        remove_dir(root, &anchor, errors);
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
        root: PathBuf,
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
    candidate.bytes = place
        .files()
        .iter()
        .filter_map(|path| fs::metadata(path).ok())
        .fold(candidate.bytes, |total, meta| {
            total.saturating_add(meta.len())
        });
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
            if metadata_nofollow(&entry.path()).is_err() {
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

/// `epicenter evict --generation <key>` — delete whole parity-key stores.
fn evict_generations(build_root: &Path, opts: &Options<'_>, query: &str) -> Result<()> {
    let store_root = crate::vault::store_root(build_root);
    if store_root.exists() {
        crate::vault::check_store_trust(&store_root)?;
    }
    if opts.delete && !crate::vault::store_accepts_imports(&store_root) {
        bail!(
            "store {} is read-only or not writable — cannot delete generations; \
             omit `--yes` for a dry run",
            store_root.display()
        );
    }
    let generations = crate::vault::generations(&store_root)?;
    let chosen: Vec<&crate::vault::GenerationInfo> = generations
        .iter()
        .filter(|generation| generation.parity.contains(query))
        .collect();
    if chosen.is_empty() {
        bail!("no vault generation matches {query:?} — `epicenter vault` lists them");
    }
    if !opts.force {
        if let Some(generation) = chosen.iter().find(|generation| generation.active) {
            bail!(
                "the active vault generation {} is protected — pass --force to delete it (the next build starts cold)",
                generation.parity
            );
        }
    }

    // Unit hashes are toolchain-specific, so a view unit with one of these
    // names belongs to the generation even in a mixed-layout view.
    let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut files: Vec<PathBuf> = Vec::new();
    for generation in &chosen {
        names.extend(crate::vault::generation_unit_names(
            &store_root,
            &generation.parity,
        )?);
        collect_tree_files(&store_root.join(&generation.parity), &mut files);
    }

    let mut views: Vec<(String, PathBuf, Vec<(Unit, ArtifactInfo)>)> = Vec::new();
    let mut skipped_views = Vec::new();
    if opts.tier.touches_view() {
        for (label, root) in known_views(build_root) {
            if crate::exec::dir_locked(&root) {
                skipped_views.push(label);
                continue;
            }
            let rows = who::collect(&root).with_context(|| format!("reading view {label}"))?;
            let units: Vec<(Unit, ArtifactInfo)> = rows
                .into_iter()
                .filter(|(unit, _)| names.contains(&unit.dir_name))
                .collect();
            if units.is_empty() {
                continue;
            }
            for (unit, arts) in &units {
                files.extend(view_unit_files(unit, arts));
            }
            views.push((label, root, units));
        }
    }

    let (nominal, freed, released, count) = util::account_files(&files);
    println!(
        "{}",
        util::heading(if opts.delete {
            "epicenter evict — generations"
        } else {
            "epicenter evict — generations (DRY RUN — pass --yes to delete)"
        })
    );
    for generation in &chosen {
        println!(
            "  {} {:<52} {:>5} unit(s) · {:>9}",
            util::dim("generation"),
            generation.parity,
            generation.units,
            human_bytes(generation.bytes)
        );
    }
    if !skipped_views.is_empty() {
        println!(
            "  {} {} view(s) in use by a live build — skipped",
            util::warn(util::GLYPH_WARN),
            skipped_views.len()
        );
    }
    println!();
    println!(
        "  {} {} generation(s) · {} unit(s) · {} nominal",
        util::dim("selection:"),
        chosen.len(),
        names.len(),
        util::green(&human_bytes(nominal))
    );
    println!(
        "  {} {} actually freed · {} links released (still held elsewhere, e.g. a locked view)",
        util::dim("result:   "),
        human_bytes(freed),
        human_bytes(released)
    );
    println!(
        "  {} {} file(s) · {} view(s) planned",
        util::dim("files:    "),
        count,
        views.len()
    );
    if !opts.delete {
        println!(
            "  {}",
            util::dim("run again with -y or --yes to delete these generations")
        );
        return Ok(());
    }

    let mut errors = 0u64;
    let mut unlinked_views = 0usize;
    for (label, root, units) in &views {
        let Some(_cargo_locks) = crate::job::cargo_locks(root)? else {
            errors += 1;
            eprintln!("view {label} became busy — skipped");
            continue;
        };
        let _job_lock = if let Some(name) = label.strip_prefix("work/") {
            match crate::util::FileLock::try_acquire(&crate::exec::job_lock_path(
                &crate::exec::work_root(build_root),
                name,
            )) {
                Ok(Some(lock)) => Some(lock),
                Ok(None) => {
                    errors += 1;
                    eprintln!("view {label} is in use by an epicenter process — skipped");
                    continue;
                }
                Err(err) => {
                    errors += 1;
                    eprintln!("view {label} lock failed: {err:#} — skipped");
                    continue;
                }
            }
        } else {
            None
        };
        for (unit, arts) in units {
            remove_view_unit(root, unit, arts, &mut errors);
        }
        unlinked_views += 1;
    }

    let mut deleted = 0usize;
    for generation in &chosen {
        match crate::vault::drop_generation(&store_root, &generation.parity) {
            Ok(true) => deleted += 1,
            Ok(false) => {
                errors += 1;
                eprintln!(
                    "generation {} is in use by a live harvest — skipped",
                    generation.parity
                );
            }
            Err(err) => {
                errors += 1;
                eprintln!("could not remove generation {}: {err:#}", generation.parity);
            }
        }
    }
    crate::vault::sweep_store_debris(&store_root);

    println!();
    println!(
        "  {} {} generation(s) deleted · {} view(s) unlinked · {} actually freed · {} links released",
        util::green(util::GLYPH_PASS),
        deleted,
        unlinked_views,
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
        util::dim("`epicenter vault` shows what the store holds now")
    );
    Ok(())
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
    // Hold the lock descriptors for the entire unlink operation.
    let Some(_cargo_locks) = crate::job::cargo_locks(&root)? else {
        bail!(
            "view {} is in use by a live build — unlink when it finishes",
            root.display()
        );
    };
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
        files.extend(view_unit_files(unit, arts));
    }
    let (nominal, freed, released, count) = util::account_files(&files);

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
    // `_cargo_locks` has been held since the start: any live build is fenced
    // out, and re-probing the same locks here would see *our* own guard and
    // refuse forever (the "became busy" self-lock).
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

fn remove_dir(root: &Path, path: &Path, errors: &mut u64) {
    if let Err(err) = crate::util::remove_tree(root, path) {
        *errors += 1;
        eprintln!("could not remove {}: {err:#}", path.display());
    }
}

fn remove_file(root: &Path, path: &Path, errors: &mut u64) {
    if let Err(err) = crate::util::remove_file(root, path) {
        *errors += 1;
        eprintln!("could not remove {}: {err:#}", path.display());
    }
}

#[cfg(test)]
mod tests;
