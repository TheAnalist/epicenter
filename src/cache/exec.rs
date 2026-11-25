//! `epicenter exec` — run one command against a fresh per-job build dir
//! seeded from the vault.
//!
//! A job gets its own directory under the per-user OS work root
//! (`$XDG_CACHE_HOME/epicenter/work/<id>/`, overridable with `--work-root`)
//! that plays the role of Cargo's build dir for the child process
//! (`CARGO_BUILD_BUILD_DIR` — no config file is written). The vault's unit
//! groups are hard-linked in first, so the build starts warm; the units the
//! job produces can be harvested back. Because every job owns its build dir,
//! jobs never contend on Cargo's per-build-dir lock, and the job dir itself
//! is a disposable view: deleting it removes no state the vault still holds.
//!
//! stdout and stderr of the command pass through untouched; epicenter's own
//! frame lines go to stderr, and the command's exit code becomes epicenter's
//! exit code.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

use crate::fingerprint;
use crate::settings::LinkPolicy;
use crate::util::{
    self, GLYPH_FAIL, GLYPH_INFO, GLYPH_PASS, human_bytes, human_duration, metadata_nofollow,
};
use crate::vault;

pub use crate::job::JOB_MARKER;
pub(crate) use crate::job::{
    EXEC_COMMAND_MAX_CHARS, EXEC_RECORD_VERSION, ExecRecord, RecordCoverage, cargo_locks,
    existing_cargo_locks, job_marker_token, record_covers, remove_record, unix_now,
    write_job_marker, write_record,
};
#[cfg(test)]
pub(crate) use crate::job::{JOB_MARKER_VERSION, record_for_test};

static WORK_ROOT_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

/// Install the CLI's resolved work root once per process. Callers that use
/// the library directly still get the legacy build-sibling fallback.
pub fn set_work_root_override(path: PathBuf) -> Result<()> {
    WORK_ROOT_OVERRIDE
        .set(path)
        .map_err(|_| anyhow::anyhow!("work root override is already installed"))
}

/// The local per-VM work root: explicit policy override when installed, else
/// the legacy build sibling for library/test callers.
pub fn work_root(build_root: &Path) -> PathBuf {
    WORK_ROOT_OVERRIDE
        .get()
        .cloned()
        .unwrap_or_else(|| build_root.parent().unwrap_or(build_root).join("work"))
}

#[cfg(test)]
fn has_job_marker(work_dir: &Path) -> Result<bool> {
    Ok(job_marker_token(work_dir)?.is_some())
}

fn create_job_dir(work_dir: &Path) -> Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(work_dir)
            .with_context(|| format!("creating job dir {}", work_dir.display()))?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(work_dir)
            .with_context(|| format!("creating job dir {}", work_dir.display()))?;
        crate::util::check_private_dir(work_dir, crate::util::Privacy::Repair)?;
    }
    match write_job_marker(work_dir) {
        Ok(token) => Ok(token),
        Err(err) => {
            let _ = fs::remove_dir(work_dir);
            Err(err)
        }
    }
}

/// One job dir as the read-only summary sees it.
#[derive(Debug, Clone)]
pub struct WorkDirInfo {
    pub name: String,
    pub files: u64,
    pub bytes: u64,
    /// Newest file mtime — the dir's last activity.
    pub newest: Option<SystemTime>,
}

/// What the `work/` tier currently holds (read-only summary).
#[derive(Debug, Default)]
pub struct WorkTier {
    pub dirs: usize,
    pub files: u64,
    pub bytes: u64,
    /// Newest file mtime across all job dirs — the tier's last activity.
    pub newest: Option<SystemTime>,
    /// Per-dir detail, oldest activity first (the most collectible on top).
    pub entries: Vec<WorkDirInfo>,
}

/// Summarize the job dirs under `work/`.
pub fn work_tier(build_root: &Path) -> Result<WorkTier> {
    let mut tier = WorkTier::default();
    let Ok(entries) = std::fs::read_dir(work_root(build_root)) else {
        return Ok(tier);
    };
    let mut budget = util::ScanBudget::new("work dirs");
    for entry in entries.flatten() {
        budget.spend()?;
        if !entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = util::safe_display(&entry.file_name());
        if name.starts_with('.') {
            continue;
        }
        if metadata_nofollow(&entry.path()).is_err() {
            continue;
        }
        let mut info = WorkDirInfo {
            name,
            files: 0,
            bytes: 0,
            newest: None,
        };
        let job_dir = entry.path();
        for file in util::SafeWalk::new(&job_dir).walk().flatten() {
            budget.spend()?;
            if !file.file_type().is_file() {
                continue;
            }
            if let Ok(meta) = file.metadata() {
                info.files = info.files.saturating_add(1);
                info.bytes = info.bytes.saturating_add(meta.len());
                if let Ok(modified) = meta.modified() {
                    if info.newest.map_or(true, |current| modified > current) {
                        info.newest = Some(modified);
                    }
                }
            }
        }
        tier.dirs = tier.dirs.saturating_add(1);
        tier.files = tier.files.saturating_add(info.files);
        tier.bytes = tier.bytes.saturating_add(info.bytes);
        if let Some(modified) = info.newest {
            if tier.newest.map_or(true, |current| modified > current) {
                tier.newest = Some(modified);
            }
        }
        tier.entries.push(info);
    }
    tier.entries.sort_by_key(|info| info.newest);
    Ok(tier)
}

/// Advisory check: existing locks only, no sentinel creation. Used by read
/// paths (`status`, `evict` discovery) that must not write into a view.
pub(crate) fn dir_locked(dir: &Path) -> bool {
    match existing_cargo_locks(dir) {
        Ok(Some(locks)) => {
            drop(locks);
            false
        }
        _ => true,
    }
}

/// Path of the per-job epicenter lock (outside the job dir, so `--rm` can
/// delete the dir while the lock is held).
pub(crate) fn job_lock_path(work_root: &Path, job_id: &str) -> PathBuf {
    work_root.join(format!(".lock-{job_id}"))
}

/// Remove the per-job lock file once the job dir is gone and no process holds
/// the lock. A held lock (a live job) or an existing dir keeps it.
pub(crate) fn remove_job_lock(work_root: &Path, job_id: &str) {
    let dir = work_root.join(job_id);
    let path = job_lock_path(work_root, job_id);
    if dir.exists() || !path.exists() {
        return;
    }
    let Ok(Some(_lock)) = crate::util::FileLock::try_acquire(&path) else {
        return;
    };
    if !dir.exists() {
        let _ = fs::remove_file(&path);
    }
}

/// Clear `.lock-*` debris whose job dir is gone (a crash, or a removal from
/// before this cleanup existed). Locks of live or kept jobs are left alone.
pub(crate) fn sweep_job_locks(work_root: &Path) {
    let Ok(entries) = fs::read_dir(work_root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(job_id) = name.strip_prefix(".lock-") {
            if !job_id.is_empty() {
                remove_job_lock(work_root, job_id);
            }
            continue;
        }
        if let Some(job_id) = name
            .strip_prefix(".exec-")
            .and_then(|rest| rest.strip_suffix(".json"))
        {
            if !job_id.is_empty() && !work_root.join(job_id).exists() {
                remove_record(work_root, job_id);
            }
        }
    }
}

/// What the caller wants.
pub struct Options<'a> {
    /// Job id / work-dir name; `None` mints one.
    pub job_id: Option<&'a str>,
    /// Directory the command runs in (default: the current directory).
    pub cwd: Option<PathBuf>,
    /// Store the units the job produced back into the vault.
    pub harvest_back: bool,
    /// Compress copied artifacts when harvesting.
    pub compress: bool,
    /// Remove the work dir after the run — success or failure. Without it
    /// the dir is kept for inspection.
    pub remove_on_success: bool,
    /// Continue in an existing job dir instead of refusing (restore is
    /// idempotent; a dir a live build holds is still refused).
    pub reuse: bool,
    /// The child's `CARGO_TARGET_DIR`: `Some("job")` means `<work dir>/target`
    /// (per-job finals — the fully parallel case); any other value is a path.
    pub target_dir: Option<&'a str>,
    /// Preset override for `CARGO_INCREMENTAL`; `None` leaves Cargo's config.
    pub incremental: Option<bool>,
    /// How dependencies are installed into the job dir.
    pub link: LinkPolicy,
    /// Global `cargo_home` policy; `None` leaves the child's environment
    /// untouched.
    pub cargo_home: Option<&'a Path>,
    /// Skip remote compatible-unit fetch for this job.
    pub no_remote: bool,
    /// Effective remote policy; `None` when the endpoint is unconfigured.
    pub remote: Option<&'a crate::settings::RemotePolicy>,
    /// The command, argv-style.
    pub command: &'a [String],
}

/// True when the job dir holds nothing but its marker.
///
/// That is the only safe adoption case: a crash between `create_job_dir` and
/// `write_record`, or a dir from an intermediate version. There is no planted
/// build state to consume.
fn job_dir_is_unseeded(work_dir: &Path) -> Result<bool> {
    for entry in
        fs::read_dir(work_dir).with_context(|| format!("reading job dir {}", work_dir.display()))?
    {
        let entry = entry?;
        if entry.file_name() == JOB_MARKER {
            continue;
        }
        return Ok(false);
    }
    Ok(true)
}

/// Resolve `--target-dir`: the bare flag (`"job"`) picks `<work dir>/target`,
/// so finals live and die with the job; a value is a path, resolved against
/// the command's working directory when relative.
fn resolve_target_dir(raw: &str, work_dir: &Path, cwd: Option<&Path>) -> PathBuf {
    if raw == "job" {
        return work_dir.join("target");
    }
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        return path;
    }
    let base = cwd
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_default();
    base.join(path)
}

/// The directory the child will run in, as an absolute path when possible.
fn project_dir(opts: &Options<'_>) -> Option<PathBuf> {
    match &opts.cwd {
        Some(dir) if dir.is_absolute() => Some(dir.clone()),
        Some(dir) => std::env::current_dir().ok().map(|cwd| cwd.join(dir)),
        None => std::env::current_dir().ok(),
    }
}

#[derive(Debug, Default)]
struct ChildCargo {
    selector: Option<String>,
    version: Option<String>,
    /// Profile directory Cargo will use, e.g. `debug` or `release`.
    profile: Option<String>,
    target: Option<String>,
    /// Whether the subcommand produces units that a restored view can serve.
    builds_units: bool,
}

/// `+toolchain`, version, profile and target of a cargo child. A non-cargo
/// program returns the default (empty) value.
fn child_cargo(command: &[String]) -> ChildCargo {
    let Some(program) = command.first() else {
        return ChildCargo::default();
    };
    let is_cargo = Path::new(program)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .map(|stem| stem.eq_ignore_ascii_case("cargo"))
        .unwrap_or(false);
    if !is_cargo {
        return ChildCargo::default();
    }
    // rustup's `+toolchain` must be the first argument after the program.
    let selector = command
        .get(1)
        .and_then(|arg| arg.strip_prefix('+'))
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let subcommand = cargo_subcommand(command);
    let builds_units = matches!(
        subcommand.as_deref(),
        Some("build" | "check" | "test" | "bench" | "clippy" | "run" | "rustc" | "doc" | "fix")
    );
    let profile = builds_units.then(|| profile_from_args(command, subcommand.as_deref()));
    let target = target_from_args(command);
    let Ok(mut probe) = crate::util::command_for(program) else {
        return ChildCargo {
            selector,
            profile,
            target,
            builds_units,
            version: None,
        };
    };
    if let Some(selector) = &selector {
        probe.arg(format!("+{selector}"));
    }
    let version = probe
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|text| text.starts_with("cargo "));
    ChildCargo {
        selector,
        version,
        profile,
        target,
        builds_units,
    }
}

/// First positional cargo argument after global options.
fn cargo_subcommand(command: &[String]) -> Option<String> {
    let mut args = command.iter().skip(1);
    while let Some(arg) = args.next() {
        if arg.starts_with('+') || arg.starts_with('-') {
            if matches!(
                arg.as_str(),
                "--color" | "--config" | "-Z" | "--manifest-path" | "--target-dir"
            ) {
                args.next();
            }
            continue;
        }
        return Some(arg.clone());
    }
    None
}

fn profile_from_args(command: &[String], subcommand: Option<&str>) -> String {
    let mut explicit = None;
    let mut release = false;
    let mut args = command.iter().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--" {
            break;
        }
        if arg == "--release" || arg == "-r" {
            release = true;
        } else if let Some(profile) = arg.strip_prefix("--profile=") {
            explicit = Some(profile.to_string());
        } else if arg == "--profile" {
            explicit = args.next().cloned();
        }
    }
    if let Some(profile) = explicit {
        return match profile.as_str() {
            "dev" | "test" => "debug".to_string(),
            "bench" | "release" => "release".to_string(),
            other => other.to_string(),
        };
    }
    if release || subcommand == Some("bench") {
        "release".to_string()
    } else {
        "debug".to_string()
    }
}

fn target_from_args(command: &[String]) -> Option<String> {
    let mut args = command.iter().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--" {
            break;
        }
        if let Some(target) = arg.strip_prefix("--target=") {
            return Some(target.to_string());
        }
        if arg == "--target" {
            return args.next().cloned();
        }
    }
    None
}

fn print_remote(report: &crate::remote::FetchReport) {
    if report.disabled {
        return;
    }
    if let Some(warning) = &report.warning {
        eprintln!("  {} {}", util::warn(util::GLYPH_WARN), util::dim(warning));
    }
    if let Some(reason) = &report.fallback {
        eprintln!(
            "  {} {}",
            util::dim(&format!("{:<11}", "remote")),
            util::dim(&format!("skipped: {reason}"))
        );
        return;
    }
    let suffix = if report.cache_store.is_some() {
        "  (cache store)"
    } else {
        ""
    };
    eprintln!(
        "  {} {} unit(s) · {} file(s) · {}{}",
        util::dim(&format!("{:<11}", "remote")),
        report.imported,
        report.files,
        util::green(&human_bytes(report.bytes)),
        util::dim(suffix)
    );
}

/// Run the job; returns the command's exit code.
pub fn run(store_root: &Path, work_root: &Path, opts: &Options<'_>) -> Result<i32> {
    let Some(program) = opts.command.first() else {
        bail!("exec needs a command — `epicenter exec -- <cmd>`");
    };
    if let Some(cargo_home) = opts.cargo_home {
        crate::util::validate_private_dir(cargo_home, "cargo home")?;
    }
    let job_id = match opts.job_id {
        Some(id) => sanitize_job_id(id)?,
        None => default_job_id(),
    };
    // The work root is local per VM and must never overlap the vault: a
    // shared/read-only store is not a place to create job dirs, and a work
    // root that is an ancestor of the store could make `evict --work-dirs`
    // treat the store as a job dir.
    if work_root
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!(
            "work root {} contains `..`; use a normalized path",
            work_root.display()
        );
    }
    if work_root.starts_with(store_root) || store_root.starts_with(work_root) {
        bail!(
            "work root {} overlaps the vault {} — choose a separate local directory",
            work_root.display(),
            store_root.display()
        );
    }
    // Private work root + per-job epicenter lock (outside the job dir, so
    // --rm can remove the dir while the lock is held).
    crate::util::ensure_windows_user_path(work_root, "work root")?;
    crate::util::create_private_dir_all(work_root)?;
    let work_root = crate::util::validate_state_root(work_root, "work root")?;
    if let Ok(store) = store_root.canonicalize() {
        if work_root.starts_with(&store) || store.starts_with(&work_root) {
            bail!(
                "work root {} overlaps the vault {} — choose a separate local directory",
                work_root.display(),
                store.display()
            );
        }
    }
    let work_root = work_root.as_path();

    if opts.harvest_back && !crate::vault::store_accepts_imports(store_root) {
        bail!(
            "store {} is read-only or not writable — `--harvest` needs a writable store; run without `--harvest`",
            store_root.display()
        );
    }

    // A job dir must stay on this machine's disk: a network mount is a second
    // trust domain, and a harvest record written there proves nothing.
    if crate::vault::store_is_shared_mount(work_root) {
        bail!(
            "work root {} is a network/shared mount — job dirs must stay local",
            work_root.display()
        );
    }
    // Acquire the per-job lock BEFORE looking at/creating the dir: the bulk
    // work-dir GC takes the same lock and must never see an unlocked empty dir.
    let job_lock = match crate::util::FileLock::try_acquire(&job_lock_path(work_root, &job_id))? {
        Some(lock) => lock,
        None => bail!(
            "job {} is in use by another epicenter process — wait for it, or use another --id",
            job_id
        ),
    };
    let work_dir = work_root.join(&job_id);
    let mut reused = false;
    let mut adopted = false;
    let mut reuse_locks: Option<Vec<fs::File>> = None;
    let job_token = if let Ok(meta) = metadata_nofollow(&work_dir) {
        if !opts.reuse {
            bail!(
                "job dir {} already exists — pick another --id, pass --reuse to continue in it, or remove it",
                work_dir.display()
            );
        }
        if !meta.is_dir() {
            bail!("{} exists and is not a real directory", work_dir.display());
        }
        // Reject, never repair: a permissive job dir may have been planted
        // before a chmod could run.
        crate::util::check_private_dir(&work_dir, crate::util::Privacy::Enforce)?;
        let Some(token) = job_marker_token(&work_dir)? else {
            bail!(
                "job dir {} has no {} marker (created by epicenter < 0.1.0?); remove it or use a new --id",
                work_dir.display(),
                JOB_MARKER
            );
        };
        match record_covers(&work_dir, &token)? {
            RecordCoverage::Matching => {}
            // A marker-only dir is safe to adopt: there is no build state a
            // previous writer could have planted. The record is written below,
            // before restore.
            RecordCoverage::Absent => {
                if !job_dir_is_unseeded(&work_dir)? {
                    bail!(
                        "job dir {} has no exec record and contains build state; refusing --reuse — remove it or use a new --id",
                        work_dir.display()
                    );
                }
                adopted = true;
            }
            RecordCoverage::Mismatch => bail!(
                "job dir {} has an exec record for a different build (token or path mismatch); refusing --reuse — remove it or use a new --id",
                work_dir.display()
            ),
            RecordCoverage::Untrusted => bail!(
                "job dir {} has an exec record this host does not trust (symlink, foreign owner, or permissive mode); refusing --reuse",
                work_dir.display()
            ),
        }

        let Some(locks) = cargo_locks(&work_dir)? else {
            bail!(
                "job dir {} is in use by a live build — wait for it, or use another --id",
                work_dir.display()
            );
        };
        // Keep Cargo out while restoring into the reused view. The locks must
        // be released before the child starts (otherwise its own Cargo would
        // block), so this is a best-effort narrowing, not a full guarantee.
        reuse_locks = Some(locks);
        reused = true;
        token
    } else {
        create_job_dir(&work_dir)?
    };
    let target_dir = opts
        .target_dir
        .map(|raw| resolve_target_dir(raw, &work_dir, opts.cwd.as_deref()));

    eprintln!(
        "{}",
        util::heading(&format!("epicenter exec — job {job_id}"))
    );
    eprintln!(
        "  {} {}{}",
        util::dim(&format!("{:<11}", "work dir")),
        work_dir.display(),
        if reused {
            util::dim("  (reused)")
        } else {
            String::new()
        }
    );
    if adopted {
        eprintln!(
            "  {} adopting a marker-only job dir (no exec record yet)",
            util::info(GLYPH_INFO)
        );
    }

    // An empty vault is a cold build (fail-open), but a corrupt/tampered
    // vault is not: never run the command over unverified artifacts.
    // The store is one global generation, so seed only the packages this
    // project resolves to: restoring all of it puts every other project's
    // units in the job dir (214 fingerprints for a one-dependency project).
    // A missing or unreadable lock keeps the whole-generation seed.
    let source_dir = project_dir(opts);
    let packages = source_dir.as_deref().and_then(|cwd| {
        crate::lockfile::LockIndex::load(
            cwd,
            crate::lockfile::manifest_arg(opts.command).as_deref(),
        )
    });
    if packages.is_none() {
        eprintln!(
            "  {} {}",
            util::dim(&format!("{:<11}", "lock")),
            util::dim("no readable Cargo.lock; seeding without a lock filter")
        );
    }
    // The child may select another toolchain (`cargo +nightly`), and Cargo
    // 1.99-nightly+ writes the new build-dir layout. Both decide which vault
    // generation/layout can actually be reused.
    let child = child_cargo(opts.command);
    let selector = child.selector.clone();
    let cargo_version = child.version.clone();
    let layout = cargo_version
        .as_deref()
        .map(|version| fingerprint::layout_for_cargo(version, opts.command));

    // Fetch remote units before seeding. A miss, offline source, missing lock
    // or unsupported target is a local build, never a job failure.
    let mut remote_fetch: Option<crate::remote::FetchReport> = None;
    if let Some(policy) = opts.remote
        && !opts.no_remote
        && policy.enabled
    {
        let skip = if !child.builds_units {
            Some("not a cargo unit-producing command")
        } else if child.target.is_some() {
            Some("child --target is not seeded remotely in 0.1.0")
        } else if packages.is_none() {
            Some("no readable Cargo.lock")
        } else {
            None
        };
        if let Some(reason) = skip {
            eprintln!(
                "  {} {}",
                util::dim(&format!("{:<11}", "remote")),
                util::dim(reason)
            );
        } else {
            match crate::remote::source_for(policy) {
                Ok(source) => {
                    let request = crate::remote::FetchRequest {
                        remote: policy,
                        source: source.as_ref(),
                        store_root,
                        state_root: None,
                        packages: packages.as_ref(),
                        selector: selector.as_deref(),
                        layout,
                        profile: child.profile.as_deref(),
                        unit_filter: None,
                        local: None,
                        generation: None,
                        now: crate::util::now_secs(),
                        dry_run: false,
                    };
                    match crate::remote::fetch_and_import(&request) {
                        Ok(report) => {
                            print_remote(&report);
                            remote_fetch = Some(report);
                        }
                        Err(err) => eprintln!(
                            "  {} {}",
                            util::dim(&format!("{:<11}", "remote")),
                            util::dim(&format!("skipped: {err:#}"))
                        ),
                    }
                }
                Err(err) => eprintln!(
                    "  {} {}",
                    util::dim(&format!("{:<11}", "remote")),
                    util::dim(&format!("skipped: {err:#}"))
                ),
            }
        }
    }

    // Write the provenance record before restore, so a crash mid-restore still
    // leaves a recorded job and the next `--reuse` is allowed. It lives in the
    // private work root, never in the build dir the child can write.
    let canonical_build = std::fs::canonicalize(&work_dir).unwrap_or_else(|_| work_dir.clone());
    let mut record = ExecRecord {
        version: EXEC_RECORD_VERSION,
        run_id: format!("{job_id}-{job_token}"),
        token: job_token.clone(),
        build_root: canonical_build.to_string_lossy().into_owned(),
        source_root: source_dir
            .as_deref()
            .map(|dir| {
                std::fs::canonicalize(dir)
                    .unwrap_or_else(|_| dir.to_path_buf())
                    .to_string_lossy()
                    .into_owned()
            })
            .unwrap_or_default(),
        toolchain: cargo_version.clone().unwrap_or_default(),
        command: opts
            .command
            .join(" ")
            .chars()
            .take(EXEC_COMMAND_MAX_CHARS)
            .collect(),
        started: unix_now(),
        finished: 0,
        exit_code: -1,
    };
    write_record(work_root, &job_id, &record)?;

    let mut restore = vault::restore_with(
        &work_dir,
        store_root,
        None,
        packages.as_ref(),
        layout,
        child.profile.as_deref(),
        selector.as_deref(),
        false,
        opts.link,
    )?;
    if let Some(cache_store) = remote_fetch
        .as_ref()
        .and_then(|report| report.cache_store.as_deref())
    {
        let overlay = vault::restore_with(
            &work_dir,
            cache_store,
            None,
            packages.as_ref(),
            layout,
            child.profile.as_deref(),
            selector.as_deref(),
            false,
            opts.link,
        )?;
        restore.merge_secondary(overlay);
        // The cache layer is a real overlay: the main store's "empty
        // generation" note no longer describes what was seeded.
        restore.note = None;
    }
    if restore.fatal_errors > 0 {
        bail!(
            "vault restore refused {} unverified file(s) — refusing to run the command over unverified state",
            restore.fatal_errors
        );
    }
    match &restore.note {
        Some(_) if opts.harvest_back => eprintln!(
            "  {} cold start — the vault has nothing for this generation yet; --harvest will store what this job builds",
            util::info(GLYPH_INFO)
        ),
        Some(_) => eprintln!(
            "  {} cold start — the vault has nothing for this generation yet; pass --harvest to seed it from this job",
            util::info(GLYPH_INFO)
        ),
        None => eprintln!(
            "  {} {} unit(s) · {} file(s) · {}",
            util::dim(&format!("{:<11}", "vault")),
            restore.units_linked,
            restore.files_linked + restore.files_copied,
            util::green(&human_bytes(restore.bytes))
        ),
    }
    eprintln!(
        "  {} CARGO_BUILD_BUILD_DIR (this job only; no config change)",
        util::dim(&format!("{:<11}", "build-dir"))
    );
    if let Some(cargo_home) = opts.cargo_home {
        eprintln!(
            "  {} {} (global cargo_home policy)",
            util::dim(&format!("{:<11}", "cargo home")),
            cargo_home.display()
        );
    }
    if opts.no_remote {
        eprintln!(
            "  {} disabled by --no-remote",
            util::dim(&format!("{:<11}", "remote"))
        );
    }
    if let (Some(layout), Some(version)) = (layout, cargo_version.as_deref()) {
        eprintln!(
            "  {} {} · {}",
            util::dim(&format!("{:<11}", "layout")),
            layout.label(),
            util::dim(version)
        );
    }
    if let Some(target) = &target_dir {
        eprintln!(
            "  {} {}{}",
            util::dim(&format!("{:<11}", "target dir")),
            target.display(),
            util::dim("  (CARGO_TARGET_DIR — finals live and die with this job)")
        );
    }
    drop(reuse_locks);
    eprintln!("{}", util::dim("  ── command ──"));
    let _ = std::io::stderr().flush();

    let started = Instant::now();
    let mut child = crate::util::command_for(program)?;
    child.args(&opts.command[1..]);
    child.env("CARGO_BUILD_BUILD_DIR", &work_dir);
    if let Some(cargo_home) = opts.cargo_home {
        child.env("CARGO_HOME", cargo_home);
    }
    if let Some(target) = &target_dir {
        child.env("CARGO_TARGET_DIR", target);
    }
    if let Some(incremental) = opts.incremental {
        child.env("CARGO_INCREMENTAL", if incremental { "1" } else { "0" });
    }
    if let Some(dir) = &opts.cwd {
        child.current_dir(dir);
    }
    let mut child = child
        .spawn()
        .with_context(|| format!("cannot run `{program}` — is it installed and on PATH?"))?;
    let memory = ChildMemory::start(&child);
    let status = child
        .wait()
        .with_context(|| format!("cannot run `{program}` — is it installed and on PATH?"))?;
    let elapsed = started.elapsed();
    let code = exit_code(&status);
    memory.record_build(opts.command, elapsed);
    record.finished = unix_now();
    record.exit_code = code;
    // The pre-spawn record is already valid; a failed update only loses the
    // finish time, so it must not fail the job.
    if let Err(err) = write_record(work_root, &job_id, &record) {
        eprintln!(
            "  {} could not update the exec record: {err:#}",
            util::warn(util::GLYPH_WARN)
        );
    }

    let harvested = if opts.harvest_back {
        Some(vault::harvest_with(
            &work_dir,
            store_root,
            None,
            false,
            selector.as_deref(),
            layout,
            opts.compress,
        )?)
    } else {
        None
    };
    let mut removed = false;
    let mut remove_error = None;
    if opts.remove_on_success {
        match util::remove_tree(work_root, &work_dir) {
            Ok(()) => removed = true,
            Err(err) => remove_error = Some(err),
        }
    }

    eprintln!("{}", util::dim("  ── end ──"));
    let mark = if code == 0 {
        util::green(GLYPH_PASS)
    } else {
        util::fail(GLYPH_FAIL)
    };
    eprintln!("  {mark} exit {code} · {}", human_duration(elapsed));
    if let Some(report) = &harvested {
        if let Some(note) = &report.note {
            // Harvest refused wholesale (e.g. the job predates the toolchain).
            eprintln!("  {} {note}", util::warn(util::GLYPH_WARN));
        } else {
            let mut line = format!(
                "{} newly stored · {} refreshed · {} already in the vault",
                report.stored, report.refreshed, report.unchanged
            );
            let skipped = report.skipped_stale + report.skipped_incomplete;
            if skipped > 0 {
                line.push_str(&format!(" · {skipped} skipped"));
            }
            eprintln!("  {} {line}", util::dim(&format!("{:<11}", "harvest")));
        }
    }
    if removed {
        eprintln!(
            "  {} {} (--rm)",
            util::dim(&format!("{:<11}", "work dir")),
            util::dim("removed")
        );
    } else if let Some(err) = &remove_error {
        eprintln!(
            "  {} {} — could not remove it: {err}",
            util::dim(&format!("{:<11}", "work dir")),
            work_dir.display()
        );
    } else {
        eprintln!(
            "  {} {} {}",
            util::dim(&format!("{:<11}", "work dir")),
            work_dir.display(),
            util::dim("(kept — pass --rm to remove)")
        );
    }
    // The job dir is gone: drop its outside lock and clear old lock debris.
    // A kept dir keeps its lock (the next `--reuse` takes the same file).
    drop(job_lock);
    if removed {
        remove_job_lock(work_root, &job_id);
        remove_record(work_root, &job_id);
        sweep_job_locks(work_root);
    }
    Ok(code)
}

/// Samples the resident set of a child's whole process tree while it runs.
///
/// Unix gets this after the fact from `RUSAGE_CHILDREN`. Windows has no
/// equivalent: once the child is reaped its memory counters are gone, so the
/// tree has to be observed while it is alive. The child is placed in a Job
/// object; the sampler then asks that job for its own member PIDs, never the
/// machine's process list. Start it immediately after `spawn`, keep it alive
/// across `wait`, then call [`finish`](Self::finish).
pub struct ChildMemory {
    #[cfg(windows)]
    sampler: Option<win_rss::Sampler>,
}

impl ChildMemory {
    pub fn start(child: &std::process::Child) -> Self {
        #[cfg(windows)]
        {
            Self {
                sampler: win_rss::Sampler::start(child.id()),
            }
        }
        #[cfg(not(windows))]
        {
            let _ = child;
            Self {}
        }
    }

    /// Stop the sampler and return the peak RSS, if it was observable.
    pub fn finish(self) -> Result<Option<u64>> {
        #[cfg(windows)]
        {
            let rss_bytes: Result<Option<u64>> = match self.sampler {
                Some(sampler) => sampler.finish(),
                None => Ok(None),
            };
            rss_bytes
        }
        #[cfg(unix)]
        {
            Ok(unix_peak_rss())
        }
        #[cfg(not(any(unix, windows)))]
        {
            Ok(None)
        }
    }

    /// Record the last job's wall time and peak child RSS for `doctor`.
    /// `None` means the state file could not be written; a missing peak is
    /// stored as JSON `null` rather than a misleading zero.
    pub fn record_build(
        self,
        command: &[String],
        elapsed: std::time::Duration,
    ) -> Option<Result<()>> {
        let peak = match self.finish() {
            Ok(peak) => peak,
            Err(err) => {
                eprintln!(
                    "could not sample peak resident set size memory of {}: {err:#}",
                    util::dim(&format!("{:?}", command)),
                );
                None
            }
        };
        let state = crate::paths::state_dir().ok()?;
        if crate::util::create_private_dir_all(&state).is_err() {
            return None;
        }
        let path = state.join("last-build.json");
        let payload = serde_json::json!({
            "command": command.join(" "),
            "elapsed_secs": elapsed.as_secs_f64(),
            "peak_rss_bytes": peak,
            "at_unix": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0),
        });
        if let Ok(text) = serde_json::to_string(&payload) {
            let _ = crate::util::write_atomic_private(&path, text.as_bytes());
        }

        Some(Ok(()))
    }
}

#[cfg(windows)]
mod win_rss {
    use std::ffi::c_void;
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use anyhow::Context;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicProcessIdList,
        JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    };
    use windows_sys::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
        PROCESS_VM_READ,
    };

    /// Frequent enough to catch cargo's short rustc invocations, cheap enough
    /// to disappear next to a build.
    const SAMPLE_EVERY: Duration = Duration::from_millis(100);

    /// Concurrent build processes are bounded by Cargo's jobserver; 1024
    /// leaves a wide margin while keeping the query buffer on the stack.
    const MAX_JOB_PROCESSES: usize = 1024;

    /// `JOBOBJECT_BASIC_PROCESS_ID_LIST` with room for more than one PID.
    /// Win32 declares `ProcessIdList[1]`; callers pass a larger trailing
    /// array and the matching buffer size.
    #[repr(C)]
    struct ProcessIdList {
        _assigned: u32,
        listed: u32,
        ids: [usize; MAX_JOB_PROCESSES],
    }

    /// Owns the job handle. Closing it does not terminate members because no
    /// kill-on-close limit is set.
    struct Job(HANDLE);

    // A kernel handle is process-wide and safe to use from another thread.
    unsafe impl Send for Job {}

    impl Job {
        fn create(process_id: u32) -> Option<Self> {
            let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if handle.is_null() {
                return None;
            }
            let job = Self(handle);
            // Explicit breakaway stays allowed: epicenter observes the build,
            // it does not sandbox it. A tool that asks to leave is simply not
            // counted, rather than failing to launch.
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_BREAKAWAY_OK;
            let configured = unsafe {
                SetInformationJobObject(
                    job.0,
                    JobObjectExtendedLimitInformation,
                    std::ptr::from_ref(&limits).cast::<c_void>(),
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            } != 0;
            if !configured {
                return None;
            }
            let process =
                unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, process_id) };
            if process.is_null() {
                return None;
            }
            let assigned = unsafe { AssignProcessToJobObject(job.0, process) } != 0;
            unsafe { CloseHandle(process) };
            assigned.then_some(job)
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    pub struct Sampler {
        stop: Option<mpsc::Sender<()>>,
        /// `None` after `finish`; the inner result preserves a spawn failure.
        worker: Option<anyhow::Result<JoinHandle<u64>>>,
    }

    impl Sampler {
        pub fn start(root_pid: u32) -> Option<Self> {
            let job = Job::create(root_pid)?;
            let (stop, stopped) = mpsc::channel();
            let worker = thread::Builder::new()
                .name("epicenter-rss".into())
                .spawn(move || sample_loop(job, &stopped))
                .map_err(|e| anyhow::format_err!(e));
            Some(Self {
                stop: Some(stop),
                worker: Some(worker),
            })
        }

        pub fn finish(mut self) -> anyhow::Result<Option<u64>> {
            self.stop.take();
            let worker = self
                .worker
                .take()
                .context("RSS sampler worker was already taken")??;
            let peak = worker
                .join()
                .map_err(|_| anyhow::anyhow!("RSS sampler worker panicked"))?;
            Ok((peak > 0).then_some(peak))
        }
    }

    impl Drop for Sampler {
        fn drop(&mut self) {
            self.stop.take();
            if let Some(worker) = self.worker.take() {
                if let Ok(worker) = worker {
                    let _ = worker.join();
                }
            }
        }
    }

    fn sample_loop(job: Job, stop: &mpsc::Receiver<()>) -> u64 {
        let mut peak = 0u64;
        loop {
            peak = peak.max(job_rss(job.0));
            match stop.recv_timeout(SAMPLE_EVERY) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => return peak,
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }

    /// Fill `list` with the job's current members and return how many IDs
    /// were written.
    fn job_pids(job: HANDLE, list: &mut ProcessIdList) -> Option<usize> {
        let mut returned = 0u32;
        let ok = unsafe {
            QueryInformationJobObject(
                job,
                JobObjectBasicProcessIdList,
                std::ptr::from_mut(list).cast::<c_void>(),
                std::mem::size_of::<ProcessIdList>() as u32,
                &mut returned,
            )
        };
        (ok != 0).then(|| (list.listed as usize).min(MAX_JOB_PROCESSES))
    }

    /// Sum the working sets of the job's current members. The job contains
    /// only epicenter's child and its descendants — no machine-wide scan.
    fn job_rss(job: HANDLE) -> u64 {
        let mut list: ProcessIdList = unsafe { std::mem::zeroed() };
        let Some(count) = job_pids(job, &mut list) else {
            return 0;
        };
        list.ids[..count]
            .iter()
            .filter_map(|&pid| working_set(pid as u32))
            .sum()
    }

    fn working_set(pid: u32) -> Option<u64> {
        let handle =
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid) };
        if handle.is_null() {
            return None;
        }
        let mut counters: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
        counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        let ok = unsafe { K32GetProcessMemoryInfo(handle, &mut counters, counters.cb) } != 0;
        unsafe { CloseHandle(handle) };
        ok.then_some(counters.WorkingSetSize as u64)
    }

    #[cfg(test)]
    mod tests;
}

/// Peak RSS of all waited-for children: `RUSAGE_CHILDREN` includes waited-for
/// descendants, so it covers Cargo and every `rustc`/linker it ran.
///
/// `ru_maxrss` is bytes on macOS and KiB on the other Unixes.
#[cfg(unix)]
fn unix_peak_rss() -> Option<u64> {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage) } != 0 {
        return None;
    }
    Some(if cfg!(target_os = "macos") {
        usage.ru_maxrss as u64
    } else {
        usage.ru_maxrss as u64 * 1024
    })
}

/// Signals use the shell convention: 128 + signal number.
fn exit_code(status: &ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

fn default_job_id() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    format!("job-{}-{}", stamp_from_unix(secs), std::process::id())
}

/// `YYYYMMDD-HHMMSS` in UTC — sortable, readable, filesystem-safe.
fn stamp_from_unix(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    format!(
        "{year:04}{month:02}{day:02}-{:02}{:02}{:02}",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    )
}

/// Days since the Unix epoch to a civil date — the standard shift-and-correct
/// integer algorithm, no lookup tables.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = yoe as i64 + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

/// Job ids become directory names: plain characters only.
fn sanitize_job_id(id: &str) -> Result<String> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        bail!("--id must not be empty");
    }
    if trimmed == "." || trimmed == ".." || trimmed.starts_with('.') {
        bail!("--id {id:?} is not a usable directory name");
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("--id {id:?}: use letters, digits, `-`, `_` or `.`");
    }
    if trimmed.ends_with(['.', ' ']) {
        bail!("--id {id:?} must not end with '.' or ' ' (Windows strips it)");
    }
    if crate::util::is_windows_reserved(trimmed) {
        bail!("--id {id:?} is a reserved Windows device name");
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests;
