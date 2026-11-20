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

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use std::{fs, io};

use anyhow::{Context, Result, bail};

use crate::fingerprint;
use crate::settings::LinkPolicy;
use crate::util::{
    self, GLYPH_FAIL, GLYPH_INFO, GLYPH_PASS, human_bytes, human_duration, metadata_nofollow,
};
use crate::vault;

static WORK_ROOT_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

/// Marker written into a newly created job dir. `--reuse` refuses a
/// pre-existing directory without it, so a shared work root cannot be seeded
/// with a bare directory. The token is not a secret; `O_EXCL` creation is the
/// primary guard.
pub const JOB_MARKER: &str = ".epicenter-job";
const JOB_MARKER_VERSION: &str = "epicenter-job-v1";

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

fn job_marker_path(work_dir: &Path) -> PathBuf {
    work_dir.join(JOB_MARKER)
}

fn write_job_marker(work_dir: &Path) -> Result<String> {
    let mut token = [0u8; 16];
    getrandom::fill(&mut token).map_err(|err| anyhow::anyhow!("generating job token: {err}"))?;
    let token_hex: String = token.iter().map(|byte| format!("{byte:02x}")).collect();
    let body = format!("{JOB_MARKER_VERSION}\n{token_hex}\n");
    crate::util::write_atomic_private(&job_marker_path(work_dir), body.as_bytes())
        .with_context(|| format!("writing job marker in {}", work_dir.display()))?;
    Ok(token_hex)
}

/// The job token, when `work_dir` carries a well-formed marker.
pub(crate) fn job_marker_token(work_dir: &Path) -> Result<Option<String>> {
    let text = match crate::util::read_trusted_config(&job_marker_path(work_dir), 1024) {
        Ok(text) => text,
        Err(err)
            if err.kind() == std::io::ErrorKind::NotFound
                || err.kind() == std::io::ErrorKind::InvalidInput =>
        {
            return Ok(None);
        }
        Err(err) => {
            return Err(err)
                .with_context(|| format!("reading job marker in {}", work_dir.display()));
        }
    };
    let mut lines = text.lines();
    if lines.next() != Some(JOB_MARKER_VERSION) {
        return Ok(None);
    }
    let Some(token) = lines.next() else {
        return Ok(None);
    };
    Ok(
        (token.len() == 32 && token.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| token.to_string()),
    )
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

/// A reparse/symlink root cannot be inspected safely, so lock scans treat it as
/// "in use" (fail closed) instead of returning an empty lock set.
fn root_is_reparse(dir: &Path) -> bool {
    matches!(
        metadata_nofollow(dir),
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput
    )
}

/// Does a live build hold this build dir? Cargo takes an exclusive advisory
/// lock on `<build-dir>/<profile>/.cargo-build-lock` for the duration of a
/// build; the lock file itself survives idle builds, so only lock contention
/// means "in use". Shared by `exec` (reuse refusal) and `evict` (view guards).
///
/// `cargo_locks` returns the held descriptors so a caller that is about to
/// delete/enter a view can keep Cargo out for the whole operation. A check
/// that drops the locks immediately is only advisory and races a build that
/// starts one instruction later.
pub(crate) fn cargo_locks(dir: &Path) -> Result<Option<Vec<fs::File>>> {
    // Cargo puts the lock at `<build>/<profile>/.cargo-build-lock` or, with
    // `--target`, at `<build>/<triple>/<profile>/.cargo-build-lock`. Walk a
    // bounded depth and take every lock, not just direct children.
    //
    // Keep symlinked files visible so a planted `.cargo-build-lock` is rejected
    // by `open_lock_file` (fail closed), but prune reparse directories so the
    // scan cannot write a sentinel outside `dir` through a junction. A reparse
    // root is treated as un-inspectable and fails closed.
    //
    // A profile directory without a lock file gets a sentinel: otherwise a
    // build that starts after this check is not fenced at all. Creating the
    // sentinel is safe because Cargo uses the same path and only contends on
    // the advisory lock.
    //
    // Windows refuses to rename a directory while any file inside it is open
    // (even with FILE_SHARE_DELETE), so a caller that renames/removes `dir`
    // must drop these handles first.
    if root_is_reparse(dir) {
        return Ok(None);
    }
    let mut lock_paths = std::collections::BTreeSet::new();
    let entries = util::SafeWalk::new(dir)
        .depth(3)
        .keep_links()
        .walk()
        .collect::<Result<Vec<_>, _>>()?;
    for entry in entries {
        if entry.file_name().to_string_lossy() == ".cargo-build-lock" {
            lock_paths.insert(entry.path().to_path_buf());
            continue;
        }
        if entry.depth() <= 2
            && metadata_nofollow(entry.path()).is_ok_and(|meta| meta.is_dir())
            && is_cargo_profile_dir(entry.path())
        {
            lock_paths.insert(entry.path().join(".cargo-build-lock"));
        }
    }
    if is_cargo_profile_dir(dir) {
        lock_paths.insert(dir.join(".cargo-build-lock"));
    }

    let mut locks = Vec::with_capacity(lock_paths.len());
    for path in lock_paths {
        // `open_lock_file` is no-follow, creates a missing sentinel with
        // O_EXCL, and rejects a symlink/reparse target. Any failure fails
        // closed: the caller treats it as "a build may be running".
        let Ok(file) = util::open_lock_file(&path) else {
            return Ok(None);
        };
        if !try_lock_now(&file) {
            return Ok(None);
        }
        locks.push(file);
    }
    Ok(Some(locks))
}

/// Does `dir` look like a Cargo profile directory? A profile is the only
/// place Cargo puts `.cargo-build-lock`; `deps`/`.fingerprint`/`build`/
/// `incremental` identify one before the first build creates the lock.
fn is_cargo_profile_dir(dir: &Path) -> bool {
    [
        ".cargo-build-lock",
        "deps",
        ".fingerprint",
        "build",
        "incremental",
    ]
    .iter()
    .any(|name| dir.join(name).symlink_metadata().is_ok())
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

/// `try_lock` can be interrupted by a signal from an unrelated child process;
/// retry that case, but treat every other error (including contention) as
/// "in use". A lock released by a closed descriptor can take a moment to
/// become visible again on network filesystems, so a contention result is
/// retried briefly before the caller fails closed.
fn try_lock_now(file: &fs::File) -> bool {
    for attempt in 0..4 {
        loop {
            match file.try_lock() {
                Ok(()) => return true,
                Err(std::fs::TryLockError::Error(err))
                    if err.kind() == std::io::ErrorKind::Interrupted =>
                {
                    continue;
                }
                Err(_) => break,
            }
        }
        if attempt < 3 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    false
}

fn existing_cargo_locks(dir: &Path) -> Result<Option<Vec<fs::File>>> {
    // Keep symlinked files visible (a planted lock must be rejected) and treat
    // a reparse root as un-inspectable (fail closed).
    if root_is_reparse(dir) {
        return Ok(None);
    }
    let entries = util::SafeWalk::new(dir)
        .depth(3)
        .keep_links()
        .walk()
        .collect::<Result<Vec<_>, _>>()?;
    let mut locks = Vec::new();
    for entry in entries {
        if entry.file_name().to_string_lossy() != ".cargo-build-lock" {
            continue;
        }
        // A symlink/non-regular lock is treated as held (fail closed).
        if !entry.file_type().is_file() {
            return Ok(None);
        }
        let Ok(file) = util::open_lock_file(entry.path()) else {
            return Ok(None);
        };
        if !try_lock_now(&file) {
            return Ok(None);
        }
        locks.push(file);
    }
    Ok(Some(locks))
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

/// Provenance record for one job dir, written outside the build root.
///
/// A build dir is untrusted input: anything that can write it can also write a
/// complete Cargo fingerprint, and shape checks cannot tell the difference.
/// This record lives in the private work root instead, next to the job lock, so
/// `harvest` can tell a build this host ran (`epicenter exec`) from a directory
/// someone else handed it. It proves *who ran the build*, not that the build is
/// safe: a build script inside a recorded run can still write files.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ExecRecord {
    pub version: u32,
    pub run_id: String,
    /// The `.epicenter-job` token of the job dir this run wrote.
    pub token: String,
    /// Canonical job dir.
    pub build_root: String,
    /// Canonical directory the command ran in.
    pub source_root: String,
    pub toolchain: String,
    pub command: String,
    pub started: u64,
    pub finished: u64,
    pub exit_code: i32,
}

const EXEC_RECORD_VERSION: u32 = 1;
const EXEC_RECORD_MAX_BYTES: u64 = 8 * 1024;
const EXEC_COMMAND_MAX_CHARS: usize = 1024;

fn record_path(work_root: &Path, job_id: &str) -> PathBuf {
    work_root.join(format!(".exec-{job_id}.json"))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn write_record(work_root: &Path, job_id: &str, record: &ExecRecord) -> Result<()> {
    let body = serde_json::to_vec(record).context("serializing the exec record")?;
    crate::util::write_atomic_private(&record_path(work_root, job_id), &body)
        .with_context(|| format!("writing the exec record for job {job_id}"))
}

/// What a record file on disk is, before the job/token comparison.
enum RecordFile {
    /// No record at all: a new job, or a dir from an epicenter that did not
    /// write records yet.
    Absent,
    /// The path exists but is not a trusted regular file: a symlink/reparse
    /// point, a foreign owner, a permissive mode, an oversized file, or JSON
    /// that does not parse. Never adopt or overwrite it.
    Untrusted,
    Present(ExecRecord),
}

/// What `record_covers` found for one job dir.
pub(crate) enum RecordCoverage {
    /// A trusted record for this exact job dir and marker token.
    Matching,
    /// No record file.
    Absent,
    /// A record exists, but for a different token, version, or build path.
    Mismatch,
    /// A record path exists but is not something this host wrote.
    Untrusted,
}

/// Does this error mean "the record path exists but is not ours"?
///
/// `read_trusted_config` reports a non-regular/oversized file or a reparse
/// point as `InvalidInput`, a foreign owner or permissive mode as
/// `PermissionDenied`, and `O_NOFOLLOW` reports a symlink as `ELOOP`.
fn is_untrusted_record_error(err: &io::Error) -> bool {
    if matches!(
        err.kind(),
        io::ErrorKind::InvalidInput | io::ErrorKind::PermissionDenied
    ) {
        return true;
    }
    #[cfg(unix)]
    if err.raw_os_error() == Some(libc::ELOOP) {
        return true;
    }
    false
}

fn load_record(work_root: &Path, job_id: &str) -> Result<RecordFile> {
    let path = record_path(work_root, job_id);
    let text = match crate::util::read_trusted_config(&path, EXEC_RECORD_MAX_BYTES) {
        Ok(text) => text,
        // No record: a new job, or a migration from epicenter < 0.1.0.
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(RecordFile::Absent),
        // The path exists but is a symlink/reparse point, not a regular file,
        // owned by another user, group/world-writable, or oversized. It is not
        // ours, so it is neither adopted nor overwritten.
        Err(err) if is_untrusted_record_error(&err) => {
            return Ok(RecordFile::Untrusted);
        }
        Err(err) => {
            return Err(err).with_context(|| format!("reading the exec record {}", path.display()));
        }
    };
    match serde_json::from_str(&text) {
        Ok(record) => Ok(RecordFile::Present(record)),
        Err(_) => Ok(RecordFile::Untrusted),
    }
}

/// The record covering `build_root`, if this host wrote it for the job whose
/// marker token is `token`.
pub(crate) fn record_covers(build_root: &Path, token: &str) -> Result<RecordCoverage> {
    let (Some(work_root), Some(job_id)) = (
        build_root.parent(),
        build_root.file_name().and_then(|name| name.to_str()),
    ) else {
        bail!(
            "cannot derive a job id from {} — refusing to read its exec record",
            build_root.display()
        );
    };
    let record = match load_record(work_root, job_id)? {
        RecordFile::Absent => return Ok(RecordCoverage::Absent),
        RecordFile::Untrusted => return Ok(RecordCoverage::Untrusted),
        RecordFile::Present(record) => record,
    };
    if record.version != EXEC_RECORD_VERSION || record.token != token {
        return Ok(RecordCoverage::Mismatch);
    }
    let canonical = std::fs::canonicalize(build_root).unwrap_or_else(|_| build_root.to_path_buf());
    if record.build_root != canonical.to_string_lossy() {
        return Ok(RecordCoverage::Mismatch);
    }
    Ok(RecordCoverage::Matching)
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

#[cfg(test)]
pub(crate) fn record_for_test(build_root: &Path) -> Result<()> {
    let token = job_marker_token(build_root)?.context("job marker")?;
    let work_root = build_root.parent().context("work root")?;
    let job_id = build_root
        .file_name()
        .and_then(|name| name.to_str())
        .context("job id")?;
    let canonical = std::fs::canonicalize(build_root).unwrap_or_else(|_| build_root.to_path_buf());
    let record = ExecRecord {
        version: EXEC_RECORD_VERSION,
        run_id: "test".into(),
        token,
        build_root: canonical.to_string_lossy().into_owned(),
        source_root: String::new(),
        toolchain: String::new(),
        command: "test".into(),
        started: 0,
        finished: 0,
        exit_code: 0,
    };
    write_record(work_root, job_id, &record)
}

fn remove_record(work_root: &Path, job_id: &str) {
    let path = record_path(work_root, job_id);
    if crate::util::metadata_nofollow(&path).is_ok_and(|meta| meta.is_file()) {
        let _ = std::fs::remove_file(&path);
    }
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
    mod tests {
        use super::*;

        #[test]
        fn job_lists_the_child_and_its_descendants() -> std::io::Result<()> {
            let mut child = std::process::Command::new("cmd")
                .args(["/C", "ping -n 2 127.0.0.1 >NUL"])
                .spawn()?;
            let job = Job::create(child.id()).expect("assigning the child to a job");
            let mut count = 0;
            for _ in 0..10 {
                let mut list: ProcessIdList = unsafe { std::mem::zeroed() };
                count = job_pids(job.0, &mut list).unwrap_or(0);
                if count >= 2 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let status = child.wait()?;
            assert!(status.success());
            assert!(count >= 2, "job members: {count}");
            Ok(())
        }
    }
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
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn utc_stamp_is_correct_and_sortable() {
        assert_eq!(stamp_from_unix(0), "19700101-000000");
        assert_eq!(stamp_from_unix(86_399), "19700101-235959");
        assert_eq!(stamp_from_unix(86_400), "19700102-000000");
        assert_eq!(stamp_from_unix(1_800_000_000), "20270115-080000");
    }

    #[test]
    fn job_ids_are_path_safe() {
        assert_eq!(sanitize_job_id(" ci-1234_ok ").unwrap(), "ci-1234_ok");
        assert!(sanitize_job_id("").is_err());
        assert!(sanitize_job_id("..").is_err());
        assert!(sanitize_job_id("../x").is_err());
        assert!(sanitize_job_id("a/b").is_err());
        assert!(sanitize_job_id(".hidden").is_err());
        assert!(sanitize_job_id("has space").is_err());
        assert!(sanitize_job_id("CON").is_err());
        assert!(sanitize_job_id("com1").is_err());
        assert!(sanitize_job_id("trailing.").is_err());
        assert!(sanitize_job_id("CON.txt").is_err());
        assert!(sanitize_job_id("NUL.log").is_err());
        assert!(sanitize_job_id("COM1.txt").is_err());
    }

    /// One synthetic unit in a build dir, harvested into a temp vault.
    fn seeded_store() -> Result<(tempfile::TempDir, tempfile::TempDir)> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        let unit = build.path().join("debug/.fingerprint/x-1122334455667788");
        fs::create_dir_all(&unit)?;
        fs::write(unit.join("lib-x"), "aaaabbbbccccdddd")?;
        fs::write(
            unit.join("lib-x.json"),
            r#"{"rustc":1,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[]}"#,
        )?;
        fs::write(unit.join("dep-lib-x"), [0u8; 4])?;
        fs::create_dir_all(build.path().join("debug/deps"))?;
        fs::write(
            build.path().join("debug/deps/libx-1122334455667788.rlib"),
            [1u8; 8],
        )?;
        vault::harvest(build.path(), store.path(), None, false)?;
        Ok((build, store))
    }

    fn synthetic_unit(
        root: &Path,
        profile: &str,
        package: &str,
        hash: &str,
        byte: u8,
    ) -> Result<()> {
        let unit = root
            .join(profile)
            .join(".fingerprint")
            .join(format!("{package}-{hash}"));
        fs::create_dir_all(&unit)?;
        fs::write(unit.join(format!("lib-{package}")), "5d82713a7f2d05e2")?;
        fs::write(
            unit.join(format!("lib-{package}.json")),
            r#"{"rustc":1,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[]}"#,
        )?;
        fs::write(unit.join(format!("dep-lib-{package}")), [0u8; 8])?;
        fs::create_dir_all(root.join(profile).join("deps"))?;
        fs::write(
            root.join(profile)
                .join("deps")
                .join(format!("lib{package}-{hash}.rlib")),
            [byte; 32],
        )?;
        Ok(())
    }

    fn seeded_profiles_store() -> Result<(tempfile::TempDir, tempfile::TempDir)> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        synthetic_unit(build.path(), "debug", "debugdep", "1111111111111111", 1)?;
        synthetic_unit(build.path(), "release", "releasedep", "2222222222222222", 2)?;
        vault::harvest(build.path(), store.path(), None, false)?;
        Ok((build, store))
    }

    #[cfg(unix)]
    #[test]
    fn exec_seeds_the_job_and_propagates_the_exit_code() -> Result<()> {
        let (_build, store) = seeded_store()?;
        let work = tempfile::tempdir()?;
        // The synthetic store unit is for package `x`: name it in a lock so
        // this test does not depend on whatever Cargo.lock exists above /tmp.
        let project = tempfile::tempdir()?;
        fs::write(
            project.path().join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"x\"\nversion = \"1.0.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"abababababababababababababababababababababababababababababababab\"\n",
        )?;
        let job_dir = work.path().join("jobtest");
        let command = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "test \"$CARGO_BUILD_BUILD_DIR\" = '{}' && exit 7",
                job_dir.display()
            ),
        ];
        let opts = Options {
            job_id: Some("jobtest"),
            cwd: Some(project.path().to_path_buf()),
            harvest_back: false,
            compress: true,
            remove_on_success: false,
            reuse: false,
            target_dir: None,
            incremental: None,
            link: LinkPolicy::Auto,
            cargo_home: None,
            no_remote: false,
            remote: None,
            command: &command,
        };
        let code = run(store.path(), work.path(), &opts)?;
        assert_eq!(code, 7, "the command's exit code is the job's exit code");
        assert!(
            job_dir
                .join("debug/.fingerprint/x-1122334455667788/lib-x")
                .is_file(),
            "the vault seeded the job"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn exec_sets_the_configured_cargo_home_in_the_child() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let (_build, store) = seeded_store()?;
        let work = tempfile::tempdir()?;
        let cargo = tempfile::tempdir()?;
        fs::set_permissions(cargo.path(), fs::Permissions::from_mode(0o700))?;
        let command = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("test \"$CARGO_HOME\" = '{}'", cargo.path().display()),
        ];
        let opts = Options {
            job_id: Some("cargo-home"),
            cwd: None,
            harvest_back: false,
            compress: true,
            remove_on_success: false,
            reuse: false,
            target_dir: None,
            incremental: None,
            link: LinkPolicy::Auto,
            cargo_home: Some(cargo.path()),
            no_remote: false,
            remote: None,
            command: &command,
        };
        assert_eq!(run(store.path(), work.path(), &opts)?, 0);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn exec_seeds_only_the_child_profile() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let (_build, store) = seeded_profiles_store()?;
        let work = tempfile::tempdir()?;
        let project = tempfile::tempdir()?;
        let checksum_a = "ab".repeat(32);
        let checksum_b = "cd".repeat(32);
        fs::write(
            project.path().join("Cargo.lock"),
            format!(
                "version = 4\n\n[[package]]\nname = \"debugdep\"\nversion = \"1.0.0\"\n\
                 source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                 checksum = \"{checksum_a}\"\n\n\
                 [[package]]\nname = \"releasedep\"\nversion = \"1.0.0\"\n\
                 source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                 checksum = \"{checksum_b}\"\n"
            ),
        )?;
        let bin = tempfile::tempdir()?;
        let cargo = bin.path().join("cargo");
        fs::write(
            &cargo,
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo 'cargo 1.99.1 (000000000 2026-01-01)'\n  exit 0\nfi\nexit 0\n",
        )?;
        fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755))?;
        let cargo = cargo.to_string_lossy().into_owned();

        let bench = vec![cargo.clone(), "bench".to_string()];
        let mut opts = Options {
            job_id: Some("bench"),
            cwd: Some(project.path().to_path_buf()),
            harvest_back: false,
            compress: true,
            remove_on_success: false,
            reuse: false,
            target_dir: None,
            incremental: None,
            link: LinkPolicy::Auto,
            cargo_home: None,
            no_remote: false,
            remote: None,
            command: &bench,
        };
        assert_eq!(run(store.path(), work.path(), &opts)?, 0);
        assert!(
            work.path()
                .join("bench/release/.fingerprint/releasedep-2222222222222222/lib-releasedep")
                .is_file(),
            "cargo bench seeds release units"
        );
        assert!(
            !work
                .path()
                .join("bench/debug/.fingerprint/debugdep-1111111111111111")
                .exists(),
            "cargo bench does not seed debug units"
        );

        let build = vec![cargo, "build".to_string()];
        opts.job_id = Some("devjob");
        opts.command = &build;
        assert_eq!(run(store.path(), work.path(), &opts)?, 0);
        assert!(
            work.path()
                .join("devjob/debug/.fingerprint/debugdep-1111111111111111/lib-debugdep")
                .is_file(),
            "cargo build seeds debug units"
        );
        assert!(
            !work
                .path()
                .join("devjob/release/.fingerprint/releasedep-2222222222222222")
                .exists(),
            "cargo build does not seed release units"
        );
        Ok(())
    }

    #[test]
    fn exec_seeds_only_the_packages_in_the_project_lock() -> Result<()> {
        let (_build, store) = seeded_store()?;
        let work = tempfile::tempdir()?;
        let project = tempfile::tempdir()?;
        let command: Vec<String> = vec!["true".into()];
        let lock = project.path().join("Cargo.lock");

        // The project's lock does not name the stored unit: do not seed it.
        fs::write(
            &lock,
            "version = 4\n\n[[package]]\nname = \"unrelated\"\nversion = \"1.0.0\"\n",
        )?;
        let opts = Options {
            job_id: Some("filtered"),
            cwd: Some(project.path().to_path_buf()),
            harvest_back: false,
            compress: true,
            remove_on_success: false,
            reuse: false,
            target_dir: None,
            incremental: None,
            link: LinkPolicy::Auto,
            cargo_home: None,
            no_remote: false,
            remote: None,
            command: &command,
        };
        assert_eq!(run(store.path(), work.path(), &opts)?, 0);
        assert!(
            !work
                .path()
                .join("filtered/debug/.fingerprint/x-1122334455667788")
                .exists(),
            "a unit outside the lock is not seeded"
        );

        // Naming the package in the lock seeds exactly that unit.
        fs::write(
            &lock,
            "version = 4\n\n[[package]]\nname = \"x\"\nversion = \"1.0.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"abababababababababababababababababababababababababababababababab\"\n",
        )?;
        let opts = Options {
            job_id: Some("seeded"),
            ..opts
        };
        assert_eq!(run(store.path(), work.path(), &opts)?, 0);
        assert!(
            work.path()
                .join("seeded/debug/.fingerprint/x-1122334455667788/lib-x")
                .is_file(),
            "a unit inside the lock is seeded"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn exec_rm_removes_the_job_dir_either_way() -> Result<()> {
        let (_build, store) = seeded_store()?;
        let work = tempfile::tempdir()?;
        // Old lock debris from a job dir that no longer exists (or a crash).
        fs::write(work.path().join(".lock-orphan"), b"")?;

        let ok: Vec<String> = vec!["true".into()];
        let opts = Options {
            job_id: Some("j-ok"),
            cwd: None,
            harvest_back: false,
            compress: true,
            remove_on_success: true,
            reuse: false,
            target_dir: None,
            incremental: None,
            link: LinkPolicy::Auto,
            cargo_home: None,
            no_remote: false,
            remote: None,
            command: &ok,
        };
        assert_eq!(run(store.path(), work.path(), &opts)?, 0);
        assert!(!work.path().join("j-ok").exists(), "success -> removed");
        assert!(
            !work.path().join(".lock-j-ok").exists(),
            "success -> its job lock removed"
        );
        assert!(
            !work.path().join(".lock-orphan").exists(),
            "orphan lock debris swept"
        );

        // `--rm` is explicit: a failing build is removed too (the fixed
        // rmeta-era failure mode used to leave dirs piling up here).
        let bad: Vec<String> = vec!["false".into()];
        let opts = Options {
            job_id: Some("j-bad"),
            cwd: None,
            harvest_back: false,
            compress: true,
            remove_on_success: true,
            reuse: false,
            target_dir: None,
            incremental: None,
            link: LinkPolicy::Auto,
            cargo_home: None,
            no_remote: false,
            remote: None,
            command: &bad,
        };
        assert_eq!(run(store.path(), work.path(), &opts)?, 1);
        assert!(
            !work.path().join("j-bad").exists(),
            "--rm -> removed on failure too"
        );
        assert!(
            !work.path().join(".lock-j-bad").exists(),
            "--rm -> its job lock removed on failure too"
        );

        // Without --rm the dir stays for inspection.
        let kept: Vec<String> = vec!["true".into()];
        let opts = Options {
            job_id: Some("j-keep"),
            cwd: None,
            harvest_back: false,
            compress: true,
            remove_on_success: false,
            reuse: false,
            target_dir: None,
            incremental: None,
            link: LinkPolicy::Auto,
            cargo_home: None,
            no_remote: false,
            remote: None,
            command: &kept,
        };
        assert_eq!(run(store.path(), work.path(), &opts)?, 0);
        assert!(
            work.path().join("j-keep").exists(),
            "no --rm -> kept for inspection"
        );
        assert!(
            work.path().join(".lock-j-keep").exists(),
            "a kept job keeps its lock for the next --reuse"
        );
        Ok(())
    }

    #[test]
    fn work_tier_summarizes_job_dirs() -> Result<()> {
        let home = tempfile::tempdir()?;
        let build = home.path().join("build");
        fs::create_dir_all(&build)?;
        let debug = home.path().join("work/ci-1/debug");
        fs::create_dir_all(&debug)?;
        fs::write(debug.join("a.bin"), [0u8; 100])?;
        fs::write(debug.join("b.bin"), [0u8; 50])?;

        let tier = work_tier(&build)?;
        assert_eq!(tier.dirs, 1);
        assert_eq!(tier.files, 2);
        assert_eq!(tier.bytes, 150);
        assert!(tier.newest.is_some());
        assert_eq!(tier.entries.len(), 1);
        assert_eq!(tier.entries[0].name, "ci-1");
        assert_eq!(tier.entries[0].bytes, 150);
        assert_eq!(tier.entries[0].files, 2);
        Ok(())
    }

    #[test]
    fn exec_refuses_a_used_job_dir() -> Result<()> {
        let (_build, store) = seeded_store()?;
        let work = tempfile::tempdir()?;
        fs::create_dir_all(work.path().join("taken"))?;
        let command: Vec<String> = vec!["true".into()];
        let opts = Options {
            job_id: Some("taken"),
            cwd: None,
            harvest_back: false,
            compress: true,
            remove_on_success: false,
            reuse: false,
            target_dir: None,
            incremental: None,
            link: LinkPolicy::Auto,
            cargo_home: None,
            no_remote: false,
            remote: None,
            command: &command,
        };
        let err = run(store.path(), work.path(), &opts).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
        assert!(err.to_string().contains("--reuse"), "mentions the way out");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn target_dir_resolution() {
        let work = Path::new("/cache/work/ci-1");
        let cwd = Path::new("/project");
        assert_eq!(
            resolve_target_dir("job", work, Some(cwd)),
            PathBuf::from("/cache/work/ci-1/target")
        );
        assert_eq!(
            resolve_target_dir("/abs/finals", work, Some(cwd)),
            PathBuf::from("/abs/finals")
        );
        assert_eq!(
            resolve_target_dir("rel/finals", work, Some(cwd)),
            PathBuf::from("/project/rel/finals")
        );
    }

    #[cfg(unix)]
    #[test]
    fn exec_reuse_continues_in_an_existing_dir() -> Result<()> {
        let (_build, store) = seeded_store()?;
        let work = tempfile::tempdir()?;
        let ok: Vec<String> = vec!["true".into()];
        let fresh = Options {
            job_id: Some("j1"),
            cwd: None,
            harvest_back: false,
            compress: true,
            remove_on_success: false,
            reuse: false,
            target_dir: None,
            incremental: None,
            link: LinkPolicy::Auto,
            cargo_home: None,
            no_remote: false,
            remote: None,
            command: &ok,
        };
        assert_eq!(run(store.path(), work.path(), &fresh)?, 0);

        let err = run(store.path(), work.path(), &fresh).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");

        let again = Options {
            reuse: true,
            ..fresh
        };
        assert_eq!(run(store.path(), work.path(), &again)?, 0);
        Ok(())
    }

    #[test]
    fn exec_reuse_refuses_a_locked_dir() -> Result<()> {
        let (_build, store) = seeded_store()?;
        let work = tempfile::tempdir()?;
        let dir = work.path().join("busy");
        crate::util::create_private_dir_all(&dir)?;
        let debug = dir.join("debug");
        crate::util::create_private_dir_all(&debug)?;
        write_job_marker(&dir)?;
        record_for_test(&dir)?;
        let lock = debug.join(".cargo-build-lock");
        fs::write(&lock, b"")?;
        let held = fs::OpenOptions::new().write(true).open(&lock)?;
        held.try_lock().context("test holds the lock")?;

        let cmd: Vec<String> = vec!["true".into()];
        let opts = Options {
            job_id: Some("busy"),
            cwd: None,
            harvest_back: false,
            compress: true,
            remove_on_success: false,
            reuse: true,
            target_dir: None,
            incremental: None,
            link: LinkPolicy::Auto,
            cargo_home: None,
            no_remote: false,
            remote: None,
            command: &cmd,
        };
        let err = run(store.path(), work.path(), &opts).unwrap_err();
        assert!(err.to_string().contains("in use"), "{err}");
        Ok(())
    }

    #[test]
    fn nested_target_lock_is_detected() -> Result<()> {
        let home = tempfile::tempdir()?;
        let job = home.path().join("job/debug");
        fs::create_dir_all(&job)?;
        let lock = job.join(".cargo-build-lock");
        fs::write(&lock, b"")?;
        let held = fs::OpenOptions::new().write(true).open(&lock)?;
        held.try_lock().context("test holds the lock")?;
        assert!(dir_locked(&home.path().join("job")), "direct profile lock");

        let nested = home.path().join("cross/x86_64-unknown-linux-gnu/debug");
        fs::create_dir_all(&nested)?;
        let lock = nested.join(".cargo-build-lock");
        fs::write(&lock, b"")?;
        let held = fs::OpenOptions::new().write(true).open(&lock)?;
        held.try_lock().context("test holds the nested lock")?;
        assert!(
            dir_locked(&home.path().join("cross")),
            "target-triple lock must be found"
        );
        Ok(())
    }

    #[test]
    fn cargo_locks_creates_a_sentinel_for_an_existing_profile() -> Result<()> {
        let home = tempfile::tempdir()?;
        let job = home.path().join("job");
        let profile = job.join("debug");
        fs::create_dir_all(profile.join("deps"))?;

        let locks = cargo_locks(&job)?.expect("sentinel acquired");
        let lock_path = profile.join(".cargo-build-lock");
        assert!(lock_path.is_file(), "the sentinel is created");
        let second = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)?;
        assert!(
            second.try_lock().is_err(),
            "a second opener must contend with the held sentinel"
        );
        drop(locks);
        assert!(
            cargo_locks(&job)?.is_some(),
            "the sentinel is reusable after the lock is released"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn cargo_locks_refuses_a_symlinked_lock() -> Result<()> {
        let home = tempfile::tempdir()?;
        let profile = home.path().join("job/debug");
        fs::create_dir_all(&profile)?;
        let victim = home.path().join("victim");
        fs::write(&victim, b"")?;
        std::os::unix::fs::symlink(&victim, profile.join(".cargo-build-lock"))?;
        assert!(
            cargo_locks(&home.path().join("job"))?.is_none(),
            "a symlinked lock fails closed"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn an_uninspectable_root_is_treated_as_locked() -> Result<()> {
        let home = tempfile::tempdir()?;
        let real = home.path().join("real");
        fs::create_dir(&real)?;
        let link = home.path().join("link");
        std::os::unix::fs::symlink(&real, &link)?;
        assert!(
            cargo_locks(&link)?.is_none(),
            "a reparse root cannot be inspected and must fail closed"
        );
        assert!(dir_locked(&link), "the advisory check agrees");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn new_job_dirs_are_marked_and_reuse_requires_the_marker() -> Result<()> {
        let (_build, store) = seeded_store()?;
        let work = tempfile::tempdir()?;
        let command: Vec<String> = vec!["true".into()];
        let fresh = Options {
            job_id: Some("marked"),
            cwd: None,
            harvest_back: false,
            compress: true,
            remove_on_success: false,
            reuse: false,
            target_dir: None,
            incremental: None,
            link: LinkPolicy::Auto,
            cargo_home: None,
            no_remote: false,
            remote: None,
            command: &command,
        };
        assert_eq!(run(store.path(), work.path(), &fresh)?, 0);
        assert!(has_job_marker(&work.path().join("marked"))?);

        fs::remove_file(work.path().join("marked").join(JOB_MARKER))?;
        let reuse = Options {
            reuse: true,
            ..fresh
        };
        let err = run(store.path(), work.path(), &reuse).unwrap_err();
        assert!(err.to_string().contains(".epicenter-job"), "{err}");
        Ok(())
    }

    #[test]
    fn exec_reuse_adopts_a_marker_only_dir() -> Result<()> {
        let (_build, store) = seeded_store()?;
        let work = tempfile::tempdir()?;
        let dir = work.path().join("adopt");
        crate::util::create_private_dir_all(&dir)?;
        write_job_marker(&dir)?;

        let command: Vec<String> = vec!["true".into()];
        let opts = Options {
            job_id: Some("adopt"),
            cwd: None,
            harvest_back: false,
            compress: true,
            remove_on_success: false,
            reuse: true,
            target_dir: None,
            incremental: None,
            link: LinkPolicy::Auto,
            cargo_home: None,
            no_remote: false,
            remote: None,
            command: &command,
        };
        assert_eq!(run(store.path(), work.path(), &opts)?, 0);
        assert!(
            work.path().join(".exec-adopt.json").is_file(),
            "a marker-only dir is adopted with a record"
        );
        Ok(())
    }

    #[test]
    fn exec_reuse_refuses_a_planted_dir_without_a_record() -> Result<()> {
        let (_build, store) = seeded_store()?;
        let work = tempfile::tempdir()?;
        let dir = work.path().join("planted");
        crate::util::create_private_dir_all(&dir)?;
        write_job_marker(&dir)?;
        fs::write(dir.join("planted.txt"), b"payload")?;

        let command: Vec<String> = vec!["true".into()];
        let opts = Options {
            job_id: Some("planted"),
            cwd: None,
            harvest_back: false,
            compress: true,
            remove_on_success: false,
            reuse: true,
            target_dir: None,
            incremental: None,
            link: LinkPolicy::Auto,
            cargo_home: None,
            no_remote: false,
            remote: None,
            command: &command,
        };
        let err = run(store.path(), work.path(), &opts).unwrap_err();
        assert!(err.to_string().contains("no exec record"), "{err}");
        Ok(())
    }

    #[test]
    fn exec_reuse_refuses_a_record_for_another_token() -> Result<()> {
        let (_build, store) = seeded_store()?;
        let work = tempfile::tempdir()?;
        let dir = work.path().join("mismatch");
        crate::util::create_private_dir_all(&dir)?;
        write_job_marker(&dir)?;
        record_for_test(&dir)?;
        // Replace the marker token; the record still names the old one.
        fs::write(
            dir.join(JOB_MARKER),
            format!("{JOB_MARKER_VERSION}\n{}\n", "f".repeat(32)),
        )?;

        let command: Vec<String> = vec!["true".into()];
        let opts = Options {
            job_id: Some("mismatch"),
            cwd: None,
            harvest_back: false,
            compress: true,
            remove_on_success: false,
            reuse: true,
            target_dir: None,
            incremental: None,
            link: LinkPolicy::Auto,
            cargo_home: None,
            no_remote: false,
            remote: None,
            command: &command,
        };
        let err = run(store.path(), work.path(), &opts).unwrap_err();
        assert!(err.to_string().contains("different build"), "{err}");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn exec_reuse_refuses_a_symlinked_record() -> Result<()> {
        let (_build, store) = seeded_store()?;
        let work = tempfile::tempdir()?;
        let dir = work.path().join("linked");
        crate::util::create_private_dir_all(&dir)?;
        write_job_marker(&dir)?;
        record_for_test(&dir)?;
        let record = work.path().join(".exec-linked.json");
        let target = work.path().join("record-target.json");
        fs::write(&target, b"{}")?;
        fs::remove_file(&record)?;
        std::os::unix::fs::symlink(&target, &record)?;

        let command: Vec<String> = vec!["true".into()];
        let opts = Options {
            job_id: Some("linked"),
            cwd: None,
            harvest_back: false,
            compress: true,
            remove_on_success: false,
            reuse: true,
            target_dir: None,
            incremental: None,
            link: LinkPolicy::Auto,
            cargo_home: None,
            no_remote: false,
            remote: None,
            command: &command,
        };
        let err = run(store.path(), work.path(), &opts).unwrap_err();
        assert!(err.to_string().contains("does not trust"), "{err}");
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn windows_memory_sampler_sees_the_child_tree() -> Result<()> {
        // cmd spawns ping, so this also exercises job membership across
        // descendants. ping keeps both alive for about a second — several
        // sample ticks.
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "ping -n 2 127.0.0.1 >NUL"])
            .spawn()?;
        let memory = ChildMemory::start(&child);
        let status = child.wait()?;
        let peak = memory.finish()?;
        assert!(status.success());
        assert!(peak.is_some(), "no working set sampled for the child tree");
        Ok(())
    }

    #[test]
    fn default_work_root_is_not_derived_from_the_build_root() -> Result<()> {
        let default = crate::paths::default_work_root()?;
        assert!(default.is_absolute(), "{}", default.display());
        assert!(
            default.ends_with("epicenter/work"),
            "unexpected default {}",
            default.display()
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn exec_exports_a_per_job_target_dir() -> Result<()> {
        let (_build, store) = seeded_store()?;
        let work = tempfile::tempdir()?;
        let job_dir = work.path().join("t1");
        let command = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "test \"$CARGO_TARGET_DIR\" = '{}'",
                job_dir.join("target").display()
            ),
        ];
        let opts = Options {
            job_id: Some("t1"),
            cwd: None,
            harvest_back: false,
            compress: true,
            remove_on_success: false,
            reuse: false,
            target_dir: Some("job"),
            incremental: None,
            link: LinkPolicy::Auto,
            cargo_home: None,
            no_remote: false,
            remote: None,
            command: &command,
        };
        assert_eq!(run(store.path(), work.path(), &opts)?, 0);
        Ok(())
    }

    #[test]
    fn child_cargo_reads_profile_target_and_subcommand() {
        let command = vec![
            "cargo".to_string(),
            "+nightly".to_string(),
            "test".to_string(),
            "--release".to_string(),
            "--target".to_string(),
            "wasm32-unknown-unknown".to_string(),
        ];
        let child = child_cargo(&command);
        assert!(child.builds_units);
        assert_eq!(child.selector.as_deref(), Some("nightly"));
        assert_eq!(child.profile.as_deref(), Some("release"));
        assert_eq!(child.target.as_deref(), Some("wasm32-unknown-unknown"));

        let child = child_cargo(&[
            "cargo".to_string(),
            "build".to_string(),
            "--profile=dev".to_string(),
        ]);
        assert_eq!(child.profile.as_deref(), Some("debug"));
        assert!(child.target.is_none());

        let child = child_cargo(&["cargo".to_string(), "bench".to_string()]);
        assert_eq!(
            child.profile.as_deref(),
            Some("release"),
            "the bench subcommand defaults to the release profile"
        );

        let child = child_cargo(&["cargo".to_string(), "test".to_string(), "bench".to_string()]);
        assert_eq!(
            child.profile.as_deref(),
            Some("debug"),
            "a literal bench test filter is not the bench subcommand"
        );

        let child = child_cargo(&[
            "cargo".to_string(),
            "build".to_string(),
            "--profile".to_string(),
            "bench".to_string(),
        ]);
        assert_eq!(child.profile.as_deref(), Some("release"));

        let child = child_cargo(&["cargo".to_string(), "build".to_string(), "-r".to_string()]);
        assert_eq!(child.profile.as_deref(), Some("release"));

        let child = child_cargo(&["cargo".to_string(), "metadata".to_string()]);
        assert!(!child.builds_units);
        assert!(child.profile.is_none());
    }
}
