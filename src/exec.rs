//! `epicenter exec` — run one command against a fresh per-job build dir
//! seeded from the vault.
//!
//! A job gets its own directory under `{cargo-cache-home}/epicenter/work/<id>/`
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
use std::process::{Command, ExitStatus};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use walkdir::WalkDir;

use anyhow::{Context, Result, bail};

use crate::util::{self, GLYPH_FAIL, GLYPH_INFO, GLYPH_PASS, human_bytes, human_duration};
use crate::vault;

/// `{cargo-cache-home}/epicenter/work` — the home of per-job working dirs,
/// a sibling of `build/` and `store/`.
pub fn work_root(build_root: &Path) -> PathBuf {
    build_root.parent().unwrap_or(build_root).join("work")
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
    for entry in entries.flatten() {
        if !entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let mut info = WorkDirInfo {
            name,
            files: 0,
            bytes: 0,
            newest: None,
        };
        for file in WalkDir::new(entry.path()).min_depth(1).into_iter().flatten() {
            if !file.file_type().is_file() {
                continue;
            }
            if let Ok(meta) = file.metadata() {
                info.files += 1;
                info.bytes += meta.len();
                if let Ok(modified) = meta.modified() {
                    if info.newest.map_or(true, |current| modified > current) {
                        info.newest = Some(modified);
                    }
                }
            }
        }
        tier.dirs += 1;
        tier.files += info.files;
        tier.bytes += info.bytes;
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

/// Does a live build hold this build dir? Cargo takes an exclusive advisory
/// lock on `<build-dir>/<profile>/.cargo-build-lock` for the duration of a
/// build; the lock file itself survives idle builds, so only lock contention
/// means "in use". Shared by `exec` (reuse refusal) and `evict` (view guards).
pub(crate) fn dir_locked(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return true;
    };
    for entry in entries.flatten() {
        if !entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
            continue;
        }
        let lock = entry.path().join(".cargo-build-lock");
        if lock.is_file() && lock_held(&lock) {
            return true;
        }
    }
    false
}

/// A lock we cannot take is a lock somebody else holds.
fn lock_held(lock: &Path) -> bool {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(lock)
        .or_else(|_| std::fs::File::open(lock));
    let Ok(file) = file else {
        return true;
    };
    match file.try_lock() {
        Ok(()) => {
            let _ = file.unlock();
            false
        }
        Err(_) => true,
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
    /// Remove the work dir after the run — success or failure. Without it
    /// the dir is kept for inspection.
    pub remove_on_success: bool,
    /// Continue in an existing job dir instead of refusing (restore is
    /// idempotent; a dir a live build holds is still refused).
    pub reuse: bool,
    /// The child's `CARGO_TARGET_DIR`: `Some("job")` means `<work dir>/target`
    /// (per-job finals — the fully parallel case); any other value is a path.
    pub target_dir: Option<&'a str>,
    /// The command, argv-style.
    pub command: &'a [String],
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

/// Run the job; returns the command's exit code.
pub fn run(store_root: &Path, work_root: &Path, opts: &Options<'_>) -> Result<i32> {
    let Some(program) = opts.command.first() else {
        bail!("exec needs a command — `epicenter exec -- <cmd>`");
    };
    let job_id = match opts.job_id {
        Some(id) => sanitize_job_id(id)?,
        None => default_job_id(),
    };
    let work_dir = work_root.join(&job_id);
    let mut reused = false;
    if work_dir.exists() {
        if !opts.reuse {
            bail!(
                "job dir {} already exists — pick another --id, pass --reuse to continue in it, or remove it",
                work_dir.display()
            );
        }
        if !work_dir.is_dir() {
            bail!("{} exists and is not a directory", work_dir.display());
        }
        if dir_locked(&work_dir) {
            bail!(
                "job dir {} is in use by a live build — wait for it, or use another --id",
                work_dir.display()
            );
        }
        reused = true;
    } else {
        std::fs::create_dir_all(&work_dir)
            .with_context(|| format!("creating {}", work_dir.display()))?;
    }
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

    // Fail-open seeding: an empty vault simply means a cold build. The hint
    // is about THIS step (before the command) — `--harvest` stores afterwards.
    let restore = vault::restore(&work_dir, store_root, None, false)?;
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
    if let Some(target) = &target_dir {
        eprintln!(
            "  {} {}{}",
            util::dim(&format!("{:<11}", "target dir")),
            target.display(),
            util::dim("  (CARGO_TARGET_DIR — finals live and die with this job)")
        );
    }
    eprintln!("{}", util::dim("  ── command ──"));
    let _ = std::io::stderr().flush();

    let started = Instant::now();
    let mut child = Command::new(program);
    child.args(&opts.command[1..]);
    child.env("CARGO_BUILD_BUILD_DIR", &work_dir);
    if let Some(target) = &target_dir {
        child.env("CARGO_TARGET_DIR", target);
    }
    if let Some(dir) = &opts.cwd {
        child.current_dir(dir);
    }
    let status = child
        .status()
        .with_context(|| format!("cannot run `{program}` — is it installed and on PATH?"))?;
    let elapsed = started.elapsed();
    let code = exit_code(&status);

    let harvested = if opts.harvest_back {
        Some(vault::harvest(&work_dir, store_root, None, false)?)
    } else {
        None
    };
    let mut removed = false;
    let mut remove_error = None;
    if opts.remove_on_success {
        match force_remove_dir(&work_dir) {
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
    Ok(code)
}

/// Remove a job dir robustly: read-only files (a wrapper's store, copied
/// state) block `remove_dir_all` on Windows, so clear the flag and retry
/// once; report the original error if the retry fails too.
fn force_remove_dir(path: &Path) -> std::io::Result<()> {
    let first = match std::fs::remove_dir_all(path) {
        Ok(()) => return Ok(()),
        Err(err) => err,
    };
    for entry in WalkDir::new(path) {
        let Ok(entry) = entry else { continue };
        let Ok(meta) = entry.metadata() else { continue };
        let mut perms = meta.permissions();
        if perms.readonly() {
            perms.set_readonly(false);
            let _ = std::fs::set_permissions(entry.path(), perms);
        }
    }
    std::fs::remove_dir_all(path).map_err(|_| first)
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
    }

    /// One synthetic unit in a build dir, harvested into a temp vault.
    fn seeded_store() -> Result<(tempfile::TempDir, tempfile::TempDir)> {
        let build = tempfile::tempdir()?;
        let store = tempfile::tempdir()?;
        let unit = build.path().join("debug/.fingerprint/x-1122334455667788");
        fs::create_dir_all(&unit)?;
        fs::write(unit.join("lib-x"), "aaaabbbbccccdddd")?;
        fs::write(unit.join("dep-lib-x"), [0u8; 4])?;
        fs::create_dir_all(build.path().join("debug/deps"))?;
        fs::write(
            build.path().join("debug/deps/libx-1122334455667788.rlib"),
            [1u8; 8],
        )?;
        vault::harvest(build.path(), store.path(), None, false)?;
        Ok((build, store))
    }

    #[cfg(unix)]
    #[test]
    fn exec_seeds_the_job_and_propagates_the_exit_code() -> Result<()> {
        let (_build, store) = seeded_store()?;
        let work = tempfile::tempdir()?;
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
            cwd: None,
            harvest_back: false,
            remove_on_success: false,
            reuse: false,
            target_dir: None,
            command: &command,
        };
        let code = run(store.path(), work.path(), &opts)?;
        assert_eq!(code, 7, "the command's exit code is the job's exit code");
        assert!(
            job_dir.join("debug/.fingerprint/x-1122334455667788/lib-x").is_file(),
            "the vault seeded the job"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn exec_rm_removes_the_job_dir_either_way() -> Result<()> {
        let (_build, store) = seeded_store()?;
        let work = tempfile::tempdir()?;

        let ok: Vec<String> = vec!["true".into()];
        let opts = Options {
            job_id: Some("j-ok"),
            cwd: None,
            harvest_back: false,
            remove_on_success: true,
            reuse: false,
            target_dir: None,
            command: &ok,
        };
        assert_eq!(run(store.path(), work.path(), &opts)?, 0);
        assert!(!work.path().join("j-ok").exists(), "success -> removed");

        // `--rm` is explicit: a failing build is removed too (the fixed
        // rmeta-era failure mode used to leave dirs piling up here).
        let bad: Vec<String> = vec!["false".into()];
        let opts = Options {
            job_id: Some("j-bad"),
            cwd: None,
            harvest_back: false,
            remove_on_success: true,
            reuse: false,
            target_dir: None,
            command: &bad,
        };
        assert_eq!(run(store.path(), work.path(), &opts)?, 1);
        assert!(
            !work.path().join("j-bad").exists(),
            "--rm -> removed on failure too"
        );

        // Without --rm the dir stays for inspection.
        let kept: Vec<String> = vec!["true".into()];
        let opts = Options {
            job_id: Some("j-keep"),
            cwd: None,
            harvest_back: false,
            remove_on_success: false,
            reuse: false,
            target_dir: None,
            command: &kept,
        };
        assert_eq!(run(store.path(), work.path(), &opts)?, 0);
        assert!(
            work.path().join("j-keep").exists(),
            "no --rm -> kept for inspection"
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
            remove_on_success: false,
            reuse: false,
            target_dir: None,
            command: &command,
        };
        let err = run(store.path(), work.path(), &opts).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
        assert!(err.to_string().contains("--reuse"), "mentions the way out");
        Ok(())
    }

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
            remove_on_success: false,
            reuse: false,
            target_dir: None,
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
        let debug = work.path().join("busy/debug");
        fs::create_dir_all(&debug)?;
        let lock = debug.join(".cargo-build-lock");
        fs::write(&lock, b"")?;
        let held = fs::OpenOptions::new().write(true).open(&lock)?;
        held.try_lock().context("test holds the lock")?;

        let cmd: Vec<String> = vec!["true".into()];
        let opts = Options {
            job_id: Some("busy"),
            cwd: None,
            harvest_back: false,
            remove_on_success: false,
            reuse: true,
            target_dir: None,
            command: &cmd,
        };
        let err = run(store.path(), work.path(), &opts).unwrap_err();
        assert!(err.to_string().contains("in use"), "{err}");
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
            remove_on_success: false,
            reuse: false,
            target_dir: Some("job"),
            command: &command,
        };
        assert_eq!(run(store.path(), work.path(), &opts)?, 0);
        Ok(())
    }
}
