//! Per-job state that outlives one process: the job-dir marker, Cargo's build
//! locks, and the exec record that proves who wrote a build dir.
//!
//! A build dir is untrusted input: anything that can write it can also write a
//! complete Cargo fingerprint. The record and the marker live in the private
//! work root instead, so a caller can tell a build this host ran from a
//! directory someone else handed it.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs, io};

use anyhow::{Context, Result, bail};

use crate::util::{self, metadata_nofollow};

/// Marker written into a newly created job dir. `--reuse` refuses a
/// pre-existing directory without it, so a shared work root cannot be seeded
/// with a bare directory. The token is not a secret; `O_EXCL` creation is the
/// primary guard.
pub const JOB_MARKER: &str = ".epicenter-job";
pub(crate) const JOB_MARKER_VERSION: &str = "epicenter-job-v1";

fn job_marker_path(work_dir: &Path) -> PathBuf {
    work_dir.join(JOB_MARKER)
}

pub(crate) fn write_job_marker(work_dir: &Path) -> Result<String> {
    let mut token = [0u8; 16];
    getrandom::fill(&mut token).map_err(|err| anyhow::anyhow!("generating job token: {err}"))?;
    let token_hex: String = token.iter().map(|byte| format!("{byte:02x}")).collect();
    let body = format!("{JOB_MARKER_VERSION}\n{token_hex}\n");
    util::write_atomic_private(&job_marker_path(work_dir), body.as_bytes())
        .with_context(|| format!("writing job marker in {}", work_dir.display()))?;
    Ok(token_hex)
}

/// The job token, when `work_dir` carries a well-formed marker.
pub(crate) fn job_marker_token(work_dir: &Path) -> Result<Option<String>> {
    let text = match util::read_trusted_config(&job_marker_path(work_dir), 1024) {
        Ok(text) => text,
        Err(err)
            if err.kind() == io::ErrorKind::NotFound
                || err.kind() == io::ErrorKind::InvalidInput =>
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

/// A reparse/symlink root cannot be inspected safely, so lock scans treat it as
/// "in use" (fail closed) instead of returning an empty lock set.
fn root_is_reparse(dir: &Path) -> bool {
    matches!(
        metadata_nofollow(dir),
        Err(err) if err.kind() == io::ErrorKind::InvalidInput
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

pub(crate) fn existing_cargo_locks(dir: &Path) -> Result<Option<Vec<fs::File>>> {
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

pub(crate) const EXEC_RECORD_VERSION: u32 = 1;
const EXEC_RECORD_MAX_BYTES: u64 = 8 * 1024;
pub(crate) const EXEC_COMMAND_MAX_CHARS: usize = 1024;

fn record_path(work_root: &Path, job_id: &str) -> PathBuf {
    work_root.join(format!(".exec-{job_id}.json"))
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn write_record(work_root: &Path, job_id: &str, record: &ExecRecord) -> Result<()> {
    let body = serde_json::to_vec(record).context("serializing the exec record")?;
    util::write_atomic_private(&record_path(work_root, job_id), &body)
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
    let text = match util::read_trusted_config(&path, EXEC_RECORD_MAX_BYTES) {
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

pub(crate) fn remove_record(work_root: &Path, job_id: &str) {
    let path = record_path(work_root, job_id);
    if metadata_nofollow(&path).is_ok_and(|meta| meta.is_file()) {
        let _ = std::fs::remove_file(&path);
    }
}
