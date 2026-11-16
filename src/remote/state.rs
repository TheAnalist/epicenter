//! Per-endpoint replay/rollback state and `doctor` status.
//!
//! The highest accepted sequence is persisted outside the remote cache, next
//! to the vault keys. A valid signature is not enough: an older signed index
//! is a rollback, and two different bodies at the same sequence are
//! equivocation. Expiry is checked with the pointer signature.

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::{
    Compatibility, IndexPointer, PublisherMetadata, SCHEMA_VERSION, ensure_sha256, read_capped,
    sha256_hex,
};
use crate::settings::RemotePolicy;

const MAX_STATE_BYTES: u64 = 1024 * 1024;

/// Persisted last-accepted index metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteState {
    pub schema: u32,
    pub endpoint: String,
    pub key_id: String,
    pub sequence: u64,
    pub body_sha256: String,
    pub expires: u64,
    pub fetched_at: u64,
    pub publisher: PublisherMetadata,
    pub compatibility: Compatibility,
}

/// Advisory status for `doctor`; derived from a previously verified state.
#[derive(Debug, Clone, Serialize)]
pub struct IndexStatus {
    pub endpoint: String,
    pub key_id: String,
    pub sequence: u64,
    pub body_sha256: String,
    pub expires: u64,
    pub fetched_at: u64,
    pub publisher: PublisherMetadata,
    pub mismatches: Vec<super::Mismatch>,
}

impl IndexStatus {
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires < now
    }
}

/// `state_dir()/remote/<endpoint+key hash>.json`.
pub fn state_path(remote: &RemotePolicy) -> Result<PathBuf> {
    state_file(&crate::paths::state_dir()?, remote)
}

fn state_file(root: &Path, remote: &RemotePolicy) -> Result<PathBuf> {
    let url = remote.url.as_deref().context("remote has no endpoint")?;
    let key_id = remote
        .key_id
        .as_deref()
        .context("remote has no publisher key")?;
    let name = sha256_hex(format!("{url}\0{key_id}").as_bytes());
    Ok(root.join(super::STATE_DIR).join(format!("{name}.json")))
}

/// Load and validate the last accepted state, if one exists.
pub fn load_state(remote: &RemotePolicy) -> Result<Option<RemoteState>> {
    load_state_at(&crate::paths::state_dir()?, remote)
}

pub(crate) fn load_state_at(root: &Path, remote: &RemotePolicy) -> Result<Option<RemoteState>> {
    let path = state_file(root, remote)?;
    match crate::util::metadata_nofollow(&path) {
        Ok(meta) => {
            if !meta.is_file() {
                bail!("remote state {} is not a regular file", path.display());
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("inspecting {}", path.display()));
        }
    }
    let bytes = read_capped(&path, MAX_STATE_BYTES, "remote state")?;
    let state: RemoteState =
        serde_json::from_slice(&bytes).context("parsing the remote replay state")?;
    state.validate(remote)?;
    Ok(Some(state))
}

impl RemoteState {
    fn validate(&self, remote: &RemotePolicy) -> Result<()> {
        ensure!(
            self.schema == SCHEMA_VERSION,
            "remote state schema {} is not supported",
            self.schema
        );
        ensure!(
            Some(self.endpoint.as_str()) == remote.url.as_deref(),
            "remote state belongs to a different endpoint"
        );
        ensure!(
            Some(self.key_id.as_str()) == remote.key_id.as_deref(),
            "remote state belongs to a different publisher key"
        );
        ensure!(self.sequence > 0, "remote state has no sequence");
        ensure_sha256(&self.body_sha256, "state body SHA-256")?;
        ensure!(
            self.fetched_at > 0 && self.expires > 0,
            "remote state has no timestamps"
        );
        ensure!(
            self.expires > self.fetched_at,
            "remote state was recorded after its index expired"
        );
        ensure!(
            self.publisher.built_at <= self.expires,
            "publisher timestamp is after the index expiry"
        );
        self.publisher.validate()?;
        self.compatibility.validate()?;
        Ok(())
    }
}

/// Check the signed pointer against the persisted sequence and, when the body
/// is new, persist it atomically. `body` must already be verified.
pub fn record_state(
    remote: &RemotePolicy,
    pointer: &IndexPointer,
    body: &super::IndexBody,
    now: u64,
) -> Result<()> {
    record_state_at(&crate::paths::state_dir()?, remote, pointer, body, now)
}

pub(crate) fn record_state_at(
    root: &Path,
    remote: &RemotePolicy,
    pointer: &IndexPointer,
    body: &super::IndexBody,
    now: u64,
) -> Result<()> {
    let pinned = remote
        .publisher_key
        .as_deref()
        .context("remote has no publisher key")?;
    pointer.verify(pinned, now)?;
    let canonical = body.canonical_bytes()?;
    let body = super::verify_body(pointer, &canonical, now)?;
    body.validate_reader(remote.tier)?;
    ensure_metadata_matches(pointer, &body)?;
    // Serialize the load-check-write per endpoint/key. Without this, two
    // concurrent fetches can both read the old sequence and accept different
    // bodies at the same sequence, or write a lower sequence after a higher
    // one. The lock is held through the atomic write.
    let path = state_file(root, remote)?;
    let lock_path = path.with_extension("json.lock");
    let _state_lock = crate::util::FileLock::acquire(&lock_path)?;
    let existing = load_state_at(root, remote)?;
    check_replay(existing.as_ref(), pointer)?;
    if existing.as_ref().is_some_and(|state| {
        state.sequence == pointer.sequence && state.body_sha256 == pointer.body_sha256
    }) {
        return Ok(());
    }
    let state = RemoteState {
        schema: SCHEMA_VERSION,
        endpoint: remote.url.clone().context("remote has no endpoint")?,
        key_id: pointer.key_id.clone(),
        sequence: pointer.sequence,
        body_sha256: pointer.body_sha256.clone(),
        expires: pointer.expires,
        fetched_at: now,
        publisher: body.publisher.clone(),
        compatibility: body.compatibility.clone(),
    };
    state.validate(remote)?;
    let bytes = serde_json::to_vec_pretty(&state)?;
    crate::util::write_atomic_private(&path, &bytes)?;
    Ok(())
}

fn ensure_metadata_matches(pointer: &IndexPointer, body: &super::IndexBody) -> Result<()> {
    ensure!(
        body.schema == pointer.schema
            && body.key_id == pointer.key_id
            && body.sequence == pointer.sequence
            && body.created == pointer.created
            && body.expires == pointer.expires,
        "remote index body does not match the signed pointer"
    );
    Ok(())
}

fn check_replay(existing: Option<&RemoteState>, pointer: &IndexPointer) -> Result<()> {
    let Some(existing) = existing else {
        return Ok(());
    };
    match pointer.sequence.cmp(&existing.sequence) {
        std::cmp::Ordering::Less => bail!(
            "remote index rolled back from sequence {} to {}; keeping the newer local state",
            existing.sequence,
            pointer.sequence
        ),
        std::cmp::Ordering::Equal if pointer.body_sha256 != existing.body_sha256 => bail!(
            "remote index reuses sequence {} with different bytes; refusing equivocation",
            pointer.sequence
        ),
        _ => Ok(()),
    }
}

/// Advisory status for `doctor`: last verified sequence plus machine-level
/// compatibility mismatches. Does not contact the network.
pub fn status(remote: &RemotePolicy) -> Result<Option<IndexStatus>> {
    status_at(&crate::paths::state_dir()?, remote)
}

pub(crate) fn status_at(root: &Path, remote: &RemotePolicy) -> Result<Option<IndexStatus>> {
    let Some(state) = load_state_at(root, remote)? else {
        return Ok(None);
    };
    let local = super::LocalEnvironment::gather()?;
    Ok(Some(IndexStatus {
        endpoint: state.endpoint.clone(),
        key_id: state.key_id.clone(),
        sequence: state.sequence,
        body_sha256: state.body_sha256.clone(),
        expires: state.expires,
        fetched_at: state.fetched_at,
        mismatches: state.compatibility.compare_local(&local),
        publisher: state.publisher,
    }))
}

/// Remove the local replay state for an endpoint/key. Admin/dev escape hatch;
/// a legitimate sequence reset requires re-pinning a new key instead.
pub fn clear_state(remote: &RemotePolicy) -> Result<()> {
    clear_state_at(&crate::paths::state_dir()?, remote)
}

pub(crate) fn clear_state_at(root: &Path, remote: &RemotePolicy) -> Result<()> {
    let path = state_file(root, remote)?;
    // Serialize with record_state_at: a clear racing a record must not leave
    // the state half-removed/half-recreated.
    let _state_lock = crate::util::FileLock::acquire(&path.with_extension("json.lock"))?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("removing {}", path.display())),
    }
}
