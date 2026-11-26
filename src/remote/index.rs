//! Canonical signed index: pointer, body, schema and validation.
//!
//! Only the small pointer is signed. It commits to the canonical body bytes,
//! so the body is immutable and can be cached independently:
//!
//! ```text
//! index.json             <- Ed25519 signature over canonical pointer bytes
//! indexes/<sha256>.json  <- canonical IndexBody, addressed by its hash
//! ```

use anyhow::{Context, Result, bail, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use super::{
    MAX_CLOCK_SKEW_SECS, MAX_INDEX_BODY_BYTES, MAX_INDEX_FILES, MAX_INDEX_POINTER_BYTES,
    MAX_INDEX_UNITS, MAX_INDEX_VALIDITY_SECS, RemoteFile, RemoteUnit, SCHEMA_VERSION, body_path,
    read_capped, sha256_hex,
};
use crate::settings::{self, RemoteTier};

const SIGNING_DOMAIN: &[u8] = b"epicenter.remote.index.v1\0";
pub(crate) const MAX_TOOL_BYTES: usize = 256;
pub(crate) const MAX_COMMIT_BYTES: usize = 256;
pub(crate) const MAX_CI_JOB_BYTES: usize = 4096;
pub(crate) const MAX_NOTES_BYTES: usize = 16 * 1024;

/// The signed pointer stored at `index.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IndexPointer {
    pub schema: u32,
    pub key_id: String,
    pub sequence: u64,
    pub created: u64,
    pub expires: u64,
    pub body_sha256: String,
    pub body_size: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

impl IndexPointer {
    /// Canonical bytes covered by the signature (signature field cleared).
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        Ok(serde_json::to_vec(&unsigned)?)
    }

    pub fn sign(&mut self, key: &SigningKey) -> Result<()> {
        let body = self.unsigned_bytes()?;
        self.signature = crate::vault::hex_encode(&key.sign(&signing_message(&body)).to_bytes());
        Ok(())
    }

    /// Verify the signature against the pinned public key and check the
    /// sequence/expiry window. Also rejects a pointer whose key id does not
    /// match the pinned key: rotation happens only through the trusted
    /// CI/admin channel.
    pub fn verify(&self, pinned_public_key: &str, now: u64) -> Result<()> {
        self.verify_signature(pinned_public_key)?;
        self.validate_time(now)
    }

    /// Verify the pinned key id and signature without applying the expiry
    /// window. A publisher needs this to read the last sequence from an index
    /// that has expired; readers still use [`IndexPointer::verify`].
    pub fn verify_signature(&self, pinned_public_key: &str) -> Result<()> {
        self.validate_shape()?;
        ensure!(
            !self.signature.is_empty(),
            "remote index pointer is not signed"
        );
        let pinned = settings::normalize_remote_publisher_key(pinned_public_key)?;
        let expected = settings::remote_key_id(&pinned)?;
        ensure!(
            self.key_id == expected,
            "remote index is signed by {} but the pinned publisher is {}; rotate the pin \
             only through the trusted CI/admin channel",
            self.key_id,
            expected
        );
        let signature = crate::vault::hex_decode(&self.signature, "index signature")?;
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| anyhow::anyhow!("index signature must be 64 bytes"))?;
        let signature = Signature::from_bytes(&signature);
        let key = verifying_key(&pinned)?;
        key.verify_strict(&signing_message(&self.unsigned_bytes()?), &signature)
            .map_err(|_| anyhow::anyhow!("remote index failed its Ed25519 signature check"))
    }

    pub fn validate_shape(&self) -> Result<()> {
        self.meta().validate_shape()?;
        super::validate::lower_hex(&self.body_sha256, 64, "index body SHA-256")?;
        ensure!(
            (1..=MAX_INDEX_BODY_BYTES).contains(&self.body_size),
            "remote index body size {} is outside 1..={MAX_INDEX_BODY_BYTES}",
            self.body_size
        );
        if !self.signature.is_empty() {
            super::validate::lower_hex(&self.signature, 128, "index signature")?;
        }
        Ok(())
    }

    fn meta(&self) -> IndexMeta<'_> {
        IndexMeta {
            schema: self.schema,
            key_id: &self.key_id,
            sequence: self.sequence,
            created: self.created,
            expires: self.expires,
        }
    }

    fn validate_time(&self, now: u64) -> Result<()> {
        ensure!(
            !self.signature.is_empty(),
            "remote index pointer is not signed"
        );
        self.meta().validate_time(now)
    }
}

/// The metadata a pointer and its body must agree on. Borrowing the fields
/// keeps the wire shape unchanged while sharing shape and time validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IndexMeta<'a> {
    schema: u32,
    key_id: &'a str,
    sequence: u64,
    created: u64,
    expires: u64,
}

impl IndexMeta<'_> {
    fn validate_shape(&self) -> Result<()> {
        ensure!(
            self.schema == SCHEMA_VERSION,
            "remote index schema {} is not supported (expected {SCHEMA_VERSION})",
            self.schema
        );
        validate_key_id(self.key_id)?;
        ensure!(self.sequence > 0, "remote index sequence must start at 1");
        validate_window(self.created, self.expires)
    }

    fn validate_time(&self, now: u64) -> Result<()> {
        ensure!(
            self.created <= now.saturating_add(MAX_CLOCK_SKEW_SECS),
            "remote index was created {} seconds in the future; check the clock",
            self.created.saturating_sub(now)
        );
        ensure!(
            self.expires >= now,
            "remote index expired {} seconds ago; ask CI to publish a fresh index",
            now.saturating_sub(self.expires)
        );
        Ok(())
    }
}

/// The canonical, hash-addressed index document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IndexBody {
    pub schema: u32,
    pub key_id: String,
    pub sequence: u64,
    pub created: u64,
    pub expires: u64,
    pub tier: RemoteTier,
    pub publisher: PublisherMetadata,
    pub compatibility: super::Compatibility,
    pub units: Vec<RemoteUnit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlobIdentity<'a> {
    sha256: &'a str,
    size: u64,
    blob_size: u64,
    compression: super::Compression,
}

impl<'a> From<&'a RemoteFile> for BlobIdentity<'a> {
    fn from(file: &'a RemoteFile) -> Self {
        Self {
            sha256: &file.sha256,
            size: file.size,
            blob_size: file.blob_size,
            compression: file.compression,
        }
    }
}

impl IndexBody {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn validate_shape(&self) -> Result<()> {
        self.meta().validate_shape()?;
        self.publisher.validate()?;
        self.compatibility.validate()?;
        self.validate_units()
    }

    fn meta(&self) -> IndexMeta<'_> {
        IndexMeta {
            schema: self.schema,
            key_id: &self.key_id,
            sequence: self.sequence,
            created: self.created,
            expires: self.expires,
        }
    }

    fn validate_units(&self) -> Result<()> {
        super::validate::count(self.units.len(), MAX_INDEX_UNITS, "remote index units")?;
        let mut names = HashSet::with_capacity(self.units.len());
        let mut destinations: HashMap<String, &str> = HashMap::new();
        let mut blobs: HashMap<&str, BlobIdentity<'_>> = HashMap::new();
        let mut contents: HashMap<&str, u64> = HashMap::new();
        let mut files = 0usize;

        for unit in &self.units {
            unit.validate()?;
            ensure!(
                names.insert(unit.name.to_ascii_lowercase()),
                "duplicate unit {:?} in remote index",
                unit.name
            );
            files = files
                .checked_add(unit.files.len())
                .context("remote index file count overflow")?;
            ensure!(
                files <= MAX_INDEX_FILES,
                "remote index has more than {MAX_INDEX_FILES} files"
            );

            for file in &unit.files {
                let destination = super::validate::relative_key(&file.dest);
                if let Some(owner) = destinations.insert(destination, unit.name.as_str()) {
                    bail!(
                        "duplicate destination {:?} in remote index (units {:?} and {:?})",
                        file.dest,
                        owner,
                        unit.name
                    );
                }
                let identity = BlobIdentity::from(file);
                match blobs.entry(file.blob.as_str()) {
                    std::collections::hash_map::Entry::Occupied(entry) => {
                        ensure!(
                            entry.get() == &identity,
                            "blob {} is referenced with conflicting content/size/compression",
                            file.blob
                        );
                    }
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(identity);
                    }
                }
                match contents.entry(file.sha256.as_str()) {
                    std::collections::hash_map::Entry::Occupied(entry) => {
                        ensure!(
                            *entry.get() == file.size,
                            "content {} is referenced with conflicting sizes",
                            file.sha256
                        );
                    }
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(file.size);
                    }
                }
            }
        }
        Ok(())
    }

    /// Validate the content against the tier it claims.
    ///
    /// A `libraries` reader accepts a `full` index: the reader-side filter
    /// imports only non-executable units, so one published index can serve
    /// both reader tiers. A `libraries` index is still required to be free of
    /// executable units; mislabeling it is an index error, not a miss.
    pub fn validate_for(&self, reader: RemoteTier) -> Result<()> {
        self.validate_shape()?;
        self.validate_reader(reader)
    }

    pub(crate) fn validate_reader(&self, _reader: RemoteTier) -> Result<()> {
        if self.tier == RemoteTier::Libraries
            && let Some(unit) = self.units.iter().find(|unit| unit.is_executable())
        {
            let detail = unit
                .executable_file()
                .map(|file| file.path.as_str())
                .unwrap_or(unit.memo.as_str());
            bail!(
                "`libraries` remote index contains executable unit {:?} \
                 (kind {:?}, file {:?}); re-publish with tier = \"full\" or exclude it",
                unit.name,
                unit.kind,
                detail
            );
        }
        Ok(())
    }

    /// Full reader gate: tier rules plus the machine-level compatibility tuple.
    /// `full` executable units are accepted only when the rustc/Cargo/target/
    /// cargo-home/flags/layout/registry tuple matches this machine.
    pub fn validate_for_local(
        &self,
        reader: RemoteTier,
        local: &super::LocalEnvironment,
    ) -> Result<()> {
        self.validate_for(reader)?;
        let mismatches = self.compatibility.compare_local(local);
        ensure!(
            mismatches.is_empty(),
            "remote index compatibility mismatch: {}",
            mismatches
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        );
        Ok(())
    }

    fn validate_time(&self, now: u64) -> Result<()> {
        self.meta().validate_time(now)?;
        ensure!(
            self.publisher.built_at <= self.expires,
            "publisher timestamp is after the index expiry"
        );
        ensure!(
            self.publisher.built_at <= now.saturating_add(MAX_CLOCK_SKEW_SECS),
            "publisher timestamp is {} seconds in the future; check the clock",
            self.publisher.built_at.saturating_sub(now)
        );
        Ok(())
    }

    fn validate_self(&self, now: u64) -> Result<()> {
        self.validate_shape()?;
        self.validate_time(now)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublisherMetadata {
    /// Tool and version that produced the index, e.g. `epicenter-cli 0.1.0`.
    pub tool: String,
    /// Source commit of the workspace/CI job.
    pub source_commit: String,
    /// Unix seconds of the publish.
    pub built_at: u64,
    /// CI job identifier or URL; empty when unavailable.
    pub ci_job: String,
    /// Human-readable note; empty when unavailable.
    pub notes: String,
}

impl PublisherMetadata {
    pub(crate) fn validate(&self) -> Result<()> {
        super::validate::text(&self.tool, "publisher tool", MAX_TOOL_BYTES)?;
        super::validate::text(
            &self.source_commit,
            "publisher source commit",
            MAX_COMMIT_BYTES,
        )?;
        ensure!(
            self.built_at > 0,
            "publisher built_at must be a Unix timestamp"
        );
        if !self.ci_job.is_empty() {
            super::validate::text(&self.ci_job, "publisher CI job", MAX_CI_JOB_BYTES)?;
            super::validate::no_url_credentials(&self.ci_job, "publisher CI job")?;
        }
        super::validate::multiline(&self.notes, "publisher notes", MAX_NOTES_BYTES)?;
        super::validate::no_url_credentials(&self.notes, "publisher notes")?;
        Ok(())
    }
}

/// Human-readable copy of the signed metadata, stored at `publisher.json`.
/// It is not a trust anchor; readers verify `index.json` and the body hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublisherReport {
    pub schema: u32,
    pub key_id: String,
    pub sequence: u64,
    pub body_sha256: String,
    pub tier: RemoteTier,
    pub publisher: PublisherMetadata,
    pub compatibility: super::Compatibility,
}

pub fn publisher_report(index: &SignedIndex) -> Result<Vec<u8>> {
    let report = PublisherReport {
        schema: index.pointer.schema,
        key_id: index.pointer.key_id.clone(),
        sequence: index.pointer.sequence,
        body_sha256: index.pointer.body_sha256.clone(),
        tier: index.body.tier,
        publisher: index.body.publisher.clone(),
        compatibility: index.body.compatibility.clone(),
    };
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// A signed index: the pointer, its canonical body and the exact body bytes.
/// The constructors are [`make_index`] and the reader verifiers, so carrying
/// one means the pointer and body have already been checked.
#[derive(Debug, Clone)]
pub struct SignedIndex {
    pointer: IndexPointer,
    body: IndexBody,
    body_bytes: Vec<u8>,
}

/// Reader-facing name for a [`SignedIndex`] produced by verification.
pub type VerifiedIndex = SignedIndex;

impl SignedIndex {
    pub fn pointer(&self) -> &IndexPointer {
        &self.pointer
    }

    pub fn body(&self) -> &IndexBody {
        &self.body
    }

    pub fn body_bytes(&self) -> &[u8] {
        &self.body_bytes
    }

    pub(crate) fn pointer_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&self.pointer)?)
    }
}

/// Build and sign an index body. The body carries the creation/expiry window
/// that the pointer repeats and signs.
pub fn make_index(body: IndexBody, key: &SigningKey, now: u64) -> Result<SignedIndex> {
    body.validate_self(now)?;
    body.validate_reader(body.tier)?;
    let expected =
        settings::remote_key_id(&crate::vault::hex_encode(&key.verifying_key().to_bytes()))?;
    ensure!(
        body.key_id == expected,
        "remote index body is pinned to {} but the signing key is {}",
        body.key_id,
        expected
    );
    let body_bytes = body.canonical_bytes()?;
    ensure!(
        body_bytes.len() as u64 <= MAX_INDEX_BODY_BYTES,
        "remote index body is {} bytes (cap {MAX_INDEX_BODY_BYTES})",
        body_bytes.len()
    );
    let meta = body.meta();
    let mut pointer = IndexPointer {
        schema: meta.schema,
        key_id: meta.key_id.to_string(),
        sequence: meta.sequence,
        created: meta.created,
        expires: meta.expires,
        body_sha256: sha256_hex(&body_bytes),
        body_size: body_bytes.len() as u64,
        signature: String::new(),
    };
    pointer.sign(key)?;
    Ok(SignedIndex {
        pointer,
        body,
        body_bytes,
    })
}

/// Verify the pointer and the body hash/size. The body is checked for
/// canonical encoding before it is returned.
pub fn verify_body(pointer: &IndexPointer, bytes: &[u8], now: u64) -> Result<IndexBody> {
    ensure!(
        bytes.len() as u64 == pointer.body_size,
        "remote index body is {} bytes but the pointer commits to {}",
        bytes.len(),
        pointer.body_size
    );
    ensure!(
        bytes.len() as u64 <= MAX_INDEX_BODY_BYTES,
        "remote index body is {} bytes (cap {MAX_INDEX_BODY_BYTES})",
        bytes.len()
    );
    ensure!(
        sha256_hex(bytes) == pointer.body_sha256,
        "remote index body does not match the SHA-256 in the signed pointer"
    );
    let body: IndexBody = serde_json::from_slice(bytes).context("parsing the remote index body")?;
    ensure!(
        body.canonical_bytes()? == bytes,
        "remote index body is not in canonical form"
    );
    body.validate_self(now)?;
    body.validate_reader(body.tier)?;
    ensure_metadata_matches(pointer, &body)?;
    Ok(body)
}

fn ensure_metadata_matches(pointer: &IndexPointer, body: &IndexBody) -> Result<()> {
    ensure!(
        pointer.meta() == body.meta(),
        "remote index body metadata does not match the signed pointer"
    );
    Ok(())
}

fn finish_index(
    pointer: IndexPointer,
    body_bytes: &[u8],
    reader: RemoteTier,
    now: u64,
) -> Result<SignedIndex> {
    let body = verify_body(&pointer, body_bytes, now)?;
    body.validate_reader(reader)?;
    Ok(SignedIndex {
        pointer,
        body,
        body_bytes: body_bytes.to_vec(),
    })
}

/// Parse and fully verify `index.json` + `indexes/<sha256>.json`.
pub fn verify_index(
    pointer_bytes: &[u8],
    body_bytes: &[u8],
    pinned_public_key: &str,
    reader: RemoteTier,
    now: u64,
) -> Result<VerifiedIndex> {
    ensure!(
        pointer_bytes.len() as u64 <= MAX_INDEX_POINTER_BYTES,
        "remote index pointer is too large"
    );
    let pointer: IndexPointer =
        serde_json::from_slice(pointer_bytes).context("parsing the remote index pointer")?;
    pointer.verify(pinned_public_key, now)?;
    finish_index(pointer, body_bytes, reader, now)
}

/// Write a signed pointer/body pair into a local staging tree.
///
/// The body and blobs are put-if-absent (an existing object must have the same
/// bytes); `publisher.json` and `index.json` are replaced last.
pub fn write_index_tree(root: &Path, index: &SignedIndex) -> Result<()> {
    let body_file = body_path(root, &index.pointer.body_sha256)?;
    match crate::util::probe_file(&body_file, "index body")? {
        Some(_) => {
            let existing = read_capped(&body_file, MAX_INDEX_BODY_BYTES, "index body")?;
            ensure!(
                existing == index.body_bytes,
                "index body {} already exists with different bytes",
                body_file.display()
            );
        }
        None => crate::util::write_atomic_private(&body_file, &index.body_bytes)?,
    }
    let report = publisher_report(index)?;
    let report_path = root.join(super::PUBLISHER_FILE);
    crate::util::write_atomic_private(&report_path, &report)?;
    let pointer_path = root.join(super::INDEX_FILE);
    crate::util::write_atomic_private(&pointer_path, &index.pointer_bytes()?)?;
    Ok(())
}

/// Read and verify a local staging tree (used by tests and the publisher's
/// post-upload check).
pub fn read_index_tree(
    root: &Path,
    pinned_public_key: &str,
    reader: RemoteTier,
    now: u64,
) -> Result<VerifiedIndex> {
    let pointer_bytes = read_capped(
        &root.join(super::INDEX_FILE),
        MAX_INDEX_POINTER_BYTES,
        "index pointer",
    )?;
    let pointer: IndexPointer =
        serde_json::from_slice(&pointer_bytes).context("parsing the remote index pointer")?;
    // Authenticate the pointer before reading whatever body it names.
    pointer.verify(pinned_public_key, now)?;
    let body_bytes = read_capped(
        &body_path(root, &pointer.body_sha256)?,
        MAX_INDEX_BODY_BYTES,
        "index body",
    )?;
    finish_index(pointer, &body_bytes, reader, now)
}

fn signing_message(unsigned: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNING_DOMAIN.len() + unsigned.len());
    message.extend_from_slice(SIGNING_DOMAIN);
    message.extend_from_slice(unsigned);
    message
}

fn verifying_key(public_key: &str) -> Result<VerifyingKey> {
    let bytes = crate::vault::hex_decode(public_key, "publisher public key")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("publisher public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|err| anyhow::anyhow!("publisher public key is invalid: {err}"))
}

fn validate_key_id(text: &str) -> Result<()> {
    let hex = text
        .strip_prefix("ed25519:")
        .context("remote key id must start with `ed25519:`")?;
    super::validate::lower_hex(hex, 16, "remote key id suffix")
}

fn validate_window(created: u64, expires: u64) -> Result<()> {
    ensure!(
        created > 0,
        "remote index created time must be a Unix timestamp"
    );
    ensure!(
        expires > created,
        "remote index expiry must be after its creation"
    );
    ensure!(
        expires - created <= MAX_INDEX_VALIDITY_SECS,
        "remote index validity is {} seconds (cap {MAX_INDEX_VALIDITY_SECS})",
        expires - created
    );
    Ok(())
}
