//! The signed `manifest.json` of one generation: schema, trust and I/O.

use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey};
use serde::{Deserialize, Serialize};

use crate::fingerprint;
use crate::util;

use super::keys::{
    constant_time_eq, existing_signing_key, hmac_sha256, legacy_manifest_key_path, manifest_key,
    manifest_key_path, manifest_signing_key, read_store_public_key, write_store_public_key,
};
#[cfg(windows)]
use super::layout::require_private_windows_acl;
use super::layout::{
    GENERATION_MARKER, manifest_path, store_is_read_only, units_dir, write_marker,
};
use super::{hex_decode, hex_encode};

// ── manifest ────────────────────────────────────────────────────────────────

/// `manifest.json` of one generation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    pub parity_key: String,
    pub toolchain: String,
    /// Unix seconds of the first harvest of this generation.
    pub created: u64,
    /// Unix seconds of the last harvest.
    pub updated: u64,
    pub units: Vec<UnitEntry>,
    /// HMAC-SHA256 over the manifest body (excluding this field), keyed by
    /// the per-user vault key. An empty value is old/untrusted and refused.
    /// Kept for local, single-trust-domain stores and old manifests.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mac: String,
    /// Ed25519 signature over the same body, verifiable with the public key
    /// stored in the vault. Required for read-only/foreign readers.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

/// One stored unit group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitEntry {
    /// Fingerprint dir name: `<pkg>-<16hex>`.
    pub name: String,
    pub profile: String,
    /// Memo file name, e.g. `lib-serde`.
    pub memo: String,
    /// Memo file content — the authoritative 16-hex hash.
    pub hash: String,
    /// Package version the unit was compiled from, when the build dir records
    /// it (registry crates via rustc's `.d` source list). Restore only seeds
    /// it into a lock that resolves the same version; `None` keeps the
    /// name-only match for git/path crates and older manifests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Canonical mtime of the whole group (whole seconds).
    pub stamp: u64,
    /// Build-dir layout this group reconstructs. Absent in manifests written
    /// before the new layout; inferred from the destinations when missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout: Option<fingerprint::UnitLayout>,
    pub files: Vec<FileEntry>,
}

impl UnitEntry {
    /// The layout this group reconstructs (recorded, or inferred).
    pub fn layout(&self) -> fingerprint::UnitLayout {
        self.layout.unwrap_or_else(|| {
            if self
                .files
                .iter()
                .any(|file| file.dest.starts_with(".fingerprint/"))
            {
                fingerprint::UnitLayout::Classic
            } else if self
                .files
                .iter()
                .any(|file| file.dest.contains("/fingerprint/"))
            {
                fingerprint::UnitLayout::New
            } else {
                fingerprint::UnitLayout::Classic
            }
        })
    }
}

/// One stored file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Path inside the unit group.
    pub path: String,
    /// Path relative to the profile dir in a build dir.
    pub dest: String,
    pub size: u64,
    /// SHA-256 of the file content (empty only in pre-fix manifests).
    #[serde(default)]
    pub sha256: String,
    /// `memo` | `fingerprint` | `dep-info` | `artifact` | `build-tree`.
    pub role: String,
    /// Content-addressed gzip blob relative to the generation root, when the
    /// stored bytes are compressed. Old manifests omit this and stay raw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
}

impl UnitEntry {
    /// Reject every path that could escape the store or the view.
    pub(crate) fn validate(&self) -> Result<()> {
        util::validate_component(&self.name, "unit name")?;
        util::validate_component(&self.profile, "profile")?;
        util::validate_component(&self.memo, "memo file")?;
        if !self.hash.is_empty() && !fingerprint::looks_like_hash(&self.hash) {
            let shown: String = self.hash.chars().take(32).collect();
            anyhow::bail!("invalid memo hash {shown:?} in unit {}", self.name);
        }
        if let Some(version) = &self.version {
            if version.is_empty()
                || version.len() > 64
                || !version
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '+'))
            {
                anyhow::bail!("invalid package version {version:?} in unit {}", self.name);
            }
        }
        let mut paths = std::collections::HashSet::with_capacity(self.files.len());
        for file in &self.files {
            util::validate_rel(&file.path, "stored file path")?;
            util::validate_rel(&file.dest, "destination path")?;
            if !paths.insert(file.path.to_lowercase()) {
                anyhow::bail!(
                    "duplicate case-insensitive file path {:?} in unit {}",
                    file.path,
                    self.name
                );
            }
            if !file.sha256.is_empty()
                && (file.sha256.len() != 64
                    || !file.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()))
            {
                anyhow::bail!("invalid SHA-256 for {} in unit {}", file.path, self.name);
            }
            if file.size > util::MAX_FILE_BYTES {
                anyhow::bail!(
                    "file {} in unit {} is {} bytes (cap {})",
                    file.path,
                    self.name,
                    file.size,
                    util::MAX_FILE_BYTES
                );
            }
            if let Some(object) = &file.object {
                util::validate_rel(object, "object path")?;
                if !object.starts_with("blobs/") || !object.ends_with(".gz") {
                    anyhow::bail!("invalid object path {object:?} in unit {}", self.name);
                }
            }
        }
        Ok(())
    }
}

impl Manifest {
    /// Reject every path that could escape the store or the view. This runs
    /// before any consumer (restore/verify/evict) touches a manifest path.
    pub fn validate(&self) -> Result<()> {
        let mut names = std::collections::HashSet::with_capacity(self.units.len());
        for unit in &self.units {
            unit.validate()?;
            // Windows/macOS/SMB map these to one directory. Reject the
            // collision instead of producing a platform-dependent restore.
            if !names.insert(unit.name.to_lowercase()) {
                anyhow::bail!(
                    "duplicate case-insensitive unit name {:?} in the manifest",
                    unit.name
                );
            }
        }
        Ok(())
    }
}

fn manifest_body(manifest: &Manifest) -> Result<Vec<u8>> {
    let mut unsigned = manifest.clone();
    unsigned.mac.clear();
    unsigned.signature.clear();
    Ok(serde_json::to_vec(&unsigned)?)
}

pub(crate) fn manifest_mac(manifest: &Manifest) -> Result<String> {
    Ok(hex_encode(&hmac_sha256(
        &manifest_key()?,
        &manifest_body(manifest)?,
    )))
}

fn manifest_signature(manifest: &Manifest, key: &SigningKey) -> Result<String> {
    let signature = key.sign(&manifest_body(manifest)?);
    Ok(hex_encode(&signature.to_bytes()))
}

pub(crate) fn verify_manifest_signature(
    store_root: &Path,
    manifest: &Manifest,
    path: &Path,
) -> Result<()> {
    let body = manifest_body(manifest)?;
    let signature = hex_decode(&manifest.signature, "manifest signature")?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| anyhow::anyhow!("manifest {} has a malformed signature", path.display()))?;
    let signature = Signature::from_bytes(&signature);
    let key = match read_store_public_key(store_root) {
        Ok(key) => key,
        Err(err) => {
            if let Some(signing) = existing_signing_key()? {
                signing.verifying_key()
            } else {
                return Err(err).with_context(|| {
                    format!(
                        "manifest {} is signed but the reader has no public key",
                        path.display()
                    )
                });
            }
        }
    };
    key.verify_strict(&body, &signature).map_err(|_| {
        anyhow::anyhow!(
            "manifest {} failed its Ed25519 signature check",
            path.display()
        )
    })
}

fn store_is_owned(store_root: &Path) -> bool {
    util::metadata_nofollow(store_root)
        .map(|meta| util::owned_by_us(store_root, &meta))
        .unwrap_or(false)
}

pub(crate) fn load_manifest(store_root: &Path, parity: &str) -> Result<Option<Manifest>> {
    load_manifest_at(store_root, parity, false)
}

/// Load a manifest. `repair` is true only for writer paths that already hold
/// the generation lock; readers never delete units or rewrite the manifest.
pub(crate) fn load_manifest_at(
    store_root: &Path,
    parity: &str,
    repair: bool,
) -> Result<Option<Manifest>> {
    let path = manifest_path(store_root, parity);
    let rel = Path::new(parity).join("manifest.json");
    if let Err(err) = util::check_regular_chain(store_root, &rel) {
        if util::is_not_found(&err) {
            return Ok(None);
        }
        return Err(err).with_context(|| format!("validating manifest path {}", path.display()));
    }
    let Some(meta) = util::probe(&path, "manifest")? else {
        return Ok(None);
    };
    // The manifest is the list of files that will be executed/linked. Never
    // parse one that is a symlink. A foreign, writable manifest is not a
    // reader; only a read-only mount may be foreign.
    if !meta.is_file() {
        anyhow::bail!("{} is not a regular manifest file", path.display());
    }
    let read_only = store_is_read_only(store_root);
    let owned = store_is_owned(store_root);
    if !util::owned_by_us(&path, &meta) && !read_only {
        anyhow::bail!("{} is owned by another user", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !read_only && meta.mode() & 0o022 != 0 {
            anyhow::bail!(
                "{} is group/world-writable (mode {:o})",
                path.display(),
                meta.mode() & 0o777
            );
        }
    }
    // A private store root is not enough: a generation (or its manifest) can
    // carry a child ACL that grants another principal write access. Check the
    // generation before trusting any of its entries. A read-only foreign store
    // is verified by the manifest signature instead.
    #[cfg(windows)]
    if !read_only {
        let generation = store_root.join(parity);
        match util::metadata_nofollow(&generation) {
            Ok(meta) if meta.is_dir() => require_private_windows_acl(&generation, "generation")?,
            Ok(_) => anyhow::bail!(
                "generation {} is not a real directory",
                generation.display()
            ),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                anyhow::bail!(
                    "generation {} is a symlink/reparse point",
                    generation.display()
                );
            }
            Err(err) => {
                return Err(err).with_context(|| format!("inspecting {}", generation.display()));
            }
        }
        require_private_windows_acl(&path, "manifest")?;
    }
    let text = if read_only {
        crate::util::read_small_text(&path, 16 * 1024 * 1024)
            .with_context(|| format!("reading {}", path.display()))?
    } else {
        crate::util::read_trusted_config(&path, 16 * 1024 * 1024)
            .with_context(|| format!("reading {}", path.display()))?
    };
    let mut manifest: Manifest =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    if !manifest.signature.is_empty() {
        verify_manifest_signature(store_root, &manifest, &path)?;
    } else {
        let local_hmac_key =
            manifest_key_path()?.is_file() || legacy_manifest_key_path()?.is_file();
        if !local_hmac_key {
            anyhow::bail!(
                "manifest {} has no Ed25519 signature and the local HMAC key is missing; re-harvest it on the writer",
                path.display()
            );
        }
        if manifest.mac.len() != 64 {
            anyhow::bail!(
                "manifest {} is unsigned (re-harvest this generation)",
                path.display()
            );
        }
        let expected = manifest_mac(&manifest)?;
        if !constant_time_eq(manifest.mac.as_bytes(), expected.as_bytes()) {
            anyhow::bail!("manifest {} failed its MAC check", path.display());
        }
    }
    // A valid signature/MAC with an invalid entry used to brick the whole
    // generation. A writer may repair in place; a reader only filters the
    // invalid entries in memory and never writes the store.
    if let Err(err) = manifest.validate() {
        let can_repair = repair && !read_only && owned;
        let mut kept = Vec::with_capacity(manifest.units.len());
        let mut dropped = Vec::new();
        for unit in manifest.units.drain(..) {
            if unit.validate().is_ok() {
                kept.push(unit);
            } else {
                dropped.push(unit);
            }
        }
        manifest.units = kept;
        eprintln!(
            "warning: {} {} invalid unit(s) from {} ({err:#})",
            if can_repair { "dropped" } else { "ignored" },
            dropped.len(),
            path.display()
        );
        if can_repair {
            // Their stored groups are unreachable now (no valid memo hash to
            // restore), so remove them instead of leaving verify to flag
            // orphans.
            let units = units_dir(store_root, parity);
            for unit in &dropped {
                if util::validate_component(&unit.name, "unit name").is_err() {
                    continue;
                }
                let dir = units.join(&unit.name);
                if util::metadata_nofollow(&dir).is_ok_and(|meta| meta.is_dir()) {
                    let _ = util::remove_tree(store_root, &dir);
                }
            }
            let _ = save_manifest(store_root, parity, &manifest);
        }
    }
    Ok(Some(manifest))
}

pub(crate) fn save_manifest(store_root: &Path, parity: &str, manifest: &Manifest) -> Result<()> {
    util::validate_component(parity, "generation")?;
    manifest.validate()?;
    let dir = store_root.join(parity);
    util::create_private_dir_all(&dir)?;
    write_marker(&dir.join(GENERATION_MARKER))?;
    let signing_key = manifest_signing_key()?;
    write_store_public_key(store_root, &signing_key)?;
    let mut signed = manifest.clone();
    signed.mac.clear();
    signed.signature.clear();
    signed.mac = manifest_mac(&signed)?;
    signed.signature = manifest_signature(&signed, &signing_key)?;
    let what = serde_json::to_string_pretty(&signed)?;
    // O_EXCL + a random, symlink-free temp path: never write through a
    // planted temp link.
    let (tmp, ()) = util::with_temp_file(&dir, "manifest.json.tmp", "", 0o600, |file| {
        file.write_all(what.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    })?;
    let target = manifest_path(store_root, parity);
    if let Err(err) = fs::rename(&tmp, &target) {
        let _ = fs::remove_file(&tmp);
        return Err(err).with_context(|| format!("installing {}", target.display()));
    }
    #[cfg(unix)]
    if let Ok(parent) = fs::File::open(&dir) {
        let _ = parent.sync_all();
    }
    Ok(())
}
