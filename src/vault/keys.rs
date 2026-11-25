//! Per-user manifest keys and the store's public key.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::util;

/// Public Ed25519 key for the store manifest, written by the trusted writer
/// next to the store marker. Readers need no private key.
pub const PUBKEY_FILE: &str = ".epicenter-pubkey";

/// Per-user epicenter state file, independent of CARGO_HOME.
fn state_file_path(name: &str) -> Result<PathBuf> {
    let path = crate::paths::state_dir()?.join(name);
    #[cfg(windows)]
    crate::util::ensure_windows_user_path(&path, "epicenter state")?;
    Ok(path)
}

/// Pre-0.1.1 state location under the ambient Cargo home. Read-only fallback
/// so moving `cargo_home` never rotates a writer identity.
fn legacy_state_file_path(name: &str) -> Result<PathBuf> {
    let path = crate::paths::ambient_cargo_home()?
        .join("epicenter")
        .join(name);
    #[cfg(windows)]
    crate::util::ensure_windows_user_path(&path, "legacy epicenter state")?;
    Ok(path)
}

/// Where the per-user vault MAC key lives. Outside the store on purpose:
/// a store-write attacker must not be able to rewrite the key as well.
pub(crate) fn manifest_key_path() -> Result<PathBuf> {
    state_file_path("manifest.key")
}

pub(crate) fn legacy_manifest_key_path() -> Result<PathBuf> {
    legacy_state_file_path("manifest.key")
}

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > block.len() {
        let digest = Sha256::digest(key);
        block[..32].copy_from_slice(&digest);
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    let mut outer = Sha256::new();
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for index in 0..64 {
        ipad[index] ^= block[index];
        opad[index] ^= block[index];
    }
    inner.update(ipad);
    inner.update(data);
    let inner = inner.finalize();
    outer.update(opad);
    outer.update(inner);
    let out = outer.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

pub(crate) use crate::util::{hex_decode, hex_encode};

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

pub(crate) fn read_key_file(path: &Path) -> Result<Vec<u8>> {
    let mut file = util::open_regular(path, false)
        .with_context(|| format!("opening vault key {}", path.display()))?;
    let meta = file.metadata()?;
    if !util::owned_by_us(path, &meta) {
        anyhow::bail!(
            "vault key {} is owned by an untrusted principal",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o077 != 0 {
            anyhow::bail!(
                "vault key {} is accessible by other users (mode {:o})",
                path.display(),
                meta.mode() & 0o777
            );
        }
    }
    #[cfg(windows)]
    if util::windows_acl_is_private(path) != Some(true) {
        anyhow::bail!(
            "vault key {} DACL grants write access to an untrusted principal",
            path.display()
        );
    }
    let mut key = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut key)?;
    if key.len() != 32 {
        anyhow::bail!("vault key {} is malformed", path.display());
    }
    Ok(key)
}

pub(crate) fn write_new_key_file(path: &Path, key: &[u8; 32]) -> Result<Vec<u8>> {
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent", path.display()))?;
    util::create_private_dir_all(parent)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(key)?;
            file.sync_all()?;
            Ok(key.to_vec())
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => read_key_file(path),
        Err(err) => Err(err).with_context(|| format!("creating vault key {}", path.display())),
    }
}

fn read_existing_key(path: &Path) -> Result<Option<Vec<u8>>> {
    match util::probe(path, "vault key")? {
        Some(meta) if meta.is_file() => Ok(Some(read_key_file(path)?)),
        Some(_) => anyhow::bail!("vault key {} is not a regular file", path.display()),
        None => Ok(None),
    }
}

pub(crate) fn manifest_key() -> Result<Vec<u8>> {
    let path = manifest_key_path()?;
    if let Some(key) = read_existing_key(&path)? {
        return Ok(key);
    }
    // Keep using an existing legacy key instead of rotating the MAC.
    let legacy = legacy_manifest_key_path()?;
    if let Some(key) = read_existing_key(&legacy)? {
        return Ok(key);
    }
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|err| anyhow::anyhow!("generating vault key: {err}"))?;
    write_new_key_file(&path, &key)
}

fn manifest_signing_key_path() -> Result<PathBuf> {
    state_file_path("manifest.ed25519")
}

fn legacy_manifest_signing_key_path() -> Result<PathBuf> {
    legacy_state_file_path("manifest.ed25519")
}

fn signing_key_from_bytes(bytes: Vec<u8>, path: &Path) -> Result<SigningKey> {
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing key {} is malformed", path.display()))?;
    Ok(SigningKey::from_bytes(&seed))
}

pub(crate) fn load_or_migrate_signing_key(path: &Path, legacy: &Path) -> Result<SigningKey> {
    if let Some(bytes) = read_existing_key(path)? {
        return signing_key_from_bytes(bytes, path);
    }
    // A writer migrates the old key explicitly instead of minting a new
    // identity. Readers still fall back to the legacy path in
    // `existing_signing_key`.
    if let Some(bytes) = read_existing_key(legacy)? {
        let seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("signing key {} is malformed", legacy.display()))?;
        let stored = write_new_key_file(path, &seed)?;
        return signing_key_from_bytes(stored, path);
    }
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|err| anyhow::anyhow!("generating signing key: {err}"))?;
    let bytes = write_new_key_file(path, &key)?;
    signing_key_from_bytes(bytes, path)
}

pub(crate) fn manifest_signing_key() -> Result<SigningKey> {
    load_or_migrate_signing_key(
        &manifest_signing_key_path()?,
        &legacy_manifest_signing_key_path()?,
    )
}

pub(crate) fn existing_signing_key() -> Result<Option<SigningKey>> {
    let path = manifest_signing_key_path()?;
    if let Some(bytes) = read_existing_key(&path)? {
        return Ok(Some(signing_key_from_bytes(bytes, &path)?));
    }
    let legacy = legacy_manifest_signing_key_path()?;
    if let Some(bytes) = read_existing_key(&legacy)? {
        return Ok(Some(signing_key_from_bytes(bytes, &legacy)?));
    }
    Ok(None)
}

fn store_public_key_path(store_root: &Path) -> PathBuf {
    store_root.join(PUBKEY_FILE)
}

pub(crate) fn read_store_public_key(store_root: &Path) -> Result<VerifyingKey> {
    let path = store_public_key_path(store_root);
    let text = crate::util::read_small_text(&path, 16 * 1024)
        .with_context(|| format!("reading vault public key {}", path.display()))?;
    let bytes = hex_decode(&text, "vault public key")?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("vault public key {} is malformed", path.display()))?;
    VerifyingKey::from_bytes(&key)
        .map_err(|err| anyhow::anyhow!("vault public key {} is invalid: {err}", path.display()))
}

pub(crate) fn write_store_public_key(store_root: &Path, key: &SigningKey) -> Result<()> {
    let path = store_public_key_path(store_root);
    let wanted = format!("{}\n", hex_encode(&key.verifying_key().to_bytes()));
    if let Ok(existing) = crate::util::read_small_text(&path, 16 * 1024) {
        if existing.trim() == wanted.trim() {
            return Ok(());
        }
        anyhow::bail!(
            "store public key {} does not match the writer's signing key; rotation is not automatic",
            path.display()
        );
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Public key: readable by every reader; the store root itself may be
        // 0755 for a shared read-only mount.
        options.mode(0o644);
    }
    match options.open(&path) {
        Ok(mut file) => {
            file.write_all(wanted.as_bytes())?;
            file.sync_all()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // The process umask must not hide the public key from readers.
                // Use the held fd, never a path that could be swapped.
                file.set_permissions(fs::Permissions::from_mode(0o644))
                    .with_context(|| format!("making {} readable", path.display()))?;
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = crate::util::read_small_text(&path, 16 * 1024)
                .with_context(|| format!("reading {}", path.display()))?;
            if existing.trim() == wanted.trim() {
                Ok(())
            } else {
                anyhow::bail!(
                    "store public key {} does not match the writer's signing key; rotation is not automatic",
                    path.display()
                )
            }
        }
        Err(err) => Err(err).with_context(|| format!("creating {}", path.display())),
    }
}
