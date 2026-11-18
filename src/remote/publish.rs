//! CI-only publisher: turn one stored generation into a signed local index
//! tree and an ordered upload plan.
//!
//! This module deliberately stops before the network. It verifies the store,
//! selects publishable units, reuses the vault's stored blobs, signs the index
//! and writes a private staging tree. The transport layer only consumes the
//! returned [`Upload`] list.

use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{
    BlobRef, Compression, FileRole, IndexBody, IndexPointer, LocalEnvironment,
    MAX_INDEX_VALIDITY_SECS, PublisherMetadata, RemoteFile, RemoteUnit, RemoteUnitKind,
    SCHEMA_VERSION, SignedIndex, SourceKind, UnitSource, Upload, make_index, now_secs, read_capped,
    sha256_hex, upload_plan, write_index_tree,
};
use crate::fingerprint;
use crate::lockfile::{LockIndex, LockSource};
use crate::settings::{self, RemoteTier};
use crate::vault::{self, StoredUnit};

const MAX_PUBLISHER_KEY_BYTES: u64 = 1024;

/// Everything one publish invocation needs. Paths are borrowed so the CLI can
/// keep its argument struct small.
pub struct PublishRequest<'a> {
    pub store_root: &'a Path,
    pub cwd: &'a Path,
    pub url: &'a str,
    pub tier: RemoteTier,
    pub generation: Option<&'a str>,
    pub profile: Option<&'a str>,
    /// Rustup selector used for the build (`nightly`, `1.91.0`, ...).
    pub selector: Option<&'a str>,
    pub sequence: Option<u64>,
    /// The current remote pointer, when the transport already fetched it.
    /// Local staging reads its own `index.json` when this is absent.
    pub current_pointer: Option<&'a IndexPointer>,
    pub valid_for: Duration,
    pub source_commit: &'a str,
    pub ci_job: &'a str,
    pub notes: &'a str,
    pub expect_key_id: Option<&'a str>,
    pub rotate_key: bool,
    pub publisher_state: Option<&'a Path>,
    pub out_dir: Option<&'a Path>,
    pub lockfile: Option<&'a Path>,
}

/// A completed local publish. `uploads` is the P3.6 transport input.
pub struct PublishOutcome {
    pub url: String,
    pub tier: RemoteTier,
    pub generation: String,
    pub units: usize,
    pub files: usize,
    pub bytes: u64,
    pub blobs: usize,
    pub skipped_workspace: usize,
    pub skipped_tier: usize,
    pub public_key: String,
    pub identity_created: bool,
    pub publisher_state: PathBuf,
    pub out_dir: PathBuf,
    pub index: SignedIndex,
    pub uploads: Vec<Upload>,
}

struct PublisherIdentity {
    key: SigningKey,
    public_key: String,
    key_id: String,
    created: bool,
}

struct PublishUnit {
    remote: RemoteUnit,
    sources: Vec<PathBuf>,
}

/// Publish one store generation into a private local staging tree.
pub fn publish(request: &PublishRequest<'_>) -> Result<PublishOutcome> {
    let url = settings::normalize_remote_url(request.url)?;
    ensure!(
        url.split_once("://")
            .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("s3")),
        "the publisher requires an `s3://bucket/prefix` URL; `https://` is reader-only"
    );
    let valid_secs = request.valid_for.as_secs();
    ensure!(
        (1..=MAX_INDEX_VALIDITY_SECS).contains(&valid_secs),
        "index validity must be between 1 second and {MAX_INDEX_VALIDITY_SECS} seconds"
    );

    let bucket = bucket_name(&url)?.to_string();
    let out_dir = match request.out_dir {
        Some(path) => path.to_path_buf(),
        None => crate::paths::state_dir()?
            .join("remote-publish")
            .join(staging_id(&url)),
    };
    ensure!(
        !out_dir.starts_with(request.store_root) && !request.store_root.starts_with(&out_dir),
        "publisher staging {} must be outside the store {}",
        out_dir.display(),
        request.store_root.display()
    );
    crate::util::create_private_dir_all(&out_dir)?;
    let out_real = fs::canonicalize(&out_dir).unwrap_or_else(|_| out_dir.clone());
    let store_real =
        fs::canonicalize(request.store_root).unwrap_or_else(|_| request.store_root.to_path_buf());
    ensure!(
        !out_real.starts_with(&store_real) && !store_real.starts_with(&out_real),
        "publisher staging {} resolves inside the store {}",
        out_dir.display(),
        request.store_root.display()
    );

    let _publish_lock = crate::util::FileLock::acquire(&out_dir.join(".publish.lock"))?;
    let current = match request.current_pointer {
        Some(pointer) => {
            pointer.validate_shape()?;
            Some(pointer.clone())
        }
        None => read_current_pointer(&out_dir)?,
    };
    let current_key_id = current.as_ref().map(|pointer| pointer.key_id.as_str());
    let state_dir = publisher_state_dir(request.publisher_state)?;
    crate::util::create_private_dir_all(&state_dir)?;
    let state_real = fs::canonicalize(&state_dir).unwrap_or_else(|_| state_dir.clone());
    ensure!(
        !state_real.starts_with(&store_real),
        "publisher identity directory {} must be outside the store {}",
        state_dir.display(),
        request.store_root.display()
    );
    ensure!(
        state_real != out_real,
        "publisher identity directory and staging directory must be different"
    );
    let identity = resolve_identity(
        &state_dir,
        &bucket,
        current_key_id,
        request.expect_key_id,
        request.rotate_key,
    )?;
    if let Some(pointer) = &current
        && !request.rotate_key
    {
        pointer
            .verify_signature(&identity.public_key)
            .context("the existing staging index does not match the publisher identity")?;
    }
    let sequence = choose_sequence(request.sequence, current.as_ref())?;

    let lock = match request.lockfile {
        Some(path) => LockIndex::parse(path)
            .with_context(|| format!("reading Cargo.lock {}", path.display()))?,
        None => LockIndex::load(request.cwd, None).context(
            "publishing requires a Cargo.lock; run from the workspace or pass --lockfile",
        )?,
    };
    let generation = match request.generation {
        Some(generation) => generation.to_string(),
        None => vault::parity_key_of(request.selector)?,
    };
    let selection = select_units(
        vault::stored_units(request.store_root)?,
        &generation,
        request.profile,
        request.tier,
        &lock,
    )?;
    ensure!(
        !selection.units.is_empty(),
        "no publishable units in generation {generation}; run `epicenter exec --harvest` first, \
         check the Cargo.lock, or try --tier full"
    );

    let unit_count = selection.units.len();
    let files = selection
        .units
        .iter()
        .map(|unit| unit.remote.files.len())
        .sum();
    let bytes = selection
        .units
        .iter()
        .flat_map(|unit| &unit.remote.files)
        .map(|file| file.size)
        .sum();
    stage_blobs(&out_dir, &selection.units)?;

    let units: Vec<RemoteUnit> = selection
        .units
        .into_iter()
        .map(|unit| unit.remote)
        .collect();
    let compatibility =
        super::Compatibility::from_local(&LocalEnvironment::gather_for(request.selector)?, &units)?;
    let now = now_secs();
    let body = IndexBody {
        schema: SCHEMA_VERSION,
        key_id: identity.key_id.clone(),
        sequence,
        created: now,
        expires: now.saturating_add(valid_secs),
        tier: request.tier,
        publisher: PublisherMetadata {
            tool: format!("epicenter-cli {}", env!("CARGO_PKG_VERSION")),
            source_commit: request.source_commit.to_string(),
            built_at: now,
            ci_job: request.ci_job.to_string(),
            notes: request.notes.to_string(),
        },
        compatibility,
        units,
    };
    let index = make_index(body, &identity.key, now)?;

    write_index_tree(&out_dir, &index)?;
    // Read our own output through the reader path before declaring success.
    super::read_index_tree(&out_dir, &identity.public_key, request.tier, now)?;
    let uploads = upload_plan(&out_dir, &index)?;

    let blobs = uploads
        .iter()
        .filter(|upload| upload.key.starts_with("blobs/"))
        .count();

    Ok(PublishOutcome {
        url,
        tier: request.tier,
        generation,
        units: unit_count,
        files,
        bytes,
        blobs,
        skipped_workspace: selection.skipped_workspace,
        skipped_tier: selection.skipped_tier,
        public_key: identity.public_key,
        identity_created: identity.created,
        publisher_state: state_dir,
        out_dir,
        index,
        uploads,
    })
}

fn bucket_name(url: &str) -> Result<&str> {
    let (_, rest) = url.split_once("://").context("remote URL has no scheme")?;
    let bucket = rest.split('/').next().unwrap_or(rest);
    ensure!(!bucket.is_empty(), "remote URL has no bucket");
    Ok(bucket)
}

fn bucket_id(bucket: &str) -> String {
    sha256_hex(bucket.as_bytes())[..16].to_string()
}

fn staging_id(url: &str) -> String {
    sha256_hex(url.as_bytes())[..16].to_string()
}

fn publisher_state_dir(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if let Some(path) = std::env::var_os("EPICENTER_PUBLISHER_STATE")
        && !path.is_empty()
    {
        return Ok(PathBuf::from(path));
    }
    Ok(crate::paths::state_dir()?.join("publisher"))
}

fn key_path(state_dir: &Path, bucket: &str) -> PathBuf {
    state_dir.join(format!("publisher-{}.key", bucket_id(bucket)))
}

fn resolve_identity(
    state_dir: &Path,
    bucket: &str,
    current_key_id: Option<&str>,
    expected_key_id: Option<&str>,
    rotate: bool,
) -> Result<PublisherIdentity> {
    crate::util::create_private_dir_all(state_dir)?;
    let path = key_path(state_dir, bucket);

    if rotate {
        ensure!(
            expected_key_id.is_none(),
            "`--rotate-key` and `--expect-key-id` are mutually exclusive; rotate first, then \
             update the pin"
        );
        let identity = new_identity()?;
        write_key(&path, &identity.key, true)?;
        return Ok(identity);
    }

    match read_key(&path) {
        Ok(key) => {
            let identity = identity_from_key(key, false);
            validate_identity_pin(&identity, &path, current_key_id, expected_key_id)?;
            Ok(identity)
        }
        Err(err) if crate::util::is_not_found(&err) => {
            ensure!(
                current_key_id.is_none() && expected_key_id.is_none(),
                "publisher identity {} is missing, but {}; mount the publisher state directory \
                 on persistent private storage, set EPICENTER_PUBLISHER_STATE, or pass \
                 --rotate-key and re-pin readers",
                path.display(),
                current_key_id
                    .map(|key| format!("the existing index is signed by {key}"))
                    .or_else(|| expected_key_id.map(|key| format!("readers pin {key}")))
                    .unwrap_or_else(|| "a publisher identity is required".to_string())
            );
            let identity = new_identity()?;
            let created = write_key(&path, &identity.key, false)?;
            // If another publisher won the create race, its key is the
            // identity that the index must use.
            let key = read_key(&path)?;
            let identity = identity_from_key(key, created);
            validate_identity_pin(&identity, &path, current_key_id, expected_key_id)?;
            Ok(identity)
        }
        Err(err) => {
            Err(err).with_context(|| format!("reading publisher identity {}", path.display()))
        }
    }
}

fn validate_identity_pin(
    identity: &PublisherIdentity,
    path: &Path,
    current_key_id: Option<&str>,
    expected_key_id: Option<&str>,
) -> Result<()> {
    if let Some(expected) = expected_key_id {
        ensure!(
            identity.key_id == expected,
            "publisher key {} is {}, but the configured pin is {expected}; refusing to sign \
             with an unexpected identity",
            path.display(),
            identity.key_id
        );
    }
    if let Some(current) = current_key_id {
        ensure!(
            identity.key_id == current,
            "publisher key {} is {}, but the existing index is signed by {current}; restore the \
             publisher state directory or pass --rotate-key and re-pin readers",
            path.display(),
            identity.key_id
        );
    }
    Ok(())
}

fn identity_from_key(key: SigningKey, created: bool) -> PublisherIdentity {
    let public_key = crate::vault::hex_encode(&key.verifying_key().to_bytes());
    let key_id = settings::remote_key_id(&public_key).expect("valid Ed25519 public key");
    PublisherIdentity {
        key,
        public_key,
        key_id,
        created,
    }
}

fn new_identity() -> Result<PublisherIdentity> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|err| anyhow::anyhow!("generating the publisher key: {err}"))?;
    let key = SigningKey::from_bytes(&seed);
    let public_key = crate::vault::hex_encode(&key.verifying_key().to_bytes());
    let key_id = settings::remote_key_id(&public_key)?;
    Ok(PublisherIdentity {
        key,
        public_key,
        key_id,
        created: true,
    })
}

fn read_key(path: &Path) -> Result<SigningKey> {
    let text = crate::util::read_private_text(path, MAX_PUBLISHER_KEY_BYTES)?;
    let bytes = crate::vault::hex_decode(text.trim(), "publisher private key")?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("publisher private key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn write_key(path: &Path, key: &SigningKey, replace: bool) -> Result<bool> {
    if let Some(parent) = path.parent() {
        crate::util::create_private_dir_all(parent)?;
    }
    let text = format!("{}\n", crate::vault::hex_encode(&key.to_bytes()));
    if replace {
        crate::util::write_atomic_private(path, text.as_bytes())?;
        return Ok(true);
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(text.as_bytes())
                .with_context(|| format!("writing publisher identity {}", path.display()))?;
            file.sync_all()
                .with_context(|| format!("syncing publisher identity {}", path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(fs::Permissions::from_mode(0o600))
                    .with_context(|| format!("securing publisher identity {}", path.display()))?;
            }
            Ok(true)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            // Two publishers raced. The winner's key is the identity.
            Ok(false)
        }
        Err(err) => {
            Err(err).with_context(|| format!("creating publisher identity {}", path.display()))
        }
    }
}

fn read_current_pointer(out_dir: &Path) -> Result<Option<IndexPointer>> {
    let path = out_dir.join(super::INDEX_FILE);
    if crate::util::probe_file(&path, "staged index")?.is_none() {
        return Ok(None);
    }
    let bytes = read_capped(&path, super::MAX_INDEX_POINTER_BYTES, "index pointer")?;
    let pointer: IndexPointer =
        serde_json::from_slice(&bytes).context("parsing the staged index pointer")?;
    pointer.validate_shape()?;
    Ok(Some(pointer))
}

fn choose_sequence(explicit: Option<u64>, current: Option<&IndexPointer>) -> Result<u64> {
    let next = current
        .map(|pointer| {
            pointer
                .sequence
                .checked_add(1)
                .context("remote index sequence overflow")
        })
        .transpose()?
        .unwrap_or(1);
    match explicit {
        Some(sequence) => {
            ensure!(sequence > 0, "sequence must start at 1");
            if let Some(current) = current {
                ensure!(
                    sequence > current.sequence,
                    "sequence {sequence} would not advance past the staged sequence {}",
                    current.sequence
                );
            }
            Ok(sequence)
        }
        None => Ok(next),
    }
}

struct Selection {
    units: Vec<PublishUnit>,
    skipped_workspace: usize,
    skipped_tier: usize,
}

fn select_units(
    stored_units: Vec<StoredUnit>,
    generation: &str,
    profile: Option<&str>,
    tier: RemoteTier,
    lock: &LockIndex,
) -> Result<Selection> {
    let mut units = Vec::new();
    let mut skipped_workspace = 0usize;
    let mut skipped_tier = 0usize;
    let mut profiles = HashSet::new();

    for stored in stored_units {
        if stored.generation != generation {
            continue;
        }
        let store_root = stored.store_root.as_path();
        if let Some(profile) = profile
            && stored.entry.profile != profile
        {
            continue;
        }
        let unit_dir = crate::util::metadata_nofollow(&stored.dir)
            .with_context(|| format!("inspecting stored unit {}", stored.dir.display()))?;
        ensure!(
            unit_dir.is_dir(),
            "stored unit {} is not a real directory",
            stored.dir.display()
        );

        let kind = RemoteUnitKind::from(fingerprint::classify_kind(&stored.entry.memo));
        if kind == RemoteUnitKind::Other
            || (tier == RemoteTier::Libraries && kind != RemoteUnitKind::Lib)
        {
            skipped_tier += 1;
            continue;
        }

        let package = stored
            .entry
            .name
            .rsplit_once('-')
            .map(|(package, _)| package)
            .unwrap_or(stored.entry.name.as_str());
        let source = match lock.resolve(package, stored.entry.version.as_deref())? {
            Some(LockSource::Registry { index, checksum }) => UnitSource {
                kind: SourceKind::Registry,
                id: index,
                checksum: Some(checksum),
            },
            Some(LockSource::Git { id }) => UnitSource {
                kind: SourceKind::Git,
                id,
                checksum: None,
            },
            Some(LockSource::Path) | None => {
                skipped_workspace += 1;
                continue;
            }
        };

        let json_name = format!("{}.json", stored.entry.memo);
        let json_path = stored.dir.join(&json_name);
        let json_rel = Path::new(&stored.generation)
            .join("units")
            .join(&stored.entry.name)
            .join(&json_name);
        crate::util::check_regular_chain(store_root, &json_rel)?;
        let text = crate::util::read_small_text(&json_path, 1024 * 1024)
            .with_context(|| format!("reading stored fingerprint {}", json_path.display()))?;
        let fingerprint = fingerprint::parse_fingerprint(&text)
            .with_context(|| format!("parsing stored fingerprint {}", json_path.display()))?;
        let compat = super::UnitCompatibility::from_fingerprint(&fingerprint);

        let mut files = Vec::new();
        for file in &stored.entry.files {
            let role = FileRole::try_from(file.role.as_str())
                .with_context(|| format!("unit {}", stored.entry.name))?;
            let (source_path, blob) = blob_for_file(store_root, &stored, file)?;
            files.push((
                RemoteFile {
                    path: file.path.clone(),
                    dest: file.dest.clone(),
                    size: file.size,
                    sha256: file.sha256.clone(),
                    role,
                    blob: blob.blob,
                    blob_size: blob.blob_size,
                    compression: blob.compression,
                },
                source_path,
            ));
        }
        files.sort_by(|left, right| left.0.path.cmp(&right.0.path));

        let (files, sources): (Vec<_>, Vec<_>) = files.into_iter().unzip();
        let remote = RemoteUnit {
            name: stored.entry.name.clone(),
            package: package.to_string(),
            version: stored.entry.version.clone(),
            profile: stored.entry.profile.clone(),
            memo: stored.entry.memo.clone(),
            hash: stored.entry.hash.clone(),
            stamp: stored.entry.stamp,
            layout: stored.entry.layout(),
            kind,
            source,
            compat,
            files,
        };
        if tier == RemoteTier::Libraries && remote.is_executable() {
            skipped_tier += 1;
            continue;
        }
        profiles.insert(remote.profile.clone());
        units.push(PublishUnit { remote, sources });
    }

    ensure!(
        profiles.len() <= 1,
        "generation {generation} has multiple profiles ({}); pass --profile to publish one",
        profiles.into_iter().collect::<Vec<_>>().join(", ")
    );
    units.sort_by(|left, right| left.remote.name.cmp(&right.remote.name));
    Ok(Selection {
        units,
        skipped_workspace,
        skipped_tier,
    })
}

fn blob_for_file(
    store_root: &Path,
    stored: &StoredUnit,
    file: &vault::FileEntry,
) -> Result<(PathBuf, BlobRef)> {
    if let Some(object) = &file.object {
        let source = store_root.join(&stored.generation).join(object);
        let object_rel = Path::new(&stored.generation).join(object);
        crate::util::check_regular_chain(store_root, &object_rel)?;
        let (decoded_size, decoded_hash) =
            crate::util::decompress_file_hashed(&source, false, file.size)
                .with_context(|| format!("verifying stored blob {}", source.display()))?;
        ensure!(
            decoded_size == file.size && decoded_hash == file.sha256,
            "stored blob {} does not match its recorded decoded size/hash",
            source.display()
        );
        let blob = crate::util::sha256_file(&source)?;
        let blob_size = crate::util::metadata_nofollow(&source)?.len();
        ensure!(
            blob_size > 0 && blob_size < file.size,
            "stored gzip blob {} is not smaller than its decoded size",
            source.display()
        );
        Ok((
            source,
            BlobRef {
                blob,
                blob_size,
                sha256: file.sha256.clone(),
                size: file.size,
                compression: Compression::Gzip,
            },
        ))
    } else {
        let source = stored.dir.join(&file.path);
        let rel = Path::new(&stored.generation)
            .join("units")
            .join(&stored.entry.name)
            .join(&file.path);
        crate::util::check_regular_chain(store_root, &rel)?;
        crate::util::verify_file_hash(&source, file.size, &file.sha256, "stored file")?;
        Ok((
            source,
            BlobRef {
                blob: file.sha256.clone(),
                blob_size: file.size,
                sha256: file.sha256.clone(),
                size: file.size,
                compression: Compression::Raw,
            },
        ))
    }
}

fn stage_blobs(out_dir: &Path, units: &[PublishUnit]) -> Result<()> {
    let mut seen = HashSet::new();
    for unit in units {
        for (file, source) in unit.remote.files.iter().zip(&unit.sources) {
            if !seen.insert(file.blob.as_str()) {
                continue;
            }
            let destination = super::blob_path(out_dir, &file.blob)?;
            stage_object(source, &destination, file.blob_size, &file.blob)?;
        }
    }
    Ok(())
}

fn stage_object(src: &Path, dst: &Path, size: u64, hash: &str) -> Result<()> {
    if crate::util::probe_file(dst, "staged blob")?.is_some() {
        return verify_object(dst, size, hash);
    }
    if let Some(parent) = dst.parent() {
        crate::util::create_private_dir_all(parent)?;
    }
    match fs::hard_link(src, dst) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => match crate::util::copy_file_verified_unowned(src, dst, size, hash) {
            Ok(_) => {}
            Err(err)
                if crate::util::io_error(&err)
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists) => {}
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("staging blob {} -> {}", src.display(), dst.display())
                });
            }
        },
    }
    verify_object(dst, size, hash)
}

fn verify_object(path: &Path, size: u64, hash: &str) -> Result<()> {
    crate::util::verify_file_hash(path, size, hash, "staged blob")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::UnitLayout;
    use std::fs;

    fn package_dir(root: &Path, generation: &str, name: &str) -> PathBuf {
        root.join(generation).join("units").join(name)
    }

    fn write_unit(root: &Path, generation: &str, name: &str, memo: &str) -> PathBuf {
        let dir = package_dir(root, generation, name);
        fs::create_dir_all(&dir).unwrap();
        let json = serde_json::json!({
            "rustc": "1",
            "features": "[]",
            "declared_features": "[]",
            "target": "2",
            "profile": "3",
            "path": "4",
            "config": "5",
            "deps": [],
            "rustflags": [],
            "compile_kind": "0"
        });
        fs::write(dir.join(format!("{memo}.json")), json.to_string()).unwrap();
        fs::write(dir.join(memo), b"aabbccddeeff0011").unwrap();
        dir
    }

    fn file_entry(path: &str, role: &str, bytes: &[u8]) -> vault::FileEntry {
        vault::FileEntry {
            path: path.to_string(),
            dest: format!("deps/{path}"),
            size: bytes.len() as u64,
            sha256: sha256_hex(bytes),
            role: role.to_string(),
            object: None,
        }
    }

    fn stored_unit(
        root: &Path,
        generation: &str,
        name: &str,
        memo: &str,
        files: Vec<vault::FileEntry>,
    ) -> StoredUnit {
        StoredUnit {
            generation: generation.to_string(),
            entry: vault::UnitEntry {
                name: name.to_string(),
                profile: "debug".to_string(),
                memo: memo.to_string(),
                hash: "aabbccddeeff0011".to_string(),
                version: Some("1.0.0".to_string()),
                stamp: 1,
                layout: Some(UnitLayout::Classic),
                files,
            },
            dir: package_dir(root, generation, name),
            store_root: root.to_path_buf(),
        }
    }

    #[test]
    fn select_units_skips_workspace_and_respects_tiers() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        let generation = "gen";
        let lib_name = "serde-0011223344556677";
        let lib_dir = write_unit(root, generation, lib_name, "lib-serde");
        fs::write(lib_dir.join("libserde.rlib"), b"rlib")?;
        let lib = stored_unit(
            root,
            generation,
            lib_name,
            "lib-serde",
            vec![file_entry("libserde.rlib", "artifact", b"rlib")],
        );

        let build_name = "serde-8899aabbccddeeff";
        let build_dir = write_unit(root, generation, build_name, "build-script-build");
        fs::write(build_dir.join("build-script-build"), b"bin")?;
        let mut build = stored_unit(
            root,
            generation,
            build_name,
            "build-script-build",
            vec![file_entry("build-script-build", "artifact", b"bin")],
        );
        build.entry.version = lib.entry.version.clone();

        let local_name = "local-1111222233334444";
        let local_dir = write_unit(root, generation, local_name, "lib-local");
        fs::write(local_dir.join("liblocal.rlib"), b"local")?;
        let local = stored_unit(
            root,
            generation,
            local_name,
            "lib-local",
            vec![file_entry("liblocal.rlib", "artifact", b"local")],
        );

        let lock_path = root.join("Cargo.lock");
        fs::write(
            &lock_path,
            "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"abababababababababababababababababababababababababababababababab\"\n",
        )?;
        let lock = LockIndex::parse(&lock_path).expect("lock parses");

        let libraries = select_units(
            vec![lib.clone(), build.clone(), local.clone()],
            generation,
            None,
            RemoteTier::Libraries,
            &lock,
        )?;
        assert_eq!(libraries.units.len(), 1);
        assert_eq!(libraries.units[0].remote.name, lib_name);
        assert_eq!(libraries.skipped_tier, 1);
        assert_eq!(libraries.skipped_workspace, 1);

        let full = select_units(
            vec![lib, build, local],
            generation,
            None,
            RemoteTier::Full,
            &lock,
        )?;
        assert_eq!(full.units.len(), 2);
        assert_eq!(full.skipped_workspace, 1);
        assert!(
            full.units
                .iter()
                .any(|unit| unit.remote.kind == RemoteUnitKind::BuildScript)
        );
        Ok(())
    }

    #[test]
    fn identity_is_created_once_and_refuses_silent_rotation() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let first = resolve_identity(dir.path(), "bucket", None, None, false)?;
        assert!(first.created);
        let second = resolve_identity(dir.path(), "bucket", Some(&first.key_id), None, false)?;
        assert!(!second.created);
        assert_eq!(first.key_id, second.key_id);

        let rotated = resolve_identity(dir.path(), "bucket", Some(&first.key_id), None, true)?;
        assert!(rotated.created);
        assert_ne!(rotated.key_id, first.key_id);
        let third = resolve_identity(dir.path(), "bucket", Some(&rotated.key_id), None, false)?;
        assert_eq!(third.key_id, rotated.key_id);

        let other = tempfile::tempdir()?;
        let err = resolve_identity(other.path(), "bucket", Some(&first.key_id), None, false)
            .err()
            .expect("a missing identity with an existing pin must fail");
        assert!(format!("{err:#}").contains("missing"), "{err:#}");
        Ok(())
    }

    #[test]
    fn sequence_advances_or_refuses_rollback() {
        let pointer = IndexPointer {
            schema: SCHEMA_VERSION,
            key_id: "ed25519:0000000000000000".to_string(),
            sequence: 7,
            created: 1,
            expires: 2,
            body_sha256: "00".repeat(32),
            body_size: 1,
            signature: String::new(),
        };
        assert_eq!(choose_sequence(None, Some(&pointer)).unwrap(), 8);
        assert!(choose_sequence(Some(7), Some(&pointer)).is_err());
        assert_eq!(choose_sequence(Some(9), Some(&pointer)).unwrap(), 9);
    }

    #[test]
    fn raw_blob_is_the_decoded_hash_and_gzip_reuses_the_store_object() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        let generation = "gen";
        let name = "serde-0011223344556677";
        let unit_dir = write_unit(root, generation, name, "lib-serde");
        fs::write(unit_dir.join("libserde.rlib"), b"rlib")?;
        let entry = stored_unit(
            root,
            generation,
            name,
            "lib-serde",
            vec![file_entry("libserde.rlib", "artifact", b"rlib")],
        );
        let (source, blob) = blob_for_file(root, &entry, &entry.entry.files[0])?;
        assert_eq!(blob.compression, Compression::Raw);
        assert_eq!(blob.blob, sha256_hex(b"rlib"));
        assert_eq!(source, unit_dir.join("libserde.rlib"));

        use flate2::Compression as GzipLevel;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let payload = vec![b'a'; 8192];
        let mut encoder = GzEncoder::new(Vec::new(), GzipLevel::fast());
        encoder.write_all(&payload)?;
        let gz = encoder.finish()?;
        let object = "blobs/aa/0011223344556677.gz";
        let object_path = root.join(generation).join(object);
        fs::create_dir_all(object_path.parent().unwrap())?;
        fs::write(&object_path, &gz)?;
        let compressed = stored_unit(
            root,
            generation,
            "zip-0011223344556677",
            "lib-zip",
            vec![vault::FileEntry {
                path: "libzip.rlib".to_string(),
                dest: "deps/libzip.rlib".to_string(),
                size: payload.len() as u64,
                sha256: sha256_hex(&payload),
                role: "artifact".to_string(),
                object: Some(object.to_string()),
            }],
        );
        let (source, blob) = blob_for_file(root, &compressed, &compressed.entry.files[0])?;
        assert_eq!(blob.compression, Compression::Gzip);
        assert_eq!(blob.sha256, sha256_hex(&payload));
        assert_eq!(blob.blob, sha256_hex(&gz));
        assert_eq!(blob.blob_size, gz.len() as u64);
        assert_eq!(source, object_path);
        Ok(())
    }

    #[test]
    fn fingerprint_json_is_available_from_the_store_copy() {
        let json = r#"{"rustc":1,"features":"[]","declared_features":"[]","target":2,
            "profile":3,"path":4,"config":5,"deps":[],"rustflags":[],"compile_kind":0}"#;
        assert!(fingerprint::parse_fingerprint(json).is_some());
    }

    #[test]
    fn publishes_a_store_generation_end_to_end() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = temp.path().join("store");
        let generation = "gen";
        let name = "serde-0011223344556677";
        let unit_dir = package_dir(&store, generation, name);
        fs::create_dir_all(&unit_dir)?;

        let json = br#"{"rustc":1,"features":"[]","declared_features":"[]","target":2,"profile":3,"path":4,"config":5,"deps":[],"rustflags":[],"compile_kind":0}"#;
        let memo = b"aabbccddeeff0011";
        let rlib = b"rlib";
        fs::write(unit_dir.join("lib-serde.json"), json)?;
        fs::write(unit_dir.join("lib-serde"), memo)?;
        fs::write(unit_dir.join("libserde.rlib"), rlib)?;

        let files = vec![
            vault::FileEntry {
                path: "lib-serde.json".to_string(),
                dest: format!(".fingerprint/{name}/lib-serde.json"),
                size: json.len() as u64,
                sha256: sha256_hex(json),
                role: "fingerprint".to_string(),
                object: None,
            },
            vault::FileEntry {
                path: "lib-serde".to_string(),
                dest: format!(".fingerprint/{name}/lib-serde"),
                size: memo.len() as u64,
                sha256: sha256_hex(memo),
                role: "memo".to_string(),
                object: None,
            },
            vault::FileEntry {
                path: "libserde.rlib".to_string(),
                dest: "deps/libserde.rlib".to_string(),
                size: rlib.len() as u64,
                sha256: sha256_hex(rlib),
                role: "artifact".to_string(),
                object: None,
            },
        ];
        let manifest = vault::Manifest {
            parity_key: generation.to_string(),
            toolchain: "rustc 1.91.0 (test)".to_string(),
            created: 1,
            updated: 1,
            units: vec![vault::UnitEntry {
                name: name.to_string(),
                profile: "debug".to_string(),
                memo: "lib-serde".to_string(),
                hash: "aabbccddeeff0011".to_string(),
                version: Some("1.0.0".to_string()),
                stamp: 1,
                layout: Some(UnitLayout::Classic),
                files,
            }],
            mac: String::new(),
            signature: String::new(),
        };
        vault::save_manifest(&store, generation, &manifest)?;

        let lock_path = temp.path().join("Cargo.lock");
        fs::write(
            &lock_path,
            "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"abababababababababababababababababababababababababababababababab\"\n",
        )?;

        let out_dir = temp.path().join("out");
        let publisher_state = temp.path().join("publisher");
        let request = PublishRequest {
            store_root: &store,
            cwd: temp.path(),
            url: "s3://bucket/prefix",
            tier: RemoteTier::Libraries,
            generation: Some(generation),
            profile: Some("debug"),
            selector: None,
            sequence: None,
            current_pointer: None,
            valid_for: Duration::from_secs(3_600),
            source_commit: "0123456789abcdef0123456789abcdef01234567",
            ci_job: "ci/test",
            notes: "",
            expect_key_id: None,
            rotate_key: false,
            publisher_state: Some(&publisher_state),
            out_dir: Some(&out_dir),
            lockfile: Some(&lock_path),
        };
        let first = publish(&request)?;
        assert_eq!(first.units, 1);
        assert_eq!(first.files, 3);
        assert_eq!(first.index.pointer().sequence, 1);
        assert_eq!(
            first.uploads.last().map(|upload| upload.key.as_str()),
            Some("index.json")
        );
        assert!(first.identity_created);

        let second = publish(&request)?;
        assert_eq!(second.index.pointer().sequence, 2);
        assert_eq!(second.index.pointer().key_id, first.index.pointer().key_id);
        assert!(!second.identity_created);
        Ok(())
    }
}
