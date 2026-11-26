//! Install verified remote unit groups into a local generation.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::fingerprint;
use crate::util::{self, metadata_nofollow, now_secs};

use super::harvest::{make_read_only, set_stamp, sweep_staging};
use super::layout::{
    GENERATION_MARKER, ensure_store_root, lock_generation, units_dir, write_marker,
};
use super::manifest::{FileEntry, Manifest, UnitEntry, load_manifest, save_manifest};

// ── remote import ───────────────────────────────────────────────────────────

/// Where a remote file's verified bytes live locally.
pub enum ImportSource {
    /// Already decoded bytes (the cache blob for a `none` compression).
    Raw(PathBuf),
    /// Stored gzip bytes; the decoded size/hash are in the index.
    Gzip(PathBuf),
}

/// One verified file to install into a vault generation.
pub struct ImportFile {
    pub path: String,
    pub dest: String,
    pub size: u64,
    pub sha256: String,
    pub role: String,
    pub source: ImportSource,
}

/// One verified unit group to install into a vault generation.
pub struct ImportUnit {
    pub name: String,
    pub profile: String,
    pub memo: String,
    pub hash: String,
    pub version: Option<String>,
    pub stamp: u64,
    pub layout: fingerprint::UnitLayout,
    pub files: Vec<ImportFile>,
}

/// What one import did.
#[derive(Debug, Default)]
pub struct ImportReport {
    pub stored: usize,
    pub skipped: usize,
    pub files: usize,
    pub bytes: u64,
}

/// Install verified remote units into one generation.
///
/// The caller has already verified the signed index and every file hash. This
/// writer is the only step that touches the local vault: it stages complete
/// unit groups under hidden names, stamps raw files to the unit stamp, keeps
/// the store read-only, preserves gzip objects under the local decoded-hash
/// path, merges the manifest once and re-signs it with the local key.
///
/// An existing identical unit is skipped. A conflicting local unit or a
/// destination already owned by another unit keeps the local copy and is
/// reported as skipped; import never overwrites a local unit.
pub fn import_units(
    store_root: &Path,
    generation: &str,
    toolchain: &str,
    units: &[ImportUnit],
) -> Result<ImportReport> {
    util::validate_component(generation, "generation")?;
    if units.is_empty() {
        return Ok(ImportReport::default());
    }
    ensure_store_root(store_root)?;
    let generation_root = store_root.join(generation);
    util::create_private_dir_all(&generation_root)?;
    write_marker(&generation_root.join(GENERATION_MARKER))?;
    let units_root = units_dir(store_root, generation);
    util::create_private_dir_all(&units_root)?;
    let _lock = lock_generation(store_root, generation)?;
    sweep_staging(&units_root)?;

    let loaded = load_manifest(store_root, generation)?;
    let had_manifest = loaded.is_some();
    let mut manifest = loaded.unwrap_or_else(|| Manifest {
        parity_key: generation.to_string(),
        toolchain: toolchain.to_string(),
        created: now_secs(),
        updated: 0,
        units: Vec::new(),
        mac: String::new(),
        signature: String::new(),
    });
    if manifest.toolchain.is_empty() {
        manifest.toolchain = toolchain.to_string();
    }

    // Match the manifest's case-insensitive identity: a differently-cased
    // name is the same unit on the filesystems the store targets.
    let mut index: std::collections::HashMap<String, usize> = manifest
        .units
        .iter()
        .enumerate()
        .map(|(at, entry)| (unit_identity(&entry.name), at))
        .collect();
    let mut owners: std::collections::HashMap<String, String> = manifest
        .units
        .iter()
        .flat_map(|entry| {
            entry.files.iter().map(move |file| {
                (
                    import_dest_key(&entry.profile, &file.dest),
                    entry.name.clone(),
                )
            })
        })
        .collect();
    let mut report = ImportReport::default();
    let mut renamed: Vec<PathBuf> = Vec::new();

    let result = (|| -> Result<()> {
        for unit in units {
            let entry = import_entry(unit)?;

            if let Some(&slot) = index.get(&unit_identity(&unit.name)) {
                if same_import_unit(&manifest.units[slot], &entry) {
                    report.skipped += 1;
                } else {
                    eprintln!(
                        "import: keeping local unit {} (remote copy differs)",
                        unit.name
                    );
                    report.skipped += 1;
                }
                continue;
            }
            if entry.files.iter().any(|file| {
                owners
                    .get(&import_dest_key(&entry.profile, &file.dest))
                    .is_some_and(|owner| owner != &entry.name)
            }) {
                eprintln!(
                    "import: skipping unit {} (destination already owned by another unit)",
                    unit.name
                );
                report.skipped += 1;
                continue;
            }

            let stage = units_root.join(format!(
                ".{}.import.tmp-{}-{}",
                unit.name,
                std::process::id(),
                util::temp_nonce()
            ));
            util::create_private_dir_all(&stage)?;
            let final_dir = units_root.join(&unit.name);
            let installed = (|| -> Result<()> {
                for file in &unit.files {
                    let rel = util::validate_rel(&file.path, "import file path")?;
                    let dst = stage.join(&rel);
                    if let Some(parent) = dst.parent() {
                        util::create_private_dir_all(parent)?;
                    }
                    match &file.source {
                        ImportSource::Raw(src) => {
                            install_import_raw(&dst, src, file.size, &file.sha256, unit.stamp)?;
                        }
                        ImportSource::Gzip(src) => {
                            let object = install_import_blob(
                                &generation_root,
                                &file.sha256,
                                file.size,
                                src,
                            )?;
                            let src_object = generation_root.join(&object);
                            match fs::hard_link(&src_object, &dst) {
                                Ok(()) => {}
                                Err(_) => {
                                    fs::copy(&src_object, &dst).with_context(|| {
                                        format!(
                                            "linking {} -> {}",
                                            src_object.display(),
                                            dst.display()
                                        )
                                    })?;
                                    make_read_only(&dst)?;
                                }
                            }
                        }
                    }
                }

                match metadata_nofollow(&final_dir) {
                    Ok(meta) if meta.is_dir() => util::remove_tree(store_root, &final_dir)?,
                    Ok(_) => anyhow::bail!(
                        "import target {} is not a real directory",
                        final_dir.display()
                    ),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => {
                        return Err(err)
                            .with_context(|| format!("inspecting {}", final_dir.display()));
                    }
                }
                fs::rename(&stage, &final_dir)
                    .with_context(|| format!("installing imported unit {}", final_dir.display()))?;
                Ok(())
            })();
            if let Err(err) = installed {
                let _ = util::remove_tree(store_root, &stage);
                return Err(err).with_context(|| format!("importing unit {}", unit.name));
            }
            renamed.push(final_dir);

            for file in &entry.files {
                owners.insert(
                    import_dest_key(&entry.profile, &file.dest),
                    entry.name.clone(),
                );
            }
            report.files += entry.files.len();
            report.bytes = report
                .bytes
                .saturating_add(entry.files.iter().map(|file| file.size).sum::<u64>());
            report.stored += 1;
            index.insert(unit_identity(&entry.name), manifest.units.len());
            manifest.units.push(entry);
        }

        if report.stored > 0 {
            manifest.units.sort_by(|a, b| {
                (a.profile.as_str(), a.name.as_str()).cmp(&(b.profile.as_str(), b.name.as_str()))
            });
            manifest.updated = now_secs();
            save_manifest(store_root, generation, &manifest)?;
        }
        Ok(())
    })();

    if let Err(err) = result {
        for dir in renamed.iter().rev() {
            let _ = util::remove_tree(store_root, dir);
        }
        if !had_manifest {
            // Keep the generation lock through cleanup: a concurrent import
            // must not save a manifest this failed import then deletes.
            let _ = util::remove_tree(store_root, &generation_root);
        }
        return Err(err);
    }
    if !had_manifest && report.stored == 0 {
        let _ = util::remove_tree(store_root, &generation_root);
    }
    Ok(report)
}

/// Units that are not in the target generation yet. A same-name entry counts
/// as present even when its content differs: import keeps the local copy, so
/// there is nothing to fetch for it.
pub fn missing_import_units(
    store_root: &Path,
    generation: &str,
    units: &[ImportUnit],
) -> Result<Vec<usize>> {
    if units.is_empty() || !store_root.exists() {
        return Ok((0..units.len()).collect());
    }
    let Some(manifest) = load_manifest(store_root, generation)? else {
        return Ok((0..units.len()).collect());
    };
    let present: std::collections::HashSet<&str> = manifest
        .units
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    Ok(units
        .iter()
        .enumerate()
        .filter(|(_, unit)| !present.contains(unit.name.as_str()))
        .map(|(at, _)| at)
        .collect())
}

fn import_entry(unit: &ImportUnit) -> Result<UnitEntry> {
    let mut entry = UnitEntry {
        name: unit.name.clone(),
        profile: unit.profile.clone(),
        memo: unit.memo.clone(),
        hash: unit.hash.clone(),
        version: unit.version.clone(),
        stamp: unit.stamp,
        layout: Some(unit.layout),
        files: Vec::with_capacity(unit.files.len()),
    };
    for file in &unit.files {
        anyhow::ensure!(
            file.sha256.len() == 64 && file.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "import file {} has an invalid SHA-256",
            file.path
        );
        entry.files.push(FileEntry {
            path: file.path.clone(),
            dest: file.dest.clone(),
            size: file.size,
            sha256: file.sha256.clone(),
            role: file.role.clone(),
            object: match file.source {
                ImportSource::Gzip(_) => {
                    Some(format!("blobs/{}/{}.gz", &file.sha256[..2], file.sha256))
                }
                ImportSource::Raw(_) => None,
            },
        });
    }
    entry.validate()?;
    Ok(entry)
}

fn unit_identity(name: &str) -> String {
    name.to_lowercase()
}

fn import_dest_key(profile: &str, dest: &str) -> String {
    format!(
        "{}/{}",
        profile.to_ascii_lowercase(),
        dest.to_ascii_lowercase()
    )
}

fn same_import_unit(left: &UnitEntry, right: &UnitEntry) -> bool {
    if left.hash != right.hash
        || left.profile != right.profile
        || left.memo != right.memo
        || left.stamp != right.stamp
    {
        return false;
    }
    let files = |entry: &UnitEntry| {
        let mut files: Vec<_> = entry
            .files
            .iter()
            .map(|file| {
                (
                    file.path.clone(),
                    file.dest.clone(),
                    file.size,
                    file.sha256.clone(),
                    file.role.clone(),
                )
            })
            .collect();
        files.sort();
        files
    };
    files(left) == files(right)
}

fn install_import_raw(dst: &Path, src: &Path, size: u64, sha256: &str, stamp: u64) -> Result<()> {
    let parent = dst.parent().context("import destination has no parent")?;
    let mut input = util::open_regular(src, false)
        .with_context(|| format!("opening imported file {}", src.display()))?;
    let (tmp, ()) = util::with_temp_file(parent, "import", "", 0o600, |output| {
        util::copy_verified(&mut input, output, size, sha256, src)?;
        output.flush()?;
        output.sync_all()?;
        Ok(())
    })?;
    if let Err(err) = fs::rename(&tmp, dst) {
        let _ = fs::remove_file(&tmp);
        return Err(err).with_context(|| format!("installing {}", dst.display()));
    }
    set_stamp(dst, stamp)?;
    make_read_only(dst)?;
    Ok(())
}

fn install_import_blob(
    generation_root: &Path,
    sha256: &str,
    size: u64,
    src: &Path,
) -> Result<String> {
    let object = format!("blobs/{}/{}.gz", &sha256[..2], sha256);
    let final_path = generation_root.join(&object);
    if metadata_nofollow(&final_path).is_ok() {
        verify_import_blob(&final_path, size, sha256)?;
        return Ok(object);
    }
    let parent = final_path
        .parent()
        .context("import blob path has no parent")?;
    util::create_private_dir_all(parent)?;
    let mut input = util::open_regular(src, false)
        .with_context(|| format!("opening imported blob {}", src.display()))?;
    let (tmp, ()) = util::with_temp_file(parent, "import-blob", ".gz", 0o600, |output| {
        util::copy_capped(&mut input, output, util::MAX_FILE_BYTES, src)?;
        output.flush()?;
        output.sync_all()?;
        Ok(())
    })?;
    if let Err(err) = verify_import_blob(&tmp, size, sha256) {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    match fs::hard_link(&tmp, &final_path) {
        Ok(()) => {
            let _ = fs::remove_file(&tmp);
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&tmp);
            verify_import_blob(&final_path, size, sha256)?;
        }
        Err(_) => {
            if final_path.exists() {
                let _ = fs::remove_file(&tmp);
                verify_import_blob(&final_path, size, sha256)?;
            } else if let Err(err) = fs::rename(&tmp, &final_path) {
                let _ = fs::remove_file(&tmp);
                return Err(err)
                    .with_context(|| format!("installing imported blob {}", final_path.display()));
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file = util::open_regular(&final_path, false)?;
        file.set_permissions(fs::Permissions::from_mode(0o444))?;
    }
    Ok(object)
}

fn verify_import_blob(path: &Path, size: u64, sha256: &str) -> Result<()> {
    let (found_size, found_hash) = util::decompress_file_hashed(path, true, size)?;
    anyhow::ensure!(
        found_size == size && found_hash == sha256,
        "imported blob {} does not match its signed size/SHA-256",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn raw_unit(
        name: &str,
        memo: &str,
        dest: &str,
        body: &[u8],
        source: &Path,
    ) -> Result<ImportUnit> {
        let file = source.join(memo);
        fs::write(&file, body)?;
        Ok(ImportUnit {
            name: name.into(),
            profile: "debug".into(),
            memo: memo.into(),
            hash: "aabbccddeeff0011".into(),
            version: None,
            stamp: now_secs(),
            layout: fingerprint::UnitLayout::Classic,
            files: vec![ImportFile {
                path: memo.into(),
                dest: dest.into(),
                size: body.len() as u64,
                sha256: crate::vault::hex_encode(&Sha256::digest(body)),
                role: "memo".into(),
                source: ImportSource::Raw(file),
            }],
        })
    }

    #[test]
    fn failed_final_install_removes_the_staged_unit() -> Result<()> {
        let store = tempfile::tempdir()?;
        let source = tempfile::tempdir()?;
        let first = raw_unit(
            "first-0000000000000001",
            "lib-first",
            "deps/libfirst",
            b"first",
            source.path(),
        )?;
        import_units(store.path(), "generation", "test", &[first])?;

        let units_root = units_dir(store.path(), "generation");
        fs::write(units_root.join("second-0000000000000002"), b"occupied")?;
        let second = raw_unit(
            "second-0000000000000002",
            "lib-second",
            "deps/libsecond",
            b"second",
            source.path(),
        )?;
        assert!(import_units(store.path(), "generation", "test", &[second]).is_err());

        let leftovers: Vec<_> = fs::read_dir(&units_root)?
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".import.tmp"))
            .collect();
        assert!(leftovers.is_empty(), "leftover staging: {leftovers:?}");
        Ok(())
    }

    #[test]
    fn case_variant_unit_is_kept_before_replacement() -> Result<()> {
        let store = tempfile::tempdir()?;
        let source = tempfile::tempdir()?;
        let local = raw_unit(
            "Demo-0000000000000001",
            "lib-demo",
            "deps/libdemo",
            b"local",
            source.path(),
        )?;
        import_units(store.path(), "generation", "test", &[local])?;

        let remote = raw_unit(
            "demo-0000000000000001",
            "lib-demo-other",
            "deps/libdemo-other",
            b"remote",
            source.path(),
        )?;
        let report = import_units(store.path(), "generation", "test", &[remote])?;
        assert_eq!(report.stored, 0);
        assert_eq!(report.skipped, 1);

        let manifest = load_manifest(store.path(), "generation")?.expect("manifest");
        assert_eq!(manifest.units.len(), 1);
        assert_eq!(manifest.units[0].name, "Demo-0000000000000001");
        Ok(())
    }
}
