use super::support::*;
use super::*;

#[cfg(unix)]
#[test]
fn restore_copies_from_a_shared_store_and_isolates_later_mutation() -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let view = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), None, false)?;
    // A group/world-writable store is a shared trust domain: restore must
    // copy, never share an inode with the view.
    fs::set_permissions(store.path(), fs::Permissions::from_mode(0o777))?;

    let report = restore(view.path(), store.path(), None, None, false)?;
    assert_eq!(report.errors, 0);
    let parity = parity_key()?;
    let stored = units_dir(store.path(), &parity)
        .join("serde-102a33f055a8d229/deps/libserde-102a33f055a8d229.rlib");
    let linked = view
        .path()
        .join("debug/deps/libserde-102a33f055a8d229.rlib");
    assert_ne!(
        fs::metadata(&stored)?.ino(),
        fs::metadata(&linked)?.ino(),
        "shared store must not share inodes"
    );
    fs::set_permissions(&linked, fs::Permissions::from_mode(0o644))?;
    fs::write(&linked, b"MUTATED-VIA-VIEW")?;
    assert_ne!(
        fs::read(&stored)?,
        b"MUTATED-VIA-VIEW",
        "the store copy is isolated from the view"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn restore_falls_back_to_copy_across_filesystems() -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let Ok(shm) = tempfile::Builder::new()
        .prefix("epi-xdev-")
        .tempdir_in("/dev/shm")
    else {
        return Ok(()); // no separate filesystem in this environment
    };
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir_in(shm.path())?;
    let view = tempfile::tempdir()?;
    if fs::metadata(store.path())?.dev() == fs::metadata(view.path())?.dev() {
        return Ok(());
    }
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), None, false)?;

    let report = restore(view.path(), store.path(), None, None, false)?;
    assert_eq!(report.errors, 0, "{:?}", report);
    let stored = units_dir(store.path(), &parity_key()?)
        .join("serde-102a33f055a8d229/deps/libserde-102a33f055a8d229.rlib");
    let copied = view
        .path()
        .join("debug/deps/libserde-102a33f055a8d229.rlib");
    assert_ne!(fs::metadata(&stored)?.ino(), fs::metadata(&copied)?.ino());
    assert_eq!(fs::read(&copied)?.len(), 64);
    Ok(())
}

#[cfg(not(unix))]
#[test]
fn compressed_install_does_not_unlink_a_racing_destination() -> Result<()> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let dir = tempfile::tempdir()?;
    let blob = dir.path().join("blob.gz");
    let file = fs::File::create(&blob)?;
    let mut encoder = GzEncoder::new(file, Compression::fast());
    encoder.write_all(b"payload")?;
    encoder.finish()?;
    let dst = dir.path().join("dst");
    fs::write(&dst, b"keep")?;
    let entry = FileEntry {
        path: "deps/libx.rlib".into(),
        dest: "deps/libx.rlib".into(),
        size: 7,
        sha256: format!("{:x}", Sha256::digest(b"payload")),
        role: "artifact".into(),
        object: None,
    };

    match install_compressed_copy(&blob, &dst, 1_700_000_000, &entry)? {
        RestoreOutcome::Existing => {}
        _ => panic!("an existing destination must win the race"),
    }
    assert_eq!(fs::read(&dst)?, b"keep");
    assert!(
        !fs::read_dir(dir.path())?.any(|entry| entry
            .map(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with(".epicenter-tmp-"))
            .unwrap_or(false)),
        "the temporary file is removed"
    );
    Ok(())
}

#[test]
fn restore_never_overwrites_existing_files() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let view = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), None, false)?;

    // A pre-existing file must survive a restore untouched.
    let occupied = view
        .path()
        .join("debug/deps/libserde-102a33f055a8d229.rlib");
    fs::create_dir_all(occupied.parent().unwrap())?;
    fs::write(&occupied, b"live artifact")?;

    let report = restore(view.path(), store.path(), None, None, false)?;
    assert_eq!(report.units_linked, 3);
    assert_eq!(report.files_existing, 1, "the live artifact was skipped");
    assert_eq!(fs::read(&occupied)?, b"live artifact");
    // A writable store is copied from; the single deps artifact of this
    // fixture was the occupied one, so nothing was linked or copied.
    assert_eq!(report.files_linked, 0, "no other deps/ artifact");
    assert!(report.files_copied >= 12, "got {}", report.files_copied);

    // Memo file content and hash landed in the right place.
    let memo = view
        .path()
        .join("debug/.fingerprint/serde-102a33f055a8d229/lib-serde");
    assert_eq!(fs::read_to_string(&memo)?.trim(), "5d82713a7f2d05e2");
    assert!(
        view.path()
            .join("debug/build/x-aabbccddeeff0011/output")
            .is_file()
    );

    // Fingerprint state is a private writable copy: cargo rewrites it in
    // place after a rebuild, and a shared inode would EACCES on the
    // read-only store copy (or mutate the store).
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        let parity = parity_key()?;
        let stored = units_dir(store.path(), &parity).join("serde-102a33f055a8d229/lib-serde");
        let view_meta = fs::metadata(&memo)?;
        assert_ne!(
            view_meta.ino(),
            fs::metadata(&stored)?.ino(),
            "state not shared"
        );
        assert_eq!(view_meta.nlink(), 1, "state owns its inode");
        assert_ne!(view_meta.permissions().mode() & 0o200, 0, "state writable");
    }

    // Second restore: everything already fresh.
    let again = restore(view.path(), store.path(), None, None, false)?;
    assert_eq!(again.units_already, 3);
    assert_eq!(again.files_linked, 0);
    assert_eq!(again.files_copied, 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn restore_marks_build_script_binaries_executable() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let view = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), None, false)?;
    let report = restore(view.path(), store.path(), None, None, false)?;
    assert_eq!(report.errors, 0);

    let path = view
        .path()
        .join("debug/build/x-1122334455667788/build_script_build-1122334455667788");
    let mode = fs::metadata(&path)?.permissions().mode();
    assert_ne!(
        mode & 0o111,
        0,
        "a restored build-script binary must be executable: {mode:o}"
    );

    let stored = stored_units(store.path())?
        .into_iter()
        .find(|unit| unit.entry.name == "x-1122334455667788")
        .and_then(|unit| {
            unit.entry
                .files
                .iter()
                .find(|file| file.role == "build-tree")
                .map(|file| unit.dir.join(&file.path))
        })
        .expect("stored build-tree file");
    assert_eq!(
        fs::metadata(&stored)?.permissions().mode() & 0o777,
        0o444,
        "the store itself stays read-only"
    );
    Ok(())
}

#[test]
fn restore_into_missing_profile_dirs_creates_them() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let view = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), None, false)?;

    let report = restore(view.path(), store.path(), None, None, false)?;
    assert_eq!(report.errors, 0);
    assert!(view.path().join("debug/.fingerprint").is_dir());
    Ok(())
}

#[test]
fn restore_filters_by_profile() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let debug_view = tempfile::tempdir()?;
    let release_view = tempfile::tempdir()?;
    synthetic_profile_unit(build.path(), "debug", "debugdep", "1111111111111111", 1)?;
    synthetic_profile_unit(build.path(), "release", "releasedep", "2222222222222222", 2)?;
    harvest(build.path(), store.path(), None, false)?;

    let debug = restore_with(
        debug_view.path(),
        store.path(),
        None,
        None,
        None,
        Some("debug"),
        None,
        false,
        LinkPolicy::Copy,
    )?;
    assert_eq!(debug.units_linked, 1);
    assert!(
        debug_view
            .path()
            .join("debug/.fingerprint/debugdep-1111111111111111/lib-debugdep")
            .is_file()
    );
    assert!(
        !debug_view.path().join("release").exists(),
        "a debug restore leaves release units out"
    );

    let release = restore_with(
        release_view.path(),
        store.path(),
        None,
        None,
        None,
        Some("release"),
        None,
        false,
        LinkPolicy::Copy,
    )?;
    assert_eq!(release.units_linked, 1);
    assert!(
        release_view
            .path()
            .join("release/.fingerprint/releasedep-2222222222222222/lib-releasedep")
            .is_file()
    );
    assert!(
        !release_view.path().join("debug").exists(),
        "a release restore leaves debug units out"
    );
    Ok(())
}

#[test]
fn restore_can_restrict_units_to_packages() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let view = tempfile::tempdir()?;
    let now = now_secs();
    synthetic_edge_dir(build.path(), now - 3600, now)?;
    harvest(build.path(), store.path(), None, false)?;

    let lock = tempfile::tempdir()?;
    let lock = lock.path().join("Cargo.lock");
    fs::write(
        &lock,
        "version = 4\n\n[[package]]\nname = \"serde_core\"\nversion = \"1.0.0\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
         checksum = \"abababababababababababababababababababababababababababababababab\"\n",
    )?;
    let packages = crate::lockfile::LockIndex::parse(&lock).expect("lock parses");
    let report = restore(view.path(), store.path(), None, Some(&packages), false)?;
    assert_eq!(report.errors, 0);
    assert!(
        view.path()
            .join("debug/.fingerprint/serde_core-b468be6fa8c1f936")
            .is_dir(),
        "a unit of a selected package is restored"
    );
    assert!(
        !view
            .path()
            .join("debug/.fingerprint/serde-746d173581f1a314")
            .exists(),
        "a unit of an unselected package is not restored"
    );

    // A path/workspace package has no source identity: its name and
    // version do not identify the checkout, so it is never seeded.
    fs::write(
        &lock,
        "version = 4\n\n[[package]]\nname = \"serde_core\"\nversion = \"1.0.0\"\n",
    )?;
    let packages = crate::lockfile::LockIndex::parse(&lock).expect("lock parses");
    let path_view = tempfile::tempdir()?;
    let report = restore(path_view.path(), store.path(), None, Some(&packages), false)?;
    assert_eq!(report.units_linked, 0, "a path-sourced unit is not seeded");
    assert!(
        !path_view
            .path()
            .join("debug/.fingerprint/serde_core-b468be6fa8c1f936")
            .exists()
    );
    Ok(())
}

#[test]
fn restore_can_filter_units_by_layout() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let view = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    synthetic_new_layout_unit(build.path(), "anyhow", "9709d57b46b8d526")?;

    harvest_with(
        build.path(),
        store.path(),
        None,
        false,
        None,
        Some(fingerprint::UnitLayout::Classic),
        true,
    )?;
    harvest_with(
        build.path(),
        store.path(),
        None,
        false,
        None,
        Some(fingerprint::UnitLayout::New),
        true,
    )?;

    let report = restore_with(
        view.path(),
        store.path(),
        None,
        None,
        Some(fingerprint::UnitLayout::New),
        None,
        None,
        false,
        LinkPolicy::Copy,
    )?;
    assert_eq!(report.errors, 0);
    assert!(
        view.path()
            .join("debug/build/anyhow/9709d57b46b8d526/fingerprint/lib-anyhow")
            .is_file()
    );
    assert!(
        !view
            .path()
            .join("debug/.fingerprint/serde-102a33f055a8d229")
            .exists(),
        "a classic unit is not restored into a new-layout child"
    );
    Ok(())
}

#[test]
fn restore_without_a_generation_reports_fail_open() -> Result<()> {
    let view = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let report = restore(view.path(), store.path(), None, None, false)?;
    assert!(report.note.is_some());
    assert_eq!(report.files_linked, 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn restore_auto_links_local_archives_and_copies_proc_macros() -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let view = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    fs::write(
        build.path().join("debug/deps/libserde-102a33f055a8d229.so"),
        [9u8; 32],
    )?;
    harvest(build.path(), store.path(), None, false)?;

    let report = restore(view.path(), store.path(), None, None, false)?;
    assert_eq!(report.errors, 0);
    let rlib = view
        .path()
        .join("debug/deps/libserde-102a33f055a8d229.rlib");
    let so = view.path().join("debug/deps/libserde-102a33f055a8d229.so");
    assert!(
        fs::metadata(&rlib)?.nlink() >= 2,
        "auto links a local private store's archive output"
    );
    assert_eq!(
        fs::metadata(&so)?.nlink(),
        1,
        "proc-macro .so stays a writable private copy"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn restore_link_policy_forces_shared_inodes() -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let view = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    fs::write(
        build.path().join("debug/deps/libserde-102a33f055a8d229.so"),
        [9u8; 32],
    )?;
    harvest(build.path(), store.path(), None, false)?;
    // Even a shared store is linked when the operator forces `link`.
    fs::set_permissions(store.path(), fs::Permissions::from_mode(0o777))?;

    let report = restore_policy(view.path(), store.path(), None, false, LinkPolicy::Link)?;
    assert_eq!(report.errors, 0);
    let rlib = view
        .path()
        .join("debug/deps/libserde-102a33f055a8d229.rlib");
    let so = view.path().join("debug/deps/libserde-102a33f055a8d229.so");
    assert_eq!(fs::metadata(&rlib)?.nlink(), 2, "rlib is linked");
    assert_eq!(fs::metadata(&so)?.nlink(), 2, "so is linked");
    Ok(())
}

#[test]
fn restore_copy_policy_never_links() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), Some("102a33f0"), false)?;

    let view = tempfile::tempdir()?;
    restore_policy(
        view.path(),
        store.path(),
        Some("102a33f0"),
        false,
        LinkPolicy::Copy,
    )?;

    let state = view
        .path()
        .join("debug/.fingerprint/serde-102a33f055a8d229/lib-serde");
    let artifact = view
        .path()
        .join("debug/deps/libserde-102a33f055a8d229.rlib");
    let metadata = view
        .path()
        .join("debug/deps/libserde-102a33f055a8d229.rmeta");
    assert!(state.is_file() && artifact.is_file() && metadata.is_file());

    let parity = parity_key()?;
    let manifest = load_manifest(store.path(), &parity)?.expect("manifest");
    let entry = manifest
        .units
        .iter()
        .find(|entry| entry.name == "serde-102a33f055a8d229")
        .expect("stored unit");
    assert_eq!(ceil_secs(fs::metadata(&state)?.modified()?), entry.stamp);

    // Rewriting restored state must not reach the store (the exact
    // failure cargo hits when it stores a rebuilt fingerprint).
    fs::write(&state, "ffffffffffffffff")?;
    let stored = units_dir(store.path(), &parity)
        .join("serde-102a33f055a8d229")
        .join("lib-serde");
    assert_eq!(fs::read_to_string(&stored)?, "5d82713a7f2d05e2");

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            fs::metadata(&artifact)?.nlink(),
            1,
            "a writable store must not share its inode with the view"
        );
        assert_eq!(fs::metadata(&state)?.nlink(), 1, "state is a private copy");
        assert_eq!(
            fs::metadata(&metadata)?.nlink(),
            1,
            ".rmeta is a private copy (rustc opens it for write)"
        );
    }
    Ok(())
}

#[test]
fn restore_binds_a_unit_to_the_lock_version() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let view = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    fs::write(
        build.path().join("debug/deps/serde-102a33f055a8d229.d"),
        "/work/deps/libserde-102a33f055a8d229.rlib: \
         /home/u/.cargo/registry/src/index.crates.io-abc/serde-1.0.219/src/lib.rs\n",
    )?;
    harvest(build.path(), store.path(), None, false)?;

    let locks = tempfile::tempdir()?;
    let lock = locks.path().join("Cargo.lock");
    fs::write(
        &lock,
        "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.218\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
         checksum = \"abababababababababababababababababababababababababababababababab\"\n",
    )?;
    let packages = crate::lockfile::LockIndex::parse(&lock).expect("lock parses");
    let report = restore(view.path(), store.path(), None, Some(&packages), false)?;
    assert_eq!(report.units_linked, 0, "a version mismatch is not seeded");
    assert!(
        !view
            .path()
            .join("debug/.fingerprint/serde-102a33f055a8d229")
            .exists()
    );

    fs::write(
        &lock,
        "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.219\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
         checksum = \"abababababababababababababababababababababababababababababababab\"\n",
    )?;
    let packages = crate::lockfile::LockIndex::parse(&lock).expect("lock parses");
    let report = restore(view.path(), store.path(), None, Some(&packages), false)?;
    assert!(report.units_linked > 0, "the matching version is seeded");
    Ok(())
}
