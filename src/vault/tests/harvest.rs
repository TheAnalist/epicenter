use super::support::*;
use super::*;

#[test]
fn parity_key_is_stable_and_shaped() -> Result<()> {
    let first = parity_key()?;
    let second = parity_key()?;
    assert_eq!(first, second);
    let tc = toolchain()?;
    assert!(first.starts_with(&format!("{}-{}", tc.release, tc.commit)));
    assert!(first.ends_with(&flags_digest(&tc.host)));
    Ok(())
}

#[test]
fn harvest_stores_groups_with_one_canonical_stamp() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;

    let report = harvest(build.path(), store.path(), None, false)?;
    assert_eq!(report.stored, 3, "lib + build-script compile + run");
    assert_eq!(report.skipped_incomplete, 0);
    assert!(report.files >= 10, "got {}", report.files);
    assert!(report.bytes > 0);

    let parity = parity_key()?;
    let manifest = load_manifest(store.path(), &parity)?.expect("manifest written");
    assert_eq!(manifest.units.len(), 3);
    let lib_entry = manifest
        .units
        .iter()
        .find(|unit| unit.name == "serde-102a33f055a8d229")
        .expect("lib unit recorded");
    assert_eq!(lib_entry.hash, "5d82713a7f2d05e2");
    assert_eq!(lib_entry.profile, "debug");

    // Every stored file of the group carries the same stamp.
    let group = units_dir(store.path(), &parity).join(&lib_entry.name);
    for file in &lib_entry.files {
        let meta = fs::metadata(group.join(&file.path))?;
        assert_eq!(
            ceil_secs(meta.modified()?),
            lib_entry.stamp,
            "{}",
            file.path
        );
        assert_eq!(meta.len(), file.size);
    }

    // Volatile files and wrapper internals never enter the store.
    assert!(!group.join("invoked.timestamp").exists());
    for file in &lib_entry.files {
        assert!(!file.path.contains("kache"), "{}", file.path);
        assert!(!file.path.ends_with(".d"), "{}", file.path);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(group.join(&lib_entry.files[0].path))?;
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o444,
            "store is read-only"
        );
    }
    Ok(())
}

#[test]
fn harvest_skips_units_without_a_memo_hash() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;

    // A failed build-script compile: artifacts exist, but cargo left only
    // cached diagnostics where the memo hash belongs.
    let failed = build
        .path()
        .join("debug/.fingerprint/broken-0011223344556677");
    fs::create_dir_all(&failed)?;
    fs::write(
        failed.join("output-build-script-build-script-build"),
        r#"{"$message_type":"diagnostic","message":"linking with `clang` failed"}"#,
    )?;
    let anchor = build.path().join("debug/build/broken-0011223344556677");
    fs::create_dir_all(&anchor)?;
    fs::write(anchor.join("build_script_build-0011223344556677"), [1u8; 8])?;

    let report = harvest(build.path(), store.path(), None, false)?;
    assert_eq!(report.stored, 3, "the three valid units are stored");
    assert_eq!(report.skipped_incomplete, 1, "the failed unit is skipped");

    let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
    assert!(
        manifest
            .units
            .iter()
            .all(|unit| unit.name != "broken-0011223344556677"),
        "a diagnostic must never become a memo hash"
    );
    Ok(())
}

#[test]
fn harvest_rejects_a_fake_unit_without_a_cargo_fingerprint() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let unit = build
        .path()
        .join("debug/.fingerprint/proc-1111222233334444");
    fs::create_dir_all(&unit)?;
    // A hand-written unit shape: a memo hash and an executable, no cargo JSON.
    fs::write(unit.join("lib-proc"), "0011223344556677")?;
    fs::create_dir_all(build.path().join("debug/deps"))?;
    fs::write(
        build.path().join("debug/deps/libproc-1111222233334444.so"),
        b"MALICIOUS-PROC-MACRO",
    )?;

    let report = harvest(build.path(), store.path(), None, false)?;
    assert_eq!(report.stored, 0, "hand-written unit must not be signed");
    assert_eq!(report.skipped_incomplete, 1);
    let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
    assert!(manifest.units.is_empty(), "{:?}", manifest.units);
    Ok(())
}

#[cfg(unix)]
#[test]
fn harvest_refuses_a_group_or_world_writable_build_root() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    fs::set_permissions(build.path(), fs::Permissions::from_mode(0o777))?;

    let err = harvest(build.path(), store.path(), None, false).unwrap_err();
    assert!(
        format!("{err:#}").contains("group/world-writable"),
        "{err:#}"
    );
    Ok(())
}

#[test]
fn harvest_is_idempotent_and_skips_incomplete_units() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    synthetic_husk(build.path())?;

    let first = harvest(build.path(), store.path(), None, false)?;
    assert_eq!(first.stored, 3);
    assert_eq!(first.skipped_incomplete, 1, "husk without artifacts");

    let second = harvest(build.path(), store.path(), None, false)?;
    assert_eq!(second.stored, 0);
    assert_eq!(second.unchanged, 3);
    assert_eq!(second.skipped_incomplete, 1);
    Ok(())
}

#[test]
fn harvest_can_skip_compression_and_gc_blobs() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    let source = build
        .path()
        .join("debug/deps/libserde-102a33f055a8d229.rmeta");
    fs::write(&source, vec![7u8; 16 * 1024])?;

    let report = harvest_with(build.path(), store.path(), None, false, None, None, false)?;
    let manifest = load_manifest(store.path(), &report.parity)?.expect("manifest");
    let file = manifest
        .units
        .iter()
        .flat_map(|entry| entry.files.iter())
        .find(|file| file.path.ends_with(".rmeta"))
        .expect("rmeta");
    assert!(file.object.is_none(), "no-compress stores raw bytes");

    let store2 = tempfile::tempdir()?;
    harvest(build.path(), store2.path(), None, false)?;
    let report2 = harvest(build.path(), store2.path(), None, false)?;
    let manifest2 = load_manifest(store2.path(), &report2.parity)?.expect("manifest");
    let object = manifest2
        .units
        .iter()
        .flat_map(|entry| entry.files.iter())
        .find_map(|file| file.object.clone())
        .expect("compressed object");
    assert!(store2.path().join(&report2.parity).join(&object).is_file());
    drop_units(
        store2.path(),
        &report2.parity,
        &["serde-102a33f055a8d229".into()],
    )?;
    assert!(!store2.path().join(&report2.parity).join(object).exists());
    Ok(())
}

#[test]
fn harvest_compresses_artifacts_and_restores_into_a_fresh_view() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    let source = build
        .path()
        .join("debug/deps/libserde-102a33f055a8d229.rmeta");
    let data = vec![7u8; 16 * 1024];
    fs::write(&source, &data)?;

    harvest(build.path(), store.path(), None, false)?;
    let parity = parity_key()?;
    let manifest = load_manifest(store.path(), &parity)?.expect("manifest");
    let entry = manifest
        .units
        .iter()
        .find(|entry| entry.name == "serde-102a33f055a8d229")
        .expect("serde unit");
    let file = entry
        .files
        .iter()
        .find(|file| file.path.ends_with(".rmeta"))
        .expect("rmeta");
    let object = file.object.as_deref().expect("compressed object");
    assert!(store.path().join(&parity).join(object).is_file());

    // A view root that does not exist yet forces every profile/deps parent
    // to be created during restore, including the compressed-object path.
    let parent = tempfile::tempdir()?;
    let view = parent.path().join("fresh-view");
    restore(&view, store.path(), None, None, false)?;
    let restored = view.join("debug/deps/libserde-102a33f055a8d229.rmeta");
    assert_eq!(fs::read(&restored)?, data);
    let reports = verify(store.path())?;
    assert!(reports.iter().all(|report| report.is_clean()));
    Ok(())
}

#[cfg(unix)]
#[test]
fn harvest_copies_library_outputs_and_keeps_build_writable() -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    let report = harvest(build.path(), store.path(), None, false)?;

    let unit = format!("serde-102a33f055a8d229");
    let stored = units_dir(store.path(), &report.parity).join(&unit);
    let build_rlib = build
        .path()
        .join("debug/deps/libserde-102a33f055a8d229.rlib");
    let stored_rlib = stored.join("deps/libserde-102a33f055a8d229.rlib");
    let build_rmeta = build
        .path()
        .join("debug/deps/libserde-102a33f055a8d229.rmeta");
    let stored_rmeta = stored.join("deps/libserde-102a33f055a8d229.rmeta");

    // Never share an inode with the live build tree: the store stamps its
    // copy read-only, and a link would make the build output read-only
    // (and let either side mutate the other).
    assert_eq!(
        fs::metadata(&build_rlib)?.nlink(),
        1,
        "build keeps its inode"
    );
    assert_eq!(
        fs::metadata(&stored_rlib)?.nlink(),
        1,
        "store owns its inode"
    );
    assert_ne!(
        fs::metadata(&build_rlib)?.ino(),
        fs::metadata(&stored_rlib)?.ino()
    );
    assert_eq!(
        fs::metadata(&stored_rlib)?.permissions().mode() & 0o777,
        0o444
    );
    assert_ne!(
        fs::metadata(&build_rlib)?.permissions().mode() & 0o200,
        0,
        "the build output stays writable for cargo"
    );
    assert_eq!(fs::metadata(&build_rmeta)?.nlink(), 1, ".rmeta is a copy");
    assert_eq!(fs::metadata(&stored_rmeta)?.nlink(), 1, ".rmeta is a copy");
    Ok(())
}

#[test]
fn repeat_harvest_does_not_rewrite_the_manifest() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;

    let first = harvest(build.path(), store.path(), None, false)?;
    let mut manifest = load_manifest(store.path(), &first.parity)?.expect("manifest");
    manifest.updated = 1;
    save_manifest(store.path(), &first.parity, &manifest)?;

    let second = harvest(build.path(), store.path(), None, false)?;
    assert_eq!(second.stored, 0);
    assert_eq!(second.unchanged, 3);
    let after = load_manifest(store.path(), &first.parity)?.expect("manifest");
    assert_eq!(after.updated, 1, "a no-op harvest must not rewrite it");
    Ok(())
}

#[test]
fn harvest_refreshes_when_the_file_set_grows() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), Some("102a33f0"), false)?;

    fs::write(
        build.path().join("debug/deps/libserde-102a33f055a8d229.so"),
        [1u8; 16],
    )?;
    let report = harvest(build.path(), store.path(), Some("102a33f0"), false)?;
    assert_eq!(report.refreshed, 1);
    assert_eq!(report.stored, 0);

    let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
    let paths: Vec<&str> = manifest.units[0]
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    assert!(
        paths.contains(&"deps/libserde-102a33f055a8d229.so"),
        "{paths:?}"
    );
    Ok(())
}

#[test]
fn harvest_stores_all_memos_of_shared_dirs() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    let lib = build
        .path()
        .join("debug/.fingerprint/serde-102a33f055a8d229");
    fs::write(lib.join("bin-serde"), "1111222233334444")?;
    fs::write(
        lib.join("bin-serde.json"),
        r#"{"rustc":12019306335353385202,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[]}"#,
    )?;
    fs::write(lib.join("dep-bin-serde"), [0u8; 8])?;

    let report = harvest(build.path(), store.path(), Some("102a33f0"), false)?;
    assert_eq!(report.stored, 1);
    let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
    let entry = &manifest.units[0];
    let paths: Vec<&str> = entry.files.iter().map(|file| file.path.as_str()).collect();
    assert!(paths.contains(&"bin-serde"), "{paths:?}");
    assert!(paths.contains(&"dep-bin-serde"), "{paths:?}");

    let reports = verify(store.path())?;
    assert!(reports[0].is_clean(), "{:?}", reports[0].problems);
    Ok(())
}

#[test]
fn harvest_dry_run_writes_nothing() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;

    let report = harvest(build.path(), store.path(), None, true)?;
    assert_eq!(report.stored, 3);
    assert_eq!(generation_names(store.path())?.len(), 0, "no generation");
    Ok(())
}

#[test]
fn harvest_unit_filter_selects_one_group() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;

    let report = harvest(build.path(), store.path(), Some("102a33f0"), false)?;
    assert_eq!(report.stored, 1);
    let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
    assert_eq!(manifest.units.len(), 1);
    assert_eq!(manifest.units[0].name, "serde-102a33f055a8d229");
    Ok(())
}

#[test]
fn harvest_and_restore_new_layout_units() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let view = tempfile::tempdir()?;
    let unit = synthetic_new_layout_unit(build.path(), "anyhow", "9709d57b46b8d526")?;

    let report = harvest_with(
        build.path(),
        store.path(),
        None,
        false,
        None,
        Some(fingerprint::UnitLayout::New),
        true,
    )?;
    assert_eq!(report.stored, 1, "{report:?}");

    let parity = parity_key()?;
    let manifest = load_manifest(store.path(), &parity)?.expect("manifest");
    let entry = &manifest.units[0];
    assert_eq!(entry.layout(), fingerprint::UnitLayout::New);
    assert!(
        entry
            .files
            .iter()
            .any(|file| file.dest == "build/anyhow/9709d57b46b8d526/fingerprint/lib-anyhow")
    );
    assert!(entry.files.iter().any(
        |file| file.dest == "build/anyhow/9709d57b46b8d526/out/libanyhow-9709d57b46b8d526.rlib"
    ));
    assert!(
        !entry.files.iter().any(|file| file.dest.ends_with(".d")),
        "rustc .d side files stay out of the vault"
    );

    let restored = restore_with(
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
    assert_eq!(restored.errors, 0);
    let root = view.path().join("debug/build/anyhow/9709d57b46b8d526");
    assert!(root.join("fingerprint/lib-anyhow").is_file());
    assert!(root.join("out/libanyhow-9709d57b46b8d526.rlib").is_file());
    assert!(root.join("out/libanyhow-9709d57b46b8d526.rmeta").is_file());
    assert!(
        !view.path().join("debug/.fingerprint").exists(),
        "no classic paths for a new-layout unit"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let rlib = root.join("out/libanyhow-9709d57b46b8d526.rlib");
        let rmeta = root.join("out/libanyhow-9709d57b46b8d526.rmeta");
        assert_eq!(fs::metadata(&rlib)?.nlink(), 1, "rlib is a private copy");
        assert_eq!(fs::metadata(&rmeta)?.nlink(), 1, "rmeta is a copy");
    }
    // The fixture's source unit survives untouched.
    assert!(unit.join("out/libanyhow-9709d57b46b8d526.rlib").is_file());
    Ok(())
}

#[test]
fn harvest_refreshes_when_only_the_layout_changes() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), Some("102a33f0"), false)?;

    let parity = parity_key()?;
    let before = load_manifest(store.path(), &parity)?.expect("manifest");
    assert_eq!(before.units[0].layout(), fingerprint::UnitLayout::Classic);
    let stamp = before.units[0].stamp;

    // Same package/hash/memo/json — only the destinations move to the
    // new layout. The "unchanged" check must notice the new dests.
    fs::remove_dir_all(build.path().join("debug/.fingerprint"))?;
    let unit = synthetic_new_layout_unit(build.path(), "serde", "102a33f055a8d229")?;
    fs::write(
        unit.join("fingerprint/lib-serde.json"),
        r#"{"rustc":12019306335353385202,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[]}"#,
    )?;
    for file in [
        unit.join("fingerprint/lib-serde"),
        unit.join("fingerprint/lib-serde.json"),
        unit.join("fingerprint/dep-lib-serde"),
        unit.join("out/libserde-102a33f055a8d229.rlib"),
        unit.join("out/libserde-102a33f055a8d229.rmeta"),
    ] {
        set_stamp(&file, stamp)?;
    }

    let report = harvest_with(
        build.path(),
        store.path(),
        Some("102a33f0"),
        false,
        None,
        Some(fingerprint::UnitLayout::New),
        true,
    )?;
    assert_eq!(report.refreshed, 1, "{report:?}");
    assert_eq!(report.stored, 0);

    let after = load_manifest(store.path(), &parity)?.expect("manifest");
    assert_eq!(
        after.units[0].layout(),
        fingerprint::UnitLayout::New,
        "the recorded layout follows the dests"
    );
    assert!(
        after.units[0]
            .files
            .iter()
            .any(|file| file.dest.starts_with("build/serde/102a33f055a8d229/"))
    );
    Ok(())
}

#[test]
fn cached_diagnostics_are_stored_as_extra_and_verify_clean() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    // Cargo's message cache lives in the fingerprint dir, next to the memo.
    fs::write(
        build
            .path()
            .join("debug/.fingerprint/serde-102a33f055a8d229/output-lib-serde"),
        r#"{"$message_type":"diagnostic","message":"warning: unused"}"#,
    )?;

    harvest(build.path(), store.path(), Some("102a33f0"), false)?;
    let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
    let output = manifest.units[0]
        .files
        .iter()
        .find(|file| file.path == "output-lib-serde")
        .expect("cached diagnostics are stored");
    assert_eq!(output.role, "extra");

    let reports = verify(store.path())?;
    assert!(reports[0].is_clean(), "{:?}", reports[0].problems);
    Ok(())
}

#[test]
fn harvest_refreshes_when_a_role_drifted() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), Some("102a33f0"), false)?;

    // A manifest from before roles were content-based: the memo is
    // recorded as something else.
    let parity = parity_key()?;
    let mut manifest = load_manifest(store.path(), &parity)?.expect("manifest");
    let memo_index = manifest.units[0]
        .files
        .iter()
        .position(|file| file.path == manifest.units[0].memo)
        .expect("memo recorded");
    manifest.units[0].files[memo_index].role = "extra".to_string();
    save_manifest(store.path(), &parity, &manifest)?;

    let report = harvest(build.path(), store.path(), Some("102a33f0"), false)?;
    assert_eq!(report.refreshed, 1, "role drift forces a refresh");
    let manifest = load_manifest(store.path(), &parity)?.expect("manifest");
    let role = &manifest.units[0].files[memo_index].role;
    assert_eq!(role, "memo", "roles are rewritten");
    Ok(())
}

#[test]
fn harvest_clamps_a_dependent_to_its_dependency() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let now = now_secs();
    // The view itself is inverted (a fragmented cache: the dependency was
    // rebuilt after its dependent) — harvest must clamp the dependent up.
    synthetic_edge_dir(build.path(), now, now - 3600)?;
    harvest(build.path(), store.path(), None, false)?;

    let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
    let dependent = manifest
        .units
        .iter()
        .find(|entry| entry.name == "serde-746d173581f1a314")
        .expect("dependent stored");
    let dependency = manifest
        .units
        .iter()
        .find(|entry| entry.name == "serde_core-b468be6fa8c1f936")
        .expect("dependency stored");
    assert!(
        dependent.stamp >= dependency.stamp,
        "clamped: {} >= {}",
        dependent.stamp,
        dependency.stamp
    );

    let reports = verify(store.path())?;
    assert!(reports[0].is_clean(), "{:?}", reports[0].problems);
    assert!(reports[0].ordering.is_empty(), "{:?}", reports[0].ordering);
    Ok(())
}

#[test]
fn harvest_stamps_groups_by_the_metadata_output() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    let now = now_secs();
    // Rustc writes `.rmeta` first and `.rlib` last: the consumable
    // moment — and therefore the stamp — is the metadata.
    set_stamp(
        &build
            .path()
            .join("debug/deps/libserde-102a33f055a8d229.rmeta"),
        now - 30,
    )?;
    set_stamp(
        &build
            .path()
            .join("debug/deps/libserde-102a33f055a8d229.rlib"),
        now,
    )?;
    harvest(build.path(), store.path(), Some("102a33f0"), false)?;

    let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
    assert_eq!(manifest.units[0].stamp, now - 30);
    Ok(())
}

#[test]
fn harvest_refuses_a_stamp_that_overflows_the_clock() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("dep-lib-x");
    fs::write(&file, b"x")?;

    let err = set_stamp(&file, u64::MAX).unwrap_err();
    assert!(format!("{err:#}").contains("out of range"), "{err:#}");
    assert_eq!(fs::read(&file)?, b"x");
    Ok(())
}

#[test]
fn harvest_stores_read_only_sources() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    // Wrappers (kache) and backup tools leave read-only files in the build
    // dir; `fs::copy` carries that attribute along, and stamping the copy
    // must not depend on the source's permissions (Windows: access denied).
    let source = build
        .path()
        .join("debug/.fingerprint/serde-102a33f055a8d229/dep-lib-serde");
    let mut perms = fs::metadata(&source)?.permissions();
    perms.set_readonly(true);
    fs::set_permissions(&source, perms)?;

    let report = harvest(build.path(), store.path(), Some("102a33f0"), false)?;
    assert_eq!(report.stored, 1);

    let parity = parity_key()?;
    let manifest = load_manifest(store.path(), &parity)?.expect("manifest");
    let stored = units_dir(store.path(), &parity)
        .join(&manifest.units[0].name)
        .join("dep-lib-serde");
    assert!(stored.is_file(), "the state file is stored");
    assert_eq!(
        ceil_secs(fs::metadata(&stored)?.modified()?),
        manifest.units[0].stamp,
        "the stored copy carries the canonical stamp"
    );
    Ok(())
}

/// Windows-only regression: `File::open` yields a GENERIC_READ handle and
/// `SetFileTime` requires FILE_WRITE_ATTRIBUTES, so stamping failed with
/// "Accesso negato" (os error 5) even when the copy itself was writable.
#[cfg(windows)]
#[test]
fn set_stamp_sets_times_on_windows() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("dep-lib-x");
    fs::write(&file, b"x")?;

    set_stamp(&file, 1_700_000_000)?;
    assert_eq!(
        ceil_secs(fs::metadata(&file)?.modified()?),
        1_700_000_000,
        "a writable copy must be stampable"
    );

    // A copy that inherited a read-only source must be writable before
    // it can be stamped.
    let mut perms = fs::metadata(&file)?.permissions();
    perms.set_readonly(true);
    fs::set_permissions(&file, perms)?;
    let mut perms = fs::metadata(&file)?.permissions();
    perms.set_readonly(false);
    fs::set_permissions(&file, perms)?;
    set_stamp(&file, 1_700_000_100)?;
    assert_eq!(
        ceil_secs(fs::metadata(&file)?.modified()?),
        1_700_000_100,
        "a copy of a read-only source must be stampable"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_failed_store_drops_its_staging_dir() -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    if fs::metadata(build.path())?.uid() == 0 {
        return Ok(()); // root reads a 000 file anyway — nothing to inject
    }
    let artifact = build
        .path()
        .join("debug/deps/libserde-102a33f055a8d229.rlib");
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o000))?;
    }

    let result = harvest(build.path(), store.path(), Some("102a33f0"), false);
    assert!(result.is_err(), "an unreadable artifact aborts the store");

    let units = units_dir(store.path(), &parity_key()?);
    if units.is_dir() {
        for entry in fs::read_dir(&units)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            assert!(!name.contains(".tmp-"), "staging leftover: {name}");
        }
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn harvest_sweeps_stale_staging_dirs() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    let units = units_dir(store.path(), &parity_key()?);

    // A crashed store run from yesterday: dot-dir, read-only leftovers.
    let stale = units.join(".serde-102a33f055a8d229.tmp-99999");
    fs::create_dir_all(&stale)?;
    let leftover = stale.join("dep-lib-serde");
    fs::write(&leftover, b"x")?;
    fs::set_permissions(&leftover, fs::Permissions::from_mode(0o444))?;
    let dir = fs::File::open(&stale)?;
    dir.set_modified(UNIX_EPOCH + Duration::from_secs(now_secs() - 7200))?;

    // A concurrent harvest's staging dir must survive the sweep.
    let fresh = units.join(".serde-102a33f055a8d229.tmp-11111");
    fs::create_dir_all(&fresh)?;

    harvest(build.path(), store.path(), Some("102a33f0"), false)?;
    assert!(!stale.exists(), "stale staging dir swept");
    assert!(fresh.exists(), "fresh staging dir left alone");
    Ok(())
}

#[test]
fn harvest_records_sha256_and_verify_flags_content_drift() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), None, false)?;

    let parity = parity_key()?;
    let manifest = load_manifest(store.path(), &parity)?.expect("manifest");
    assert!(
        manifest
            .units
            .iter()
            .flat_map(|unit| &unit.files)
            .all(|file| !file.sha256.is_empty()),
        "every stored file must carry a hash"
    );

    let entry = manifest
        .units
        .iter()
        .find(|entry| entry.name == "serde-102a33f055a8d229")
        .expect("unit");
    let file = entry
        .files
        .iter()
        .find(|file| file.path == "deps/libserde-102a33f055a8d229.rlib")
        .expect("rlib");
    let path = units_dir(store.path(), &parity)
        .join(&entry.name)
        .join(&file.path);
    let mut bytes = fs::read(&path)?;
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01; // same size, different content
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    }
    fs::write(&path, &bytes)?;
    let stamp = UNIX_EPOCH + Duration::from_secs(entry.stamp);
    fs::OpenOptions::new()
        .write(true)
        .open(&path)?
        .set_modified(stamp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444))?;
    }

    let reports = verify(store.path())?;
    assert!(
        reports[0]
            .problems
            .iter()
            .any(|problem| problem.contains("content drift")),
        "{:?}",
        reports[0].problems
    );

    let view = tempfile::tempdir()?;
    let report = restore(view.path(), store.path(), None, None, false)?;
    assert!(report.errors > 0, "tampered artifact must not install");
    assert!(
        !view.path().join(&file.dest).exists(),
        "tampered artifact must be absent from the view"
    );
    Ok(())
}

#[test]
fn concurrent_harvest_keeps_every_unit() -> Result<()> {
    let store = tempfile::tempdir()?;
    let mut builds = Vec::new();
    for index in 0..6u32 {
        let build = tempfile::tempdir()?;
        let hex = format!("{:016x}", index + 1);
        let unit = build
            .path()
            .join("debug/.fingerprint")
            .join(format!("u{index}-{hex}"));
        fs::create_dir_all(&unit)?;
        fs::write(unit.join(format!("lib-u{index}")), "0123456789abcdef")?;
        fs::write(
            unit.join(format!("lib-u{index}.json")),
            r#"{"rustc":1,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[]}"#,
        )?;
        fs::write(unit.join(format!("dep-lib-u{index}")), [0u8; 8])?;
        fs::create_dir_all(build.path().join("debug/deps"))?;
        fs::write(
            build
                .path()
                .join("debug/deps")
                .join(format!("libu{index}-{hex}.rlib")),
            [index as u8; 8],
        )?;
        builds.push(build);
    }
    std::thread::scope(|scope| {
        for build in &builds {
            scope.spawn(|| harvest(build.path(), store.path(), None, false));
        }
    });
    let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
    assert_eq!(manifest.units.len(), builds.len(), "{:?}", manifest.units);
    Ok(())
}

#[cfg(unix)]
#[test]
fn harvest_rejects_a_symlinked_build_root() -> Result<()> {
    let victim = tempfile::tempdir()?;
    synthetic_build_dir(victim.path())?;
    let home = tempfile::tempdir()?;
    let build = home.path().join("build");
    std::os::unix::fs::symlink(victim.path(), &build)?;
    let store = tempfile::tempdir()?;
    let err = harvest(&build, store.path(), None, false).unwrap_err();
    assert!(format!("{err:#}").contains("symlink/reparse"), "{err:#}");
    Ok(())
}

#[test]
fn harvest_refuses_a_job_dir_without_an_exec_record() -> Result<()> {
    let home = tempfile::tempdir()?;
    let build = job_dir(home.path())?;
    synthetic_build_dir(&build)?;
    let store = tempfile::tempdir()?;

    let err = harvest(&build, store.path(), None, false).unwrap_err();
    assert!(err.to_string().contains("exec record"), "{err}");
    assert!(
        load_manifest(store.path(), &parity_key()?)?.is_none(),
        "nothing was signed"
    );
    Ok(())
}

#[test]
fn harvest_accepts_a_job_dir_with_an_exec_record() -> Result<()> {
    let home = tempfile::tempdir()?;
    let build = job_dir(home.path())?;
    synthetic_build_dir(&build)?;
    let store = tempfile::tempdir()?;
    crate::job::record_for_test(&build)?;

    let report = harvest(&build, store.path(), None, false)?;
    assert!(report.stored > 0);
    Ok(())
}

#[test]
fn harvest_takes_the_generation_lock_before_creating_state() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    let parity = parity_key()?;
    // A directory where the lock file belongs cannot be opened as a lock, so
    // the write path stops at the lock instead of creating the generation.
    fs::create_dir(store.path().join(format!(".lock-{parity}")))?;

    let err = harvest(build.path(), store.path(), Some("102a33f0"), false).unwrap_err();
    assert!(format!("{err:#}").contains("lock"), "{err:#}");
    assert!(
        !store.path().join(&parity).exists(),
        "no generation state is created before the lock is held"
    );
    Ok(())
}

#[test]
fn harvest_records_the_registry_version_from_dep_info() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    fs::write(
        build.path().join("debug/deps/serde-102a33f055a8d229.d"),
        "/work/deps/libserde-102a33f055a8d229.rlib: \
         /home/u/.cargo/registry/src/index.crates.io-abc/serde-1.0.219/src/lib.rs\n",
    )?;
    harvest(build.path(), store.path(), None, false)?;

    let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
    let entry = manifest
        .units
        .iter()
        .find(|entry| entry.name == "serde-102a33f055a8d229")
        .expect("serde unit stored");
    assert_eq!(entry.version.as_deref(), Some("1.0.219"));
    Ok(())
}

#[test]
fn harvest_parses_a_hyphenated_package_and_a_prerelease_version() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let jsons = r#"{"rustc":12019306335353385202,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[]}"#;
    let unit = build
        .path()
        .join("debug/.fingerprint/serde-json-aa11bb22cc33dd44");
    fs::create_dir_all(&unit)?;
    fs::write(unit.join("lib-serde_json"), "0123456789abcdef")?;
    fs::write(unit.join("lib-serde_json.json"), jsons)?;
    fs::write(unit.join("dep-lib-serde_json"), [0u8; 8])?;
    fs::create_dir_all(build.path().join("debug/deps"))?;
    fs::write(
        build
            .path()
            .join("debug/deps/libserde_json-aa11bb22cc33dd44.rlib"),
        [4u8; 16],
    )?;
    fs::write(
        build
            .path()
            .join("debug/deps/serde_json-aa11bb22cc33dd44.d"),
        "/work/deps/libserde_json-aa11bb22cc33dd44.rlib: \
         /home/u/.cargo/registry/src/index.crates.io-abc/serde-json-1.0.0-rc.1/src/lib.rs\n",
    )?;

    harvest(build.path(), store.path(), None, false)?;
    let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
    let entry = manifest
        .units
        .iter()
        .find(|entry| entry.name == "serde-json-aa11bb22cc33dd44")
        .expect("hyphenated unit stored");
    assert_eq!(entry.version.as_deref(), Some("1.0.0-rc.1"));
    Ok(())
}

#[test]
fn missing_job_marker_inside_the_work_root_is_not_a_shared_build_dir() -> Result<()> {
    let home = tempfile::tempdir()?;
    let job = home.path().join("job");
    util::create_private_dir_all(&job)?;
    let err =
        crate::vault::harvest::authorize_harvest_at(&job, HarvestTrust::Recorded, home.path())
            .expect_err("a job dir without its marker must not be signed");
    assert!(format!("{err:#}").contains("job marker"), "{err:#}");

    // Outside the work root the same directory is an ordinary build dir.
    let elsewhere = home.path().join("elsewhere");
    crate::vault::harvest::authorize_harvest_at(&job, HarvestTrust::Recorded, &elsewhere)?;
    Ok(())
}
