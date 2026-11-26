use super::support::*;
use super::*;

#[test]
fn verify_passes_clean_and_flags_drift() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), None, false)?;

    let reports = verify(store.path())?;
    assert_eq!(reports.len(), 1);
    assert!(reports[0].is_clean(), "{:?}", reports[0].problems);
    assert_eq!(reports[0].units, 3);

    // Damage one stored file: size + stamp drift must surface.
    let parity = parity_key()?;
    let victim = units_dir(store.path(), &parity).join("serde-102a33f055a8d229/dep-lib-serde");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644))?;
    }
    fs::write(&victim, [9u8; 32])?;

    let reports = verify(store.path())?;
    assert!(!reports[0].is_clean());
    assert!(
        reports[0]
            .problems
            .iter()
            .any(|line| line.contains("size drift")),
        "{:?}",
        reports[0].problems
    );
    Ok(())
}

#[test]
fn a_shared_blob_is_checked_once_and_reported_per_reference() {
    let dir = tempfile::tempdir().unwrap();
    let object = "blobs/aa/0123456789abcdef0123456789abcdef.gz";
    let file = |size: u64| FileEntry {
        path: "deps/libx.rlib".into(),
        dest: "deps/libx.rlib".into(),
        size,
        sha256: "a".repeat(64),
        role: "artifact".into(),
        object: Some(object.into()),
    };
    let unit = |name: &str, size: u64| UnitEntry {
        name: name.into(),
        profile: "debug".into(),
        memo: "lib-x".into(),
        hash: "0123456789abcdef".into(),
        version: None,
        stamp: 1,
        layout: Some(fingerprint::UnitLayout::Classic),
        files: vec![file(size)],
    };
    let manifest = Manifest {
        units: vec![
            unit("x-1111111111111111", 10),
            unit("y-2222222222222222", 20),
        ],
        ..Default::default()
    };

    // One object, one decode cap: the largest recorded size.
    let blobs = unique_blobs(&manifest);
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[object], 20);

    // A bad result is charged against every reference, in order.
    let mut checks: std::collections::BTreeMap<&str, BlobCheck> = std::collections::BTreeMap::new();
    checks.insert(
        object,
        BlobCheck::Verified {
            size: 12,
            hash: "b".repeat(64),
        },
    );
    let ctx = AuditCtx {
        units: dir.path(),
        read_only: true,
    };
    let audit = ctx.audit(&manifest.units[0], &checks);
    assert_eq!(audit.files, 1);
    assert_eq!(audit.bytes, 10);
    assert_eq!(audit.problems.len(), 1, "{:?}", audit.problems);
    assert!(audit.problems[0].contains("blob drift"));
}

#[test]
fn verify_reports_unrecorded_unit_groups() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), None, false)?;

    let stray = units_dir(store.path(), &parity_key()?).join("stray-0000000000000000");
    fs::create_dir_all(stray.join("deps"))?;
    fs::write(stray.join("deps/x.rlib"), [0u8; 4])?;

    let reports = verify(store.path())?;
    assert!(
        reports[0]
            .problems
            .iter()
            .any(|line| line.contains("stray-0000000000000000")),
        "{:?}",
        reports[0].problems
    );
    assert!(!reports[0].is_clean());
    Ok(())
}

#[test]
fn generations_summary_counts_store_files() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), None, false)?;

    let generations = generations(store.path())?;
    assert_eq!(generations.len(), 1);
    assert!(generations[0].active, "current toolchain generation");
    assert_eq!(generations[0].units, 3);
    assert!(generations[0].files >= 10);
    assert!(generations[0].linked <= generations[0].files);
    Ok(())
}

#[test]
fn verify_flags_an_inverted_store_stamp() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let now = now_secs();
    synthetic_edge_dir(build.path(), now - 3600, now)?;
    harvest(build.path(), store.path(), None, false)?;

    // Simulate a store written before the clamp existed: re-stamp the
    // dependent (files and manifest) older than its dependency.
    let parity = parity_key()?;
    let mut manifest = load_manifest(store.path(), &parity)?.expect("manifest");
    let units = units_dir(store.path(), &parity);
    let entry = manifest
        .units
        .iter_mut()
        .find(|entry| entry.name == "serde-746d173581f1a314")
        .expect("dependent stored");
    entry.stamp = now - 7200;
    for file in &entry.files {
        set_stamp(&units.join(&entry.name).join(&file.path), now - 7200)?;
    }
    save_manifest(store.path(), &parity, &manifest)?;

    let reports = verify(store.path())?;
    assert!(reports[0].is_clean(), "{:?}", reports[0].problems);
    assert_eq!(reports[0].ordering.len(), 1, "{:?}", reports[0].ordering);
    assert!(reports[0].ordering[0].contains("serde-746d173581f1a314"));
    assert!(reports[0].ordering[0].contains("serde_core-b468be6fa8c1f936"));
    Ok(())
}

#[test]
fn verify_ordering_is_quiet_when_units_are_current() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let now = now_secs();
    synthetic_edge_dir(build.path(), now - 3600, now)?;
    harvest(build.path(), store.path(), None, false)?;

    let reports = verify(store.path())?;
    assert!(reports[0].is_clean(), "{:?}", reports[0].problems);
    assert!(reports[0].ordering.is_empty(), "{:?}", reports[0].ordering);
    Ok(())
}

#[cfg(unix)]
#[test]
fn verify_does_not_traverse_a_symlinked_units_dir() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), None, false)?;

    let parity = parity_key()?;
    let units = units_dir(store.path(), &parity);
    let real = store.path().join("units.real");
    fs::rename(&units, &real)?;
    let victim = tempfile::tempdir()?;
    fs::create_dir_all(victim.path().join("stray-0000000000000000"))?;
    std::os::unix::fs::symlink(victim.path(), &units)?;

    let reports = verify(store.path())?;
    let problems = &reports[0].problems;
    assert!(
        problems
            .iter()
            .any(|line| line.contains("units directory") && line.contains("symlink")),
        "{problems:?}"
    );
    assert!(
        !problems
            .iter()
            .any(|line| line.contains("unrecorded unit group")),
        "a symlinked units dir must not be enumerated: {problems:?}"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn verify_reports_an_unreadable_extra_entry() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if util::euid() == 0 {
        return Ok(()); // root bypasses the search-bit check
    }
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), None, false)?;

    let unit_dir = units_dir(store.path(), &parity_key()?).join("serde-102a33f055a8d229");
    let locked = unit_dir.join("locked");
    fs::create_dir_all(&locked)?;
    fs::write(locked.join("stray"), b"x")?;
    // Readable but not searchable: the walk lists the child, yet a no-follow
    // stat of it fails. The audit must report the entry, not skip it.
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o400))?;

    let reports = verify(store.path())?;
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700))?;
    let problems = &reports[0].problems;
    assert!(
        problems
            .iter()
            .any(|line| line
                .contains("unreadable entry in units/serde-102a33f055a8d229/locked/stray")),
        "{problems:?}"
    );
    Ok(())
}
