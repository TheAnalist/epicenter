use super::*;

#[test]
fn failed_import_leaves_no_partial_unit() -> Result<()> {
    let store = tempfile::tempdir()?;
    let source = tempfile::tempdir()?;
    let file = source.path().join("lib-demo");
    fs::write(&file, b"wrong")?;
    let units = vec![ImportUnit {
        name: "demo-0011223344556677".into(),
        profile: "debug".into(),
        memo: "lib-demo".into(),
        hash: "aabbccddeeff0011".into(),
        version: None,
        stamp: now_secs(),
        layout: fingerprint::UnitLayout::Classic,
        files: vec![ImportFile {
            path: "lib-demo".into(),
            dest: ".fingerprint/demo-0011223344556677/lib-demo".into(),
            size: 5,
            sha256: crate::vault::hex_encode(&Sha256::digest(b"right")),
            role: "memo".into(),
            source: ImportSource::Raw(file),
        }],
    }];
    assert!(import_units(store.path(), "generation", "test", &units).is_err());
    assert!(stored_units(store.path())?.is_empty());
    assert!(
        !store
            .path()
            .join("generation/units/demo-0011223344556677")
            .exists()
    );
    Ok(())
}

#[test]
fn store_accepts_imports_allows_a_missing_store_and_rejects_read_only() -> Result<()> {
    let home = tempfile::tempdir()?;
    let missing = home.path().join("missing-store");
    assert!(!missing.exists());
    assert!(store_accepts_imports(&missing));
    assert!(!missing.exists(), "the preflight creates nothing");

    let writable = tempfile::tempdir()?;
    assert!(store_accepts_imports(writable.path()));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if util::euid() != 0 {
            let read_only = home.path().join("read-only-store");
            fs::create_dir(&read_only)?;
            fs::set_permissions(&read_only, fs::Permissions::from_mode(0o555))?;
            assert!(!store_accepts_imports(&read_only));
            fs::set_permissions(&read_only, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}
