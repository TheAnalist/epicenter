use super::support::*;
use super::*;

#[cfg(windows)]
use anyhow::Context;

#[test]
fn load_repairs_an_authentic_manifest_with_an_invalid_unit() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    let parity = parity_key()?;
    harvest(build.path(), store.path(), None, false)?;

    // Simulate an entry written before harvest validated the memo hash.
    let mut manifest = load_manifest(store.path(), &parity)?.expect("manifest");
    let bad = manifest.units[0].name.clone();
    manifest.units[0].hash = r#"{"$message_type":"diagnostic"}"#.into();
    // This fixture simulates an older HMAC-only manifest; the Ed25519
    // signature would no longer match after the field edit.
    manifest.signature.clear();
    manifest.mac = manifest_mac(&manifest)?;
    let path = manifest_path(store.path(), &parity);
    fs::write(&path, serde_json::to_string_pretty(&manifest)?)?;

    // A reader filters the invalid entry in memory but never rewrites the
    // store. The writer-only repair below is the only mutation.
    let read = load_manifest(store.path(), &parity)?.expect("manifest");
    assert!(
        read.units.iter().all(|unit| unit.name != bad),
        "the invalid entry is ignored"
    );
    assert_eq!(read.units.len(), 2, "the valid units survive");
    let raw = fs::read_to_string(&path)?;
    assert!(
        raw.contains("$message_type"),
        "the read path must not rewrite the manifest"
    );

    let repaired = load_manifest_at(store.path(), &parity, true)?.expect("manifest");
    assert!(
        repaired.units.iter().all(|unit| unit.name != bad),
        "the writer repair drops the invalid entry"
    );
    assert_eq!(repaired.units.len(), 2, "the valid units survive");
    let raw = fs::read_to_string(&path)?;
    assert!(
        !raw.contains("$message_type"),
        "the writer repair must persist on disk"
    );
    let reread = load_manifest(store.path(), &parity)?.expect("manifest");
    assert_eq!(reread.units.len(), 2);
    Ok(())
}

#[cfg(unix)]
#[test]
fn drop_units_refuses_a_symlinked_generation() -> Result<()> {
    let store = tempfile::tempdir()?;
    let victim = tempfile::tempdir()?;
    fs::create_dir_all(victim.path().join("units/x"))?;
    fs::write(victim.path().join("units/x/keep"), b"keep")?;
    std::os::unix::fs::symlink(victim.path(), store.path().join("victim-parity"))?;

    let err = drop_units(store.path(), "victim-parity", &["x".into()]).unwrap_err();
    assert!(format!("{err:#}").contains("symlink") || format!("{err:#}").contains("reparse"));
    assert!(
        victim.path().join("units/x/keep").exists(),
        "a symlinked generation must not redirect deletion"
    );
    Ok(())
}

#[test]
fn manifest_validation_rejects_escapes() {
    let unit = |name: &str, profile: &str, path: &str, dest: &str| UnitEntry {
        name: name.into(),
        profile: profile.into(),
        memo: "lib-x".into(),
        hash: "0123456789abcdef".into(),
        version: None,
        stamp: 1,
        layout: None,
        files: vec![FileEntry {
            path: path.into(),
            dest: dest.into(),
            size: 1,
            sha256: String::new(),
            role: "artifact".into(),
            object: None,
        }],
    };
    let base = Manifest {
        parity_key: "p".into(),
        toolchain: "t".into(),
        created: 1,
        updated: 1,
        units: vec![],
        mac: String::new(),
        signature: String::new(),
    };
    for unit in [
        unit("../escape", "debug", "deps/x", "deps/x"),
        unit("ok", "/etc", "deps/x", "deps/x"),
        unit("ok", "debug", "/etc/passwd", "deps/x"),
        unit("ok", "debug", "deps/x", "/root/.ssh/authorized_keys"),
        unit("ok", "debug", "deps/../../x", "deps/x"),
        unit(".. ", "debug", "deps/x", "deps/x"),
        unit("...", "debug", "deps/x", "deps/x"),
        unit("CON.txt", "debug", "deps/x", "deps/x"),
    ] {
        let manifest = Manifest {
            units: vec![unit],
            ..base.clone()
        };
        assert!(manifest.validate().is_err(), "must reject {manifest:?}");
    }
}

#[cfg(unix)]
#[test]
fn store_directories_are_private() -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), None, false)?;
    assert_eq!(
        fs::metadata(store.path())?.mode() & 0o077,
        0,
        "store root 0700"
    );
    let generation = store.path().join(parity_key()?);
    assert_eq!(
        fs::metadata(&generation)?.mode() & 0o077,
        0,
        "generation 0700"
    );
    Ok(())
}

#[test]
fn signing_key_migrates_from_the_legacy_cargo_home_path() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let state = dir.path().join("state/manifest.ed25519");
    let legacy = dir.path().join("cargo/epicenter/manifest.ed25519");
    let legacy_seed = [7u8; 32];
    write_new_key_file(&legacy, &legacy_seed)?;

    let key = load_or_migrate_signing_key(&state, &legacy)?;
    assert_eq!(key.to_bytes(), legacy_seed);
    assert!(state.is_file(), "the writer migrates the key");
    assert_eq!(read_key_file(&state)?, legacy_seed);

    let state_seed = [9u8; 32];
    fs::remove_file(&state)?;
    write_new_key_file(&state, &state_seed)?;
    let key = load_or_migrate_signing_key(&state, &legacy)?;
    assert_eq!(key.to_bytes(), state_seed, "the state key wins");
    Ok(())
}

#[test]
fn manifest_has_an_ed25519_signature_and_readable_public_key() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), None, false)?;
    let manifest = load_manifest(store.path(), &parity_key()?)?.expect("manifest");
    assert_eq!(manifest.signature.len(), 128);
    assert_eq!(manifest.mac.len(), 64);
    let pubkey = fs::read_to_string(store.path().join(PUBKEY_FILE))?;
    assert_eq!(pubkey.trim().len(), 64);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(store.path().join(PUBKEY_FILE))?
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }
    Ok(())
}

#[test]
fn manifest_signature_rejects_tampering() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), None, false)?;
    let parity = parity_key()?;
    let path = manifest_path(store.path(), &parity);
    let mut value: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path)?)?;
    value["toolchain"] = serde_json::Value::String("rustc forged".into());
    fs::write(&path, serde_json::to_string_pretty(&value)?)?;
    let err = load_manifest(store.path(), &parity).unwrap_err();
    assert!(format!("{err:#}").contains("signature check"), "{err:#}");
    Ok(())
}

#[cfg(windows)]
#[test]
fn load_manifest_refuses_a_permissive_generation_acl() -> Result<()> {
    let store = tempfile::tempdir()?;
    let generation = store.path().join("gen");
    fs::create_dir(&generation)?;
    // The ACL check runs before parsing, so the body need not be valid.
    fs::write(generation.join("manifest.json"), b"{}")?;
    let status = std::process::Command::new("icacls")
        .arg(&generation)
        .args(["/grant", "*S-1-5-32-545:(OI)(CI)(M)"])
        .status()
        .context("running icacls")?;
    assert!(status.success(), "icacls could not add the test ACE");
    let err = load_manifest(store.path(), "gen").unwrap_err();
    assert!(
        format!("{err:#}").contains("grants write access"),
        "{err:#}"
    );
    Ok(())
}

#[cfg(windows)]
fn make_junction(link: &Path, target: &Path) -> Result<()> {
    let script = format!(
        "New-Item -ItemType Junction -Path '{}' -Target '{}' -ErrorAction Stop | Out-Null",
        link.display(),
        target.display()
    );
    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(script)
        .status()?;
    if !status.success() {
        anyhow::bail!("mklink /J failed for {}", link.display());
    }
    Ok(())
}

#[cfg(windows)]
#[test]
fn store_root_junction_is_rejected_by_read_paths() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let base = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), None, false)?;

    let link = base.path().join("store-link");
    make_junction(&link, store.path())?;
    let names = generation_names(&link);
    let units = stored_units(&link);
    let generations = generations(&link);
    let verify = verify(&link);
    fs::remove_dir(&link)?;

    assert!(
        names.is_err(),
        "generation_names must reject a store-root junction"
    );
    assert!(
        units.is_err(),
        "stored_units must reject a store-root junction"
    );
    assert!(
        generations.is_err(),
        "generations must reject a store-root junction"
    );
    assert!(verify.is_err(), "verify must reject a store-root junction");
    Ok(())
}

#[cfg(windows)]
#[test]
fn units_junction_is_rejected_by_stored_units() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), None, false)?;
    let generation = generation_names(store.path())?.remove(0);
    let units = units_dir(store.path(), &generation);
    let victim = tempfile::tempdir()?;
    let units_real = store.path().join("units.real");
    fs::rename(&units, &units_real)?;
    make_junction(&units, victim.path())?;
    let result = stored_units(store.path());
    fs::remove_dir(&units)?;
    assert!(result.is_err(), "stored_units must reject a units junction");
    Ok(())
}

#[cfg(windows)]
#[test]
fn unit_junction_is_rejected_by_stored_units() -> Result<()> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_build_dir(build.path())?;
    harvest(build.path(), store.path(), None, false)?;
    let unit = stored_units(store.path())?.remove(0);
    let stored_dir = unit.dir.clone();
    let unit_real = store.path().join("unit.real");
    fs::rename(&stored_dir, &unit_real)?;
    let victim = tempfile::tempdir()?;
    make_junction(&stored_dir, victim.path())?;
    let result = stored_units(store.path());
    fs::remove_dir(&stored_dir)?;
    assert!(result.is_err(), "stored_units must reject a unit junction");
    Ok(())
}

#[cfg(unix)]
#[test]
fn read_only_directory_refuses_store_writers() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if util::euid() == 0 {
        return Ok(()); // root can write 0555; the mode test does not apply
    }
    let home = tempfile::tempdir()?;
    let store = home.path().join("store");
    fs::create_dir(&store)?;
    fs::set_permissions(&store, fs::Permissions::from_mode(0o555))?;

    let err = drop_units(&store, "generation", &["unit".into()]).unwrap_err();
    assert!(format!("{err:#}").contains("read-only"), "{err:#}");
    let err = drop_generation(&store, "generation").unwrap_err();
    assert!(format!("{err:#}").contains("read-only"), "{err:#}");
    let err = compact(&store, None, false).unwrap_err();
    assert!(format!("{err:#}").contains("read-only"), "{err:#}");
    // A dry run is a read-only audit and stays available.
    assert!(compact(&store, None, true).is_ok());

    fs::set_permissions(&store, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
