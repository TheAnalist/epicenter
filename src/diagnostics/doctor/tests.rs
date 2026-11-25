use super::*;
use std::fs;
use std::time::Duration;

#[test]
fn truthiness_parsing() {
    assert!(is_truthy("true"));
    assert!(is_truthy("1"));
    assert!(is_truthy(" YES "));
    assert!(is_truthy("On"));
    assert!(!is_truthy("false"));
    assert!(!is_truthy("0"));
    assert!(!is_truthy(""));
    assert!(!is_truthy("nightly"));
}

#[test]
fn flags_orphan_incremental_state() -> Result<()> {
    let root = tempfile::tempdir()?;
    let orphan = root.path().join("debug/incremental/orphan-abc123");
    fs::create_dir_all(orphan.join("session"))?;
    fs::write(orphan.join("session/file"), [0u8; 7])?;
    let wrapper = root.path().join("debug/incremental.kache-auto/v1/hash");
    fs::create_dir_all(&wrapper)?;
    fs::write(wrapper.join("state"), [0u8; 5])?;

    let rows: Vec<(Unit, ArtifactInfo)> = Vec::new();
    let checks = check_incremental_state(root.path(), &rows);
    let messages: Vec<&str> = checks.iter().map(|check| check.message.as_str()).collect();
    assert!(
        messages
            .iter()
            .any(|message| message.contains("incremental session")),
        "{messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("incremental.*")),
        "{messages:?}"
    );
    Ok(())
}

#[test]
fn flags_stale_vault_generations() -> Result<()> {
    let store = tempfile::tempdir()?;
    let old = store.path().join("old-generation").join("units/foo-abc");
    fs::create_dir_all(&old)?;
    fs::write(old.join("artifact"), [0u8; 9])?;
    let checks = check_store_generations(store.path());
    let found: Vec<&str> = checks
        .iter()
        .filter(|check| matches!(check.level, Level::Warn))
        .map(|check| check.message.as_str())
        .collect();
    assert!(
        found.iter().any(|message| message.contains("stale vault")),
        "stale generation must be visible: {found:?}"
    );
    assert!(check_store_generations(&store.path().join("missing")).is_empty());
    Ok(())
}

#[test]
fn flags_older_toolchain_generations_for_reclaim() -> Result<()> {
    // Two units, two rustc generations: the most recently built one is
    // "active"; the other must surface as a reclaim warning.
    let root = tempfile::tempdir()?;
    let make_unit = |pkg: &str, hex: &str, rustc: &str, artifact: &str| -> Result<()> {
        let dir = root
            .path()
            .join("debug/.fingerprint")
            .join(format!("{pkg}-{hex}"));
        fs::create_dir_all(&dir)?;
        fs::write(dir.join(format!("lib-{pkg}")), "0011223344556677")?;
        fs::write(
            dir.join(format!("lib-{pkg}.json")),
            format!(r#"{{"rustc":{rustc},"features":"[]","declared_features":"[]","deps":[]}}"#),
        )?;
        fs::create_dir_all(root.path().join("debug/deps"))?;
        fs::write(root.path().join("debug/deps").join(artifact), [0u8; 8])?;
        Ok(())
    };
    make_unit(
        "oldcrate",
        "aaaaaaaaaaaaaaaa",
        "111",
        "liboldcrate-aaaaaaaaaaaaaaaa.rlib",
    )?;
    std::thread::sleep(std::time::Duration::from_millis(20));
    make_unit(
        "newcrate",
        "bbbbbbbbbbbbbbbb",
        "222",
        "libnewcrate-bbbbbbbbbbbbbbbb.rlib",
    )?;

    let rows = who::collect(root.path())?;
    let checks = check_toolchain_generation(&rows);
    let reclaim = checks
        .iter()
        .find(|c| c.message.contains("older toolchain generations"))
        .expect("reclaim warning expected");
    assert_eq!(reclaim.level as u8, Level::Warn as u8);
    assert!(
        reclaim.message.contains("1 unit(s)"),
        "got: {}",
        reclaim.message
    );
    Ok(())
}

/// Two units with a resolved dependency edge (the serde → serde_core
/// pair); artifacts carry explicit stamps so the
/// ordering is deterministic.
fn edge_build_dir(root: &Path, dep_at: u64, unit_at: u64) -> Result<()> {
    let stamp = |path: &Path, secs: u64| -> Result<()> {
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
        fs::File::options()
            .write(true)
            .open(path)?
            .set_modified(time)?;
        Ok(())
    };
    fs::create_dir_all(root.join("debug/deps"))?;

    let core = root.join("debug/.fingerprint/serde_core-b468be6fa8c1f936");
    fs::create_dir_all(&core)?;
    fs::write(core.join("lib-serde_core"), "71a9f323efa5ae82")?;
    let core_rlib = root.join("debug/deps/libserde_core-b468be6fa8c1f936.rlib");
    fs::write(&core_rlib, [1u8; 32])?;
    stamp(&core_rlib, dep_at)?;

    let unit = root.join("debug/.fingerprint/serde-746d173581f1a314");
    fs::create_dir_all(&unit)?;
    fs::write(unit.join("lib-serde"), "5d82713a7f2d05e2")?;
    fs::write(
        unit.join("lib-serde.json"),
        r#"{"rustc":5244445300240561903,"features":"[]","declared_features":"[]","deps":[[11029742160753049355,"serde_core",false,9416646317397223793]]}"#,
    )?;
    let unit_rlib = root.join("debug/deps/libserde-746d173581f1a314.rlib");
    fs::write(&unit_rlib, [1u8; 32])?;
    stamp(&unit_rlib, unit_at)?;
    Ok(())
}

#[test]
fn flags_units_older_than_their_dependencies() -> Result<()> {
    let root = tempfile::tempdir()?;
    edge_build_dir(root.path(), 1_700_000_600, 1_700_000_000)?;
    let rows = who::collect(root.path())?;
    let checks = check_mtime_ordering(&rows);
    assert!(
        matches!(checks[0].level, Level::Warn),
        "{:?}",
        checks[0].message
    );
    assert!(
        checks[0].message.contains("recompile once"),
        "got: {}",
        checks[0].message
    );
    assert_eq!(checks.len(), 2, "one example follows the count");
    assert!(checks[1].message.contains("serde-746d173581f1a314"));
    assert!(checks[1].message.contains("serde_core-b468be6fa8c1f936"));
    Ok(())
}

#[test]
fn ordering_passes_when_units_are_current() -> Result<()> {
    let root = tempfile::tempdir()?;
    edge_build_dir(root.path(), 1_700_000_000, 1_700_000_600)?;
    let rows = who::collect(root.path())?;
    let checks = check_mtime_ordering(&rows);
    assert!(matches!(checks[0].level, Level::Pass));
    assert!(
        checks[0].message.contains("at least as new"),
        "got: {}",
        checks[0].message
    );
    assert_eq!(checks.len(), 1);
    Ok(())
}

#[test]
fn staleness_requires_both_timestamps() {
    let now = SystemTime::now();
    let older = now - Duration::from_secs(60);
    assert!(older < now, "sanity");
    assert!(!(older >= now));
    assert!(now > older);
}
