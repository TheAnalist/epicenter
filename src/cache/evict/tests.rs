use super::*;

/// One unit (`pkg-1122334455667788`) + its rlib in a build-dir shape.
fn write_synthetic_unit(root: &Path) -> Result<()> {
    let unit_dir = root.join("debug/.fingerprint/pkg-1122334455667788");
    fs::create_dir_all(&unit_dir)?;
    fs::write(unit_dir.join("lib-pkg"), "0011223344556677")?;
    fs::write(
        unit_dir.join("lib-pkg.json"),
        r#"{"rustc":1,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[]}"#,
    )?;
    fs::write(unit_dir.join("dep-lib-pkg"), [0u8; 8])?;
    fs::create_dir_all(root.join("debug/deps"))?;
    fs::write(
        root.join("debug/deps/libpkg-1122334455667788.rlib"),
        [0u8; 16],
    )?;
    Ok(())
}

/// A new-layout unit (`debug/build/<pkg>/<hash>/{fingerprint,out}`).
fn write_synthetic_new_unit(root: &Path, package: &str, hash: &str) -> Result<PathBuf> {
    let unit = root.join("debug/build").join(package).join(hash);
    fs::create_dir_all(unit.join("fingerprint"))?;
    fs::create_dir_all(unit.join("out"))?;
    fs::write(
        unit.join("fingerprint").join(format!("lib-{package}")),
        "0011223344556677",
    )?;
    fs::write(
        unit.join("fingerprint").join(format!("dep-lib-{package}")),
        [0u8; 8],
    )?;
    fs::write(
        unit.join("fingerprint").join(format!("lib-{package}.json")),
        r#"{"rustc":1,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[]}"#,
    )?;
    fs::write(
        unit.join("out").join(format!("lib{package}-{hash}.rlib")),
        [0u8; 16],
    )?;
    Ok(unit)
}

#[test]
fn removes_a_new_layout_unit_without_touching_siblings() -> Result<()> {
    let root = tempfile::tempdir()?;
    let one = write_synthetic_new_unit(root.path(), "anyhow", "1122334455667788")?;
    let two = write_synthetic_new_unit(root.path(), "anyhow", "8877665544332211")?;

    let units = crate::fingerprint::read_units(root.path())?;
    let unit = units
        .iter()
        .find(|unit| unit.dir_suffix == "1122334455667788")
        .expect("new-layout unit");
    let arts = crate::fingerprint::artifacts_for(root.path(), unit);
    let mut errors = 0;
    remove_view_unit(root.path(), unit, &arts, &mut errors);
    assert_eq!(errors, 0);
    assert!(!one.exists(), "the selected unit dir is removed");
    assert!(
        two.is_dir(),
        "a sibling unit of the same package must survive"
    );
    Ok(())
}

/// `{home}/build` with one unit — hermetic, so the store sits in
/// `{home}/store` and never touches anything outside the tempdir.
fn synthetic_home() -> Result<(tempfile::TempDir, PathBuf)> {
    let home = tempfile::tempdir()?;
    let build = home.path().join("build");
    fs::create_dir_all(&build)?;
    write_synthetic_unit(&build)?;
    Ok((home, build))
}

fn no_selectors() -> Options<'static> {
    Options {
        unit: None,
        stale: false,
        rustc_key: None,
        generation: None,
        husks: false,
        older_than: None,
        work_dirs: false,
        work_dir: None,
        work: None,
        crate_name: None,
        tier: Tier::All,
        force: false,
        delete: false,
    }
}

#[test]
fn resolve_view_rejects_paths_outside_the_cache() -> Result<()> {
    let home = tier_home()?;
    let build = home.path().join("build");
    let job = home.path().join("work/ci-1");
    fs::create_dir_all(&job)?;
    assert_eq!(resolve_view(&build, "ci-1")?, job);
    let outside = tempfile::tempdir()?;
    assert!(resolve_view(&build, outside.path().to_str().unwrap()).is_err());
    assert!(resolve_view(&build, "../escape").is_err());
    assert!(resolve_view(&build, "/tmp/escape").is_err());
    assert!(resolve_view(&build, ".. ").is_err());
    assert!(resolve_view(&build, "CON.txt").is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn build_view_rejects_a_symlinked_build_root() -> Result<()> {
    let home = tempfile::tempdir()?;
    let victim = tempfile::tempdir()?;
    let build = home.path().join("build");
    std::os::unix::fs::symlink(victim.path(), &build)?;
    let err = resolve_view(&build, "build").unwrap_err();
    assert!(format!("{err:#}").contains("symlink/reparse"), "{err:#}");
    Ok(())
}

#[test]
fn requires_at_least_one_selector() -> Result<()> {
    let (_home, build) = synthetic_home()?;
    assert!(run(&build, &no_selectors()).is_err());
    Ok(())
}

#[test]
fn stale_selector_skips_current_generation() -> Result<()> {
    let (_home, build) = synthetic_home()?;
    let opts = Options {
        stale: true,
        ..no_selectors()
    };
    // A single unit IS the current cohort → stale selects nothing.
    run(&build, &opts)?;
    assert!(
        build
            .join("debug/.fingerprint/pkg-1122334455667788")
            .exists()
    );
    Ok(())
}

#[test]
fn evicts_fingerprint_and_artifacts_with_force() -> Result<()> {
    let (_home, build) = synthetic_home()?;
    let opts = Options {
        unit: Some("pkg-1122334455667788"),
        force: true,
        delete: true,
        ..no_selectors()
    };
    run(&build, &opts)?;
    assert!(
        !build
            .join("debug/.fingerprint/pkg-1122334455667788")
            .exists(),
        "fingerprint dir must be gone"
    );
    assert!(
        !build
            .join("debug/deps/libpkg-1122334455667788.rlib")
            .exists(),
        "artifact must be gone"
    );
    Ok(())
}

use std::time::Duration;

/// `{home}/build` + `{home}/work` — the sibling layout of a real cache.
fn tier_home() -> Result<tempfile::TempDir> {
    let home = tempfile::tempdir()?;
    fs::create_dir_all(home.path().join("build"))?;
    fs::create_dir_all(home.path().join("work"))?;
    Ok(home)
}

/// One job dir: `work/<name>/debug/libjob.rlib`, aged by `age_days`.
fn aged_job(home: &Path, name: &str, age_days: u64) -> Result<PathBuf> {
    let debug = home.join("work").join(name).join("debug");
    fs::create_dir_all(&debug)?;
    let artifact = debug.join("libjob.rlib");
    fs::write(&artifact, [0u8; 64])?;
    if age_days > 0 {
        let when = SystemTime::now() - Duration::from_secs(age_days * 86_400);
        fs::OpenOptions::new()
            .write(true)
            .open(&artifact)?
            .set_modified(when)?;
    }
    Ok(home.join("work").join(name))
}

#[test]
fn work_dirs_collect_by_age_and_keep_young_ones() -> Result<()> {
    let home = tier_home()?;
    let build = home.path().join("build");
    let old_job = aged_job(home.path(), "old-job", 30)?;
    let fresh_job = aged_job(home.path(), "fresh-job", 0)?;

    let dry = evict_work_dirs(&build, None, false)?;
    assert_eq!((dry.scanned, dry.eligible, dry.young), (2, 1, 1));
    assert!(
        old_job.exists() && fresh_job.exists(),
        "dry run touches nothing"
    );

    fs::write(home.path().join("work/.lock-old-job"), b"")?;
    fs::write(home.path().join("work/.lock-fresh-job"), b"")?;
    fs::write(home.path().join("work/.lock-orphan"), b"")?;

    let done = evict_work_dirs(&build, None, true)?;
    assert_eq!(done.removed, 1);
    assert_eq!(done.unique_bytes, 64, "unique bytes are actually freed");
    assert!(!old_job.exists(), "aged job dir collected");
    assert!(fresh_job.exists(), "young job dir kept");
    assert!(
        !home.path().join("work/.lock-old-job").exists(),
        "the collected job's lock is removed"
    );
    assert!(
        home.path().join("work/.lock-fresh-job").is_file(),
        "the kept job's lock stays"
    );
    assert!(
        !home.path().join("work/.lock-orphan").exists(),
        "orphan lock debris is swept"
    );
    Ok(())
}

#[test]
fn work_dirs_never_collect_locked_jobs() -> Result<()> {
    let home = tier_home()?;
    let build = home.path().join("build");
    let job = aged_job(home.path(), "locked-job", 30)?;
    let lock_path = job.join("debug/.cargo-build-lock");
    fs::write(&lock_path, b"")?;
    // The lock file was also written a month ago, so age alone would collect it.
    let when = SystemTime::now() - Duration::from_secs(30 * 86_400);
    fs::OpenOptions::new()
        .write(true)
        .open(&lock_path)?
        .set_modified(when)?;

    let held = fs::OpenOptions::new().write(true).open(&lock_path)?;
    held.try_lock().context("test holds the lock")?;

    let report = evict_work_dirs(&build, None, true)?;
    assert_eq!((report.in_use, report.removed), (1, 0));
    assert!(job.exists(), "a locked job dir is never touched");

    held.unlock()?;
    drop(held);
    let report = evict_work_dirs(&build, None, true)?;
    assert_eq!(report.removed, 1);
    assert!(!job.exists());
    Ok(())
}

#[test]
fn work_dirs_cannot_be_combined_with_unit_selectors() -> Result<()> {
    let home = tier_home()?;
    let opts = Options {
        work_dirs: true,
        stale: true,
        ..no_selectors()
    };
    assert!(run(&home.path().join("build"), &opts).is_err());
    Ok(())
}

#[test]
fn work_dir_accounting_separates_unique_and_shared_bytes() -> Result<()> {
    let home = tier_home()?;
    let debug = home.path().join("work/aged-job/debug");
    fs::create_dir_all(&debug)?;
    let unique = debug.join("unique.rlib");
    let shared = debug.join("shared.rlib");
    fs::write(&unique, [0u8; 100])?;
    fs::write(&shared, [0u8; 200])?;
    // One artifact also lives in the store → its bytes are not freed here.
    fs::hard_link(&shared, home.path().join("store-copy.rlib"))?;
    let when = SystemTime::now() - Duration::from_secs(30 * 86_400);
    fs::OpenOptions::new()
        .write(true)
        .open(&unique)?
        .set_modified(when)?;
    fs::OpenOptions::new()
        .write(true)
        .open(&shared)?
        .set_modified(when)?;

    let report = evict_work_dirs(&home.path().join("build"), None, false)?;
    assert_eq!(report.unique_bytes, 100);
    assert_eq!(report.shared_bytes, 200);
    assert_eq!(report.nominal_bytes, 300);
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_job_with_only_a_symlinked_subtree_is_not_bulk_collected() -> Result<()> {
    let home = tier_home()?;
    let job = home.path().join("work/linked-job");
    fs::create_dir_all(&job)?;
    let victim = home.path().join("linked-files");
    fs::create_dir_all(&victim)?;
    fs::write(victim.join("fresh.rlib"), [0u8; 8])?;
    std::os::unix::fs::symlink(&victim, job.join("files"))?;

    let report = evict_work_dirs(&home.path().join("build"), Some("1s"), false)?;
    assert_eq!(
        report.eligible, 0,
        "a non-empty job with no visible regular file must stay put"
    );
    assert_eq!(report.young, 1);
    Ok(())
}

#[test]
fn path_containment_distinguishes_siblings_and_descendants() {
    let root = Path::new("/cache/work/job");
    assert!(path_is_within(root, root));
    assert!(path_is_within(Path::new("/cache/work/job/debug"), root));
    assert!(!path_is_within(Path::new("/cache/work/job-2"), root));
    assert!(!path_is_within(Path::new("/cache/work"), root));
}

#[test]
fn work_dir_removal_ignores_the_age_window() -> Result<()> {
    let home = tier_home()?;
    let build = home.path().join("build");
    let job = aged_job(home.path(), "fresh-job", 0)?;
    fs::write(home.path().join("work/.lock-fresh-job"), b"")?;
    fs::write(home.path().join("work/.lock-orphan"), b"")?;
    let opts = Options {
        work_dir: Some("fresh-job"),
        delete: true,
        ..no_selectors()
    };
    run(&build, &opts)?;
    assert!(
        !job.exists(),
        "an explicitly selected dir goes regardless of age"
    );
    assert!(
        !home.path().join("work/.lock-fresh-job").exists(),
        "the removed job's lock is cleaned"
    );
    assert!(
        !home.path().join("work/.lock-orphan").exists(),
        "orphan lock debris is swept"
    );
    Ok(())
}

#[cfg(windows)]
#[test]
fn work_dir_removal_releases_lock_handles_before_renaming() -> Result<()> {
    let home = tier_home()?;
    let build = home.path().join("build");
    let job = aged_job(home.path(), "win-job", 0)?;
    fs::create_dir_all(job.join("debug"))?;
    // Windows refuses to rename a directory while this file is open.
    fs::write(job.join("debug/.cargo-build-lock"), b"")?;
    let opts = Options {
        work_dir: Some("win-job"),
        delete: true,
        ..no_selectors()
    };
    run(&build, &opts)?;
    assert!(!job.exists(), "the job dir is gone");
    Ok(())
}

#[test]
fn work_dir_refuses_locked_and_unknown_targets() -> Result<()> {
    let home = tier_home()?;
    let build = home.path().join("build");
    let job = aged_job(home.path(), "locked-job", 0)?;
    let lock_path = job.join("debug/.cargo-build-lock");
    fs::write(&lock_path, b"")?;
    let held = fs::OpenOptions::new().write(true).open(&lock_path)?;
    held.try_lock().context("test holds the lock")?;

    let opts = Options {
        work_dir: Some("locked-job"),
        delete: true,
        ..no_selectors()
    };
    let err = run(&build, &opts).unwrap_err();
    assert!(err.to_string().contains("in use"), "{err}");
    assert!(job.exists(), "a locked job dir survives");
    drop(held);

    let unknown = Options {
        work_dir: Some("nope"),
        ..no_selectors()
    };
    assert!(run(&build, &unknown).is_err());
    Ok(())
}

#[test]
fn work_dir_never_targets_the_shared_build_or_outside_paths() -> Result<()> {
    let home = tier_home()?;
    let build = home.path().join("build");
    let shared = Options {
        work_dir: Some("build"),
        ..no_selectors()
    };
    let err = run(&build, &shared).unwrap_err();
    assert!(err.to_string().contains("never removed"), "{err}");

    let outside = Options {
        work_dir: Some("/tmp"),
        ..no_selectors()
    };
    assert!(
        run(&build, &outside).is_err(),
        "only job dirs under work/ — /tmp is refused"
    );
    Ok(())
}

#[test]
fn work_dir_rejects_selectors_and_sibling_modes() -> Result<()> {
    let home = tier_home()?;
    let build = home.path().join("build");
    let with_age = Options {
        work_dir: Some("x"),
        older_than: Some("30d"),
        ..no_selectors()
    };
    assert!(run(&build, &with_age).is_err());

    let with_dirs = Options {
        work_dir: Some("x"),
        work_dirs: true,
        ..no_selectors()
    };
    let err = run(&build, &with_dirs).unwrap_err();
    assert!(err.to_string().contains("one operation"), "{err}");
    Ok(())
}

/// `{home}/build` with one unit + `{home}/work/ci-1` with the same unit.
fn tiered_views() -> Result<(tempfile::TempDir, PathBuf)> {
    let home = tempfile::tempdir()?;
    fs::create_dir_all(home.path().join("build"))?;
    fs::create_dir_all(home.path().join("work"))?;
    write_synthetic_unit(&home.path().join("build"))?;
    let job = home.path().join("work/ci-1");
    write_synthetic_unit(&job)?;
    Ok((home, job))
}

#[test]
fn work_surgery_unlinks_only_the_named_view() -> Result<()> {
    let (home, job) = tiered_views()?;
    let build = home.path().join("build");
    let opts = Options {
        work: Some("ci-1"),
        crate_name: Some("pkg"),
        delete: true,
        ..no_selectors()
    };
    run(&build, &opts)?;
    assert!(
        !job.join("debug/.fingerprint/pkg-1122334455667788").exists(),
        "job fingerprint unlinked"
    );
    assert!(
        !job.join("debug/deps/libpkg-1122334455667788.rlib").exists(),
        "job artifact unlinked"
    );
    assert!(
        build
            .join("debug/.fingerprint/pkg-1122334455667788")
            .exists(),
        "build view untouched"
    );
    assert!(
        build
            .join("debug/deps/libpkg-1122334455667788.rlib")
            .exists(),
        "build artifact untouched"
    );
    assert!(!home.path().join("store").exists(), "no store was touched");
    Ok(())
}

#[test]
fn work_surgery_holds_the_cargo_lock_without_self_contention() -> Result<()> {
    let (home, job) = tiered_views()?;
    // Cargo leaves `.cargo-build-lock` behind after a build. The surgery
    // holds it for the whole unlink; it must not then probe the same
    // lock and mistake its own guard for a live build.
    fs::write(job.join("debug/.cargo-build-lock"), b"")?;
    let build = home.path().join("build");
    let opts = Options {
        work: Some("ci-1"),
        crate_name: Some("pkg"),
        delete: true,
        ..no_selectors()
    };
    run(&build, &opts)?;
    assert!(
        !job.join("debug/.fingerprint/pkg-1122334455667788").exists(),
        "the unit is unlinked while the cargo lock is held"
    );
    Ok(())
}

#[test]
fn work_surgery_accepts_the_shared_build_view() -> Result<()> {
    let (home, job) = tiered_views()?;
    let build = home.path().join("build");
    let opts = Options {
        work: Some("build"),
        unit: Some("pkg"),
        delete: true,
        ..no_selectors()
    };
    run(&build, &opts)?;
    assert!(
        !build
            .join("debug/.fingerprint/pkg-1122334455667788")
            .exists()
    );
    assert!(job.join("debug/.fingerprint/pkg-1122334455667788").exists());
    Ok(())
}

#[test]
fn work_surgery_refuses_a_locked_view() -> Result<()> {
    let (home, job) = tiered_views()?;
    let build = home.path().join("build");
    let lock_path = job.join("debug/.cargo-build-lock");
    fs::write(&lock_path, b"")?;
    let held = fs::OpenOptions::new().write(true).open(&lock_path)?;
    held.try_lock().context("test holds the lock")?;
    let opts = Options {
        work: Some("ci-1"),
        crate_name: Some("pkg"),
        delete: true,
        ..no_selectors()
    };
    let err = run(&build, &opts).unwrap_err();
    assert!(err.to_string().contains("in use"), "{err}");
    assert!(job.join("debug/.fingerprint/pkg-1122334455667788").exists());
    Ok(())
}

#[test]
fn work_surgery_requires_a_selector_and_rejects_bulk_ones() -> Result<()> {
    let (home, _job) = tiered_views()?;
    let build = home.path().join("build");
    let bare = Options {
        work: Some("ci-1"),
        ..no_selectors()
    };
    assert!(run(&build, &bare).is_err(), "needs --crate/--unit");
    let bulk = Options {
        work: Some("ci-1"),
        stale: true,
        ..no_selectors()
    };
    let err = run(&build, &bulk).unwrap_err();
    assert!(err.to_string().contains("--crate"), "{err}");
    Ok(())
}

#[test]
fn work_surgery_unknown_view_errors() -> Result<()> {
    let (home, _job) = tiered_views()?;
    let build = home.path().join("build");
    let opts = Options {
        work: Some("nope"),
        crate_name: Some("pkg"),
        ..no_selectors()
    };
    assert!(run(&build, &opts).is_err());
    Ok(())
}

/// A home where the unit is both harvested into the store and present in
/// the build view — the state a real `harvest` leaves behind.
fn harvested_home() -> Result<(tempfile::TempDir, PathBuf)> {
    let (home, build) = synthetic_home()?;
    crate::vault::harvest(&build, &home.path().join("store"), None, false)?;
    Ok((home, build))
}

#[test]
fn store_tier_drops_groups_and_prunes_the_manifest() -> Result<()> {
    let (home, build) = harvested_home()?;
    let store = home.path().join("store");
    assert_eq!(crate::vault::stored_units(&store)?.len(), 1, "harvested");

    // No --force: with --tier store the vault is the user's to trim.
    let opts = Options {
        unit: Some("pkg"),
        tier: Tier::Store,
        delete: true,
        ..no_selectors()
    };
    run(&build, &opts)?;
    assert_eq!(
        crate::vault::stored_units(&store)?.len(),
        0,
        "store record gone"
    );
    let parity = crate::vault::parity_key()?;
    assert!(
        !store.join(&parity).exists(),
        "the emptied parity-key store is removed"
    );
    assert!(
        !store.join(format!(".lock-{parity}")).exists(),
        "its generation lock is removed too"
    );
    assert!(
        build
            .join("debug/.fingerprint/pkg-1122334455667788")
            .exists(),
        "the view keeps its links"
    );
    assert!(
        build
            .join("debug/deps/libpkg-1122334455667788.rlib")
            .exists(),
        "the view keeps its artifact"
    );
    Ok(())
}

#[test]
fn generation_selector_deletes_the_parity_dir_and_lock() -> Result<()> {
    let (home, build) = harvested_home()?;
    let store = home.path().join("store");
    let parity = crate::vault::parity_key()?;
    let generation = store.join(&parity);
    let lock = store.join(format!(".lock-{parity}"));
    assert!(
        generation.is_dir() && lock.is_file(),
        "harvested generation"
    );

    let opts = Options {
        generation: Some(&parity),
        force: true,
        delete: true,
        ..no_selectors()
    };
    run(&build, &opts)?;
    assert!(!generation.exists(), "parity-key store deleted");
    assert!(!lock.exists(), "generation lock deleted");
    assert!(crate::vault::generations(&store)?.is_empty());
    Ok(())
}

#[test]
fn generation_selector_protects_the_active_generation() -> Result<()> {
    let (home, build) = harvested_home()?;
    let store = home.path().join("store");
    let parity = crate::vault::parity_key()?;
    let opts = Options {
        generation: Some(&parity),
        delete: true,
        ..no_selectors()
    };
    let err = run(&build, &opts).unwrap_err();
    assert!(err.to_string().contains("protected"), "{err}");
    assert!(store.join(&parity).is_dir(), "nothing was deleted");
    Ok(())
}

#[cfg(unix)]
#[test]
fn generation_evict_refuses_a_read_only_store() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if crate::util::euid() == 0 {
        return Ok(()); // root can write 0555; the mode test does not apply
    }
    let home = tier_home()?;
    let build = home.path().join("build");
    let store = home.path().join("store");
    fs::create_dir(&store)?;
    fs::set_permissions(&store, fs::Permissions::from_mode(0o555))?;

    let dry = Options {
        generation: Some("anything"),
        delete: false,
        ..no_selectors()
    };
    let err = run(&build, &dry).unwrap_err();
    assert!(
        err.to_string().contains("no vault generation matches"),
        "a dry run is allowed on a read-only store: {err}"
    );

    let opts = Options {
        generation: Some("anything"),
        delete: true,
        ..no_selectors()
    };
    let err = run(&build, &opts).unwrap_err();
    assert!(format!("{err:#}").contains("read-only"), "{err:#}");

    fs::set_permissions(&store, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[test]
fn debris_sweep_removes_orphan_locks_and_empty_generations() -> Result<()> {
    let (home, _build) = harvested_home()?;
    let store = home.path().join("store");
    let parity = crate::vault::parity_key()?;
    fs::write(store.join(".lock-9.9.9-deadbeef"), b"")?;
    let husk = store.join("9.9.9-deadbeef");
    fs::create_dir_all(husk.join("units"))?;
    fs::write(husk.join(crate::vault::GENERATION_MARKER), b"")?;
    // An unmarked sibling is not an epicenter generation: it must survive
    // even though it has no manifest and no units.
    let unrelated = store.join("unrelated");
    fs::create_dir_all(unrelated.join("units"))?;
    fs::write(unrelated.join("precious.txt"), b"keep")?;

    crate::vault::sweep_store_debris(&store);
    assert!(!store.join(".lock-9.9.9-deadbeef").exists());
    assert!(!store.join("9.9.9-deadbeef").exists());
    assert!(
        unrelated.join("precious.txt").is_file(),
        "unrelated directory survives"
    );
    assert!(store.join(&parity).is_dir(), "the live generation is kept");
    assert!(
        store.join(format!(".lock-{parity}")).is_file(),
        "its lock is kept"
    );
    Ok(())
}

#[test]
fn view_tier_leaves_the_store_alone() -> Result<()> {
    let (home, build) = harvested_home()?;
    let store = home.path().join("store");
    let opts = Options {
        unit: Some("pkg"),
        tier: Tier::View,
        force: true,
        delete: true,
        ..no_selectors()
    };
    run(&build, &opts)?;
    assert!(
        !build
            .join("debug/.fingerprint/pkg-1122334455667788")
            .exists()
    );
    assert_eq!(
        crate::vault::stored_units(&store)?.len(),
        1,
        "store record stays"
    );
    Ok(())
}

#[test]
fn default_tier_removes_store_and_view_together() -> Result<()> {
    let (home, build) = harvested_home()?;
    let store = home.path().join("store");
    let opts = Options {
        unit: Some("pkg"),
        force: true,
        delete: true,
        ..no_selectors()
    };
    run(&build, &opts)?;
    assert_eq!(crate::vault::stored_units(&store)?.len(), 0);
    assert!(
        !build
            .join("debug/.fingerprint/pkg-1122334455667788")
            .exists()
    );
    assert!(
        !build
            .join("debug/deps/libpkg-1122334455667788.rlib")
            .exists()
    );
    Ok(())
}

#[test]
fn current_generation_is_protected_for_views() -> Result<()> {
    let (home, build) = harvested_home()?;
    let store = home.path().join("store");
    let opts = Options {
        older_than: Some("0s"),
        delete: true,
        ..no_selectors()
    };
    run(&build, &opts)?;
    assert!(
        build
            .join("debug/.fingerprint/pkg-1122334455667788")
            .exists(),
        "a bulk selector protects the current unit without --force"
    );
    assert_eq!(crate::vault::stored_units(&store)?.len(), 1);
    Ok(())
}

#[test]
fn explicit_unit_bypasses_the_current_generation_guard() -> Result<()> {
    let (home, build) = harvested_home()?;
    let store = home.path().join("store");
    let opts = Options {
        unit: Some("pkg"),
        delete: true,
        ..no_selectors()
    };
    run(&build, &opts)?;
    assert!(
        !build
            .join("debug/.fingerprint/pkg-1122334455667788")
            .exists(),
        "an explicit --unit is deliberate: it needs no --force"
    );
    assert_eq!(crate::vault::stored_units(&store)?.len(), 0);
    Ok(())
}

#[test]
fn stale_drops_non_active_generations_from_the_store() -> Result<()> {
    let (home, build) = harvested_home()?;
    let store = home.path().join("store");
    let old = store.join("0.0.0-deadbeef-x86_64-unknown-linux-gnu-00000000");
    let unit = old.join("units/oldpkg-0000111122223333");
    fs::create_dir_all(&unit)?;
    fs::write(unit.join("lib-old"), "aaaaaaaabbbbbbbb")?;
    let manifest = crate::vault::Manifest {
        parity_key: "0.0.0-deadbeef-x86_64-unknown-linux-gnu-00000000".into(),
        toolchain: "rustc 0.0.0".into(),
        created: 1,
        updated: 1,
        signature: String::new(),
        units: vec![crate::vault::UnitEntry {
            name: "oldpkg-0000111122223333".into(),
            profile: "debug".into(),
            memo: "lib-old".into(),
            hash: "aaaaaaaabbbbbbbb".into(),
            version: None,
            stamp: 1,
            layout: None,
            files: vec![crate::vault::FileEntry {
                path: "lib-old".into(),
                dest: ".fingerprint/oldpkg-0000111122223333/lib-old".into(),
                size: 16,
                sha256: "0".repeat(64),
                role: "memo".into(),
                object: None,
            }],
        }],
        mac: String::new(),
    };
    crate::vault::save_manifest(
        &store,
        "0.0.0-deadbeef-x86_64-unknown-linux-gnu-00000000",
        &manifest,
    )?;

    let opts = Options {
        stale: true,
        tier: Tier::Store,
        delete: true,
        ..no_selectors()
    };
    run(&build, &opts)?;
    assert!(!old.exists(), "the old generation is gone");
    assert_eq!(
        crate::vault::stored_units(&store)?.len(),
        1,
        "the active generation survives"
    );
    Ok(())
}

#[test]
fn accounting_frees_only_inodes_whose_last_link_goes() -> Result<()> {
    let home = tempfile::tempdir()?;
    let a = home.path().join("a.bin");
    let b = home.path().join("b.bin");
    let store_copy = home.path().join("store-copy.bin");
    fs::write(&a, [0u8; 100])?;
    fs::write(&b, [0u8; 200])?;
    fs::hard_link(&b, &store_copy)?;

    // Both links of `b` are in the plan → its bytes are actually freed.
    let (nominal, freed, released, count) =
        util::account_files(&[a.clone(), b.clone(), store_copy.clone()]);
    assert_eq!((nominal, freed, released, count), (300, 300, 0, 3));

    // Only the view's links are removed → `b` is released, not freed.
    let (nominal, freed, released, count) = util::account_files(&[a, b]);
    assert_eq!((nominal, freed, released, count), (300, 100, 200, 2));
    Ok(())
}
