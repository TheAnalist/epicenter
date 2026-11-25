use super::*;
use std::fs;

#[test]
fn utc_stamp_is_correct_and_sortable() {
    assert_eq!(stamp_from_unix(0), "19700101-000000");
    assert_eq!(stamp_from_unix(86_399), "19700101-235959");
    assert_eq!(stamp_from_unix(86_400), "19700102-000000");
    assert_eq!(stamp_from_unix(1_800_000_000), "20270115-080000");
}

#[test]
fn job_ids_are_path_safe() {
    assert_eq!(sanitize_job_id(" ci-1234_ok ").unwrap(), "ci-1234_ok");
    assert!(sanitize_job_id("").is_err());
    assert!(sanitize_job_id("..").is_err());
    assert!(sanitize_job_id("../x").is_err());
    assert!(sanitize_job_id("a/b").is_err());
    assert!(sanitize_job_id(".hidden").is_err());
    assert!(sanitize_job_id("has space").is_err());
    assert!(sanitize_job_id("CON").is_err());
    assert!(sanitize_job_id("com1").is_err());
    assert!(sanitize_job_id("trailing.").is_err());
    assert!(sanitize_job_id("CON.txt").is_err());
    assert!(sanitize_job_id("NUL.log").is_err());
    assert!(sanitize_job_id("COM1.txt").is_err());
}

/// One synthetic unit in a build dir, harvested into a temp vault.
fn seeded_store() -> Result<(tempfile::TempDir, tempfile::TempDir)> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let unit = build.path().join("debug/.fingerprint/x-1122334455667788");
    fs::create_dir_all(&unit)?;
    fs::write(unit.join("lib-x"), "aaaabbbbccccdddd")?;
    fs::write(
        unit.join("lib-x.json"),
        r#"{"rustc":1,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[]}"#,
    )?;
    fs::write(unit.join("dep-lib-x"), [0u8; 4])?;
    fs::create_dir_all(build.path().join("debug/deps"))?;
    fs::write(
        build.path().join("debug/deps/libx-1122334455667788.rlib"),
        [1u8; 8],
    )?;
    vault::harvest(build.path(), store.path(), None, false)?;
    Ok((build, store))
}

fn synthetic_unit(root: &Path, profile: &str, package: &str, hash: &str, byte: u8) -> Result<()> {
    let unit = root
        .join(profile)
        .join(".fingerprint")
        .join(format!("{package}-{hash}"));
    fs::create_dir_all(&unit)?;
    fs::write(unit.join(format!("lib-{package}")), "5d82713a7f2d05e2")?;
    fs::write(
        unit.join(format!("lib-{package}.json")),
        r#"{"rustc":1,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[]}"#,
    )?;
    fs::write(unit.join(format!("dep-lib-{package}")), [0u8; 8])?;
    fs::create_dir_all(root.join(profile).join("deps"))?;
    fs::write(
        root.join(profile)
            .join("deps")
            .join(format!("lib{package}-{hash}.rlib")),
        [byte; 32],
    )?;
    Ok(())
}

fn seeded_profiles_store() -> Result<(tempfile::TempDir, tempfile::TempDir)> {
    let build = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    synthetic_unit(build.path(), "debug", "debugdep", "1111111111111111", 1)?;
    synthetic_unit(build.path(), "release", "releasedep", "2222222222222222", 2)?;
    vault::harvest(build.path(), store.path(), None, false)?;
    Ok((build, store))
}

#[cfg(unix)]
#[test]
fn exec_seeds_the_job_and_propagates_the_exit_code() -> Result<()> {
    let (_build, store) = seeded_store()?;
    let work = tempfile::tempdir()?;
    // The synthetic store unit is for package `x`: name it in a lock so
    // this test does not depend on whatever Cargo.lock exists above /tmp.
    let project = tempfile::tempdir()?;
    fs::write(
        project.path().join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"x\"\nversion = \"1.0.0\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
         checksum = \"abababababababababababababababababababababababababababababababab\"\n",
    )?;
    let job_dir = work.path().join("jobtest");
    let command = vec![
        "sh".to_string(),
        "-c".to_string(),
        format!(
            "test \"$CARGO_BUILD_BUILD_DIR\" = '{}' && exit 7",
            job_dir.display()
        ),
    ];
    let opts = Options {
        job_id: Some("jobtest"),
        cwd: Some(project.path().to_path_buf()),
        harvest_back: false,
        compress: true,
        remove_on_success: false,
        reuse: false,
        target_dir: None,
        incremental: None,
        link: LinkPolicy::Auto,
        cargo_home: None,
        no_remote: false,
        remote: None,
        command: &command,
    };
    let code = run(store.path(), work.path(), &opts)?;
    assert_eq!(code, 7, "the command's exit code is the job's exit code");
    assert!(
        job_dir
            .join("debug/.fingerprint/x-1122334455667788/lib-x")
            .is_file(),
        "the vault seeded the job"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn exec_sets_the_configured_cargo_home_in_the_child() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let (_build, store) = seeded_store()?;
    let work = tempfile::tempdir()?;
    let cargo = tempfile::tempdir()?;
    fs::set_permissions(cargo.path(), fs::Permissions::from_mode(0o700))?;
    let command = vec![
        "sh".to_string(),
        "-c".to_string(),
        format!("test \"$CARGO_HOME\" = '{}'", cargo.path().display()),
    ];
    let opts = Options {
        job_id: Some("cargo-home"),
        cwd: None,
        harvest_back: false,
        compress: true,
        remove_on_success: false,
        reuse: false,
        target_dir: None,
        incremental: None,
        link: LinkPolicy::Auto,
        cargo_home: Some(cargo.path()),
        no_remote: false,
        remote: None,
        command: &command,
    };
    assert_eq!(run(store.path(), work.path(), &opts)?, 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn exec_seeds_only_the_child_profile() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let (_build, store) = seeded_profiles_store()?;
    let work = tempfile::tempdir()?;
    let project = tempfile::tempdir()?;
    let checksum_a = "ab".repeat(32);
    let checksum_b = "cd".repeat(32);
    fs::write(
        project.path().join("Cargo.lock"),
        format!(
            "version = 4\n\n[[package]]\nname = \"debugdep\"\nversion = \"1.0.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"{checksum_a}\"\n\n\
             [[package]]\nname = \"releasedep\"\nversion = \"1.0.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"{checksum_b}\"\n"
        ),
    )?;
    let bin = tempfile::tempdir()?;
    let cargo = bin.path().join("cargo");
    fs::write(
        &cargo,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo 'cargo 1.99.1 (000000000 2026-01-01)'\n  exit 0\nfi\nexit 0\n",
    )?;
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755))?;
    let cargo = cargo.to_string_lossy().into_owned();

    let bench = vec![cargo.clone(), "bench".to_string()];
    let mut opts = Options {
        job_id: Some("bench"),
        cwd: Some(project.path().to_path_buf()),
        harvest_back: false,
        compress: true,
        remove_on_success: false,
        reuse: false,
        target_dir: None,
        incremental: None,
        link: LinkPolicy::Auto,
        cargo_home: None,
        no_remote: false,
        remote: None,
        command: &bench,
    };
    assert_eq!(run(store.path(), work.path(), &opts)?, 0);
    assert!(
        work.path()
            .join("bench/release/.fingerprint/releasedep-2222222222222222/lib-releasedep")
            .is_file(),
        "cargo bench seeds release units"
    );
    assert!(
        !work
            .path()
            .join("bench/debug/.fingerprint/debugdep-1111111111111111")
            .exists(),
        "cargo bench does not seed debug units"
    );

    let build = vec![cargo, "build".to_string()];
    opts.job_id = Some("devjob");
    opts.command = &build;
    assert_eq!(run(store.path(), work.path(), &opts)?, 0);
    assert!(
        work.path()
            .join("devjob/debug/.fingerprint/debugdep-1111111111111111/lib-debugdep")
            .is_file(),
        "cargo build seeds debug units"
    );
    assert!(
        !work
            .path()
            .join("devjob/release/.fingerprint/releasedep-2222222222222222")
            .exists(),
        "cargo build does not seed release units"
    );
    Ok(())
}

#[test]
fn exec_seeds_only_the_packages_in_the_project_lock() -> Result<()> {
    let (_build, store) = seeded_store()?;
    let work = tempfile::tempdir()?;
    let project = tempfile::tempdir()?;
    let command: Vec<String> = vec!["true".into()];
    let lock = project.path().join("Cargo.lock");

    // The project's lock does not name the stored unit: do not seed it.
    fs::write(
        &lock,
        "version = 4\n\n[[package]]\nname = \"unrelated\"\nversion = \"1.0.0\"\n",
    )?;
    let opts = Options {
        job_id: Some("filtered"),
        cwd: Some(project.path().to_path_buf()),
        harvest_back: false,
        compress: true,
        remove_on_success: false,
        reuse: false,
        target_dir: None,
        incremental: None,
        link: LinkPolicy::Auto,
        cargo_home: None,
        no_remote: false,
        remote: None,
        command: &command,
    };
    assert_eq!(run(store.path(), work.path(), &opts)?, 0);
    assert!(
        !work
            .path()
            .join("filtered/debug/.fingerprint/x-1122334455667788")
            .exists(),
        "a unit outside the lock is not seeded"
    );

    // Naming the package in the lock seeds exactly that unit.
    fs::write(
        &lock,
        "version = 4\n\n[[package]]\nname = \"x\"\nversion = \"1.0.0\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
         checksum = \"abababababababababababababababababababababababababababababababab\"\n",
    )?;
    let opts = Options {
        job_id: Some("seeded"),
        ..opts
    };
    assert_eq!(run(store.path(), work.path(), &opts)?, 0);
    assert!(
        work.path()
            .join("seeded/debug/.fingerprint/x-1122334455667788/lib-x")
            .is_file(),
        "a unit inside the lock is seeded"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn exec_rm_removes_the_job_dir_either_way() -> Result<()> {
    let (_build, store) = seeded_store()?;
    let work = tempfile::tempdir()?;
    // Old lock debris from a job dir that no longer exists (or a crash).
    fs::write(work.path().join(".lock-orphan"), b"")?;

    let ok: Vec<String> = vec!["true".into()];
    let opts = Options {
        job_id: Some("j-ok"),
        cwd: None,
        harvest_back: false,
        compress: true,
        remove_on_success: true,
        reuse: false,
        target_dir: None,
        incremental: None,
        link: LinkPolicy::Auto,
        cargo_home: None,
        no_remote: false,
        remote: None,
        command: &ok,
    };
    assert_eq!(run(store.path(), work.path(), &opts)?, 0);
    assert!(!work.path().join("j-ok").exists(), "success -> removed");
    assert!(
        !work.path().join(".lock-j-ok").exists(),
        "success -> its job lock removed"
    );
    assert!(
        !work.path().join(".lock-orphan").exists(),
        "orphan lock debris swept"
    );

    // `--rm` is explicit: a failing build is removed too (the fixed
    // rmeta-era failure mode used to leave dirs piling up here).
    let bad: Vec<String> = vec!["false".into()];
    let opts = Options {
        job_id: Some("j-bad"),
        cwd: None,
        harvest_back: false,
        compress: true,
        remove_on_success: true,
        reuse: false,
        target_dir: None,
        incremental: None,
        link: LinkPolicy::Auto,
        cargo_home: None,
        no_remote: false,
        remote: None,
        command: &bad,
    };
    assert_eq!(run(store.path(), work.path(), &opts)?, 1);
    assert!(
        !work.path().join("j-bad").exists(),
        "--rm -> removed on failure too"
    );
    assert!(
        !work.path().join(".lock-j-bad").exists(),
        "--rm -> its job lock removed on failure too"
    );

    // Without --rm the dir stays for inspection.
    let kept: Vec<String> = vec!["true".into()];
    let opts = Options {
        job_id: Some("j-keep"),
        cwd: None,
        harvest_back: false,
        compress: true,
        remove_on_success: false,
        reuse: false,
        target_dir: None,
        incremental: None,
        link: LinkPolicy::Auto,
        cargo_home: None,
        no_remote: false,
        remote: None,
        command: &kept,
    };
    assert_eq!(run(store.path(), work.path(), &opts)?, 0);
    assert!(
        work.path().join("j-keep").exists(),
        "no --rm -> kept for inspection"
    );
    assert!(
        work.path().join(".lock-j-keep").exists(),
        "a kept job keeps its lock for the next --reuse"
    );
    Ok(())
}

#[test]
fn work_tier_summarizes_job_dirs() -> Result<()> {
    let home = tempfile::tempdir()?;
    let build = home.path().join("build");
    fs::create_dir_all(&build)?;
    let debug = home.path().join("work/ci-1/debug");
    fs::create_dir_all(&debug)?;
    fs::write(debug.join("a.bin"), [0u8; 100])?;
    fs::write(debug.join("b.bin"), [0u8; 50])?;

    let tier = work_tier(&build)?;
    assert_eq!(tier.dirs, 1);
    assert_eq!(tier.files, 2);
    assert_eq!(tier.bytes, 150);
    assert!(tier.newest.is_some());
    assert_eq!(tier.entries.len(), 1);
    assert_eq!(tier.entries[0].name, "ci-1");
    assert_eq!(tier.entries[0].bytes, 150);
    assert_eq!(tier.entries[0].files, 2);
    Ok(())
}

#[test]
fn exec_refuses_a_used_job_dir() -> Result<()> {
    let (_build, store) = seeded_store()?;
    let work = tempfile::tempdir()?;
    fs::create_dir_all(work.path().join("taken"))?;
    let command: Vec<String> = vec!["true".into()];
    let opts = Options {
        job_id: Some("taken"),
        cwd: None,
        harvest_back: false,
        compress: true,
        remove_on_success: false,
        reuse: false,
        target_dir: None,
        incremental: None,
        link: LinkPolicy::Auto,
        cargo_home: None,
        no_remote: false,
        remote: None,
        command: &command,
    };
    let err = run(store.path(), work.path(), &opts).unwrap_err();
    assert!(err.to_string().contains("already exists"), "{err}");
    assert!(err.to_string().contains("--reuse"), "mentions the way out");
    Ok(())
}

#[cfg(unix)]
#[test]
fn target_dir_resolution() {
    let work = Path::new("/cache/work/ci-1");
    let cwd = Path::new("/project");
    assert_eq!(
        resolve_target_dir("job", work, Some(cwd)),
        PathBuf::from("/cache/work/ci-1/target")
    );
    assert_eq!(
        resolve_target_dir("/abs/finals", work, Some(cwd)),
        PathBuf::from("/abs/finals")
    );
    assert_eq!(
        resolve_target_dir("rel/finals", work, Some(cwd)),
        PathBuf::from("/project/rel/finals")
    );
}

#[cfg(unix)]
#[test]
fn exec_reuse_continues_in_an_existing_dir() -> Result<()> {
    let (_build, store) = seeded_store()?;
    let work = tempfile::tempdir()?;
    let ok: Vec<String> = vec!["true".into()];
    let fresh = Options {
        job_id: Some("j1"),
        cwd: None,
        harvest_back: false,
        compress: true,
        remove_on_success: false,
        reuse: false,
        target_dir: None,
        incremental: None,
        link: LinkPolicy::Auto,
        cargo_home: None,
        no_remote: false,
        remote: None,
        command: &ok,
    };
    assert_eq!(run(store.path(), work.path(), &fresh)?, 0);

    let err = run(store.path(), work.path(), &fresh).unwrap_err();
    assert!(err.to_string().contains("already exists"), "{err}");

    let again = Options {
        reuse: true,
        ..fresh
    };
    assert_eq!(run(store.path(), work.path(), &again)?, 0);
    Ok(())
}

#[test]
fn exec_reuse_refuses_a_locked_dir() -> Result<()> {
    let (_build, store) = seeded_store()?;
    let work = tempfile::tempdir()?;
    let dir = work.path().join("busy");
    crate::util::create_private_dir_all(&dir)?;
    let debug = dir.join("debug");
    crate::util::create_private_dir_all(&debug)?;
    write_job_marker(&dir)?;
    record_for_test(&dir)?;
    let lock = debug.join(".cargo-build-lock");
    fs::write(&lock, b"")?;
    let held = fs::OpenOptions::new().write(true).open(&lock)?;
    held.try_lock().context("test holds the lock")?;

    let cmd: Vec<String> = vec!["true".into()];
    let opts = Options {
        job_id: Some("busy"),
        cwd: None,
        harvest_back: false,
        compress: true,
        remove_on_success: false,
        reuse: true,
        target_dir: None,
        incremental: None,
        link: LinkPolicy::Auto,
        cargo_home: None,
        no_remote: false,
        remote: None,
        command: &cmd,
    };
    let err = run(store.path(), work.path(), &opts).unwrap_err();
    assert!(err.to_string().contains("in use"), "{err}");
    Ok(())
}

#[test]
fn nested_target_lock_is_detected() -> Result<()> {
    let home = tempfile::tempdir()?;
    let job = home.path().join("job/debug");
    fs::create_dir_all(&job)?;
    let lock = job.join(".cargo-build-lock");
    fs::write(&lock, b"")?;
    let held = fs::OpenOptions::new().write(true).open(&lock)?;
    held.try_lock().context("test holds the lock")?;
    assert!(dir_locked(&home.path().join("job")), "direct profile lock");

    let nested = home.path().join("cross/x86_64-unknown-linux-gnu/debug");
    fs::create_dir_all(&nested)?;
    let lock = nested.join(".cargo-build-lock");
    fs::write(&lock, b"")?;
    let held = fs::OpenOptions::new().write(true).open(&lock)?;
    held.try_lock().context("test holds the nested lock")?;
    assert!(
        dir_locked(&home.path().join("cross")),
        "target-triple lock must be found"
    );
    Ok(())
}

#[test]
fn cargo_locks_creates_a_sentinel_for_an_existing_profile() -> Result<()> {
    let home = tempfile::tempdir()?;
    let job = home.path().join("job");
    let profile = job.join("debug");
    fs::create_dir_all(profile.join("deps"))?;

    let locks = cargo_locks(&job)?.expect("sentinel acquired");
    let lock_path = profile.join(".cargo-build-lock");
    assert!(lock_path.is_file(), "the sentinel is created");
    let second = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)?;
    assert!(
        second.try_lock().is_err(),
        "a second opener must contend with the held sentinel"
    );
    drop(locks);
    assert!(
        cargo_locks(&job)?.is_some(),
        "the sentinel is reusable after the lock is released"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn cargo_locks_refuses_a_symlinked_lock() -> Result<()> {
    let home = tempfile::tempdir()?;
    let profile = home.path().join("job/debug");
    fs::create_dir_all(&profile)?;
    let victim = home.path().join("victim");
    fs::write(&victim, b"")?;
    std::os::unix::fs::symlink(&victim, profile.join(".cargo-build-lock"))?;
    assert!(
        cargo_locks(&home.path().join("job"))?.is_none(),
        "a symlinked lock fails closed"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn an_uninspectable_root_is_treated_as_locked() -> Result<()> {
    let home = tempfile::tempdir()?;
    let real = home.path().join("real");
    fs::create_dir(&real)?;
    let link = home.path().join("link");
    std::os::unix::fs::symlink(&real, &link)?;
    assert!(
        cargo_locks(&link)?.is_none(),
        "a reparse root cannot be inspected and must fail closed"
    );
    assert!(dir_locked(&link), "the advisory check agrees");
    Ok(())
}

#[cfg(unix)]
#[test]
fn new_job_dirs_are_marked_and_reuse_requires_the_marker() -> Result<()> {
    let (_build, store) = seeded_store()?;
    let work = tempfile::tempdir()?;
    let command: Vec<String> = vec!["true".into()];
    let fresh = Options {
        job_id: Some("marked"),
        cwd: None,
        harvest_back: false,
        compress: true,
        remove_on_success: false,
        reuse: false,
        target_dir: None,
        incremental: None,
        link: LinkPolicy::Auto,
        cargo_home: None,
        no_remote: false,
        remote: None,
        command: &command,
    };
    assert_eq!(run(store.path(), work.path(), &fresh)?, 0);
    assert!(has_job_marker(&work.path().join("marked"))?);

    fs::remove_file(work.path().join("marked").join(JOB_MARKER))?;
    let reuse = Options {
        reuse: true,
        ..fresh
    };
    let err = run(store.path(), work.path(), &reuse).unwrap_err();
    assert!(err.to_string().contains(".epicenter-job"), "{err}");
    Ok(())
}

#[test]
fn exec_reuse_adopts_a_marker_only_dir() -> Result<()> {
    let (_build, store) = seeded_store()?;
    let work = tempfile::tempdir()?;
    let dir = work.path().join("adopt");
    crate::util::create_private_dir_all(&dir)?;
    write_job_marker(&dir)?;

    let command: Vec<String> = vec!["true".into()];
    let opts = Options {
        job_id: Some("adopt"),
        cwd: None,
        harvest_back: false,
        compress: true,
        remove_on_success: false,
        reuse: true,
        target_dir: None,
        incremental: None,
        link: LinkPolicy::Auto,
        cargo_home: None,
        no_remote: false,
        remote: None,
        command: &command,
    };
    assert_eq!(run(store.path(), work.path(), &opts)?, 0);
    assert!(
        work.path().join(".exec-adopt.json").is_file(),
        "a marker-only dir is adopted with a record"
    );
    Ok(())
}

#[test]
fn exec_reuse_refuses_a_planted_dir_without_a_record() -> Result<()> {
    let (_build, store) = seeded_store()?;
    let work = tempfile::tempdir()?;
    let dir = work.path().join("planted");
    crate::util::create_private_dir_all(&dir)?;
    write_job_marker(&dir)?;
    fs::write(dir.join("planted.txt"), b"payload")?;

    let command: Vec<String> = vec!["true".into()];
    let opts = Options {
        job_id: Some("planted"),
        cwd: None,
        harvest_back: false,
        compress: true,
        remove_on_success: false,
        reuse: true,
        target_dir: None,
        incremental: None,
        link: LinkPolicy::Auto,
        cargo_home: None,
        no_remote: false,
        remote: None,
        command: &command,
    };
    let err = run(store.path(), work.path(), &opts).unwrap_err();
    assert!(err.to_string().contains("no exec record"), "{err}");
    Ok(())
}

#[test]
fn exec_reuse_refuses_a_record_for_another_token() -> Result<()> {
    let (_build, store) = seeded_store()?;
    let work = tempfile::tempdir()?;
    let dir = work.path().join("mismatch");
    crate::util::create_private_dir_all(&dir)?;
    write_job_marker(&dir)?;
    record_for_test(&dir)?;
    // Replace the marker token; the record still names the old one.
    fs::write(
        dir.join(JOB_MARKER),
        format!("{JOB_MARKER_VERSION}\n{}\n", "f".repeat(32)),
    )?;

    let command: Vec<String> = vec!["true".into()];
    let opts = Options {
        job_id: Some("mismatch"),
        cwd: None,
        harvest_back: false,
        compress: true,
        remove_on_success: false,
        reuse: true,
        target_dir: None,
        incremental: None,
        link: LinkPolicy::Auto,
        cargo_home: None,
        no_remote: false,
        remote: None,
        command: &command,
    };
    let err = run(store.path(), work.path(), &opts).unwrap_err();
    assert!(err.to_string().contains("different build"), "{err}");
    Ok(())
}

#[cfg(unix)]
#[test]
fn exec_reuse_refuses_a_symlinked_record() -> Result<()> {
    let (_build, store) = seeded_store()?;
    let work = tempfile::tempdir()?;
    let dir = work.path().join("linked");
    crate::util::create_private_dir_all(&dir)?;
    write_job_marker(&dir)?;
    record_for_test(&dir)?;
    let record = work.path().join(".exec-linked.json");
    let target = work.path().join("record-target.json");
    fs::write(&target, b"{}")?;
    fs::remove_file(&record)?;
    std::os::unix::fs::symlink(&target, &record)?;

    let command: Vec<String> = vec!["true".into()];
    let opts = Options {
        job_id: Some("linked"),
        cwd: None,
        harvest_back: false,
        compress: true,
        remove_on_success: false,
        reuse: true,
        target_dir: None,
        incremental: None,
        link: LinkPolicy::Auto,
        cargo_home: None,
        no_remote: false,
        remote: None,
        command: &command,
    };
    let err = run(store.path(), work.path(), &opts).unwrap_err();
    assert!(err.to_string().contains("does not trust"), "{err}");
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_memory_sampler_sees_the_child_tree() -> Result<()> {
    // cmd spawns ping, so this also exercises job membership across
    // descendants. ping keeps both alive for about a second — several
    // sample ticks.
    let mut child = std::process::Command::new("cmd")
        .args(["/C", "ping -n 2 127.0.0.1 >NUL"])
        .spawn()?;
    let memory = ChildMemory::start(&child);
    let status = child.wait()?;
    let peak = memory.finish()?;
    assert!(status.success());
    assert!(peak.is_some(), "no working set sampled for the child tree");
    Ok(())
}

#[test]
fn default_work_root_is_not_derived_from_the_build_root() -> Result<()> {
    let default = crate::paths::default_work_root()?;
    assert!(default.is_absolute(), "{}", default.display());
    assert!(
        default.ends_with("epicenter/work"),
        "unexpected default {}",
        default.display()
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn exec_exports_a_per_job_target_dir() -> Result<()> {
    let (_build, store) = seeded_store()?;
    let work = tempfile::tempdir()?;
    let job_dir = work.path().join("t1");
    let command = vec![
        "sh".to_string(),
        "-c".to_string(),
        format!(
            "test \"$CARGO_TARGET_DIR\" = '{}'",
            job_dir.join("target").display()
        ),
    ];
    let opts = Options {
        job_id: Some("t1"),
        cwd: None,
        harvest_back: false,
        compress: true,
        remove_on_success: false,
        reuse: false,
        target_dir: Some("job"),
        incremental: None,
        link: LinkPolicy::Auto,
        cargo_home: None,
        no_remote: false,
        remote: None,
        command: &command,
    };
    assert_eq!(run(store.path(), work.path(), &opts)?, 0);
    Ok(())
}

#[test]
fn child_cargo_reads_profile_target_and_subcommand() {
    let command = vec![
        "cargo".to_string(),
        "+nightly".to_string(),
        "test".to_string(),
        "--release".to_string(),
        "--target".to_string(),
        "wasm32-unknown-unknown".to_string(),
    ];
    let child = child_cargo(&command);
    assert!(child.builds_units);
    assert_eq!(child.selector.as_deref(), Some("nightly"));
    assert_eq!(child.profile.as_deref(), Some("release"));
    assert_eq!(child.target.as_deref(), Some("wasm32-unknown-unknown"));

    let child = child_cargo(&[
        "cargo".to_string(),
        "build".to_string(),
        "--profile=dev".to_string(),
    ]);
    assert_eq!(child.profile.as_deref(), Some("debug"));
    assert!(child.target.is_none());

    let child = child_cargo(&["cargo".to_string(), "bench".to_string()]);
    assert_eq!(
        child.profile.as_deref(),
        Some("release"),
        "the bench subcommand defaults to the release profile"
    );

    let child = child_cargo(&["cargo".to_string(), "test".to_string(), "bench".to_string()]);
    assert_eq!(
        child.profile.as_deref(),
        Some("debug"),
        "a literal bench test filter is not the bench subcommand"
    );

    let child = child_cargo(&[
        "cargo".to_string(),
        "build".to_string(),
        "--profile".to_string(),
        "bench".to_string(),
    ]);
    assert_eq!(child.profile.as_deref(), Some("release"));

    let child = child_cargo(&["cargo".to_string(), "build".to_string(), "-r".to_string()]);
    assert_eq!(child.profile.as_deref(), Some("release"));

    let child = child_cargo(&["cargo".to_string(), "metadata".to_string()]);
    assert!(!child.builds_units);
    assert!(child.profile.is_none());
}
