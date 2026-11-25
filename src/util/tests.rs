//! Tests for the util helpers.

use std::fs;
use std::io::Write;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};

use super::proc::exe_candidates;
use super::*;

#[cfg(windows)]
use super::nofollow::open_delete_dir_handle;

#[test]
fn parses_time_units() {
    assert_eq!(
        parse_duration("30d").unwrap(),
        Duration::from_secs(30 * 86_400)
    );
    assert_eq!(
        parse_duration("2w").unwrap(),
        Duration::from_secs(2 * 604_800)
    );
    assert_eq!(
        parse_duration("12h").unwrap(),
        Duration::from_secs(12 * 3_600)
    );
    assert_eq!(parse_duration("45").unwrap(), Duration::from_secs(45));
    assert!(parse_duration("abc").is_err());
    assert!(parse_duration("5x").is_err());
}

#[test]
fn command_for_resolves_bare_tools_and_sets_the_windows_guard() -> Result<()> {
    let command = command_for("rustc")?;
    assert!(
        Path::new(command.get_program()).is_absolute(),
        "bare tool names resolve to an absolute path"
    );
    assert!(
        command
            .get_envs()
            .any(|(key, value)| key == "NoDefaultCurrentDirectoryInExePath"
                && value == Some(std::ffi::OsStr::new("1"))),
        "Windows CWD search is disabled for every spawned tool"
    );
    Ok(())
}

#[test]
fn scan_budget_stops_at_the_limit() {
    let mut budget = ScanBudget::with_limit(2, "test");
    assert!(budget.take());
    assert!(budget.take());
    assert!(!budget.take(), "the budget is exhausted");
    let mut budget = ScanBudget::with_limit(1, "test");
    assert!(budget.spend().is_ok());
    assert!(budget.spend().is_err(), "fallible scans report the limit");
}

#[test]
fn concurrent_dir_chain_creation_accepts_already_exists() {
    let root = tempfile::tempdir().unwrap();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let base = root.path().to_path_buf();
        handles.push(std::thread::spawn(move || {
            create_dir_chain_nofollow(&base, Path::new("debug/deps"))
        }));
    }
    for handle in handles {
        handle.join().unwrap().unwrap();
    }
    assert!(root.path().join("debug/deps").is_dir());
}

#[cfg(unix)]
#[test]
fn file_lock_refuses_a_symlink() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let victim = dir.path().join("victim");
    let lock = dir.path().join("lock");
    std::os::unix::fs::symlink(&victim, &lock)?;
    assert!(FileLock::acquire(&lock).is_err());
    assert!(!victim.exists(), "the symlink target must not be created");
    Ok(())
}

#[cfg(unix)]
#[test]
fn fifo_open_is_nonblocking_and_rejected() -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("fifo");
    let name = CString::new(path.as_os_str().as_bytes())?;
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let err = open_file_nofollow(&path).unwrap_err();
    assert!(format!("{err:#}").contains("regular file"), "{err:#}");
    Ok(())
}

#[cfg(unix)]
#[test]
fn remove_tree_unlinks_a_symlink_entry_without_following_it() -> Result<()> {
    let root = tempfile::tempdir()?;
    let victim = tempfile::tempdir()?;
    let unit = root.path().join("unit");
    fs::create_dir_all(&unit)?;
    fs::write(unit.join("file"), b"x")?;
    fs::write(victim.path().join("keep"), b"keep")?;
    std::os::unix::fs::symlink(victim.path(), unit.join("link"))?;

    remove_tree(root.path(), &unit)?;
    assert!(!unit.exists(), "the unit tree is gone");
    assert!(
        victim.path().join("keep").exists(),
        "the symlink target must survive"
    );
    Ok(())
}

#[test]
fn with_temp_file_unlinks_on_failure_and_returns_the_path_on_success() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let err = with_temp_file(dir.path(), "probe", ".tmp", 0o600, |file| -> Result<()> {
        file.write_all(b"partial")?;
        anyhow::bail!("stop")
    });
    assert!(err.is_err());
    assert_eq!(fs::read_dir(dir.path())?.count(), 0, "no temp debris");

    let (path, written) = with_temp_file(dir.path(), "probe", ".tmp", 0o600, |file| {
        file.write_all(b"complete")?;
        file.sync_all()?;
        Ok(7u8)
    })?;
    assert_eq!(written, 7);
    assert_eq!(fs::read(&path)?, b"complete");
    assert_eq!(path.parent(), Some(dir.path()));
    Ok(())
}

#[test]
fn create_temp_dir_names_are_unique() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let first = create_temp_dir(dir.path(), "stage")?;
    let second = create_temp_dir(dir.path(), "stage")?;
    assert_ne!(first, second);
    assert!(first.is_dir() && second.is_dir());
    Ok(())
}

#[test]
fn write_atomic_private_leaves_a_directory_destination_intact() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let dest = dir.path().join("config.toml");
    fs::create_dir(&dest)?;
    fs::write(dest.join("keep"), b"x")?;
    assert!(write_atomic_private(&dest, b"new bytes").is_err());
    assert!(
        dest.join("keep").exists(),
        "a failed replace must not delete the destination"
    );
    Ok(())
}

#[test]
fn probe_kind_separates_missing_reparse_and_real() -> Result<()> {
    let dir = tempfile::tempdir()?;
    assert!(matches!(
        probe_kind(&dir.path().join("missing"))?,
        Probed::Missing
    ));
    let file = dir.path().join("file");
    fs::write(&file, b"x")?;
    assert!(matches!(probe_kind(&file)?, Probed::Real(_)));
    assert!(probe_lenient(&file)?.is_some());
    #[cfg(unix)]
    {
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&file, &link)?;
        assert!(matches!(probe_kind(&link)?, Probed::Reparse));
        assert!(probe_lenient(&link)?.is_none());
    }
    Ok(())
}

#[test]
fn verify_file_hash_checks_size_and_digest() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("artifact");
    fs::write(&path, b"payload")?;
    let hash = sha256_file(&path)?;
    verify_file_hash(&path, 7, &hash, "test object")?;
    assert!(verify_file_hash(&path, 8, &hash, "test object").is_err());
    assert!(verify_file_hash(&path, 7, "deadbeef", "test object").is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn trusted_path_policy_distinguishes_world_write_from_owner_only() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if euid() == 0 {
        return Ok(()); // root ignores mode bits; the policy test does not apply
    }
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("store");
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o750))?;
    assert!(
        check_trusted_path(&path, PathKind::Dir, TrustPolicy::NoForeignWrite, "store")?.is_some()
    );
    assert!(check_trusted_path(&path, PathKind::Dir, TrustPolicy::OwnerOnly, "store").is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    assert!(check_trusted_path(&path, PathKind::Dir, TrustPolicy::OwnerOnly, "store")?.is_some());
    Ok(())
}

#[cfg(unix)]
#[test]
fn walk_filter_skips_a_symlinked_subtree() -> Result<()> {
    let root = tempfile::tempdir()?;
    let victim = tempfile::tempdir()?;
    fs::write(victim.path().join("keep"), b"keep")?;
    fs::create_dir(root.path().join("real"))?;
    fs::write(root.path().join("real/file"), b"x")?;
    std::os::unix::fs::symlink(victim.path(), root.path().join("link"))?;

    let visited: Vec<PathBuf> = SafeWalk::new(root.path())
        .walk()
        .filter_map(Result::ok)
        .map(|entry| entry.into_path())
        .collect();
    assert!(
        visited
            .iter()
            .any(|path| path == &root.path().join("real/file")),
        "regular files must still be visited"
    );
    assert!(
        !visited
            .iter()
            .any(|path| path.starts_with(root.path().join("link"))
                || path.starts_with(victim.path())),
        "a symlink subtree must be skipped"
    );

    // WalkDir follows a symlinked root by default even with
    // follow_links(false); the shared constructor must stop it.
    let linked_root = root.path().join("linked-root");
    std::os::unix::fs::symlink(victim.path(), &linked_root)?;
    let visited: Vec<PathBuf> = SafeWalk::new(&linked_root)
        .walk()
        .filter_map(Result::ok)
        .map(|entry| entry.into_path())
        .collect();
    assert!(
        visited.is_empty(),
        "a symlinked root must not be traversed: {visited:?}"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn remove_tree_skips_a_symlinked_parent() -> Result<()> {
    let root = tempfile::tempdir()?;
    let victim = tempfile::tempdir()?;
    fs::create_dir_all(victim.path().join("child"))?;
    fs::write(victim.path().join("child/keep"), b"keep")?;
    std::os::unix::fs::symlink(victim.path(), root.path().join("link"))?;

    remove_tree(root.path(), &root.path().join("link/child"))?;
    assert!(
        victim.path().join("child/keep").exists(),
        "a symlinked parent must never redirect deletion"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn remove_file_and_empty_dir_stay_under_the_root() -> Result<()> {
    let root = tempfile::tempdir()?;
    let file = root.path().join("file");
    let empty = root.path().join("empty");
    let full = root.path().join("full");
    fs::write(&file, b"x")?;
    fs::create_dir(&empty)?;
    fs::create_dir(&full)?;
    fs::write(full.join("keep"), b"x")?;

    remove_file(root.path(), &file)?;
    assert!(!file.exists());
    remove_empty_dir(root.path(), &empty)?;
    assert!(!empty.exists());
    assert!(remove_empty_dir(root.path(), &full).is_err());
    assert!(full.join("keep").exists());
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
fn remove_tree_deletes_a_regular_tree_on_windows() -> Result<()> {
    let root = tempfile::tempdir()?;
    let unit = root.path().join("unit");
    fs::create_dir_all(unit.join("sub"))?;
    fs::write(unit.join("sub/file"), b"x")?;
    remove_tree(root.path(), &unit)?;
    assert!(!unit.exists(), "the whole tree is gone");
    Ok(())
}

#[cfg(windows)]
#[test]
fn remove_tree_unlinks_a_nested_junction_without_following_it() -> Result<()> {
    let root = tempfile::tempdir()?;
    let victim = tempfile::tempdir()?;
    let unit = root.path().join("unit");
    fs::create_dir_all(&unit)?;
    fs::write(victim.path().join("keep"), b"keep")?;
    make_junction(&unit.join("sub"), victim.path())?;

    remove_tree(root.path(), &unit)?;
    assert!(!unit.exists(), "the unit tree is gone");
    assert!(
        victim.path().join("keep").exists(),
        "the junction target must survive"
    );
    Ok(())
}

#[cfg(windows)]
#[test]
fn delete_dir_handle_pins_the_directory_against_rename() -> Result<()> {
    let root = tempfile::tempdir()?;
    let dir = root.path().join("pinned");
    fs::create_dir(&dir)?;
    let guard = open_delete_dir_handle(&dir)?;
    let renamed = root.path().join("renamed");
    assert!(
        fs::rename(&dir, &renamed).is_err(),
        "a no-delete-share handle must block rename"
    );
    drop(guard);
    assert!(dir.is_dir());
    remove_tree(root.path(), &dir)?;
    Ok(())
}

#[test]
fn metadata_nofollow_preserves_missing_and_rejects_links() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let missing = dir.path().join("missing");
    let err = metadata_nofollow(&missing).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);

    let regular = dir.path().join("regular");
    fs::write(&regular, b"x")?;
    let meta = metadata_nofollow(&regular)?;
    assert!(meta.is_file());

    #[cfg(unix)]
    {
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&regular, &link)?;
        let err = metadata_nofollow(&link).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_acl_rejects_a_users_write_ace() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let status = std::process::Command::new("icacls")
        .arg(dir.path())
        .args(["/grant", "*S-1-5-32-545:(OI)(CI)(M)"])
        .status()
        .context("running icacls")?;
    assert!(status.success(), "icacls could not add the test ACE");
    assert_eq!(windows_acl_is_private(dir.path()), Some(false));
    Ok(())
}

#[cfg(not(unix))]
#[test]
fn decompress_verified_preserves_already_exists() -> Result<()> {
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

    let err = decompress_file_verified(&blob, &dst, 7, "unused").unwrap_err();
    assert_eq!(
        err.root_cause()
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind),
        Some(std::io::ErrorKind::AlreadyExists)
    );
    assert_eq!(fs::read(&dst)?, b"keep", "an existing destination survives");
    Ok(())
}

#[test]
fn decompression_respects_the_recorded_size() -> Result<()> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("blob.gz");
    let file = fs::File::create(&path)?;
    let mut encoder = GzEncoder::new(file, Compression::fast());
    encoder.write_all(&[0u8; 1024 * 1024])?;
    encoder.finish()?;
    let err = decompress_file_hashed(&path, true, 1024).unwrap_err();
    assert!(format!("{err:#}").contains("exceeds"), "{err:#}");
    Ok(())
}

#[test]
fn recompressing_identical_content_accepts_the_existing_blob() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("generation");
    fs::create_dir_all(&root)?;
    let src = dir.path().join("artifact");
    fs::write(&src, vec![b'x'; 8 * 1024])?;
    let first = compress_file_hashed(&src, &root)?.expect("compressed");
    let second = compress_file_hashed(&src, &root)?.expect("reused");
    assert_eq!(first, second);
    Ok(())
}

#[test]
fn human_sizes() {
    assert_eq!(human_bytes(0), "0 B");
    assert_eq!(human_bytes(999), "999 B");
    assert_eq!(human_bytes(1000), "1.0 KB");
    assert_eq!(human_bytes(1_000_000), "1.0 MB");
    assert_eq!(human_bytes(3_200_000), "3.2 MB");
    assert_eq!(human_bytes(1_000_000_000), "1.0 GB");
    assert_eq!(human_bytes(3_500_000_000), "3.5 GB");
    assert_eq!(human_bytes(1_000_000_000_000), "1.0 TB");
    assert_eq!(human_bytes(18_000_000_000_000), "18.0 TB");
}

#[test]
fn exe_candidates_is_platform_aware() {
    let names = exe_candidates("kache");
    assert!(names.contains(&"kache".to_string()));
    #[cfg(windows)]
    assert!(names.contains(&"kache.exe".to_string()));
    #[cfg(not(windows))]
    assert_eq!(names.len(), 1);
}

#[test]
fn paint_is_pure() {
    assert_eq!(paint(false, "38;2;146;210;147", "hi"), "hi");
    assert_eq!(paint(true, "1", "hi"), "\x1b[1mhi\x1b[0m");
}

#[test]
fn manifest_paths_stay_relative_and_normal() {
    assert!(validate_rel("deps/libx-abc.rlib", "path").is_ok());
    assert!(validate_rel(".fingerprint/x-abc/lib-x", "path").is_ok());
    assert!(validate_rel("/etc/passwd", "path").is_err());
    assert!(validate_rel("../escape", "path").is_err());
    assert!(validate_rel("deps/../../escape", "path").is_err());
    assert!(validate_rel("C:\\Windows\\x", "path").is_err());
    assert!(validate_rel("deps\\x", "path").is_ok());
    assert!(validate_rel("", "path").is_err());
    assert!(validate_component("debug", "profile").is_ok());
    assert!(validate_component("..", "profile").is_err());
    assert!(validate_component("a/b", "profile").is_err());
    assert!(validate_component("a\\b", "profile").is_err());
    // Windows aliases / device stems must never pass a manifest.
    assert!(validate_component(".. ", "profile").is_err());
    assert!(validate_component("...", "profile").is_err());
    assert!(validate_component("foo.", "profile").is_err());
    assert!(validate_component("foo ", "profile").is_err());
    assert!(validate_component("CON", "profile").is_err());
    assert!(validate_component("CON.txt", "profile").is_err());
    assert!(validate_component("CONIN$", "profile").is_err());
    assert!(validate_component("CONOUT$.txt", "profile").is_err());
    assert!(validate_component("COM¹", "profile").is_err());
    assert!(validate_component("LPT³.log", "profile").is_err());
    assert!(validate_component("bad\u{1b}[31m", "profile").is_err());
    assert!(validate_component("COM1.log", "profile").is_err());
    assert!(validate_component("foo.bar", "profile").is_ok());
    assert!(validate_rel(".. /x", "path").is_err());
}

#[cfg(unix)]
#[test]
fn link_helper_hashes_and_shares_the_inode() -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir()?;
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::write(&src, b"hello")?;
    let (size, hash) = try_link_file_hashed(&src, &dst)?.expect("hard link");
    assert_eq!(size, 5);
    assert_eq!(hash, sha256_file(&src)?);
    assert_eq!(fs::metadata(&src)?.nlink(), 2);
    assert_eq!(fs::metadata(&src)?.ino(), fs::metadata(&dst)?.ino());
    Ok(())
}

#[test]
fn copies_are_hashed_and_verified() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::write(&src, b"hello")?;
    let (size, hash) = copy_file_hashed(&src, &dst)?;
    assert_eq!(size, 5);
    assert_eq!(hash, sha256_file(&src)?);
    assert_eq!(fs::read(&dst)?, b"hello");
    let bad = dir.path().join("bad");
    assert!(copy_file_verified(&src, &bad, 5, "00").is_err());
    assert!(
        !bad.exists(),
        "a failed verify must not leave the destination"
    );
    Ok(())
}

#[test]
fn duration_overflow_is_rejected() {
    assert!(parse_duration("18446744073709551615d").is_err());
    assert!(parse_duration("18446744073709551615s").is_ok());
}

#[test]
fn error_blocks_render_a_glyph_indent_and_causes() {
    let plain =
        anyhow::anyhow!("nothing selected — pass one selector:\n--stale   older toolchains");
    let block = error_block_with(false, &plain);
    assert_eq!(
        block,
        "✕ nothing selected — pass one selector:\n  --stale   older toolchains"
    );
    let colored = error_block_with(true, &plain);
    assert!(colored.contains("\u{1b}[38;2;224;108;117m✕\u{1b}[0m"));

    let chained = Err::<(), _>(anyhow::anyhow!("inner detail")).context("outer headline");
    let block = error_block_with(false, &chained.unwrap_err());
    assert_eq!(block, "✕ outer headline\n  caused by: inner detail");
}

#[test]
fn line_diff_marks_changes() {
    let diff = line_diff("a\nb\nc\n", "a\nx\nc\n");
    assert!(diff.contains("- b"), "{diff}");
    assert!(diff.contains("+ x"), "{diff}");
    assert!(diff.contains("  a"), "{diff}");
    assert!(diff.contains("  c"), "{diff}");
    assert_eq!(line_diff("same\n", "same\n"), "  same\n");
}

#[cfg(windows)]
mod windows_path_tests {
    use super::*;

    #[test]
    fn non_existent_in_profile_paths_are_accepted() {
        // tempdir is under %TEMP% (inside %USERPROFILE%); these children do
        // not exist yet, which is exactly the fresh setup/harvest/exec case.
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("cache").join("build");
        ensure_windows_user_path(&target, "cache root").unwrap();
    }

    #[test]
    fn profile_aliases_are_rejected() {
        let profile = std::env::var_os("USERPROFILE").expect("USERPROFILE");
        let profile = std::path::PathBuf::from(profile);
        let mut trailing = profile.as_os_str().to_os_string();
        trailing.push("\\");
        for target in [
            std::path::PathBuf::from(trailing),
            profile.join("."),
            profile.join(".").join("."),
            profile.join(".").join(".."),
        ] {
            assert!(
                ensure_windows_user_path(&target, "cache root").is_err(),
                "profile alias was accepted: {:?}",
                target
            );
        }
    }

    #[test]
    fn parent_dir_cannot_lexically_escape_the_profile() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("..").join("Public").join("ec");
        assert!(ensure_windows_user_path(&target, "cache root").is_err());
    }
}
