use super::support::*;
use super::*;

#[test]
fn overlap_groups_units_by_package_and_profile() -> Result<()> {
    let store = tempfile::tempdir()?;
    let first = write_overlap_unit(
        store.path(),
        "generation",
        "aaaaaaaaaaaaaaaa",
        b"0123456789",
    )?;
    write_overlap_unit(store.path(), "generation", "bbbbbbbbbbbbbbbb", &[7u8; 20])?;
    let manifest = Manifest {
        parity_key: "generation".into(),
        toolchain: "test".into(),
        created: 1,
        updated: 1,
        units: vec![
            overlap_unit("aaaaaaaaaaaaaaaa", 10),
            overlap_unit("bbbbbbbbbbbbbbbb", 20),
        ],
        mac: String::new(),
        signature: String::new(),
    };
    save_manifest(store.path(), "generation", &manifest)?;
    let active = std::collections::HashSet::from(["demo-aaaaaaaaaaaaaaaa".to_string()]);
    let report = overlap(store.path(), &active)?;
    assert_eq!(report.len(), 1);
    assert_eq!(report[0].package, "demo");
    assert_eq!(report[0].units, 2);
    assert_eq!(report[0].hashes, 2);
    assert_eq!(report[0].identical, 0);
    assert_eq!(report[0].active, 1);
    assert_eq!(report[0].bytes, 30);
    assert_eq!(report[0].unique_bytes, 30);
    assert!(first.is_file());
    assert!(report[0].unit_rows.iter().any(|unit| unit.active));
    Ok(())
}

#[test]
fn overlap_counts_identical_units_and_shared_inodes_once() -> Result<()> {
    let store = tempfile::tempdir()?;
    let first = write_overlap_unit(
        store.path(),
        "generation",
        "aaaaaaaaaaaaaaaa",
        b"0123456789",
    )?;
    let second_dir = store
        .path()
        .join("generation2")
        .join("units")
        .join("demo-aaaaaaaaaaaaaaaa");
    fs::create_dir_all(&second_dir)?;
    #[cfg(unix)]
    fs::hard_link(&first, second_dir.join("lib-demo"))?;
    #[cfg(not(unix))]
    fs::copy(&first, second_dir.join("lib-demo"))?;

    for (generation, created) in [("generation", 1u64), ("generation2", 2u64)] {
        let manifest = Manifest {
            parity_key: generation.into(),
            toolchain: "test".into(),
            created,
            updated: created,
            units: vec![overlap_unit("aaaaaaaaaaaaaaaa", 10)],
            mac: String::new(),
            signature: String::new(),
        };
        save_manifest(store.path(), generation, &manifest)?;
    }

    let report = overlap(store.path(), &Default::default())?;
    assert_eq!(report.len(), 1);
    assert_eq!(report[0].units, 2);
    assert_eq!(report[0].hashes, 1);
    assert_eq!(report[0].identical, 1);
    #[cfg(unix)]
    assert_eq!(report[0].unique_bytes, 10, "a hard link is counted once");
    Ok(())
}

fn compact_manifest(generation: &str, hashes: &[&str], size: u64) -> Manifest {
    Manifest {
        parity_key: generation.into(),
        toolchain: "test".into(),
        created: 1,
        updated: 1,
        units: hashes.iter().map(|hash| overlap_unit(hash, size)).collect(),
        mac: String::new(),
        signature: String::new(),
    }
}

#[test]
fn compact_links_identical_files_and_is_idempotent() -> Result<()> {
    let store = tempfile::tempdir()?;
    let payload = b"identical payload";
    let first = write_overlap_unit(store.path(), "generation", "aaaaaaaaaaaaaaaa", payload)?;
    let second = write_overlap_unit(store.path(), "generation", "bbbbbbbbbbbbbbbb", payload)?;
    save_manifest(
        store.path(),
        "generation",
        &compact_manifest(
            "generation",
            &["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"],
            payload.len() as u64,
        ),
    )?;

    let report = compact(store.path(), None, false)?;
    assert_eq!(report.generations, 1);
    assert_eq!(report.groups, 1);
    assert_eq!(report.linked, 1);
    assert_eq!(report.bytes_saved, payload.len() as u64);
    assert_eq!(fs::read(&first)?, payload);
    assert_eq!(fs::read(&second)?, payload);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(fs::metadata(&first)?.ino(), fs::metadata(&second)?.ino());
    }

    let again = compact(store.path(), None, false)?;
    assert_eq!(again.groups, 0);
    assert_eq!(again.linked, 0);
    assert!(again.already_shared >= 1);
    Ok(())
}

#[test]
fn compact_generation_filter_excludes_duplicates_in_other_generations() -> Result<()> {
    let store = tempfile::tempdir()?;
    let hash = "aaaaaaaaaaaaaaaa";
    let payload = b"shared bytes";
    for generation in ["selected", "other"] {
        write_overlap_unit(store.path(), generation, hash, payload)?;
        save_manifest(
            store.path(),
            generation,
            &compact_manifest(generation, &[hash], payload.len() as u64),
        )?;
    }

    let selected = compact(store.path(), Some("selected"), true)?;
    assert_eq!(selected.generations, 1);
    assert_eq!(selected.groups, 0);
    let all = compact(store.path(), None, true)?;
    assert_eq!(all.generations, 2);
    assert_eq!(all.groups, 1);

    let error = compact(store.path(), Some("missing"), true).unwrap_err();
    assert!(
        error.to_string().contains("no vault generation matches"),
        "{error}"
    );
    Ok(())
}

#[test]
fn compact_dry_run_does_not_link() -> Result<()> {
    let store = tempfile::tempdir()?;
    let payload = b"dry-run payload";
    let _first = write_overlap_unit(store.path(), "generation", "aaaaaaaaaaaaaaaa", payload)?;
    let _second = write_overlap_unit(store.path(), "generation", "bbbbbbbbbbbbbbbb", payload)?;
    save_manifest(
        store.path(),
        "generation",
        &compact_manifest(
            "generation",
            &["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"],
            payload.len() as u64,
        ),
    )?;

    let report = compact(store.path(), None, true)?;
    assert_eq!(report.groups, 1);
    assert_eq!(report.linked, 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_ne!(fs::metadata(&_first)?.ino(), fs::metadata(&_second)?.ino());
    }
    let applied = compact(store.path(), None, false)?;
    assert_eq!(applied.linked, 1);
    Ok(())
}

#[test]
fn compact_respects_raw_unit_stamps() -> Result<()> {
    let store = tempfile::tempdir()?;
    let _first = write_overlap_unit(store.path(), "generation", "aaaaaaaaaaaaaaaa", b"same")?;
    let _second = write_overlap_unit(store.path(), "generation", "bbbbbbbbbbbbbbbb", b"same")?;
    let mut one = overlap_unit("aaaaaaaaaaaaaaaa", 4);
    one.stamp = 1;
    let mut two = overlap_unit("bbbbbbbbbbbbbbbb", 4);
    two.stamp = 2;
    let manifest = Manifest {
        parity_key: "generation".into(),
        toolchain: "test".into(),
        created: 1,
        updated: 1,
        units: vec![one, two],
        mac: String::new(),
        signature: String::new(),
    };
    save_manifest(store.path(), "generation", &manifest)?;

    let report = compact(store.path(), None, false)?;
    assert_eq!(report.groups, 0);
    assert_eq!(report.linked, 0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_ne!(fs::metadata(&_first)?.ino(), fs::metadata(&_second)?.ino());
    }
    Ok(())
}

#[test]
fn compact_leaves_different_files_alone() -> Result<()> {
    let store = tempfile::tempdir()?;
    write_overlap_unit(store.path(), "generation", "aaaaaaaaaaaaaaaa", b"one")?;
    write_overlap_unit(store.path(), "generation", "bbbbbbbbbbbbbbbb", b"two")?;
    save_manifest(
        store.path(),
        "generation",
        &compact_manifest("generation", &["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"], 3),
    )?;
    let report = compact(store.path(), None, false)?;
    assert_eq!(report.groups, 0);
    assert_eq!(report.linked, 0);
    Ok(())
}

#[test]
fn compact_counts_already_hardlinked_files() -> Result<()> {
    let store = tempfile::tempdir()?;
    let first = write_overlap_unit(store.path(), "generation", "aaaaaaaaaaaaaaaa", b"shared")?;
    let second_dir = store
        .path()
        .join("generation")
        .join("units")
        .join("demo-bbbbbbbbbbbbbbbb");
    fs::create_dir_all(&second_dir)?;
    fs::hard_link(&first, second_dir.join("lib-demo"))?;
    save_manifest(
        store.path(),
        "generation",
        &compact_manifest("generation", &["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"], 6),
    )?;
    let report = compact(store.path(), None, false)?;
    assert_eq!(report.groups, 0);
    assert_eq!(report.linked, 0);
    assert!(report.already_shared >= 1);
    Ok(())
}

#[cfg(unix)]
#[test]
fn compact_counts_reclaimed_inodes_not_replaced_paths() -> Result<()> {
    let store = tempfile::tempdir()?;
    let payload = b"reclaim once";
    let _first = write_overlap_unit(store.path(), "generation", "aaaaaaaaaaaaaaaa", payload)?;
    // Two paths are hard links of one inode: replacing both frees that inode
    // once, so the report must say one file, not two.
    let second = write_overlap_unit(store.path(), "generation", "bbbbbbbbbbbbbbbb", payload)?;
    let third_dir = store
        .path()
        .join("generation")
        .join("units")
        .join("demo-cccccccccccccccc");
    fs::create_dir_all(&third_dir)?;
    fs::hard_link(&second, third_dir.join("lib-demo"))?;
    save_manifest(
        store.path(),
        "generation",
        &compact_manifest(
            "generation",
            &["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "cccccccccccccccc"],
            payload.len() as u64,
        ),
    )?;

    let report = compact(store.path(), None, false)?;
    assert_eq!(report.groups, 1);
    assert_eq!(report.linked, 1, "one inode reclaimed, not two paths");
    assert_eq!(report.bytes_saved, payload.len() as u64);
    Ok(())
}

#[cfg(unix)]
#[test]
fn overlap_counts_blob_bytes_and_shared_blobs_once() -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let store = tempfile::tempdir()?;
    let hash = "aaaaaaaaaaaaaaaa";
    let payload = b"0123456789";
    let first = write_overlap_unit(store.path(), "generation", hash, payload)?;
    let blob = store
        .path()
        .join("generation")
        .join("blobs")
        .join("aa")
        .join("bbbb.gz");
    fs::create_dir_all(blob.parent().unwrap())?;
    fs::write(&blob, b"abcde")?;

    // A second generation shares both inodes through hard links.
    let second_dir = store
        .path()
        .join("generation2")
        .join("units")
        .join(format!("demo-{hash}"));
    fs::create_dir_all(&second_dir)?;
    fs::hard_link(&first, second_dir.join("lib-demo"))?;
    let second_blob = store
        .path()
        .join("generation2")
        .join("blobs")
        .join("aa")
        .join("bbbb.gz");
    fs::create_dir_all(second_blob.parent().unwrap())?;
    fs::hard_link(&blob, &second_blob)?;

    let object = "blobs/aa/bbbb.gz";
    for (generation, created) in [("generation", 1u64), ("generation2", 2u64)] {
        let mut unit = overlap_unit(hash, payload.len() as u64);
        unit.files.push(FileEntry {
            path: "deps/libx.rlib".into(),
            dest: "deps/libx.rlib".into(),
            size: 40,
            sha256: String::new(),
            role: "artifact".into(),
            object: Some(object.into()),
        });
        save_manifest(
            store.path(),
            generation,
            &Manifest {
                parity_key: generation.into(),
                toolchain: "test".into(),
                created,
                updated: created,
                units: vec![unit],
                mac: String::new(),
                signature: String::new(),
            },
        )?;
    }

    let report = overlap(store.path(), &Default::default())?;
    assert_eq!(report.len(), 1);
    assert_eq!(
        report[0].bytes, 100,
        "recorded sizes are summarized per unit"
    );
    assert_eq!(
        report[0].unique_bytes,
        payload.len() as u64 + 5,
        "the blob counts, and hard links count once"
    );
    assert_eq!(
        fs::metadata(&first)?.ino(),
        fs::metadata(second_dir.join("lib-demo"))?.ino()
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn generations_count_blobs_without_double_counting_hard_links() -> Result<()> {
    let store = tempfile::tempdir()?;
    let file = write_overlap_unit(
        store.path(),
        "generation",
        "aaaaaaaaaaaaaaaa",
        b"0123456789",
    )?;
    let blob = store
        .path()
        .join("generation")
        .join("blobs")
        .join("aa")
        .join("object.gz");
    fs::create_dir_all(blob.parent().unwrap())?;
    fs::hard_link(&file, &blob)?;
    save_manifest(
        store.path(),
        "generation",
        &compact_manifest("generation", &["aaaaaaaaaaaaaaaa"], 10),
    )?;

    let info = &generations(store.path())?[0];
    assert_eq!(info.units, 1);
    assert_eq!(info.files, 2, "both units and blobs are store files");
    assert_eq!(info.bytes, 10, "one inode is one allocation");
    assert_eq!(info.linked, 2, "both names point at the shared inode");
    Ok(())
}
