use super::*;

/// A build dir in the shapes real Cargo writes: a lib unit, a
/// build-script compile unit, and a build-script run unit without
/// dep-info — plus volatile files and wrapper internals that must be
/// filtered out.
pub(crate) fn synthetic_build_dir(root: &Path) -> Result<()> {
    let jsons = r#"{"rustc":12019306335353385202,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[]}"#;

    let lib = root.join("debug/.fingerprint/serde-102a33f055a8d229");
    fs::create_dir_all(&lib)?;
    fs::write(lib.join("lib-serde"), "5d82713a7f2d05e2")?;
    fs::write(lib.join("lib-serde.json"), jsons)?;
    fs::write(lib.join("dep-lib-serde"), [0u8; 24])?;
    fs::write(lib.join("invoked.timestamp"), "")?;
    fs::create_dir_all(root.join("debug/deps"))?;
    fs::write(
        root.join("debug/deps/libserde-102a33f055a8d229.rlib"),
        [7u8; 64],
    )?;
    fs::write(
        root.join("debug/deps/libserde-102a33f055a8d229.rmeta"),
        [6u8; 48],
    )?;
    fs::write(
        root.join("debug/deps/serde-102a33f055a8d229.d"),
        b"side file",
    )?;
    fs::write(
        root.join("debug/deps/libserde-102a33f055a8d229.kache-real"),
        b"wrapper",
    )?;

    let compile = root.join("debug/.fingerprint/x-1122334455667788");
    fs::create_dir_all(&compile)?;
    fs::write(
        compile.join("build-script-build-script-build"),
        "aaaabbbbccccdddd",
    )?;
    fs::write(compile.join("build-script-build-script-build.json"), jsons)?;
    fs::write(
        compile.join("dep-build-script-build-script-build"),
        [0u8; 8],
    )?;
    let compile_anchor = root.join("debug/build/x-1122334455667788");
    fs::create_dir_all(&compile_anchor)?;
    fs::write(
        compile_anchor.join("build_script_build-1122334455667788"),
        [3u8; 32],
    )?;
    fs::write(
        compile_anchor.join("build_script_build-1122334455667788.d"),
        b"dep",
    )?;
    fs::write(
        compile_anchor.join("build_script_build-1122334455667788.kache-real"),
        b"wrapper",
    )?;
    fs::write(compile_anchor.join("invoked.timestamp"), "")?;

    // The run unit has no dep-info at all (real Cargo layout).
    let run = root.join("debug/.fingerprint/x-aabbccddeeff0011");
    fs::create_dir_all(&run)?;
    fs::write(
        run.join("run-build-script-build-script-build"),
        "eeeeffff00001111",
    )?;
    fs::write(run.join("run-build-script-build-script-build.json"), jsons)?;
    let run_anchor = root.join("debug/build/x-aabbccddeeff0011");
    fs::create_dir_all(&run_anchor)?;
    fs::write(
        run_anchor.join("output"),
        b"cargo:rerun-if-changed=build.rs",
    )?;
    fs::write(run_anchor.join("stderr"), b"")?;
    fs::write(run_anchor.join("invoked.timestamp"), "")?;
    Ok(())
}

/// A build dir with one incomplete unit (memo file, but no artifacts).
pub(crate) fn synthetic_husk(root: &Path) -> Result<()> {
    let unit = root.join("debug/.fingerprint/husk-aaaabbbbccccdddd");
    fs::create_dir_all(&unit)?;
    fs::write(unit.join("lib-husk"), "0000111122223333")?;
    Ok(())
}

pub(crate) fn overlap_unit(hash: &str, size: u64) -> UnitEntry {
    UnitEntry {
        name: format!("demo-{hash}"),
        profile: "debug".into(),
        memo: "lib-demo".into(),
        hash: hash.into(),
        version: None,
        stamp: 1,
        layout: None,
        files: vec![FileEntry {
            path: "lib-demo".into(),
            dest: "deps/libdemo".into(),
            size,
            sha256: "0".repeat(64),
            role: "artifact".into(),
            object: None,
        }],
    }
}

pub(crate) fn write_overlap_unit(
    store: &Path,
    generation: &str,
    hash: &str,
    bytes: &[u8],
) -> Result<PathBuf> {
    let dir = store
        .join(generation)
        .join("units")
        .join(format!("demo-{hash}"));
    fs::create_dir_all(&dir)?;
    let file = dir.join("lib-demo");
    fs::write(&file, bytes)?;
    Ok(file)
}

pub(crate) fn synthetic_profile_unit(
    root: &Path,
    profile: &str,
    package: &str,
    hash: &str,
    byte: u8,
) -> Result<()> {
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

/// A minimal new-layout unit: `debug/build/<pkg>/<hash>/{fingerprint,out}`.
pub(crate) fn synthetic_new_layout_unit(root: &Path, package: &str, hash: &str) -> Result<PathBuf> {
    let unit = root.join("debug/build").join(package).join(hash);
    fs::create_dir_all(unit.join("fingerprint"))?;
    fs::create_dir_all(unit.join("out"))?;
    fs::write(
        unit.join("fingerprint").join(format!("lib-{package}")),
        "5d82713a7f2d05e2",
    )?;
    fs::write(
        unit.join("fingerprint").join(format!("dep-lib-{package}")),
        [0u8; 8],
    )?;
    fs::write(
        unit.join("fingerprint").join(format!("lib-{package}.json")),
        r#"{"rustc":12019306335353385202,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[]}"#,
    )?;
    fs::write(
        unit.join("out").join(format!("lib{package}-{hash}.rlib")),
        [7u8; 64],
    )?;
    fs::write(
        unit.join("out").join(format!("lib{package}-{hash}.rmeta")),
        [6u8; 48],
    )?;
    Ok(unit)
}

/// Two units with a resolved dependency edge: `serde` → `serde_core`.
/// `dep_at`/`unit_at` are the stamps the files carry, so harvest stores
/// exactly that ordering.

pub(crate) fn synthetic_edge_dir(root: &Path, dep_at: u64, unit_at: u64) -> Result<()> {
    fs::create_dir_all(root.join("debug/deps"))?;
    let core = root.join("debug/.fingerprint/serde_core-b468be6fa8c1f936");
    fs::create_dir_all(&core)?;
    fs::write(core.join("lib-serde_core"), "71a9f323efa5ae82")?;
    fs::write(
        core.join("lib-serde_core.json"),
        r#"{"rustc":5244445300240561903,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[]}"#,
    )?;
    fs::write(core.join("dep-lib-serde_core"), [0u8; 8])?;
    let core_rlib = root.join("debug/deps/libserde_core-b468be6fa8c1f936.rlib");
    fs::write(&core_rlib, [1u8; 32])?;

    let unit = root.join("debug/.fingerprint/serde-746d173581f1a314");
    fs::create_dir_all(&unit)?;
    fs::write(unit.join("lib-serde"), "5d82713a7f2d05e2")?;
    fs::write(
        unit.join("lib-serde.json"),
        r#"{"rustc":5244445300240561903,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"config":4,"deps":[[11029742160753049355,"serde_core",false,9416646317397223793]]}"#,
    )?;
    fs::write(unit.join("dep-lib-serde"), [0u8; 8])?;
    let unit_rlib = root.join("debug/deps/libserde-746d173581f1a314.rlib");
    fs::write(&unit_rlib, [1u8; 32])?;

    set_stamp(&core.join("lib-serde_core"), dep_at)?;
    set_stamp(&core.join("lib-serde_core.json"), dep_at)?;
    set_stamp(&core.join("dep-lib-serde_core"), dep_at)?;
    set_stamp(&core_rlib, dep_at)?;
    set_stamp(&unit.join("lib-serde"), unit_at)?;
    set_stamp(&unit.join("lib-serde.json"), unit_at)?;
    set_stamp(&unit.join("dep-lib-serde"), unit_at)?;
    set_stamp(&unit_rlib, unit_at)?;
    Ok(())
}

/// A job-dir shape: a private build root with the exec marker, nested in a
/// work root so the record lives beside it.
pub(crate) fn job_dir(home: &Path) -> Result<PathBuf> {
    let build = home.join("job");
    util::create_private_dir_all(&build)?;
    fs::write(
        build.join(crate::job::JOB_MARKER),
        "epicenter-job-v1\n0123456789abcdef0123456789abcdef\n",
    )?;
    Ok(build)
}
