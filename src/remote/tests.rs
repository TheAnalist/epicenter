use super::*;
use crate::fingerprint::UnitLayout;
use crate::settings;
use crate::settings::{RemoteTier, RemoteTransport, Source};
use anyhow::Result;
use ed25519_dalek::SigningKey;
use std::fs;

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public_key(key: &SigningKey) -> String {
    crate::vault::hex_encode(&key.verifying_key().to_bytes())
}

fn local_environment() -> LocalEnvironment {
    // Must be absolute on the host running the test: `/opt/...` is not an
    // absolute Windows path (it has no drive/UNC prefix).
    let cargo_home = if cfg!(windows) {
        r"C:\epicenter\cargo"
    } else {
        "/opt/epicenter/cargo"
    };
    LocalEnvironment {
        rustc: RustcIdentity {
            release: "1.91.0".to_string(),
            commit: "b940084d7".to_string(),
            host: "x86_64-unknown-linux-gnu".to_string(),
            llvm: "20.1.8".to_string(),
        },
        cargo: "cargo 1.91.0 (b940084d7 2026-01-01)".to_string(),
        target: "x86_64-unknown-linux-gnu".to_string(),
        cargo_home: cargo_home.to_string(),
        rustflags_digest: "1234abcd".to_string(),
        layout: "classic".to_string(),
        registry: RegistryIdentity {
            name: "crates-io".to_string(),
            index: "https://github.com/rust-lang/crates.io-index".to_string(),
            source_path_hash: source_path_hash(std::path::Path::new(cargo_home)),
        },
    }
}

fn publisher(now: u64) -> PublisherMetadata {
    PublisherMetadata {
        tool: "epicenter-cli 0.1.0".to_string(),
        source_commit: "0123456789abcdef0123456789abcdef01234567".to_string(),
        built_at: now,
        ci_job: "ci/123".to_string(),
        notes: String::new(),
    }
}

fn body_for(
    key: &SigningKey,
    now: u64,
    sequence: u64,
    tier: RemoteTier,
    units: Vec<RemoteUnit>,
) -> IndexBody {
    IndexBody {
        schema: SCHEMA_VERSION,
        key_id: settings::remote_key_id(&public_key(key)).unwrap(),
        sequence,
        created: now.saturating_sub(60),
        expires: now + 86_400,
        tier,
        publisher: publisher(now),
        compatibility: Compatibility::from_local(&local_environment(), &units).unwrap(),
        units,
    }
}

fn test_unit(
    root: &std::path::Path,
    package: &str,
    kind: RemoteUnitKind,
    path: &str,
    role: FileRole,
    content: &[u8],
) -> RemoteUnit {
    let source = root.join(format!(".source-{package}"));
    fs::write(&source, content).unwrap();
    let blob = write_blob(&source, root).unwrap();
    let memo = match kind {
        RemoteUnitKind::Lib => "lib-test",
        RemoteUnitKind::BuildScript => "build-script-build",
        RemoteUnitKind::BuildRun => "run-build-script-build-script-build",
        RemoteUnitKind::Other => "probe",
    };
    RemoteUnit {
        name: format!("{package}-0011223344556677"),
        package: package.to_string(),
        version: None,
        profile: "release".to_string(),
        memo: memo.to_string(),
        hash: "aabbccddeeff0011".to_string(),
        stamp: 1,
        layout: UnitLayout::Classic,
        kind,
        source: UnitSource {
            kind: SourceKind::Registry,
            id: "registry+https://github.com/rust-lang/crates.io-index".to_string(),
            checksum: Some("ab".repeat(32)),
        },
        compat: UnitCompatibility {
            rustc: "1".to_string(),
            target: "2".to_string(),
            profile: "3".to_string(),
            features: vec!["default".to_string()],
            rustflags: Vec::new(),
            config: "4".to_string(),
            path: "5".to_string(),
            compile_kind: "0".to_string(),
        },
        files: vec![RemoteFile {
            path: path.to_string(),
            dest: path.to_string(),
            size: content.len() as u64,
            sha256: sha256_hex(content),
            role,
            blob: blob.blob,
            blob_size: blob.blob_size,
            compression: blob.compression,
        }],
    }
}

fn remote_policy(public: &str) -> settings::RemotePolicy {
    settings::RemotePolicy {
        tier: RemoteTier::Libraries,
        tier_source: Source::Global,
        enabled: true,
        url: Some("https://cache.example/root".to_string()),
        publisher_key: Some(public.to_string()),
        key_id: Some(settings::remote_key_id(public).unwrap()),
        cache: std::path::PathBuf::from("/tmp/remote-cache"),
        transport: RemoteTransport::AnonymousHttps,
        region: None,
    }
}

#[test]
fn index_round_trip_is_canonical_and_verified() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let now = now_secs();
    let key = signing_key(7);
    let body = body_for(&key, now, 3, RemoteTier::Libraries, Vec::new());
    let index = make_index(body, &key, now)?;
    assert_eq!(index.body().canonical_bytes()?, index.body_bytes());
    write_index_tree(dir.path(), &index)?;
    assert!(dir.path().join(PUBLISHER_FILE).is_file());

    let verified = read_index_tree(dir.path(), &public_key(&key), RemoteTier::Libraries, now)?;
    assert_eq!(verified.pointer().sequence, 3);
    assert_eq!(verified.body().tier, RemoteTier::Libraries);
    assert_eq!(verified.body_bytes(), index.body_bytes());
    assert!(index.pointer().signature.len() == 128);
    Ok(())
}

#[test]
fn signature_and_pinned_key_are_enforced() -> Result<()> {
    let now = now_secs();
    let key = signing_key(7);
    let other = signing_key(8);
    let body = body_for(&key, now, 1, RemoteTier::Libraries, Vec::new());
    let index = make_index(body, &key, now)?;
    let pointer = index.pointer();
    pointer.verify(&public_key(&key), now)?;
    assert!(pointer.verify(&public_key(&other), now).is_err());

    let mut tampered = pointer.clone();
    tampered.sequence += 1;
    assert!(tampered.verify(&public_key(&key), now).is_err());

    let mut bad_signature = pointer.clone();
    bad_signature.signature = "00".repeat(64);
    assert!(bad_signature.verify(&public_key(&key), now).is_err());

    let mut wrong_id = pointer.clone();
    wrong_id.key_id = settings::remote_key_id(&public_key(&other))?;
    assert!(wrong_id.verify(&public_key(&key), now).is_err());
    Ok(())
}

#[test]
fn body_hash_size_and_canonical_form_are_enforced() -> Result<()> {
    let now = now_secs();
    let key = signing_key(7);
    let body = body_for(&key, now, 2, RemoteTier::Libraries, Vec::new());
    let index = make_index(body, &key, now)?;
    let pointer = index.pointer();
    let bytes = index.body_bytes();

    let mut flipped = bytes.to_vec();
    flipped[0] = b' ';
    assert!(verify_body(pointer, &flipped, now).is_err());

    let short = &bytes[..bytes.len() - 1];
    assert!(verify_body(pointer, short, now).is_err());

    let pretty = serde_json::to_vec_pretty(index.body())?;
    assert!(verify_body(pointer, &pretty, now).is_err());

    assert!(verify_index(bytes, bytes, &public_key(&key), RemoteTier::Libraries, now).is_err());
    Ok(())
}

#[test]
fn expiry_future_clock_and_validity_cap_are_enforced() -> Result<()> {
    let now = now_secs();
    let key = signing_key(7);

    let mut stale = body_for(&key, now, 4, RemoteTier::Libraries, Vec::new());
    stale.created = now.saturating_sub(1_000);
    stale.expires = now.saturating_sub(1);
    stale.publisher.built_at = now.saturating_sub(500);
    let index = make_index(stale, &key, now.saturating_sub(500))?;
    let pointer = index.pointer();
    assert!(pointer.verify(&public_key(&key), now).is_err());
    assert!(
        pointer.verify_signature(&public_key(&key)).is_ok(),
        "a publisher may read the sequence from an expired index"
    );

    let future = now + MAX_CLOCK_SKEW_SECS + 100;
    let body = body_for(&key, future, 5, RemoteTier::Libraries, Vec::new());
    let index = make_index(body, &key, future)?;
    let pointer = index.pointer();
    assert!(pointer.verify(&public_key(&key), now).is_err());

    let mut future_publisher = body_for(&key, now, 5, RemoteTier::Libraries, Vec::new());
    future_publisher.publisher.built_at = now + MAX_CLOCK_SKEW_SECS + 1;
    assert!(make_index(future_publisher, &key, now).is_err());

    let mut too_long = body_for(&key, now, 6, RemoteTier::Libraries, Vec::new());
    too_long.expires = too_long.created + MAX_INDEX_VALIDITY_SECS + 1;
    assert!(too_long.validate_shape().is_err());
    Ok(())
}

#[test]
fn key_rotation_requires_a_new_pin() -> Result<()> {
    let now = now_secs();
    let old = signing_key(7);
    let new = signing_key(8);
    let old_body = body_for(&old, now, 7, RemoteTier::Libraries, Vec::new());
    let old_index = make_index(old_body, &old, now)?;
    let old_pointer = old_index.pointer();
    old_pointer.verify(&public_key(&old), now)?;
    assert!(old_pointer.verify(&public_key(&new), now).is_err());

    let new_body = body_for(&new, now, 8, RemoteTier::Libraries, Vec::new());
    let new_index = make_index(new_body, &new, now)?;
    let new_pointer = new_index.pointer();
    new_pointer.verify(&public_key(&new), now)?;
    assert!(new_pointer.verify(&public_key(&old), now).is_err());
    assert_ne!(
        settings::remote_key_id(&public_key(&old))?,
        settings::remote_key_id(&public_key(&new))?
    );
    Ok(())
}

#[test]
fn replay_state_rejects_rollback_and_equivocation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let now = now_secs();
    let key = signing_key(7);
    let public = public_key(&key);
    let remote = remote_policy(&public);

    let body = body_for(&key, now, 7, RemoteTier::Libraries, Vec::new());
    let index = make_index(body, &key, now)?;
    state::record_state_at(dir.path(), &remote, &index, now)?;
    let loaded = state::load_state_at(dir.path(), &remote)?.expect("state");
    assert_eq!(loaded.sequence, 7);

    let older = body_for(&key, now, 6, RemoteTier::Libraries, Vec::new());
    let older_index = make_index(older, &key, now)?;
    assert!(state::record_state_at(dir.path(), &remote, &older_index, now).is_err());

    let mut alternate = body_for(&key, now, 7, RemoteTier::Libraries, Vec::new());
    alternate.publisher.ci_job = "ci/other".to_string();
    let alternate_index = make_index(alternate, &key, now)?;
    assert!(state::record_state_at(dir.path(), &remote, &alternate_index, now).is_err());

    let newer = body_for(&key, now, 8, RemoteTier::Libraries, Vec::new());
    let newer_index = make_index(newer, &key, now)?;
    state::record_state_at(dir.path(), &remote, &newer_index, now)?;
    assert_eq!(
        state::load_state_at(dir.path(), &remote)?
            .expect("state")
            .sequence,
        8
    );
    Ok(())
}

#[test]
fn replay_state_serializes_concurrent_writers() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let now = now_secs();
    let key = signing_key(7);
    let remote = remote_policy(&public_key(&key));

    let mut a = body_for(&key, now, 7, RemoteTier::Libraries, Vec::new());
    a.publisher.ci_job = "ci/a".to_string();
    let pa = make_index(a, &key, now)?;
    let mut b = body_for(&key, now, 7, RemoteTier::Libraries, Vec::new());
    b.publisher.ci_job = "ci/b".to_string();
    let pb = make_index(b, &key, now)?;

    let barrier = std::sync::Barrier::new(2);
    let (first, second) = std::thread::scope(|scope| {
        let one = scope.spawn(|| {
            barrier.wait();
            state::record_state_at(dir.path(), &remote, &pa, now)
        });
        let two = scope.spawn(|| {
            barrier.wait();
            state::record_state_at(dir.path(), &remote, &pb, now)
        });
        (one.join().unwrap(), two.join().unwrap())
    });
    assert!(
        first.is_ok() != second.is_ok(),
        "exactly one writer wins a sequence: {first:?} / {second:?}"
    );
    let loaded = state::load_state_at(dir.path(), &remote)?.expect("state");
    let winner = if first.is_ok() { &pa } else { &pb };
    assert_eq!(loaded.body_sha256, winner.pointer().body_sha256);
    Ok(())
}

#[test]
fn status_reports_the_last_verified_index_and_compatibility() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let now = now_secs();
    let key = signing_key(7);
    let public = public_key(&key);
    let remote = remote_policy(&public);
    let local = LocalEnvironment::gather()?;
    let mut body = body_for(&key, now, 19, RemoteTier::Libraries, Vec::new());
    body.compatibility = Compatibility::from_local(&local, &[])?;
    let index = make_index(body, &key, now)?;
    state::record_state_at(dir.path(), &remote, &index, now)?;

    let status = state::status_at(dir.path(), &remote)?.expect("status");
    assert_eq!(status.sequence, 19);
    assert_eq!(status.key_id, remote.key_id.clone().unwrap());
    assert!(status.mismatches.is_empty(), "{:?}", status.mismatches);
    Ok(())
}

#[test]
fn tier_gate_rejects_executables_in_libraries() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let now = now_secs();
    let key = signing_key(7);
    let build_script = test_unit(
        dir.path(),
        "buildy",
        RemoteUnitKind::BuildScript,
        "build/buildy/out/build-script-build",
        FileRole::BuildTree,
        b"executable",
    );
    let body = body_for(&key, now, 9, RemoteTier::Full, vec![build_script.clone()]);
    assert!(
        body.validate_for(RemoteTier::Full).is_ok(),
        "{:?}",
        body.validate_for(RemoteTier::Full)
            .err()
            .map(|err| format!("{err:#}"))
    );
    assert!(
        body.validate_for(RemoteTier::Libraries).is_ok(),
        "a libraries reader accepts a full index and filters at import"
    );
    assert!(!build_script.importable_for(RemoteTier::Libraries));
    assert!(build_script.importable_for(RemoteTier::Full));

    let index = make_index(body, &key, now)?;
    let pointer_bytes = serde_json::to_vec(index.pointer())?;
    let bytes = index.body_bytes();
    assert!(
        verify_index(
            &pointer_bytes,
            bytes,
            &public_key(&key),
            RemoteTier::Libraries,
            now
        )
        .is_ok(),
        "the pointer/body tier gate is the index tier, not the reader filter"
    );
    assert!(
        verify_index(
            &pointer_bytes,
            bytes,
            &public_key(&key),
            RemoteTier::Full,
            now
        )
        .is_ok()
    );

    let mut mislabeled = index.body().clone();
    mislabeled.tier = RemoteTier::Libraries;
    assert!(mislabeled.validate_for(RemoteTier::Libraries).is_err());

    let proc_macro = test_unit(
        dir.path(),
        "macros",
        RemoteUnitKind::Lib,
        "deps/libmacros.so",
        FileRole::Artifact,
        b"shared object",
    );
    let body = body_for(&key, now, 10, RemoteTier::Libraries, vec![proc_macro]);
    assert!(body.validate_for(RemoteTier::Libraries).is_err());

    let binary = test_unit(
        dir.path(),
        "probe",
        RemoteUnitKind::Other,
        "deps/probe",
        FileRole::Artifact,
        b"extensionless binary",
    );
    let body = body_for(&key, now, 18, RemoteTier::Libraries, vec![binary]);
    assert!(body.validate_for(RemoteTier::Libraries).is_err());
    Ok(())
}

#[test]
fn path_workspace_and_path_traversal_are_rejected() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let now = now_secs();
    let key = signing_key(7);

    let mut local = test_unit(
        dir.path(),
        "local",
        RemoteUnitKind::Lib,
        "deps/liblocal.rlib",
        FileRole::Artifact,
        b"rlib",
    );
    local.source.kind = SourceKind::Path;
    local.source.id = "/work/local".to_string();
    local.source.checksum = None;
    let body = body_for(&key, now, 11, RemoteTier::Libraries, vec![local]);
    assert!(body.validate_shape().is_err());

    let mut credential = test_unit(
        dir.path(),
        "credential",
        RemoteUnitKind::Lib,
        "deps/libcredential.rlib",
        FileRole::Artifact,
        b"rlib",
    );
    credential.source.id = "registry+https://user:pass@cache.example/index".to_string();
    let body = body_for(&key, now, 11, RemoteTier::Libraries, vec![credential]);
    assert!(body.validate_shape().is_err());

    let mut escape = test_unit(
        dir.path(),
        "escape",
        RemoteUnitKind::Lib,
        "deps/libescape.rlib",
        FileRole::Artifact,
        b"rlib",
    );
    escape.files[0].path = "../escape".to_string();
    let body = body_for(&key, now, 12, RemoteTier::Libraries, vec![escape]);
    assert!(body.validate_shape().is_err());

    let mut oversized = test_unit(
        dir.path(),
        "oversized",
        RemoteUnitKind::Lib,
        "deps/liboversized.rlib",
        FileRole::Artifact,
        b"rlib",
    );
    oversized.files[0].size = MAX_BLOB_BYTES + 1;
    let body = body_for(&key, now, 13, RemoteTier::Libraries, vec![oversized]);
    assert!(body.validate_shape().is_err());

    let huge_pointer = vec![b' '; MAX_INDEX_POINTER_BYTES as usize + 1];
    assert!(
        verify_index(
            &huge_pointer,
            b"{}",
            &public_key(&key),
            RemoteTier::Libraries,
            now
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn duplicate_destinations_and_bad_names_are_rejected() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let now = now_secs();
    let key = signing_key(7);
    let first = test_unit(
        dir.path(),
        "one",
        RemoteUnitKind::Lib,
        "deps/libsame.rlib",
        FileRole::Artifact,
        b"one",
    );
    let mut second = test_unit(
        dir.path(),
        "two",
        RemoteUnitKind::Lib,
        "deps/libsame.rlib",
        FileRole::Artifact,
        b"two",
    );
    second.files[0].dest = first.files[0].dest.clone();
    let body = body_for(
        &key,
        now,
        14,
        RemoteTier::Libraries,
        vec![first.clone(), second],
    );
    assert!(body.validate_shape().is_err());

    let mut bad_name = first;
    bad_name.package = "different".to_string();
    let body = body_for(&key, now, 15, RemoteTier::Libraries, vec![bad_name]);
    assert!(body.validate_shape().is_err());
    Ok(())
}

#[test]
fn blob_round_trip_is_put_if_absent() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let payload = vec![b'a'; 256 * 1024];
    let source = dir.path().join("artifact.rlib");
    fs::write(&source, &payload)?;

    let blob = write_blob(&source, dir.path())?;
    assert_eq!(blob.compression, Compression::Gzip);
    assert!(blob.blob_size < blob.size);
    verify_blob(dir.path(), &blob)?;
    assert_eq!(read_blob(dir.path(), &blob)?, payload);
    let mut streamed = Vec::new();
    decode_blob(dir.path(), &blob, &mut streamed)?;
    assert_eq!(streamed, payload);

    let mut too_big = blob.clone();
    too_big.size = MAX_IN_MEMORY_BLOB_BYTES + 1;
    assert!(read_blob(dir.path(), &too_big).is_err());
    let mut short = blob.clone();
    short.size -= 1;
    assert!(decode_blob(dir.path(), &short, &mut Vec::new()).is_err());

    let again = write_blob(&source, dir.path())?;
    assert_eq!(blob, again, "an identical blob must reuse the CAS object");

    let small = dir.path().join("small.meta");
    fs::write(&small, b"tiny")?;
    let raw = write_blob(&small, dir.path())?;
    assert_eq!(raw.compression, Compression::Raw);
    assert_eq!(raw.blob, raw.sha256);
    assert_eq!(read_blob(dir.path(), &raw)?, b"tiny");

    fs::write(blob_path(dir.path(), &blob.blob)?, b"corrupt")?;
    assert!(
        write_blob(&source, dir.path()).is_err(),
        "a published blob must never be overwritten"
    );
    Ok(())
}

#[test]
fn upload_plan_replaces_the_pointer_last() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let now = now_secs();
    let key = signing_key(7);
    let unit = test_unit(
        dir.path(),
        "upload",
        RemoteUnitKind::Lib,
        "deps/libupload.rlib",
        FileRole::Artifact,
        b"payload",
    );
    let body = body_for(&key, now, 16, RemoteTier::Libraries, vec![unit]);
    let index = make_index(body, &key, now)?;
    write_index_tree(dir.path(), &index)?;
    let uploads = upload_plan(dir.path(), &index)?;
    assert_eq!(uploads.last().expect("pointer").key, INDEX_FILE);
    assert!(
        uploads.iter().any(
            |upload| upload.key.starts_with("blobs/") && upload.mode == UploadMode::PutIfAbsent
        )
    );
    assert!(
        uploads
            .iter()
            .any(|upload| upload.key.starts_with("indexes/")
                && upload.mode == UploadMode::PutIfAbsent)
    );
    assert_eq!(
        uploads
            .iter()
            .find(|upload| upload.key == PUBLISHER_FILE)
            .expect("report")
            .mode,
        UploadMode::Replace
    );
    assert_eq!(
        uploads
            .iter()
            .find(|upload| upload.key == INDEX_FILE)
            .expect("pointer")
            .mode,
        UploadMode::Replace
    );
    Ok(())
}

#[test]
fn compatibility_mismatches_name_the_field() -> Result<()> {
    let local = local_environment();
    let compatibility = Compatibility::from_local(&local, &[])?;
    assert!(compatibility.compare_local(&local).is_empty());

    let mut other = local.clone();
    other.rustc.commit = "different".to_string();
    other.cargo_home = "/different/cargo".to_string();
    other.target = "aarch64-unknown-linux-gnu".to_string();
    let mismatches = compatibility.compare_local(&other);
    let fields: Vec<&str> = mismatches
        .iter()
        .map(|mismatch| mismatch.field.as_str())
        .collect();
    assert!(fields.contains(&"rustc commit"));
    assert!(fields.contains(&"cargo home"));
    assert!(fields.contains(&"target"));

    let mut unsorted = compatibility.clone();
    unsorted.profiles = vec!["release".to_string(), "debug".to_string()];
    assert!(unsorted.validate().is_err());

    let mut credential = compatibility.clone();
    credential.registry.index = "https://token@cache.example/index".to_string();
    assert!(credential.validate().is_err());

    let mut oversize = compatibility;
    oversize.features = vec!["x".repeat(super::compat::MAX_FEATURE_BYTES + 1)];
    assert!(oversize.validate().is_err());
    Ok(())
}

#[test]
fn local_compatibility_gate_checks_the_machine_tuple() -> Result<()> {
    let local = local_environment();
    let now = now_secs();
    let key = signing_key(7);
    let mut body = body_for(&key, now, 20, RemoteTier::Libraries, Vec::new());
    body.compatibility = Compatibility::from_local(&local, &[])?;
    assert!(
        body.validate_for_local(RemoteTier::Libraries, &local)
            .is_ok()
    );

    let mut other = local;
    other.rustc.host = "aarch64-unknown-linux-gnu".to_string();
    other.target = "aarch64-unknown-linux-gnu".to_string();
    assert!(
        body.validate_for_local(RemoteTier::Libraries, &other)
            .is_err()
    );
    Ok(())
}

#[test]
fn publisher_metadata_rejects_control_characters_and_oversize_text() -> Result<()> {
    let now = now_secs();
    let key = signing_key(7);
    let mut body = body_for(&key, now, 21, RemoteTier::Libraries, Vec::new());
    body.publisher.notes = "\u{1b}[31mred".to_string();
    assert!(body.validate_shape().is_err());

    body.publisher.notes = "\u{202e}evil".to_string();
    assert!(body.validate_shape().is_err());

    body.publisher.notes.clear();
    body.publisher.ci_job = "https://token@ci.example/job".to_string();
    assert!(body.validate_shape().is_err());

    body.publisher.ci_job.clear();
    body.publisher.tool = "x".repeat(super::index::MAX_TOOL_BYTES + 1);
    assert!(body.validate_shape().is_err());
    Ok(())
}

#[test]
fn file_roles_are_typed_and_round_trip() -> Result<()> {
    let role: FileRole = serde_json::from_str("\"build-tree\"")?;
    assert_eq!(role, FileRole::BuildTree);
    assert_eq!(serde_json::to_string(&role)?, "\"build-tree\"");
    assert!(serde_json::from_str::<FileRole>("\"executable\"").is_err());
    Ok(())
}

#[test]
fn publisher_report_mirrors_the_signed_metadata() -> Result<()> {
    let now = now_secs();
    let key = signing_key(7);
    let body = body_for(&key, now, 17, RemoteTier::Full, Vec::new());
    let index = make_index(body, &key, now)?;
    let bytes = publisher_report(&index)?;
    let report: PublisherReport = serde_json::from_slice(&bytes)?;
    assert_eq!(report.sequence, 17);
    assert_eq!(report.key_id, index.pointer().key_id);
    assert_eq!(report.tier, RemoteTier::Full);
    assert_eq!(report.body_sha256, index.pointer().body_sha256);
    Ok(())
}

// ── reader / import ─────────────────────────────────────────────────────────

fn policy_at(public: &str, cache: &std::path::Path) -> settings::RemotePolicy {
    let mut policy = remote_policy(public);
    policy.cache = cache.to_path_buf();
    policy
}

fn body_for_local(
    key: &SigningKey,
    now: u64,
    sequence: u64,
    tier: RemoteTier,
    units: Vec<RemoteUnit>,
    local: &LocalEnvironment,
) -> IndexBody {
    IndexBody {
        schema: SCHEMA_VERSION,
        key_id: settings::remote_key_id(&public_key(key)).unwrap(),
        sequence,
        created: now.saturating_sub(60),
        expires: now + 86_400,
        tier,
        publisher: publisher(now),
        compatibility: Compatibility::from_local(local, &units).unwrap(),
        units,
    }
}

fn remote_file(
    root: &std::path::Path,
    path: &str,
    dest: &str,
    role: FileRole,
    content: &[u8],
) -> Result<RemoteFile> {
    let source = root.join(format!(".source-{}", crate::util::temp_nonce()));
    fs::write(&source, content)?;
    let blob = write_blob(&source, root)?;
    Ok(RemoteFile {
        path: path.to_string(),
        dest: dest.to_string(),
        size: content.len() as u64,
        sha256: super::sha256_hex(content),
        role,
        blob: blob.blob,
        blob_size: blob.blob_size,
        compression: blob.compression,
    })
}

fn lib_unit(root: &std::path::Path) -> Result<RemoteUnit> {
    lib_unit_with(root, b"artifact bytes")
}

fn lib_unit_with(root: &std::path::Path, artifact: &[u8]) -> Result<RemoteUnit> {
    let memo = b"aabbccddeeff0011";
    Ok(RemoteUnit {
        name: "demo-0011223344556677".to_string(),
        package: "demo".to_string(),
        version: Some("0.1.0".to_string()),
        profile: "debug".to_string(),
        memo: "lib-demo".to_string(),
        hash: "aabbccddeeff0011".to_string(),
        stamp: now_secs(),
        layout: UnitLayout::Classic,
        kind: RemoteUnitKind::Lib,
        source: UnitSource {
            kind: SourceKind::Registry,
            id: "https://github.com/rust-lang/crates.io-index".to_string(),
            checksum: Some("ab".repeat(32)),
        },
        compat: UnitCompatibility {
            rustc: "1".to_string(),
            target: "2".to_string(),
            profile: "3".to_string(),
            features: vec!["default".to_string()],
            rustflags: Vec::new(),
            config: "4".to_string(),
            path: "5".to_string(),
            compile_kind: "0".to_string(),
        },
        files: vec![
            remote_file(
                root,
                "lib-demo",
                ".fingerprint/demo-0011223344556677/lib-demo",
                FileRole::Memo,
                memo,
            )?,
            remote_file(
                root,
                "deps/libdemo.rlib",
                "deps/libdemo.rlib",
                FileRole::Artifact,
                artifact,
            )?,
        ],
    })
}

fn build_unit(root: &std::path::Path) -> Result<RemoteUnit> {
    Ok(RemoteUnit {
        name: "buildy-8899aabbccddeeff".to_string(),
        package: "buildy".to_string(),
        version: Some("0.1.0".to_string()),
        profile: "debug".to_string(),
        memo: "build-script-build".to_string(),
        hash: "1122334455667788".to_string(),
        stamp: now_secs(),
        layout: UnitLayout::Classic,
        kind: RemoteUnitKind::BuildScript,
        source: UnitSource {
            kind: SourceKind::Registry,
            id: "https://github.com/rust-lang/crates.io-index".to_string(),
            checksum: Some("cd".repeat(32)),
        },
        compat: UnitCompatibility {
            rustc: "1".to_string(),
            target: "2".to_string(),
            profile: "3".to_string(),
            features: vec!["default".to_string()],
            rustflags: Vec::new(),
            config: "4".to_string(),
            path: "5".to_string(),
            compile_kind: "0".to_string(),
        },
        files: vec![remote_file(
            root,
            "build/buildy/out/build-script-build",
            "build/buildy/out/build-script-build",
            FileRole::BuildTree,
            b"#!/bin/sh\nexit 0\n",
        )?],
    })
}

struct FailingSource;

impl RemoteSource for FailingSource {
    fn fetch_pointer(&self) -> Result<Vec<u8>> {
        anyhow::bail!("offline")
    }

    fn fetch_body(&self, _sha256: &str, _max_bytes: u64) -> Result<Vec<u8>> {
        anyhow::bail!("offline")
    }

    fn fetch_blob(
        &self,
        _sha256: &str,
        _max_bytes: u64,
        _out: &mut dyn std::io::Write,
    ) -> Result<()> {
        anyhow::bail!("offline")
    }
}

fn prepared_source<F>(
    key: &SigningKey,
    now: u64,
    tier: RemoteTier,
    local: &LocalEnvironment,
    build: F,
) -> Result<(tempfile::TempDir, SignedIndex)>
where
    F: FnOnce(&std::path::Path) -> Result<Vec<RemoteUnit>>,
{
    let source = tempfile::tempdir()?;
    let units = build(source.path())?;
    let body = body_for_local(key, now, 1, tier, units, local);
    let index = make_index(body, key, now)?;
    write_index_tree(source.path(), &index)?;
    Ok((source, index))
}

#[test]
fn reader_imports_and_restores_verified_units() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let view = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let key = signing_key(11);
    let local = LocalEnvironment::gather()?;
    let now = now_secs();
    let policy = policy_at(&public_key(&key), cache.path());
    let generation = crate::vault::parity_key()?;
    let (source, _index) = prepared_source(&key, now, RemoteTier::Libraries, &local, |root| {
        Ok(vec![lib_unit(root)?])
    })?;
    let report = fetch_and_import(&FetchRequest {
        remote: &policy,
        source: &DirSource::new(source.path()),
        store_root: store.path(),
        state_root: Some(state.path()),
        packages: None,
        selector: None,
        layout: None,
        profile: None,
        unit_filter: None,
        local: Some(&local),
        generation: Some(&generation),
        now,
        dry_run: false,
    })?;
    assert_eq!(report.imported, 1, "{:?}", report.fallback);
    assert!(report.fallback.is_none());
    assert!(report.cache_store.is_none());

    let reports = crate::vault::verify(store.path())?;
    assert!(
        reports.iter().all(|report| report.problems.is_empty()),
        "{:?}",
        reports
            .iter()
            .flat_map(|report| report.problems.iter())
            .collect::<Vec<_>>()
    );
    let restore = crate::vault::restore(view.path(), store.path(), None, None, false)?;
    assert_eq!(restore.errors, 0);
    assert_eq!(restore.fatal_errors, 0);
    assert_eq!(
        fs::read(view.path().join("debug/deps/libdemo.rlib"))?,
        b"artifact bytes"
    );
    Ok(())
}

#[test]
fn reader_tier_filter_skips_executable_units() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let key = signing_key(12);
    let local = LocalEnvironment::gather()?;
    let now = now_secs();
    let policy = policy_at(&public_key(&key), cache.path());
    let generation = crate::vault::parity_key()?;
    let (source, _index) = prepared_source(&key, now, RemoteTier::Full, &local, |root| {
        Ok(vec![lib_unit(root)?, build_unit(root)?])
    })?;
    let report = fetch_and_import(&FetchRequest {
        remote: &policy,
        source: &DirSource::new(source.path()),
        store_root: store.path(),
        state_root: Some(state.path()),
        packages: None,
        selector: None,
        layout: None,
        profile: None,
        unit_filter: None,
        local: Some(&local),
        generation: Some(&generation),
        now,
        dry_run: false,
    })?;
    assert_eq!(report.imported, 1);
    let stored = crate::vault::stored_units(store.path())?;
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].entry.name, "demo-0011223344556677");
    Ok(())
}

#[test]
fn reader_profile_filter_is_a_miss_not_an_error() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let key = signing_key(13);
    let local = LocalEnvironment::gather()?;
    let now = now_secs();
    let policy = policy_at(&public_key(&key), cache.path());
    let (source, _index) = prepared_source(&key, now, RemoteTier::Libraries, &local, |root| {
        let mut unit = lib_unit(root)?;
        unit.profile = "release".to_string();
        Ok(vec![unit])
    })?;
    let report = fetch_and_import(&FetchRequest {
        remote: &policy,
        source: &DirSource::new(source.path()),
        store_root: store.path(),
        state_root: Some(state.path()),
        packages: None,
        selector: None,
        layout: None,
        profile: Some("debug"),
        unit_filter: None,
        local: Some(&local),
        generation: Some("generation"),
        now,
        dry_run: false,
    })?;
    assert_eq!(report.candidates, 0);
    assert_eq!(report.imported, 0);
    assert!(report.fallback.is_none());
    Ok(())
}

#[test]
fn reader_offline_reuses_a_valid_cached_index() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let first = tempfile::tempdir()?;
    let second = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let key = signing_key(14);
    let local = LocalEnvironment::gather()?;
    let now = now_secs();
    let policy = policy_at(&public_key(&key), cache.path());
    let generation = crate::vault::parity_key()?;
    let (source, _index) = prepared_source(&key, now, RemoteTier::Libraries, &local, |root| {
        Ok(vec![lib_unit(root)?])
    })?;
    let dir_source = DirSource::new(source.path());
    let online = fetch_and_import(&FetchRequest {
        remote: &policy,
        source: &dir_source,
        store_root: first.path(),
        state_root: Some(state.path()),
        packages: None,
        selector: None,
        layout: None,
        profile: None,
        unit_filter: None,
        local: Some(&local),
        generation: Some(&generation),
        now,
        dry_run: false,
    })?;
    assert_eq!(online.imported, 1);
    let offline = fetch_and_import(&FetchRequest {
        remote: &policy,
        source: &FailingSource,
        store_root: second.path(),
        state_root: Some(state.path()),
        packages: None,
        selector: None,
        layout: None,
        profile: None,
        unit_filter: None,
        local: Some(&local),
        generation: Some(&generation),
        now,
        dry_run: false,
    })?;
    assert!(offline.offline);
    assert_eq!(offline.imported, 1, "{:?}", offline.fallback);
    assert!(offline.fallback.is_none());
    Ok(())
}

#[test]
fn reader_rejects_a_tampered_pointer_without_importing() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let key = signing_key(15);
    let local = LocalEnvironment::gather()?;
    let now = now_secs();
    let policy = policy_at(&public_key(&key), cache.path());
    let (source, _index) = prepared_source(&key, now, RemoteTier::Libraries, &local, |root| {
        Ok(vec![lib_unit(root)?])
    })?;
    let pointer = fs::read(source.path().join(INDEX_FILE))?;
    let mut tampered = pointer.clone();
    let last = tampered.len() - 2;
    tampered[last] ^= 1;
    fs::write(source.path().join(INDEX_FILE), tampered)?;
    let report = fetch_and_import(&FetchRequest {
        remote: &policy,
        source: &DirSource::new(source.path()),
        store_root: store.path(),
        state_root: Some(state.path()),
        packages: None,
        selector: None,
        layout: None,
        profile: None,
        unit_filter: None,
        local: Some(&local),
        generation: Some("generation"),
        now,
        dry_run: false,
    })?;
    assert_eq!(report.imported, 0);
    assert!(report.warning.is_some());
    assert!(report.fallback.is_some());
    assert!(crate::vault::stored_units(store.path())?.is_empty());
    Ok(())
}

#[cfg(unix)]
#[test]
fn reader_uses_the_cache_store_when_the_main_store_is_read_only() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let cache = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let view = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let key = signing_key(16);
    let local = LocalEnvironment::gather()?;
    let now = now_secs();
    let policy = policy_at(&public_key(&key), cache.path());
    let generation = crate::vault::parity_key()?;
    let (source, _index) = prepared_source(&key, now, RemoteTier::Libraries, &local, |root| {
        Ok(vec![lib_unit(root)?])
    })?;
    fs::set_permissions(store.path(), fs::Permissions::from_mode(0o555))?;
    let report = fetch_and_import(&FetchRequest {
        remote: &policy,
        source: &DirSource::new(source.path()),
        store_root: store.path(),
        state_root: Some(state.path()),
        packages: None,
        selector: None,
        layout: None,
        profile: None,
        unit_filter: None,
        local: Some(&local),
        generation: Some(&generation),
        now,
        dry_run: false,
    });
    fs::set_permissions(store.path(), fs::Permissions::from_mode(0o755))?;
    let report = report?;
    let cache_store = report.cache_store.expect("read-only main store uses cache");
    assert_eq!(report.imported, 1, "{:?}", report.fallback);
    let stored = crate::vault::stored_units(&cache_store)?;
    assert_eq!(stored.len(), 1);
    let restore = crate::vault::restore(view.path(), &cache_store, None, None, false)?;
    assert_eq!(restore.errors, 0);
    assert_eq!(
        fs::read(view.path().join("debug/deps/libdemo.rlib"))?,
        b"artifact bytes"
    );
    Ok(())
}

#[test]
fn reader_lock_filter_requires_the_matching_source() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let key = signing_key(17);
    let local = LocalEnvironment::gather()?;
    let now = now_secs();
    let policy = policy_at(&public_key(&key), cache.path());
    let (source, _index) = prepared_source(&key, now, RemoteTier::Libraries, &local, |root| {
        Ok(vec![lib_unit(root)?])
    })?;
    let lock_path = cache.path().join("Cargo.lock");
    fs::write(
        &lock_path,
        "version = 4\n\n[[package]]\nname = \"demo\"\nversion = \"0.1.0\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
         checksum = \"ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB\"\n",
    )?;
    let lock = crate::lockfile::LockIndex::parse(&lock_path).expect("lock parses");
    let report = fetch_and_import(&FetchRequest {
        remote: &policy,
        source: &DirSource::new(source.path()),
        store_root: store.path(),
        state_root: Some(state.path()),
        packages: Some(&lock),
        selector: None,
        layout: None,
        profile: None,
        unit_filter: None,
        local: Some(&local),
        generation: Some("generation"),
        now,
        dry_run: true,
    })?;
    assert_eq!(report.candidates, 1);
    assert!(report.fallback.is_none());
    Ok(())
}

#[test]
fn mixed_layout_indexes_are_accepted_and_filtered_per_unit() -> Result<()> {
    let key = signing_key(18);
    let local = LocalEnvironment::gather()?;
    let now = now_secs();
    let source = tempfile::tempdir()?;
    let unit = lib_unit(source.path())?;
    let mut body = body_for_local(&key, now, 1, RemoteTier::Libraries, vec![unit], &local);
    body.compatibility.layout = "mixed".to_string();
    body.validate_for_local(RemoteTier::Libraries, &local)?;
    Ok(())
}

#[test]
fn reader_preserves_compressed_blobs_and_verify_is_clean() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let view = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let key = signing_key(19);
    let local = LocalEnvironment::gather()?;
    let now = now_secs();
    let policy = policy_at(&public_key(&key), cache.path());
    let generation = crate::vault::parity_key()?;
    let artifact = vec![b'x'; 64 * 1024];
    let (source, _index) = prepared_source(&key, now, RemoteTier::Libraries, &local, |root| {
        Ok(vec![lib_unit_with(root, &artifact)?])
    })?;
    let report = fetch_and_import(&FetchRequest {
        remote: &policy,
        source: &DirSource::new(source.path()),
        store_root: store.path(),
        state_root: Some(state.path()),
        packages: None,
        selector: None,
        layout: None,
        profile: None,
        unit_filter: None,
        local: Some(&local),
        generation: Some(&generation),
        now,
        dry_run: false,
    })?;
    assert_eq!(report.imported, 1, "{:?}", report.fallback);
    let stored = crate::vault::stored_units(store.path())?;
    let artifact = stored[0]
        .entry
        .files
        .iter()
        .find(|file| file.path == "deps/libdemo.rlib")
        .expect("artifact");
    assert!(artifact.object.is_some(), "large artifact is a gzip object");
    let reports = crate::vault::verify(store.path())?;
    assert!(
        reports.iter().all(|report| report.problems.is_empty()),
        "{:?}",
        reports
            .iter()
            .flat_map(|report| report.problems.iter())
            .collect::<Vec<_>>()
    );
    let restore = crate::vault::restore(view.path(), store.path(), None, None, false)?;
    assert_eq!(restore.errors, 0);
    assert_eq!(
        fs::read(view.path().join("debug/deps/libdemo.rlib"))?.len(),
        64 * 1024
    );
    Ok(())
}

#[test]
fn reader_dry_run_writes_nothing() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let key = signing_key(20);
    let local = LocalEnvironment::gather()?;
    let now = now_secs();
    let policy = policy_at(&public_key(&key), cache.path());
    let (source, _index) = prepared_source(&key, now, RemoteTier::Libraries, &local, |root| {
        Ok(vec![lib_unit(root)?])
    })?;
    let report = fetch_and_import(&FetchRequest {
        remote: &policy,
        source: &DirSource::new(source.path()),
        store_root: store.path(),
        state_root: Some(state.path()),
        packages: None,
        selector: None,
        layout: None,
        profile: None,
        unit_filter: None,
        local: Some(&local),
        generation: Some("generation"),
        now,
        dry_run: true,
    })?;
    assert_eq!(report.candidates, 1);
    assert_eq!(report.imported, 0);
    assert!(report.fallback.is_none());
    assert!(!super::cache::endpoint_root(&policy)?.exists());
    assert!(crate::vault::stored_units(store.path())?.is_empty());
    Ok(())
}

#[test]
fn reader_rejects_a_poisoned_cached_blob() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let first = tempfile::tempdir()?;
    let second = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let key = signing_key(21);
    let local = LocalEnvironment::gather()?;
    let now = now_secs();
    let policy = policy_at(&public_key(&key), cache.path());
    let generation = crate::vault::parity_key()?;
    let (source, index) = prepared_source(&key, now, RemoteTier::Libraries, &local, |root| {
        Ok(vec![lib_unit(root)?])
    })?;
    let dir_source = DirSource::new(source.path());
    let online = fetch_and_import(&FetchRequest {
        remote: &policy,
        source: &dir_source,
        store_root: first.path(),
        state_root: Some(state.path()),
        packages: None,
        selector: None,
        layout: None,
        profile: None,
        unit_filter: None,
        local: Some(&local),
        generation: Some(&generation),
        now,
        dry_run: false,
    })?;
    assert_eq!(online.imported, 1);
    let blob = &index.body().units[0].files[0].blob;
    let cached = super::cache::endpoint_root(&policy)?
        .join(BLOBS_DIR)
        .join(blob);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&cached, fs::Permissions::from_mode(0o644))?;
    }
    fs::write(&cached, b"poison")?;
    let offline = fetch_and_import(&FetchRequest {
        remote: &policy,
        source: &FailingSource,
        store_root: second.path(),
        state_root: Some(state.path()),
        packages: None,
        selector: None,
        layout: None,
        profile: None,
        unit_filter: None,
        local: Some(&local),
        generation: Some(&generation),
        now,
        dry_run: false,
    })?;
    assert_eq!(offline.imported, 0);
    assert!(offline.fallback.is_some());
    assert!(crate::vault::stored_units(second.path())?.is_empty());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn reader_copies_across_filesystems() -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let shm = std::path::Path::new("/dev/shm");
    if !shm.is_dir() {
        return Ok(());
    }
    let cache = tempfile::Builder::new()
        .prefix("epicenter-remote-")
        .tempdir_in(shm)?;
    let store = tempfile::tempdir()?;
    if fs::metadata(cache.path())?.dev() == fs::metadata(store.path())?.dev() {
        return Ok(());
    }
    let state = tempfile::tempdir()?;
    let key = signing_key(22);
    let local = LocalEnvironment::gather()?;
    let now = now_secs();
    let policy = policy_at(&public_key(&key), cache.path());
    let generation = crate::vault::parity_key()?;
    let (source, _index) = prepared_source(&key, now, RemoteTier::Libraries, &local, |root| {
        Ok(vec![lib_unit(root)?])
    })?;
    let report = fetch_and_import(&FetchRequest {
        remote: &policy,
        source: &DirSource::new(source.path()),
        store_root: store.path(),
        state_root: Some(state.path()),
        packages: None,
        selector: None,
        layout: None,
        profile: None,
        unit_filter: None,
        local: Some(&local),
        generation: Some(&generation),
        now,
        dry_run: false,
    })?;
    assert_eq!(report.imported, 1, "{:?}", report.fallback);
    assert_eq!(crate::vault::stored_units(store.path())?.len(), 1);
    Ok(())
}

struct NoBlobSource<'a> {
    inner: &'a DirSource,
}

impl RemoteSource for NoBlobSource<'_> {
    fn fetch_pointer(&self) -> Result<Vec<u8>> {
        self.inner.fetch_pointer()
    }

    fn fetch_body(&self, sha256: &str, max_bytes: u64) -> Result<Vec<u8>> {
        self.inner.fetch_body(sha256, max_bytes)
    }

    fn fetch_blob(
        &self,
        _sha256: &str,
        _max_bytes: u64,
        _out: &mut dyn std::io::Write,
    ) -> Result<()> {
        anyhow::bail!("a warm generation must not fetch blobs")
    }
}

#[test]
fn reader_skips_blobs_when_the_generation_is_already_present() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let key = signing_key(23);
    let local = LocalEnvironment::gather()?;
    let now = now_secs();
    let policy = policy_at(&public_key(&key), cache.path());
    let generation = crate::vault::parity_key()?;
    let (source, _index) = prepared_source(&key, now, RemoteTier::Libraries, &local, |root| {
        Ok(vec![lib_unit(root)?])
    })?;
    let dir_source = DirSource::new(source.path());
    assert_eq!(
        fetch_and_import(&FetchRequest {
            remote: &policy,
            source: &dir_source,
            store_root: store.path(),
            state_root: Some(state.path()),
            packages: None,
            selector: None,
            layout: None,
            profile: None,
            unit_filter: None,
            local: Some(&local),
            generation: Some(&generation),
            now,
            dry_run: false,
        })?
        .imported,
        1
    );
    let warm = fetch_and_import(&FetchRequest {
        remote: &policy,
        source: &NoBlobSource { inner: &dir_source },
        store_root: store.path(),
        state_root: Some(state.path()),
        packages: None,
        selector: None,
        layout: None,
        profile: None,
        unit_filter: None,
        local: Some(&local),
        generation: Some(&generation),
        now,
        dry_run: false,
    })?;
    assert_eq!(warm.imported, 0);
    assert_eq!(warm.skipped, 1);
    assert!(warm.fallback.is_none(), "{:?}", warm.fallback);
    Ok(())
}

#[cfg(unix)]
#[test]
fn reader_rejects_symlinked_cache_roots() -> Result<()> {
    use std::os::unix::fs::symlink;
    let key = signing_key(24);
    let public = public_key(&key);
    let store = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let now = now_secs();

    let case = |policy: &settings::RemotePolicy| {
        fetch_and_import(&FetchRequest {
            remote: policy,
            source: &FailingSource,
            store_root: store.path(),
            state_root: Some(state.path()),
            packages: None,
            selector: None,
            layout: None,
            profile: None,
            unit_filter: None,
            local: None,
            generation: Some("generation"),
            now,
            dry_run: false,
        })
    };

    // Symlinked cache root.
    let base = tempfile::tempdir()?;
    let victim = tempfile::tempdir()?;
    let cache = base.path().join("cache");
    symlink(victim.path(), &cache)?;
    let policy = policy_at(&public, &cache);
    assert!(case(&policy).is_err());

    // Symlinked endpoint.
    let cache = tempfile::tempdir()?;
    let policy = policy_at(&public, cache.path());
    let endpoint = super::cache::endpoint_root(&policy)?;
    fs::create_dir_all(cache.path())?;
    symlink(victim.path(), &endpoint)?;
    assert!(case(&policy).is_err());

    // Symlinked cache store.
    let cache = tempfile::tempdir()?;
    let policy = policy_at(&public, cache.path());
    let endpoint = super::cache::endpoint_root(&policy)?;
    fs::create_dir_all(&endpoint)?;
    symlink(victim.path(), endpoint.join("store"))?;
    assert!(case(&policy).is_err());
    Ok(())
}
