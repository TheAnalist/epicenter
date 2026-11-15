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
    let cargo_home = "/opt/epicenter/cargo";
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
    role: &str,
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
            role: role.to_string(),
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
    let (pointer, bytes) = make_index(&body, &key, now)?;
    assert_eq!(body.canonical_bytes()?, bytes);
    write_index_tree(dir.path(), &pointer, &bytes)?;
    assert!(dir.path().join(PUBLISHER_FILE).is_file());

    let verified = read_index_tree(dir.path(), &public_key(&key), now)?;
    assert_eq!(verified.pointer.sequence, 3);
    assert_eq!(verified.body.tier, RemoteTier::Libraries);
    assert_eq!(verified.body_bytes, bytes);
    assert!(pointer.signature.len() == 128);
    Ok(())
}

#[test]
fn signature_and_pinned_key_are_enforced() -> Result<()> {
    let now = now_secs();
    let key = signing_key(7);
    let other = signing_key(8);
    let body = body_for(&key, now, 1, RemoteTier::Libraries, Vec::new());
    let (pointer, _) = make_index(&body, &key, now)?;
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
    let (pointer, bytes) = make_index(&body, &key, now)?;

    let mut flipped = bytes.clone();
    flipped[0] = b' ';
    assert!(verify_body(&pointer, &flipped, now).is_err());

    let short = &bytes[..bytes.len() - 1];
    assert!(verify_body(&pointer, short, now).is_err());

    let pretty = serde_json::to_vec_pretty(&body)?;
    assert!(verify_body(&pointer, &pretty, now).is_err());

    assert!(verify_index(&bytes, &bytes, &public_key(&key), now).is_err());
    Ok(())
}

#[test]
fn expiry_future_clock_and_validity_cap_are_enforced() -> Result<()> {
    let now = now_secs();
    let key = signing_key(7);

    let mut stale = body_for(&key, now, 4, RemoteTier::Libraries, Vec::new());
    stale.created = now.saturating_sub(1_000);
    stale.expires = now.saturating_sub(1);
    let (pointer, _) = make_index(&stale, &key, now.saturating_sub(500))?;
    assert!(pointer.verify(&public_key(&key), now).is_err());

    let future = now + MAX_CLOCK_SKEW_SECS + 100;
    let body = body_for(&key, future, 5, RemoteTier::Libraries, Vec::new());
    let (pointer, _) = make_index(&body, &key, future)?;
    assert!(pointer.verify(&public_key(&key), now).is_err());

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
    let (old_pointer, _) = make_index(&old_body, &old, now)?;
    old_pointer.verify(&public_key(&old), now)?;
    assert!(old_pointer.verify(&public_key(&new), now).is_err());

    let new_body = body_for(&new, now, 8, RemoteTier::Libraries, Vec::new());
    let (new_pointer, _) = make_index(&new_body, &new, now)?;
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
    let (pointer, _) = make_index(&body, &key, now)?;
    state::record_state_at(dir.path(), &remote, &pointer, &body, now)?;
    let loaded = state::load_state_at(dir.path(), &remote)?.expect("state");
    assert_eq!(loaded.sequence, 7);

    let older = body_for(&key, now, 6, RemoteTier::Libraries, Vec::new());
    let (older_pointer, _) = make_index(&older, &key, now)?;
    assert!(state::record_state_at(dir.path(), &remote, &older_pointer, &older, now).is_err());

    let mut alternate = body_for(&key, now, 7, RemoteTier::Libraries, Vec::new());
    alternate.publisher.ci_job = "ci/other".to_string();
    let (alternate_pointer, _) = make_index(&alternate, &key, now)?;
    assert!(
        state::record_state_at(dir.path(), &remote, &alternate_pointer, &alternate, now).is_err()
    );

    let newer = body_for(&key, now, 8, RemoteTier::Libraries, Vec::new());
    let (newer_pointer, _) = make_index(&newer, &key, now)?;
    state::record_state_at(dir.path(), &remote, &newer_pointer, &newer, now)?;
    assert_eq!(
        state::load_state_at(dir.path(), &remote)?
            .expect("state")
            .sequence,
        8
    );
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
    let (pointer, _) = make_index(&body, &key, now)?;
    state::record_state_at(dir.path(), &remote, &pointer, &body, now)?;

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
        "build-tree",
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
    assert!(body.validate_for(RemoteTier::Libraries).is_err());

    let mut mislabeled = body;
    mislabeled.tier = RemoteTier::Libraries;
    assert!(mislabeled.validate_for(RemoteTier::Libraries).is_err());

    let proc_macro = test_unit(
        dir.path(),
        "macros",
        RemoteUnitKind::Lib,
        "deps/libmacros.so",
        "artifact",
        b"shared object",
    );
    let body = body_for(&key, now, 10, RemoteTier::Libraries, vec![proc_macro]);
    assert!(body.validate_for(RemoteTier::Libraries).is_err());

    let binary = test_unit(
        dir.path(),
        "probe",
        RemoteUnitKind::Other,
        "deps/probe",
        "artifact",
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
        "artifact",
        b"rlib",
    );
    local.source.kind = SourceKind::Path;
    local.source.id = "/work/local".to_string();
    local.source.checksum = None;
    let body = body_for(&key, now, 11, RemoteTier::Libraries, vec![local]);
    assert!(body.validate_shape().is_err());

    let mut escape = test_unit(
        dir.path(),
        "escape",
        RemoteUnitKind::Lib,
        "deps/libescape.rlib",
        "artifact",
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
        "artifact",
        b"rlib",
    );
    oversized.files[0].size = MAX_BLOB_BYTES + 1;
    let body = body_for(&key, now, 13, RemoteTier::Libraries, vec![oversized]);
    assert!(body.validate_shape().is_err());

    let huge_pointer = vec![b' '; MAX_INDEX_POINTER_BYTES as usize + 1];
    assert!(verify_index(&huge_pointer, b"{}", &public_key(&key), now).is_err());
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
        "artifact",
        b"one",
    );
    let mut second = test_unit(
        dir.path(),
        "two",
        RemoteUnitKind::Lib,
        "deps/libsame.rlib",
        "artifact",
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
        "artifact",
        b"payload",
    );
    let body = body_for(&key, now, 16, RemoteTier::Libraries, vec![unit]);
    let (pointer, bytes) = make_index(&body, &key, now)?;
    write_index_tree(dir.path(), &pointer, &bytes)?;
    let uploads = upload_plan(dir.path(), &pointer, &bytes)?;
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

    let mut unsorted = compatibility;
    unsorted.profiles = vec!["release".to_string(), "debug".to_string()];
    assert!(unsorted.validate().is_err());
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
fn publisher_report_mirrors_the_signed_metadata() -> Result<()> {
    let now = now_secs();
    let key = signing_key(7);
    let body = body_for(&key, now, 17, RemoteTier::Full, Vec::new());
    let (pointer, _) = make_index(&body, &key, now)?;
    let bytes = publisher_report(&pointer, &body)?;
    let report: PublisherReport = serde_json::from_slice(&bytes)?;
    assert_eq!(report.sequence, 17);
    assert_eq!(report.key_id, pointer.key_id);
    assert_eq!(report.tier, RemoteTier::Full);
    assert_eq!(report.body_sha256, pointer.body_sha256);
    Ok(())
}
