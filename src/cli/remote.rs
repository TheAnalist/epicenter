use anyhow::{Context, Result};

use epicenter_cli::remote::RemoteSource as _;
use epicenter_cli::util::metadata_nofollow;
use epicenter_cli::{config, lockfile, remote, settings, util, vault};

use super::args::{FetchArgs, PublishArgs};
use super::label;

pub(super) fn cmd_publish(args: &PublishArgs, settings: &settings::Settings) -> Result<()> {
    let policy = settings.remote()?;
    let tier = args.tier.map(Into::into).unwrap_or(policy.tier);
    let url = match args.url.as_deref() {
        Some(raw) => settings::normalize_remote_url(raw)?,
        None => policy
            .url
            .clone()
            .context("no `[remote] url`; pass `--url s3://bucket/prefix`")?,
    };
    let expected_key_id = match args.expect_key_id.as_deref() {
        // A full public key (with or without the `ed25519:` prefix) is
        // normalized to the short id that signs the index.
        Some(raw) if settings::is_publisher_key_hex(raw) => {
            let key = settings::normalize_remote_publisher_key(raw)?;
            Some(settings::remote_key_id(&key)?)
        }
        Some(raw) => Some(raw.to_string()),
        // A rotation deliberately changes the pinned identity; do not treat
        // the old global pin as an expectation for the new key.
        None if args.rotate_key => None,
        None => policy.key_id.clone(),
    };
    let valid_for = util::parse_duration(&args.valid_for)?;
    let source_commit = detect_source_commit(args.source_commit.as_deref())?;
    let ci_job = detect_ci_job(args.ci_job.as_deref());
    let build_root = config::cache_root()?;
    let store_root = vault::store_root(&build_root);
    let cwd = std::env::current_dir().context("resolving the working directory")?;

    let region = policy
        .region
        .clone()
        .or_else(settings::aws_region)
        .context("the S3 publisher requires AWS_REGION or AWS_DEFAULT_REGION")?;
    let transport = remote::TransportConfig::for_s3(&url, &region)?;
    let client = std::sync::Arc::new(remote::S3Client::new(&transport)?);
    let source = remote::S3Source::from_client(client.clone());
    let sink = remote::S3Sink::from_client(client);
    let expected_public_key = args
        .expect_key_id
        .as_deref()
        .filter(|raw| settings::is_publisher_key_hex(raw));
    let mut current: Option<remote::RemotePointer> = None;
    if let Some(fetched) = source.fetch_pointer_optional()? {
        let pointer: remote::IndexPointer =
            serde_json::from_slice(&fetched.bytes).context("parsing the remote index pointer")?;
        let verify_key = expected_public_key
            .or(policy.publisher_key.as_deref())
            .context(
                "a remote index exists; verifying it needs the full publisher public key \
                 (64 hex, not a short key id) via --expect-key-id or `setup --remote-key`",
            )?;
        pointer.verify_signature(verify_key)?;
        current = Some(remote::RemotePointer {
            pointer,
            etag: fetched.etag,
        });
    }
    if current.is_none()
        && !args.reset_sequence
        && sink.head_lenient(remote::PUBLISHER_FILE)?.is_some()
    {
        anyhow::bail!(
            "remote publisher.json exists but index.json is missing; \
             refusing to restart at sequence 1 (use --reset-sequence only after investigating)"
        );
    }

    let outcome = remote::publish(&remote::PublishRequest {
        store_root: &store_root,
        cwd: &cwd,
        url: &url,
        tier,
        generation: args.generation.as_deref(),
        profile: args.profile.as_deref(),
        selector: args.toolchain.as_deref(),
        sequence: args.sequence,
        current: current.as_ref(),
        reset_sequence: args.reset_sequence,
        allow_staged_pointer: false,
        valid_for,
        source_commit: &source_commit,
        ci_job: &ci_job,
        notes: args.notes.as_deref().unwrap_or_default(),
        expect_key_id: expected_key_id.as_deref(),
        rotate_key: args.rotate_key,
        publisher_state: args.publisher_state.as_deref(),
        out_dir: args.out_dir.as_deref(),
        lockfile: args.lockfile.as_deref(),
    })?;

    let heading = if args.rotate_key {
        "epicenter store publish — CI publisher (key rotation)"
    } else {
        "epicenter store publish — CI publisher"
    };
    println!("{}", util::heading(heading));
    println!("  {} {}", label("endpoint"), outcome.url);
    println!("  {} {}", label("tier"), outcome.tier.as_str());
    println!("  {} {}", label("generation"), outcome.generation);
    println!(
        "  {} {} unit(s) · {} file(s) · {}",
        label("staged"),
        outcome.units,
        outcome.files,
        util::human_bytes(outcome.bytes)
    );
    if outcome.skipped_workspace > 0 || outcome.skipped_tier > 0 {
        println!(
            "  {} {} workspace/path · {} outside the tier",
            label("skipped"),
            outcome.skipped_workspace,
            outcome.skipped_tier
        );
    }
    println!(
        "  {} sequence {} · {} blob(s) · {} upload(s)",
        label("index"),
        outcome.index.pointer().sequence,
        outcome.blobs,
        outcome.uploads.len()
    );
    println!(
        "  {} expires {} (unix)",
        label("validity"),
        outcome.index.body().expires
    );
    println!("  {} {}", label("key id"), outcome.index.pointer().key_id);
    println!("  {} {}", label("public key"), outcome.public_key);
    println!("  {} {}", label("staging"), outcome.out_dir.display());
    println!(
        "  {} {}",
        label("identity"),
        outcome.publisher_state.display()
    );
    if outcome.identity_created {
        println!(
            "  {} new publisher identity created; keep the publisher state directory private \
             and persistent",
            util::warn(util::GLYPH_WARN)
        );
    }
    if args.dry_run {
        println!(
            "  {} staged only (dry run; no PUT/POST/DELETE, no publisher state update)",
            label("upload")
        );
    } else {
        let report = remote::upload(&remote::UploadRequest {
            sink: &sink,
            uploads: &outcome.uploads,
            current: current.as_ref(),
        })?;
        remote::record_publish_state(&outcome, report.pointer_etag.clone())?;
        println!(
            "  {} {} uploaded · {} already present · {}",
            label("upload"),
            report.uploaded,
            report.skipped,
            util::green(&util::human_bytes(report.bytes))
        );
    }
    let reader_url = match args.reader_url.as_deref() {
        Some(raw) => settings::normalize_remote_url(raw)?,
        None => outcome.url.clone(),
    };
    println!();
    println!("  {}", util::dim("handoff for readers:"));
    println!(
        "  epicenter setup --remote-url '{}' --remote-key '{}' --remote-tier {}",
        reader_url,
        outcome.public_key,
        outcome.tier.as_str()
    );
    println!(
        "  {}",
        util::dim(
            "objects upload as blobs → index body → publisher.json → index.json last; \
             the local staging tree remains available for inspection"
        )
    );
    Ok(())
}

fn detect_source_commit(explicit: Option<&str>) -> Result<String> {
    if let Some(value) = explicit.map(str::trim).filter(|value| !value.is_empty()) {
        return Ok(value.to_string());
    }
    for name in [
        "EPICENTER_SOURCE_COMMIT",
        "GITHUB_SHA",
        "CI_COMMIT_SHA",
        "CI_COMMIT_ID",
        "BUILD_SOURCEVERSION",
    ] {
        if let Ok(value) = std::env::var(name) {
            let value = value.trim();
            if !value.is_empty() {
                return Ok(value.to_string());
            }
        }
    }
    if let Ok(mut git) = util::command_for("git")
        && let Ok(output) = git.args(["rev-parse", "HEAD"]).output()
        && output.status.success()
    {
        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !value.is_empty() {
            return Ok(value);
        }
    }
    anyhow::bail!(
        "publisher source commit is unknown; pass `--source-commit <sha>` or set \
         GITHUB_SHA/CI_COMMIT_SHA"
    )
}

fn detect_ci_job(explicit: Option<&str>) -> String {
    if let Some(value) = explicit.map(str::trim).filter(|value| !value.is_empty()) {
        return value.to_string();
    }
    for name in [
        "EPICENTER_CI_JOB",
        "CI_JOB_URL",
        "GITHUB_RUN_URL",
        "BUILD_BUILDURI",
    ] {
        if let Ok(value) = std::env::var(name) {
            let value = value.trim();
            if !value.is_empty() {
                return value.to_string();
            }
        }
    }
    String::new()
}

pub(super) fn cmd_fetch(args: &FetchArgs, settings: &settings::Settings) -> Result<()> {
    let policy = settings.remote()?;
    anyhow::ensure!(
        policy.enabled,
        "no remote endpoint configured; set `[remote] url` and `publisher_key`"
    );
    let root = config::cache_root()?;
    let store = vault::store_root(&root);
    let cwd = std::env::current_dir()?;
    let packages = lockfile::LockIndex::load(&cwd, None);
    anyhow::ensure!(
        packages.is_some() || args.all,
        "no readable Cargo.lock; rerun with --all to import every compatible unit"
    );
    println!(
        "{}",
        util::heading("epicenter store fetch — verified remote units")
    );
    let source = remote::source_for(&policy)?;
    let report = remote::fetch_and_import(&remote::FetchRequest {
        remote: &policy,
        source: source.as_ref(),
        store_root: &store,
        state_root: None,
        packages: packages.as_ref(),
        selector: None,
        layout: None,
        profile: None,
        unit_filter: args.unit.as_deref(),
        local: None,
        generation: None,
        now: util::now_secs(),
        dry_run: args.dry_run,
    })?;
    println!(
        "  {} sequence {} · {} · tier {}",
        label("index"),
        report.sequence,
        report.key_id,
        report.tier
    );
    if let Some(warning) = &report.warning {
        println!("  {} {}", util::warn(util::GLYPH_WARN), warning);
    }
    if let Some(reason) = &report.fallback {
        anyhow::bail!("remote fetch failed: {reason}");
    }
    println!(
        "  {} {} unit(s) · {} file(s) · {}",
        label(if args.dry_run { "found" } else { "imported" }),
        if args.dry_run {
            report.candidates
        } else {
            report.imported
        },
        report.files,
        util::green(&util::human_bytes(report.bytes))
    );
    if report.skipped > 0 {
        println!("  {} {} unit(s)", label("skipped"), report.skipped);
    }
    if let Some(cache_store) = &report.cache_store {
        println!(
            "  {} {} (main store is read-only)",
            label("cache"),
            cache_store.display()
        );
    }
    if args.dry_run {
        println!(
            "  {}",
            util::dim("dry run — pointer/body verified, nothing written")
        );
    }
    Ok(())
}

fn print_remote_summary(report: &remote::FetchReport) {
    if report.disabled {
        return;
    }
    if let Some(warning) = &report.warning {
        println!("  {} {}", util::warn(util::GLYPH_WARN), warning);
    }
    if let Some(reason) = &report.fallback {
        println!(
            "  {} skipped: {reason}",
            util::dim(&format!("{:<13}", "remote"))
        );
        return;
    }
    println!(
        "  {} {} unit(s) · {} file(s) · {}{}",
        label("remote"),
        report.imported,
        report.files,
        util::green(&util::human_bytes(report.bytes)),
        if report.cache_store.is_some() {
            util::dim("  (cache store)")
        } else {
            String::new()
        }
    );
}

pub(super) fn cmd_restore(
    link: settings::LinkPolicy,
    into: Option<&std::path::Path>,
    unit: Option<&str>,
    no_remote: bool,
    dry_run: bool,
    remote: Option<&settings::RemotePolicy>,
) -> Result<()> {
    if no_remote {
        println!(
            "  {} disabled by --no-remote",
            util::dim(&format!("{:<13}", "remote"))
        );
    }
    let root = config::cache_root()?;
    let view = into
        .map(std::path::Path::to_path_buf)
        .unwrap_or(root.clone());
    // ensure view dir is not a symlink/reparse point
    metadata_nofollow(&view)?;
    if into.is_none() && root.is_dir() {
        util::check_private_dir(&root, util::Privacy::Repair)?;
    }
    if dry_run {
        println!(
            "{}",
            util::heading(&format!(
                "epicenter restore — DRY RUN (nothing is linked) → {}",
                view.display()
            ))
        );
    } else {
        println!(
            "{}",
            util::heading(&format!("epicenter restore — vault → {}", view.display()))
        );
    }
    let store = vault::store_root(&config::cache_root()?);
    // ensure store is not a symlink/reparse point
    metadata_nofollow(&store)?;
    let packages = std::env::current_dir()
        .ok()
        .and_then(|cwd| lockfile::LockIndex::load(&cwd, None));
    if packages.is_none() {
        println!(
            "  {} {}",
            label("lock"),
            util::dim("no readable Cargo.lock; seeding without a lock filter")
        );
    }
    let mut remote_fetch: Option<remote::FetchReport> = None;
    if dry_run {
        if remote.is_some_and(|policy| policy.enabled) {
            println!(
                "  {} skipped in --dry-run (nothing is fetched)",
                util::dim(&format!("{:<13}", "remote"))
            );
        }
    } else if let Some(policy) = remote.filter(|policy| policy.enabled) {
        if packages.is_none() {
            println!(
                "  {} skipped: no readable Cargo.lock",
                util::dim(&format!("{:<13}", "remote"))
            );
        } else {
            match remote::source_for(policy) {
                Ok(source) => {
                    let request = remote::FetchRequest {
                        remote: policy,
                        source: source.as_ref(),
                        store_root: &store,
                        state_root: None,
                        packages: packages.as_ref(),
                        selector: None,
                        layout: None,
                        profile: None,
                        unit_filter: unit,
                        local: None,
                        generation: None,
                        now: util::now_secs(),
                        dry_run: false,
                    };
                    match remote::fetch_and_import(&request) {
                        Ok(report) => {
                            print_remote_summary(&report);
                            remote_fetch = Some(report);
                        }
                        Err(err) => println!(
                            "  {} skipped: {err:#}",
                            util::dim(&format!("{:<13}", "remote"))
                        ),
                    }
                }
                Err(err) => println!(
                    "  {} skipped: {err:#}",
                    util::dim(&format!("{:<13}", "remote"))
                ),
            }
        }
    }
    let mut report = vault::restore_with(
        &view,
        &store,
        unit,
        packages.as_ref(),
        None,
        None,
        None,
        dry_run,
        link,
    )?;
    if let Some(cache_store) = remote_fetch
        .as_ref()
        .and_then(|report| report.cache_store.as_deref())
    {
        let overlay = vault::restore_with(
            &view,
            cache_store,
            unit,
            packages.as_ref(),
            None,
            None,
            None,
            dry_run,
            link,
        )?;
        report.merge_secondary(overlay);
        report.note = None;
    }
    println!("  {} {}", label("parity"), report.parity);
    if let Some(note) = &report.note {
        println!("  {} {note}", util::info(util::GLYPH_INFO));
        return Ok(());
    }
    println!(
        "  {} {} unit(s) · {} file(s) · {}",
        label(if dry_run { "would link" } else { "linked" }),
        report.units_linked,
        report.files_linked,
        util::green(&util::human_bytes(report.bytes))
    );
    if report.files_copied > 0 {
        println!(
            "  {} {} file(s) copied and stamped (fingerprint state and build trees — cargo rewrites these in place)",
            label("copied"),
            report.files_copied
        );
    }
    if report.units_already > 0 {
        println!(
            "  {} {} unit(s) already fresh here",
            label("already"),
            report.units_already
        );
    }
    if report.files_existing > 0 {
        println!(
            "  {} {} file(s) left untouched",
            label("existing"),
            report.files_existing
        );
    }
    if report.errors > 0 {
        println!(
            "  {} {} (see messages above)",
            label("errors"),
            util::fail(&report.errors.to_string())
        );
    }
    if report.fatal_errors > 0 {
        anyhow::bail!(
            "restore refused {} unverified file(s) — refusing to report success",
            report.fatal_errors
        );
    }
    Ok(())
}
