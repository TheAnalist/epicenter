use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};

use epicenter_cli::util::metadata_nofollow;
use epicenter_cli::{config, doctor, exec, prune, settings, status, util, vault};

use super::args::{CompactArgs, DoctorArgs, OverlapArgs, PruneArgs, StatusArgs};

pub(super) fn cmd_status(args: &StatusArgs) -> Result<()> {
    let root = config::cache_root()?;
    if let Some(unit) = &args.unit {
        return epicenter_cli::who::explain(&root, unit);
    }
    if args.units {
        return epicenter_cli::who::run(&root, args.filter.as_deref());
    }
    if args.json {
        if !root.is_dir() {
            println!(
                "{}",
                serde_json::json!({"root": root.display().to_string(), "exists": false})
            );
            return Ok(());
        }
        let summary = status::summarize(&root)?;
        let oldest = summary
            .oldest
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs());
        let payload = serde_json::json!({
            "root": summary.root.display().to_string(),
            "exists": true,
            "bytes": summary.total_bytes,
            "files": summary.total_files,
            "linked_files": summary.linked_files,
            "oldest_unix": oldest,
            "dirs": summary
                .dirs
                .iter()
                .map(|dir| serde_json::json!({
                    "name": dir.name,
                    "bytes": dir.bytes,
                    "files": dir.files,
                }))
                .collect::<Vec<_>>(),
            "top_units": summary
                .top_units
                .iter()
                .map(|(unit, bytes)| serde_json::json!({
                    "unit": unit,
                    "bytes": bytes,
                }))
                .collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }
    if !root.is_dir() {
        println!("no shared cache yet at {}", root.display());
        println!("run `epicenter setup` to create it");
        return Ok(());
    }
    let summary = status::summarize(&root)?;

    println!("{}", util::heading("epicenter status — shared build cache"));
    println!(
        "  {} {}",
        util::dim(&format!("{:<14}", "location")),
        summary.root.display()
    );
    let linked = if summary.linked_files > 0 {
        format!(" · {} hard-linked", summary.linked_files)
    } else {
        String::new()
    };
    println!(
        "  {} {} in {} files{}",
        util::dim(&format!("{:<14}", "total")),
        util::green(&util::human_bytes(summary.total_bytes)),
        summary.total_files,
        util::dim(&linked)
    );
    if let Some(oldest) = summary.oldest {
        println!(
            "  {} {} old",
            util::dim(&format!("{:<14}", "oldest unit")),
            util::human_age(oldest)
        );
    }
    println!();
    println!("  {}", util::green("by directory"));
    for dir in &summary.dirs {
        println!(
            "    {:<14} {:>10}  {}",
            dir.name,
            util::human_bytes(dir.bytes),
            util::dim(&format!("{:>6} files", dir.files))
        );
    }
    if !summary.top_units.is_empty() {
        println!();
        println!("  {}", util::green("largest units"));
        for (key, bytes) in &summary.top_units {
            println!("    {:<44} {:>10}", key, util::human_bytes(*bytes));
        }
    }
    Ok(())
}

pub(super) fn cmd_prune(args: &PruneArgs) -> Result<()> {
    let duration = util::parse_duration(&args.older_than)?;
    let cutoff = SystemTime::now()
        .checked_sub(duration)
        .context("computing cutoff time")?;
    let root = config::cache_root()?;
    if !root.is_dir() {
        println!("no shared cache at {} — nothing to prune", root.display());
        return Ok(());
    }
    let delete = !args.dry_run && args.yes || args.y;
    let opts = prune::Options {
        keep_latest: args.keep_latest,
        incremental: args.incremental,
    };
    if !delete {
        println!(
            "{}",
            util::heading(
                "epicenter prune — DRY RUN (nothing is deleted; pass -y or --yes to delete for real)"
            )
        );
    } else {
        println!("{}", util::heading("epicenter prune — deleting"));
    }
    let report = prune::prune_with(&root, cutoff, delete, &opts)?;
    match args.keep_latest {
        Some(keep) => println!(
            "  {} newest {} group(s) per package/kind",
            util::dim(&format!("{:<13}", "retention")),
            keep
        ),
        None => println!(
            "  {} units untouched for more than {}",
            util::dim(&format!("{:<13}", "threshold")),
            args.older_than
        ),
    }
    if args.incremental {
        println!(
            "  {} incremental state only",
            util::dim(&format!("{:<13}", "scope"))
        );
    }
    println!(
        "  {} {} unit(s) · {} file(s) · {} actually freed · {} links released",
        util::dim(&format!("{:<13}", "would remove")),
        report.removed_groups,
        report.files_freed,
        util::green(&util::human_bytes(report.bytes_freed)),
        util::human_bytes(report.bytes_released)
    );
    println!(
        "  {} {} kept",
        util::dim(&format!("{:<13}", "recent units")),
        report.kept_groups
    );
    if report.errors > 0 {
        println!(
            "  {} {} (see messages above)",
            util::dim(&format!("{:<13}", "errors")),
            util::fail(&report.errors.to_string())
        );
    }
    Ok(())
}

pub(super) fn cmd_overlap(args: &OverlapArgs) -> Result<()> {
    let build = config::cache_root()?;
    let store = vault::store_root(&build);
    metadata_nofollow(&store)?;
    let active = match epicenter_cli::who::active_unit_names(&build) {
        Ok(active) => active,
        Err(err) => {
            eprintln!(
                "  {} could not read the active build view: {err:#}",
                util::warn(util::GLYPH_WARN)
            );
            Default::default()
        }
    };
    let packages = vault::overlap(&store, &active)?;

    if args.json {
        let report: Vec<_> = packages
            .iter()
            .map(|package| {
                serde_json::json!({
                    "package": &package.package,
                    "profile": &package.profile,
                    "units": package.units,
                    "hashes": package.hashes,
                    "identical": package.identical,
                    "active": package.active,
                    "bytes": package.bytes,
                    "unique_bytes": package.unique_bytes,
                    "generations": package.generations,
                    "unit_rows": package
                        .unit_rows
                        .iter()
                        .map(|unit| serde_json::json!({
                            "name": &unit.name,
                            "hash": &unit.hash,
                            "generation": &unit.generation,
                            "stamp": unit.stamp,
                            "bytes": unit.bytes,
                            "active": unit.active,
                        }))
                        .collect::<Vec<_>>(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!(
        "{}",
        util::heading("epicenter store overlap — package/profile variants")
    );
    let multi: Vec<&vault::OverlapPackage> = packages
        .iter()
        .filter(|package| package.units > 1)
        .collect();
    if multi.is_empty() {
        println!("  no package has more than one stored unit variant");
        return Ok(());
    }

    let width = multi
        .iter()
        .map(|package| package.package.len())
        .max()
        .unwrap_or(12)
        .clamp(12, 48);
    let header = format!(
        "{:<width$} {:<10} {:>6} {:>8} {:>9} {:>8} {:>10} {:>10} {:>5}",
        "package",
        "profile",
        "units",
        "variants",
        "same hash",
        "active",
        "nominal",
        "unique",
        "gens"
    );
    println!("  {}", util::dim(&header));
    for package in &multi {
        let nominal = format!("{:>10}", util::human_bytes(package.bytes));
        let unique = format!("{:>10}", util::human_bytes(package.unique_bytes));
        println!(
            "  {:<width$} {:<10} {:>6} {:>8} {:>9} {:>8} {} {} {:>5}",
            package.package,
            package.profile,
            package.units,
            package.hashes,
            package.identical,
            package.active,
            util::green(&nominal),
            unique,
            package.generations
        );
    }

    if args.detail {
        for package in &multi {
            println!();
            println!(
                "  {}",
                util::dim(&format!("{} / {}", package.package, package.profile))
            );
            for unit in &package.unit_rows {
                let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(unit.stamp);
                let generation: String = unit.generation.chars().take(18).collect();
                let marker = if unit.active {
                    util::green("active")
                } else {
                    util::dim("      ")
                };
                println!(
                    "    {:<42} {:<16} {:>10}  {:>10}  {:<18} {}",
                    unit.name,
                    unit.hash,
                    util::human_bytes(unit.bytes),
                    util::human_age(at),
                    generation,
                    marker
                );
            }
        }
    }

    println!();
    let identical: usize = packages.iter().map(|package| package.identical).sum();
    if identical > 0 {
        println!(
            "  {} {} unit(s) share a fingerprint hash — `epicenter store compact` links only truly identical bytes",
            util::info(util::GLYPH_INFO),
            identical
        );
    }
    println!(
        "  {}",
        util::dim("different hashes = feature/profile/flag variants; they cannot be merged")
    );
    if packages
        .iter()
        .any(|package| package.active < package.units)
    {
        println!(
            "  {}",
            util::dim("inactive variants can be evicted by hash — --detail lists them")
        );
    }
    Ok(())
}

pub(super) fn cmd_compact(args: &CompactArgs) -> Result<()> {
    let store = vault::store_root(&config::cache_root()?);
    let report = vault::compact(&store, args.generation.as_deref(), args.dry_run)?;
    println!(
        "{}",
        util::heading("epicenter store compact — shared inodes")
    );
    if report.generations == 0 {
        println!("  no vault generations to compact");
        return Ok(());
    }
    if report.groups == 0 {
        println!("  nothing to compact — no duplicate files found");
        if report.already_shared > 0 {
            println!("  {} file(s) already share an inode", report.already_shared);
        }
        if report.skipped > 0 {
            println!(
                "  {} file(s) skipped (mode, type, or link error)",
                report.skipped
            );
        }
        return Ok(());
    }
    println!(
        "  {} group(s) · {} file(s) {} · {} saved",
        report.groups,
        report.linked,
        if args.dry_run { "to link" } else { "linked" },
        util::green(&util::human_bytes(report.bytes_saved))
    );
    if report.already_shared > 0 {
        println!("  {} file(s) already share an inode", report.already_shared);
    }
    if report.skipped > 0 {
        println!(
            "  {} file(s) skipped (mode, type, or link error)",
            report.skipped
        );
    }
    if args.dry_run {
        println!(
            "  {}",
            util::dim("dry run — rerun without --dry-run to link")
        );
    } else {
        println!(
            "  {}",
            util::dim("run `epicenter store verify` to audit the result")
        );
    }
    Ok(())
}

/// `epicenter doctor` printing: group checks under their section header,
/// icons colored by severity.
pub(super) fn cmd_doctor(args: &DoctorArgs, settings: &settings::Settings) -> Result<()> {
    let mut checks = doctor::run()?;
    let (policy, profile) = doctor::policy_checks(settings)?;
    checks.extend(policy);
    let failed = checks
        .iter()
        .any(|check| matches!(check.level, doctor::Level::Fail));

    if args.json {
        let payload = serde_json::json!({
            "checks": checks
                .iter()
                .map(|check| serde_json::json!({
                    "section": check.section,
                    "level": check.level.as_str(),
                    "message": &check.message,
                }))
                .collect::<Vec<_>>(),
            "profile": profile.to_json(),
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        let mut current: Option<&'static str> = None;
        for check in &checks {
            if current != Some(check.section) {
                if current.is_some() {
                    println!();
                }
                println!("{}", util::heading(&format!("── {} ──", check.section)));
                current = Some(check.section);
            }
            let icon = match check.level {
                doctor::Level::Pass => util::green(check.level.icon()),
                doctor::Level::Warn => util::warn(check.level.icon()),
                doctor::Level::Fail => util::fail(check.level.icon()),
                doctor::Level::Info => util::info(check.level.icon()),
            };
            println!("  {icon} {}", check.message);
        }
    }
    if failed {
        anyhow::bail!("doctor found failures (see ✕ above)");
    }
    Ok(())
}

/// `exec` hands the child's exit code to the caller unchanged, so a failing
/// job exits the process directly — the wrapper must not turn a failure into
/// a success. Nothing is buffered at this point: the command owns stdout and
/// epicenter's frame owns stderr.
fn exec_incremental(settings: &settings::Settings) -> Option<bool> {
    let (preset, _) = settings.preset();
    let (effective, _, _) = settings.effective_preset();
    let wrapper = config::cargo_configured_in("build", "rustc-wrapper")
        .ok()
        .flatten()
        .is_some();
    match (preset, effective) {
        (settings::Preset::Ci, _) => Some(false),
        // A wrapper cache and incremental state fight; never force it on.
        (settings::Preset::Dev, _) if wrapper => None,
        (settings::Preset::Dev, _) => Some(true),
        (settings::Preset::Auto, settings::EffectivePreset::Ci) => Some(false),
        (settings::Preset::Auto, _) => None,
    }
}

pub(super) fn cmd_exec(
    settings: &settings::Settings,
    id: Option<&str>,
    cwd: Option<PathBuf>,
    harvest: bool,
    compress: bool,
    no_remote: bool,
    work_root: Option<&Path>,
    reuse: bool,
    target_dir: Option<&str>,
    rm: bool,
    command: &[String],
) -> Result<()> {
    let remote = if no_remote {
        None
    } else {
        match settings.remote() {
            Ok(policy) => Some(policy),
            Err(err) => {
                eprintln!(
                    "  {} remote policy ignored: {err:#}",
                    util::warn(util::GLYPH_WARN)
                );
                None
            }
        }
    };
    let root = config::cache_root()?;
    let cargo_home = match settings.cargo_home()? {
        (path, settings::Source::Global) => Some(path),
        _ => None,
    };
    let work_root = match work_root {
        Some(path) => {
            if path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            {
                anyhow::bail!("--work-root must not contain `..`");
            }
            let expanded = epicenter_cli::util::expand_tilde(&path.to_string_lossy())?;
            if expanded.is_absolute() {
                expanded
            } else {
                let base = match cwd.as_deref() {
                    Some(dir) if dir.is_absolute() => dir.to_path_buf(),
                    Some(dir) => std::env::current_dir()?.join(dir),
                    None => std::env::current_dir()?,
                };
                base.join(expanded)
            }
        }
        None => exec::work_root(&root),
    };
    let opts = exec::Options {
        job_id: id,
        cwd,
        harvest_back: harvest,
        compress,
        remove_on_success: rm,
        reuse,
        target_dir,
        incremental: exec_incremental(settings),
        link: settings.link()?.0,
        cargo_home: cargo_home.as_deref(),
        no_remote,
        remote: remote.as_ref(),
        command,
    };
    let code = exec::run(&vault::store_root(&root), &work_root, &opts)?;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}
