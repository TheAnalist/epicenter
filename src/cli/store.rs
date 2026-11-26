use anyhow::Result;

use epicenter_cli::util::metadata_nofollow;
use epicenter_cli::{config, exec, status, util, vault};

use super::args::EvictArgs;
use super::label;

pub(super) fn cmd_evict(args: &EvictArgs) -> Result<()> {
    let opts = epicenter_cli::evict::Options {
        unit: args.unit.as_deref(),
        stale: args.stale,
        rustc_key: args.rustc_key.as_deref(),
        generation: args.generation.as_deref(),
        husks: args.husks,
        older_than: args.older_than.as_deref(),
        work_dirs: args.work_dirs,
        work_dir: args.work_dir.as_deref(),
        work: args.work.as_deref(),
        crate_name: args.crate_name.as_deref(),
        tier: args.tier,
        force: args.force,
        delete: super::confirmed_delete(args.dry_run, args.yes, args.y),
    };
    epicenter_cli::evict::run(&config::cache_root()?, &opts)
}

pub(super) fn cmd_harvest(
    unit: Option<&str>,
    dry_run: bool,
    no_compress: bool,
    trusted: bool,
) -> Result<()> {
    let root = config::cache_root()?;
    if !root.is_dir() {
        println!(
            "no shared cache at {} — build something first",
            root.display()
        );
        return Ok(());
    }
    if dry_run {
        println!(
            "{}",
            util::heading("epicenter harvest — DRY RUN (nothing is written)")
        );
    } else {
        println!(
            "{}",
            util::heading("epicenter harvest — shared build dir → vault")
        );
    }
    let trust = if trusted {
        vault::HarvestTrust::Trusted("--trusted")
    } else {
        vault::HarvestTrust::Recorded
    };
    let report = vault::harvest_with_trust(
        &root,
        &vault::store_root(&root),
        unit,
        dry_run,
        None,
        None,
        !no_compress,
        trust,
    )?;
    println!("  {} {}", label("parity"), report.parity);
    if let Some(reason) = &report.trusted {
        println!(
            "  {} signed in trusted-builder mode ({reason})",
            util::warn(util::GLYPH_WARN)
        );
    }
    if let Some(note) = &report.note {
        println!("  {} {note}", util::warn(util::GLYPH_WARN));
        return Ok(());
    }
    println!(
        "  {} {} unit(s) · {} file(s) · {}",
        label(if dry_run { "would store" } else { "stored" }),
        report.stored,
        report.files,
        util::green(&util::human_bytes(report.bytes))
    );
    if report.refreshed > 0 {
        println!(
            "  {} {} unit(s) with new content for an existing group",
            label("refreshed"),
            report.refreshed
        );
    }
    if report.unchanged > 0 {
        println!("  {} {} unit(s)", label("already stored"), report.unchanged);
    }
    if report.skipped_stale > 0 {
        println!(
            "  {} {} unit(s) not built by the installed toolchain",
            label("skipped"),
            report.skipped_stale
        );
    }
    if report.skipped_incomplete > 0 {
        println!(
            "  {} {} unit(s) incomplete (no complete Cargo fingerprint or no artifacts to store)",
            label("skipped"),
            report.skipped_incomplete
        );
    }
    if report.stored > 0 && !dry_run {
        println!();
        println!("→ `epicenter vault` shows the store · `epicenter verify` audits it");
    }
    Ok(())
}

pub(super) fn cmd_vault() -> Result<()> {
    let root = config::cache_root()?;
    let store = vault::store_root(&root);
    // A store that has never been harvested is simply empty; a symlink or
    // reparse point is still refused by the no-follow probe.
    util::probe(&store, "store")?;
    println!(
        "{}",
        util::heading("epicenter vault — durable store of Cargo unit groups")
    );
    println!("  {} {}", label("store"), store.display());
    println!(
        "  {} {}",
        label("view"),
        util::dim(&format!(
            "{} (the shared build dir — disposable, rebuildable from the store)",
            root.display()
        ))
    );

    let generations = vault::generations(&store)?;
    if generations.is_empty() {
        println!();
        println!(
            "  {} the vault is empty — run `epicenter harvest` after a build",
            util::info(util::GLYPH_INFO)
        );
    } else {
        println!();
        println!("  {}", util::green("generations"));
        for generation in &generations {
            let marker = if generation.active {
                util::green("[active]")
            } else {
                util::dim("[inactive]")
            };
            println!("    {}  {marker}", generation.parity);
            let mut facts = vec![
                format!("{} unit(s)", generation.units),
                format!("{} file(s)", generation.files),
                util::human_bytes(generation.bytes),
            ];
            if generation.linked > 0 {
                facts.push(format!("{} linked into views", generation.linked));
            }
            if let Some(updated) = generation.updated.filter(|updated| *updated > 0) {
                let stamp = std::time::UNIX_EPOCH + std::time::Duration::from_secs(updated);
                facts.push(format!("harvested {}", util::human_age(stamp)));
            }
            println!("      {}", util::dim(&facts.join(" · ")));
        }
    }

    let store_bytes: u64 = generations.iter().map(|generation| generation.bytes).sum();
    let store_files: usize = generations.iter().map(|generation| generation.files).sum();
    println!();
    println!("  {}", util::green("tiers"));
    println!(
        "    {:<14} {:>10} · {} file(s) across {} generation(s)",
        "store (vault)",
        util::human_bytes(store_bytes),
        store_files,
        generations.len()
    );
    if root.is_dir() {
        let view = status::summarize(&root)?;
        println!(
            "    {:<14} {:>10} · {} file(s) — disposable view",
            "build (view)",
            util::human_bytes(view.total_bytes),
            view.total_files
        );
    }
    let work = exec::work_tier(&root)?;
    if work.dirs > 0 {
        println!(
            "    {:<14} {:>10} · {} job dir(s) · last activity {} — `evict --work-dirs` collects them",
            "work (views)",
            util::human_bytes(work.bytes),
            work.dirs,
            work.newest
                .map(util::human_age)
                .unwrap_or_else(|| "?".into())
        );
    }
    Ok(())
}

pub(super) fn cmd_verify() -> Result<()> {
    let root = config::cache_root()?;
    let store = vault::store_root(&root);
    metadata_nofollow(&store)?;
    println!("{}", util::heading("epicenter verify — vault audit"));
    let reports = vault::verify(&store)?;
    let mut failed = false;
    if reports.is_empty() {
        println!(
            "  {} no generations to audit — run `epicenter harvest` after a build",
            util::info(util::GLYPH_INFO)
        );
    }
    for report in &reports {
        if !report.is_clean() {
            failed = true;
        }
        println!();
        println!("  {}", util::dim(&report.parity));
        if report.is_clean() {
            println!(
                "    {} {} unit(s) · {} file(s) · {} — sizes, stamps and hashes match the manifest",
                util::green(util::GLYPH_PASS),
                report.units,
                report.files,
                util::green(&util::human_bytes(report.bytes))
            );
        } else {
            println!(
                "    {} {} unit(s) · {} file(s) · {} — {} problem(s)",
                util::fail(util::GLYPH_FAIL),
                report.units,
                report.files,
                util::human_bytes(report.bytes),
                report.problems.len()
            );
            for problem in report.problems.iter().take(10) {
                println!("      {} {problem}", util::fail(util::GLYPH_FAIL));
            }
            if report.problems.len() > 10 {
                println!(
                    "      {} … and {} more",
                    util::dim(""),
                    report.problems.len() - 10
                );
            }
        }
        for warning in report.warnings.iter().take(10) {
            println!("      {} {warning}", util::warn(util::GLYPH_WARN));
        }
        if report.warnings.len() > 10 {
            println!(
                "      {} … and {} more",
                util::dim(""),
                report.warnings.len() - 10
            );
        }
        if !report.ordering.is_empty() {
            println!(
                "      {} {} unit(s) older than a dependency — cargo recompiles them after a restore:",
                util::warn(util::GLYPH_WARN),
                report.ordering.len()
            );
            for line in report.ordering.iter().take(5) {
                println!("      {} {line}", util::dim(""));
            }
            if report.ordering.len() > 5 {
                println!(
                    "      {} … and {} more",
                    util::dim(""),
                    report.ordering.len() - 5
                );
            }
        }
    }
    if failed {
        anyhow::bail!("vault verification found problems (see ✕ above)");
    }
    // Views are disposable by contract, so they are not vault state to audit;
    // name them when they exist instead of staying silently quiet about them.
    let work = exec::work_tier(&root)?;
    if work.dirs > 0 {
        println!();
        println!(
            "  {} {} job dir(s) under work/ are disposable views, not vault state:",
            util::info(util::GLYPH_INFO),
            work.dirs
        );
        for info in work.entries.iter().take(10) {
            println!(
                "      {:<40} {:>9} · {:>4} file(s)  {:>10} old",
                info.name,
                util::human_bytes(info.bytes),
                info.files,
                info.newest
                    .map(util::human_age)
                    .unwrap_or_else(|| "?".into())
            );
        }
        if work.entries.len() > 10 {
            println!(
                "      {} … and {} more",
                util::dim(""),
                work.entries.len() - 10
            );
        }
        println!(
            "    {}",
            util::dim(
                "collect by age with `epicenter evict --work-dirs`, or remove one now with `epicenter evict --work-dir <name>`"
            )
        );
    }
    Ok(())
}
