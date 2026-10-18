//! `epicenter` — one central build cache for every Rust project on this machine.
//!
//! CLI entry point: argument definitions and dispatch into the library
//! modules (`config`, `doctor`, `evict`, `exec`, `prune`, `status`, `vault`,
//! `who`).

use std::io::Write;
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use epicenter_cli::{config, doctor, exec, prune, status, util, vault};

#[derive(Parser)]
#[command(
    name = "epicenter",
    version,
    about = "The state layer for Cargo builds: shared cache, durable vault, per-job dirs"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Point Cargo's global build-dir at the shared cache.
    Setup {
        /// Use this directory for the shared cache instead of the default
        /// `{cargo-cache-home}/epicenter/build`: an absolute path, `~/…`, a
        /// relative path, or a cargo template like `{cargo-cache-home}/custom`.
        /// Recorded as the `[build] build-dir` key in ~/.cargo/config.toml.
        #[arg(long)]
        cache_root: Option<String>,
        /// Drop any custom cache root and return to the default template.
        #[arg(long, conflicts_with = "cache_root")]
        use_default: bool,
        /// Also wire a rustc-wrapper for compile-result caching: e.g. `kache` or `sccache`.
        #[arg(long)]
        with_wrapper: Option<String>,
        /// Remove an existing rustc-wrapper setting.
        #[arg(long, conflicts_with = "with_wrapper")]
        without_wrapper: bool,
    },
    /// Show what the shared cache currently holds.
    Status,
    /// Delete stale intermediate artifacts.
    /// Safe: Cargo detects missing artifacts and rebuilds whatever it needs.
    Prune {
        /// Remove units untouched for this long, e.g. "30d", "2w", "12h".
        #[arg(long, default_value = "30d")]
        older_than: String,
        /// Show what would be removed, without removing anything.
        #[arg(long)]
        dry_run: bool,
        /// Actually delete (without this flag nothing is deleted).
        #[arg(long)]
        yes: bool,
        /// Actually delete (without this flag nothing is deleted).
        #[arg(short)]
        y: bool,
    },
    /// Sanity-check the setup and print advice.
    Doctor,
    /// Unit ownership forensics over the shared build dir.
    Who {
        /// Filter by package name or dir hash fragment.
        #[arg(long)]
        unit: Option<String>,
    },
    /// Explain one unit in detail: identity, features, deps, artifacts,
    /// staleness reasons.
    Why {
        /// Package name, dir hash, or unit dir name.
        unit: String,
    },
    /// Remove units or stale working dirs deliberately: dry run by default,
    /// `-y` or `--yes` to delete. Current-generation units are protected unless `--force`.
    Evict {
        /// Unit to remove: dir hash fragment or package name.
        #[arg(long)]
        unit: Option<String>,
        /// All units on a stale toolchain generation.
        #[arg(long)]
        stale: bool,
        /// All units whose rustc fingerprint identity matches this (prefix).
        #[arg(long)]
        rustc_key: Option<String>,
        /// Units whose artifacts are already missing (fingerprint husks).
        #[arg(long)]
        husks: bool,
        /// Units untouched for longer than this, e.g. `30d`, `12h`.
        /// With `--work-dirs`: the max age of a job dir (default 7d).
        #[arg(long)]
        older_than: Option<String>,
        /// Collect stale per-job working dirs under `work/` (default: older
        /// than 7 days; a dir a live build has locked is never touched).
        #[arg(long)]
        work_dirs: bool,
        /// Remove ONE job dir now (name, `work/<id>`, or a path under `work/`):
        /// explicit choices bypass the GC age window, and a dir a live build
        /// has locked is refused.
        #[arg(long)]
        work_dir: Option<String>,
        /// Unlink units from ONE view only (`build`, a `work/<id>` job dir,
        /// or a path): a freshness operation — the vault is never touched.
        #[arg(long)]
        work: Option<String>,
        /// Package selector for --work (dashes and underscores both match).
        #[arg(long = "crate")]
        crate_name: Option<String>,
        /// What an eviction touches: `all` (default: store + every view),
        /// `store` (the vault only), or `view` (build dir + job dirs only).
        #[arg(long, value_enum, default_value = "all")]
        tier: epicenter_cli::evict::Tier,
        /// Also include units on the current toolchain generation.
        #[arg(long)]
        force: bool,
        /// Show what would be removed without removing it.
        #[arg(long)]
        dry_run: bool,
        /// Actually delete (without this flag nothing is deleted).
        #[arg(long)]
        yes: bool,
        /// Actually delete (without this flag nothing is deleted).
        #[arg(short)]
        y: bool,
    },
    /// Store built unit groups from the shared build dir into the vault.
    Harvest {
        /// Only units whose name contains this (package or hash fragment).
        #[arg(long)]
        unit: Option<String>,
        /// Show what would be stored, without writing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Hard-link vault unit groups into a working dir
    /// (default: the shared build dir).
    Restore {
        /// Working dir to fill (default: the shared build dir).
        #[arg(long)]
        into: Option<PathBuf>,
        /// Only units whose name contains this (package or hash fragment).
        #[arg(long)]
        unit: Option<String>,
        /// Show what would be linked, without touching any file.
        #[arg(long)]
        dry_run: bool,
    },
    /// Show the vault: generations, sizes, and links into the build view.
    Vault,
    /// Audit the vault: file sizes, canonical stamps, hash contents.
    Verify,
    /// Run a command against a fresh per-job build dir seeded from the vault:
    /// one line for CI jobs and agent sandboxes (`epicenter exec -- cargo test`).
    Exec {
        /// Job id / work-dir name (default: `job-<UTC timestamp>-<pid>`).
        #[arg(long)]
        id: Option<String>,
        /// Directory to run the command in (default: the current directory).
        #[arg(long)]
        cwd: Option<PathBuf>,
        /// Store the units this job produced back into the vault.
        #[arg(long)]
        harvest: bool,
        /// Continue in an existing job dir instead of refusing (restore is
        /// idempotent; a dir a live build holds is still refused).
        #[arg(long)]
        reuse: bool,
        /// Finals dir for fully parallel jobs: bare `--target-dir` uses
        /// `<work dir>/target`; a value selects that path instead (relative
        /// paths resolve against the working directory).
        #[arg(long, num_args = 0..=1, default_missing_value = "job", value_name = "DIR")]
        target_dir: Option<String>,
        /// Remove the work dir after a successful run (kept on failure).
        #[arg(long)]
        rm: bool,
        /// The command to run — everything after the first non-option argument.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

fn main() {
    // Mitigate Broken pipe with number `head`/`less` piping of the binary:
    // print cleanly, exit code 141 (128+13, the SIGPIPE convention), never a
    // backtrace wall.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if info.to_string().contains("Broken pipe") {
            std::process::exit(141);
        }
        default_hook(info);
    }));

    if let Err(err) = run() {
        eprintln!("{}", util::error_block(&err));
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Setup {
            cache_root,
            use_default,
            with_wrapper,
            without_wrapper,
        } => cmd_setup(
            cache_root.as_deref(),
            use_default,
            with_wrapper.as_deref(),
            without_wrapper,
        ),
        Command::Status => cmd_status(),
        Command::Prune {
            older_than,
            dry_run,
            yes,
            y,
        } => cmd_prune(&older_than, dry_run, yes, y),
        Command::Doctor => cmd_doctor(),
        Command::Who { unit } => epicenter_cli::who::run(&config::cache_root()?, unit.as_deref()),
        Command::Why { unit } => epicenter_cli::who::explain(&config::cache_root()?, &unit),
        Command::Evict {
            unit,
            stale,
            rustc_key,
            husks,
            older_than,
            work_dirs,
            work_dir,
            work,
            crate_name,
            tier,
            force,
            dry_run,
            yes,
            y,
        } => {
            let opts = epicenter_cli::evict::Options {
                unit: unit.as_deref(),
                stale,
                rustc_key: rustc_key.as_deref(),
                husks,
                older_than: older_than.as_deref(),
                work_dirs,
                work_dir: work_dir.as_deref(),
                work: work.as_deref(),
                crate_name: crate_name.as_deref(),
                tier,
                force,
                delete: !dry_run && yes || y,
            };
            epicenter_cli::evict::run(&config::cache_root()?, &opts)
        }
        Command::Harvest { unit, dry_run } => cmd_harvest(unit.as_deref(), dry_run),
        Command::Restore {
            into,
            unit,
            dry_run,
        } => cmd_restore(into.as_deref(), unit.as_deref(), dry_run),
        Command::Vault => cmd_vault(),
        Command::Verify => cmd_verify(),
        Command::Exec {
            id,
            cwd,
            harvest,
            rm,
            reuse,
            target_dir,
            command,
        } => cmd_exec(
            id.as_deref(),
            cwd,
            harvest,
            reuse,
            target_dir.as_deref(),
            rm,
            &command,
        ),
    }
}

fn cmd_setup(
    cache_root: Option<&str>,
    use_default: bool,
    with_wrapper: Option<&str>,
    without_wrapper: bool,
) -> Result<()> {
    let mut wrapper_path: Option<PathBuf> = None;
    if let Some(name) = with_wrapper {
        if name.is_empty() || name.contains('/') || name.contains('\\') {
            anyhow::bail!("--with-wrapper wants a plain command name, like `kache`");
        }
        match util::which_path(name) {
            Some(path) => wrapper_path = Some(path),
            None => anyhow::bail!(
                "{name} not found — looked in PATH and in the cargo bin dir \
                 ($CARGO_HOME/bin). Install it first (e.g. `cargo install {name}`), \
                 or put its directory on PATH"
            ),
        }
    }
    let report = config::setup(cache_root, use_default, with_wrapper, without_wrapper)?;
    println!(
        "{} shared cache ready at {}",
        util::green(util::GLYPH_PASS),
        report.root.display()
    );
    println!(
        "{} build-dir:     {}",
        util::green(util::GLYPH_PASS),
        report.build_dir_edit.describe()
    );
    if report.using_override {
        println!(
            "{} cache root:    custom (build-dir in ~/.cargo/config.toml)",
            util::green(util::GLYPH_PASS)
        );
        if let Some(raw) = cache_root {
            println!("                 {}", util::dim(raw));
        }
    } else if use_default {
        println!(
            "{} cache root:    back to the default template (override removed)",
            util::green(util::GLYPH_PASS)
        );
    }
    if report.wrapper_edit.is_some() {
        println!("{} rustc-wrapper: added", util::green(util::GLYPH_PASS));
        // Show where the wrapper binary was discovered — and teach the PATH
        // story when it only lives in the cargo bin dir: cargo spawns the
        // wrapper by NAME at build time, which needs PATH.
        if let Some(name) = with_wrapper {
            if let Some(path) = &wrapper_path {
                println!("  {name} binary: {}", path.display());
                if !util::on_path(name) {
                    println!(
                        "{} {name} is NOT on PATH — add the cargo bin dir (Windows: %CARGO_HOME%\\bin) so cargo can spawn it",
                        util::warn(util::GLYPH_WARN)
                    );
                }
            }
        }
    }
    if let Some(backup) = &report.backup {
        println!(
            "  backup of previous cargo config: {}",
            util::dim(&backup.display().to_string())
        );
    }
    println!();
    println!("→ every `cargo build` on this machine now shares one cache.");
    println!("  Try `epicenter status` after your next build.");
    Ok(())
}

fn cmd_status() -> Result<()> {
    let root = config::cache_root()?;
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
    println!(
        "  {} {} in {} files",
        util::dim(&format!("{:<14}", "total")),
        util::green(&util::human_bytes(summary.total_bytes)),
        summary.total_files
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

fn cmd_prune(older_than: &str, dry_run: bool, yes: bool, y: bool) -> Result<()> {
    let duration = util::parse_duration(older_than)?;
    let cutoff = SystemTime::now()
        .checked_sub(duration)
        .context("computing cutoff time")?;
    let root = config::cache_root()?;
    if !root.is_dir() {
        println!("no shared cache at {} — nothing to prune", root.display());
        return Ok(());
    }
    let delete = !dry_run && yes || y;
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
    let report = prune::prune(&root, cutoff, delete)?;
    println!(
        "  {} units untouched for more than {}",
        util::dim(&format!("{:<13}", "threshold")),
        older_than
    );
    println!(
        "  {} {} unit(s) · {} file(s) · {}",
        util::dim(&format!("{:<13}", "would remove")),
        report.removed_groups,
        report.files_freed,
        util::green(&util::human_bytes(report.bytes_freed))
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

/// `epicenter doctor` printing: group checks under their section header,
/// icons colored by severity.
fn cmd_doctor() -> Result<()> {
    let checks = doctor::run()?;
    let mut current: Option<&'static str> = None;
    for check in checks {
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
    Ok(())
}

/// A dim, aligned label column (13 chars, matching the other commands).
fn label(text: &str) -> String {
    util::dim(&format!("{text:<13}"))
}

/// `exec` hands the child's exit code to the caller unchanged, so a failing
/// job exits the process directly — the wrapper must not turn a failure into
/// a success. Nothing is buffered at this point: the command owns stdout and
/// epicenter's frame owns stderr.
fn cmd_exec(
    id: Option<&str>,
    cwd: Option<PathBuf>,
    harvest: bool,
    reuse: bool,
    target_dir: Option<&str>,
    rm: bool,
    command: &[String],
) -> Result<()> {
    let root = config::cache_root()?;
    let opts = exec::Options {
        job_id: id,
        cwd,
        harvest_back: harvest,
        remove_on_success: rm,
        reuse,
        target_dir,
        command,
    };
    let code = exec::run(&vault::store_root(&root), &exec::work_root(&root), &opts)?;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

fn cmd_harvest(unit: Option<&str>, dry_run: bool) -> Result<()> {
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
    let report = vault::harvest(&root, &vault::store_root(&root), unit, dry_run)?;
    println!("  {} {}", label("parity"), report.parity);
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
            "  {} {} unit(s) incomplete (no artifacts to store)",
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

fn cmd_restore(into: Option<&std::path::Path>, unit: Option<&str>, dry_run: bool) -> Result<()> {
    let root = config::cache_root()?;
    let view = into.map(std::path::Path::to_path_buf).unwrap_or(root);
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
    let report = vault::restore(&view, &store, unit, dry_run)?;
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
    Ok(())
}

fn cmd_vault() -> Result<()> {
    let root = config::cache_root()?;
    let store = vault::store_root(&root);
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

fn cmd_verify() -> Result<()> {
    let root = config::cache_root()?;
    let store = vault::store_root(&root);
    println!("{}", util::heading("epicenter verify — vault audit"));
    let reports = vault::verify(&store)?;
    if reports.is_empty() {
        println!(
            "  {} no generations to audit — run `epicenter harvest` after a build",
            util::info(util::GLYPH_INFO)
        );
    }
    for report in &reports {
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
