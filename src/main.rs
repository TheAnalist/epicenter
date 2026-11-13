//! `epicenter` — the state layer for Cargo builds (CLI entry point).
//!
//! CLI entry point: argument definitions and dispatch into the library
//! modules (`config`, `doctor`, `evict`, `exec`, `prune`, `status`, `vault`,
//! `who`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use epicenter_cli::{config, doctor, exec, paths, profile, prune, settings, status, util, vault};

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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PresetArg {
    Auto,
    Dev,
    Ci,
}

impl From<PresetArg> for settings::Preset {
    fn from(value: PresetArg) -> Self {
        match value {
            PresetArg::Auto => settings::Preset::Auto,
            PresetArg::Dev => settings::Preset::Dev,
            PresetArg::Ci => settings::Preset::Ci,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LinkerArg {
    Auto,
    System,
    Lld,
    Wild,
    Mold,
    Gold,
}

impl From<LinkerArg> for settings::LinkerChoice {
    fn from(value: LinkerArg) -> Self {
        match value {
            LinkerArg::Auto => settings::LinkerChoice::Auto,
            LinkerArg::System => settings::LinkerChoice::System,
            LinkerArg::Lld => settings::LinkerChoice::Lld,
            LinkerArg::Wild => settings::LinkerChoice::Wild,
            LinkerArg::Mold => settings::LinkerChoice::Mold,
            LinkerArg::Gold => settings::LinkerChoice::Gold,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RemoteTierArg {
    Libraries,
    Full,
}

impl From<RemoteTierArg> for settings::RemoteTier {
    fn from(value: RemoteTierArg) -> Self {
        match value {
            RemoteTierArg::Libraries => settings::RemoteTier::Libraries,
            RemoteTierArg::Full => settings::RemoteTier::Full,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum WrapperArg {
    Kache,
    Sccache,
    #[value(name = "none")]
    Off,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DevDebugArg {
    Full,
    Line,
    None,
}

impl From<DevDebugArg> for profile::DevDebug {
    fn from(value: DevDebugArg) -> Self {
        match value {
            DevDebugArg::Full => profile::DevDebug::Full,
            DevDebugArg::Line => profile::DevDebug::Line,
            DevDebugArg::None => profile::DevDebug::None,
        }
    }
}

#[derive(clap::Args)]
struct SetupArgs {
    /// One intent instead of per-knob flags: auto (default), dev, or ci.
    #[arg(long, value_enum)]
    preset: Option<PresetArg>,
    /// Toolchain linker: auto (keep what is configured), system, lld, wild, mold, gold.
    #[arg(long, value_enum)]
    linker: Option<LinkerArg>,
    /// External compile cache: kache, sccache, or none (remove it).
    #[arg(long, value_enum, conflicts_with_all = ["with_wrapper", "without_wrapper"])]
    wrapper: Option<WrapperArg>,
    /// Memory budget for the job cap (e.g. `16GiB`); same as `memory` in
    /// epicenter.toml. A bare integer is MiB.
    #[arg(long, alias = "memory-budget", value_name = "SIZE")]
    memory: Option<String>,
    /// Use this directory for the shared cache instead of the default
    /// `{cargo-cache-home}/epicenter/build`: an absolute path, `~/…`, a
    /// relative path, or a cargo template like `{cargo-cache-home}/custom`.
    #[arg(long)]
    cache_root: Option<String>,
    /// Drop any custom cache root and return to the default template.
    #[arg(long, conflicts_with = "cache_root")]
    use_default: bool,
    /// Local per-VM job-dir root (absolute, `~/…`, or relative). Global-only;
    /// `default` clears the override.
    #[arg(long, value_name = "PATH")]
    work_root: Option<String>,
    /// Global machine-level CARGO_HOME used by `exec`. Must be absolute and
    /// identical on every machine/VM that shares remote units; `default`
    /// clears the override.
    #[arg(long, value_name = "PATH")]
    cargo_home: Option<String>,
    /// Remote endpoint: `https://…` for anonymous reads or
    /// `s3://bucket/prefix` for authenticated S3.
    #[arg(long, value_name = "URL", conflicts_with = "remote_off")]
    remote_url: Option<String>,
    /// Pinned Ed25519 publisher public key, as 64 hex characters or a file
    /// containing it. Obtain it from CI/admin, never from the bucket.
    #[arg(long, value_name = "HEX|FILE", conflicts_with = "remote_off")]
    remote_key: Option<String>,
    /// Remote artifact tier written to the global `[remote]` table.
    #[arg(long, value_enum, conflicts_with = "remote_off")]
    remote_tier: Option<RemoteTierArg>,
    /// Remove the global `[remote]` policy table.
    #[arg(
        long,
        conflicts_with_all = ["remote_url", "remote_key", "remote_tier"]
    )]
    remote_off: bool,
    /// Print the effective policy and the exact config diff; write nothing.
    #[arg(long)]
    dry_run: bool,
    /// Explicitly write the recommended dev/release profile to the workspace
    /// Cargo.toml. Never a normal setup side effect.
    #[arg(long, conflicts_with = "revert")]
    write_profile: bool,
    /// Debug detail for the written dev profile: full, line, or none.
    #[arg(long, value_enum, requires = "write_profile")]
    dev_debug: Option<DevDebugArg>,
    /// After setup, run one `cargo build` and record wall time/RSS for doctor.
    #[arg(long, conflicts_with = "revert")]
    measure: bool,
    /// Restore the newest setup backups (Cargo config + global epicenter.toml).
    #[arg(
        long,
        alias = "revert-config",
        conflicts_with_all = [
            "cache_root",
            "use_default",
            "work_root",
            "cargo_home",
            "remote_url",
            "remote_key",
            "remote_tier",
            "remote_off",
            "preset",
            "linker",
            "wrapper",
            "memory",
            "with_wrapper",
            "without_wrapper",
            "write_profile"
        ]
    )]
    revert: bool,
    /// Legacy form of --wrapper <name> (kept for one release).
    #[arg(long, hide = true, conflicts_with = "without_wrapper")]
    with_wrapper: Option<String>,
    /// Legacy form of --wrapper none (kept for one release).
    #[arg(long, hide = true)]
    without_wrapper: bool,
}

#[derive(clap::Args)]
struct StatusArgs {
    /// Machine-readable summary (not available with --units/--unit).
    #[arg(long, conflicts_with_all = ["units", "unit"])]
    json: bool,
    /// Replace the old `who` table.
    #[arg(long, conflicts_with = "unit")]
    units: bool,
    /// Filter the --units table by package name or dir hash fragment.
    #[arg(long, requires = "units", value_name = "QUERY")]
    filter: Option<String>,
    /// Replace the old `why` explainer.
    #[arg(long, value_name = "NAME")]
    unit: Option<String>,
}

#[derive(clap::Args)]
struct PruneArgs {
    /// Remove units untouched for this long, e.g. "30d", "2w", "12h".
    #[arg(long, default_value = "30d")]
    older_than: String,
    /// Keep the newest N groups per package/kind and remove older duplicates.
    #[arg(long, value_name = "N")]
    keep_latest: Option<usize>,
    /// Only prune incremental state (`incremental/` and `incremental.*`).
    #[arg(long)]
    incremental: bool,
    /// Show what would be removed, without removing anything.
    #[arg(long)]
    dry_run: bool,
    /// Actually delete (without this flag nothing is deleted).
    #[arg(long)]
    yes: bool,
    /// Actually delete (without this flag nothing is deleted).
    #[arg(short)]
    y: bool,
}

#[derive(clap::Args)]
struct OverlapArgs {
    /// Machine-readable report.
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args)]
struct EvictArgs {
    /// Unit to remove: dir hash fragment or package name.
    #[arg(long)]
    unit: Option<String>,
    /// All units on a stale toolchain generation.
    #[arg(long)]
    stale: bool,
    /// All units whose rustc fingerprint identity matches this (prefix).
    #[arg(long)]
    rustc_key: Option<String>,
    /// Delete a whole parity-key vault generation (exact key or a
    /// substring such as `1.97.1`): its units, manifest and lock.
    /// With the default `--tier all`, matching view units are unlinked too.
    #[arg(long)]
    generation: Option<String>,
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
    /// Also include current-generation units matched by bulk selectors
    /// (an explicit `--unit` is deliberate and needs no --force).
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
}

#[derive(clap::Args)]
struct HarvestArgs {
    /// Only units whose name contains this (package or hash fragment).
    #[arg(long)]
    unit: Option<String>,
    /// Store copied artifacts raw; skip gzip blobs.
    #[arg(long)]
    no_compress: bool,
    /// Show what would be stored, without writing anything.
    #[arg(long)]
    dry_run: bool,
}

#[derive(clap::Args)]
struct RestoreArgs {
    /// Working dir to fill (default: the shared build dir).
    #[arg(long)]
    into: Option<PathBuf>,
    /// Only units whose name contains this (package or hash fragment).
    #[arg(long)]
    unit: Option<String>,
    /// Skip remote compatible-unit fetch.
    #[arg(long)]
    no_remote: bool,
    /// Show what would be linked, without touching any file.
    #[arg(long)]
    dry_run: bool,
}

#[derive(clap::Args)]
struct DoctorArgs {
    /// Machine-readable checks plus the effective profile.
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Point Cargo's global state at a preset/linker policy.
    Setup(SetupArgs),
    /// Show what the shared cache currently holds.
    Status(StatusArgs),
    /// Explain the effective profile and audit the setup.
    Doctor(DoctorArgs),
    /// Run a command against a fresh per-job build dir seeded from the vault:
    /// one line for CI jobs and agent sandboxes (`epicenter exec -- cargo test`).
    /// The child's build/target dirs are pinned through environment variables;
    /// project/local build-dir config is not consulted. Registry/network
    /// config still applies. A `cargo +toolchain` child is seeded from that
    /// toolchain's generation, including Cargo's new per-unit build-dir
    /// layout (nightly 1.99+ / 1.100).
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
        /// Store copied artifacts raw instead of gzip blobs.
        #[arg(long)]
        no_compress: bool,
        /// Skip remote compatible-unit fetch for this job.
        #[arg(long)]
        no_remote: bool,
        /// Per-job work dir root; overrides the global `work` policy.
        #[arg(long, value_name = "PATH")]
        work_root: Option<PathBuf>,
        /// Continue in an existing job dir instead of refusing (restore is
        /// idempotent; a dir a live build holds is still refused).
        #[arg(long)]
        reuse: bool,
        /// Finals dir for fully parallel jobs: bare `--target-dir` uses
        /// `<work dir>/target`; a value selects that path instead (relative
        /// paths resolve against the working directory).
        #[arg(long, num_args = 0..=1, default_missing_value = "job", value_name = "DIR")]
        target_dir: Option<String>,
        /// Remove the work dir after the run — success or failure (default: keep it for inspection).
        #[arg(long)]
        rm: bool,
        /// The command to run — everything after the first non-option argument.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Advanced maintenance: vault, verify, prune, evict, harvest, restore.
    Store {
        #[command(subcommand)]
        command: StoreCommand,
    },
    /// Old name for `epicenter store prune` (kept for one release).
    #[command(hide = true)]
    Prune(PruneArgs),
    /// Old name for `epicenter store evict` (kept for one release).
    #[command(hide = true)]
    Evict(EvictArgs),
    /// Old name for `epicenter store harvest` (kept for one release).
    #[command(hide = true)]
    Harvest(HarvestArgs),
    /// Old name for `epicenter store restore` (kept for one release).
    #[command(hide = true)]
    Restore(RestoreArgs),
    /// Old name for `epicenter store vault` (kept for one release).
    #[command(hide = true)]
    Vault,
    /// Old name for `epicenter store verify` (kept for one release).
    #[command(hide = true)]
    Verify,
    /// Old name for `epicenter status --units` (kept for one release).
    #[command(hide = true)]
    Who {
        /// Filter by package name or dir hash fragment.
        #[arg(long)]
        unit: Option<String>,
    },
    /// Old name for `epicenter status --unit` (kept for one release).
    #[command(hide = true)]
    Why {
        /// Package name, dir hash, or unit dir name.
        unit: String,
    },
}

#[derive(Subcommand)]
enum StoreCommand {
    /// Show the vault: generations, sizes, and links into the build view.
    Vault,
    /// Audit the vault: file sizes, canonical stamps, hash contents.
    Verify,
    /// Delete stale intermediate artifacts.
    Prune(PruneArgs),
    /// Remove units or stale working dirs deliberately.
    Evict(EvictArgs),
    /// Store built unit groups from the shared build dir into the vault.
    Harvest(HarvestArgs),
    /// Hard-link vault unit groups into a working dir.
    Restore(RestoreArgs),
    /// Report package/profile variants that occupy the vault repeatedly.
    Overlap(OverlapArgs),
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
    let cli = Cli::parse();
    let cwd = match &cli.command {
        Command::Exec { cwd, .. } => cwd.clone().unwrap_or(std::env::current_dir()?),
        _ => std::env::current_dir()?,
    };
    let settings = settings::load(&cwd)?;
    match settings.cargo_home()? {
        (path, settings::Source::Global) => paths::set_cargo_home_override(Some(path)),
        _ => paths::set_cargo_home_override(None),
    }
    if let Some((store, _)) = settings.store()? {
        vault::set_store_override(store)?;
    }
    let (work_root, _) = settings.work_root_or_default()?;
    exec::set_work_root_override(work_root)?;
    let link = settings.link()?.0;
    match cli.command {
        Command::Setup(args) => cmd_setup(&args, &settings),
        Command::Status(args) => cmd_status(&args),
        Command::Doctor(args) => cmd_doctor(&args, &settings),
        Command::Prune(args) => cmd_prune(&args),
        Command::Who { unit } => epicenter_cli::who::run(&config::cache_root()?, unit.as_deref()),
        Command::Why { unit } => epicenter_cli::who::explain(&config::cache_root()?, &unit),
        Command::Evict(args) => cmd_evict(&args),
        Command::Harvest(args) => cmd_harvest(args.unit.as_deref(), args.dry_run, args.no_compress),
        Command::Restore(args) => {
            if !args.no_remote {
                let _ = settings.remote()?;
            }
            cmd_restore(
                link,
                args.into.as_deref(),
                args.unit.as_deref(),
                args.no_remote,
                args.dry_run,
            )
        }
        Command::Vault => cmd_vault(),
        Command::Verify => cmd_verify(),
        Command::Store { command } => cmd_store(command, &settings),
        Command::Exec {
            id,
            cwd,
            harvest,
            no_compress,
            no_remote,
            work_root,
            rm,
            reuse,
            target_dir,
            command,
        } => cmd_exec(
            &settings,
            id.as_deref(),
            cwd,
            harvest,
            !no_compress,
            no_remote,
            work_root.as_deref(),
            reuse,
            target_dir.as_deref(),
            rm,
            &command,
        ),
    }
}

fn cmd_store(command: StoreCommand, settings: &settings::Settings) -> Result<()> {
    let link = settings.link()?.0;
    match command {
        StoreCommand::Vault => cmd_vault(),
        StoreCommand::Verify => cmd_verify(),
        StoreCommand::Prune(args) => cmd_prune(&args),
        StoreCommand::Evict(args) => cmd_evict(&args),
        StoreCommand::Harvest(args) => {
            cmd_harvest(args.unit.as_deref(), args.dry_run, args.no_compress)
        }
        StoreCommand::Restore(args) => {
            if !args.no_remote {
                let _ = settings.remote()?;
            }
            cmd_restore(
                link,
                args.into.as_deref(),
                args.unit.as_deref(),
                args.no_remote,
                args.dry_run,
            )
        }
        StoreCommand::Overlap(args) => cmd_overlap(&args),
    }
}

fn cmd_evict(args: &EvictArgs) -> Result<()> {
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
        delete: !args.dry_run && args.yes || args.y,
    };
    epicenter_cli::evict::run(&config::cache_root()?, &opts)
}

fn resolve_remote_key_arg(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    let hex = trimmed.strip_prefix("ed25519:").unwrap_or(trimmed);
    if hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return settings::normalize_remote_publisher_key(trimmed);
    }
    let text = util::read_small_text(Path::new(trimmed), 64 * 1024)
        .with_context(|| format!("reading remote public key {}", trimmed))?;
    let key = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .context("remote public key file is empty")?;
    settings::normalize_remote_publisher_key(key)
}

fn cmd_setup(args: &SetupArgs, settings: &settings::Settings) -> Result<()> {
    if args.revert {
        let reports = config::revert_backups(args.dry_run)?;
        println!(
            "{}",
            util::heading(if args.dry_run {
                "epicenter setup — revert (dry run)"
            } else {
                "epicenter setup — revert"
            })
        );
        for report in &reports {
            println!("  {} {}", label("config"), report.config.display());
            println!(
                "  {} {}",
                label("restore"),
                util::green(&report.backup.display().to_string())
            );
        }
        if args.dry_run {
            println!("  {}", util::dim("dry run: nothing restored"));
        }
        return Ok(());
    }

    let profile_report = if args.write_profile {
        Some(profile::write_recommended(
            args.dry_run,
            args.dev_debug
                .map(Into::into)
                .unwrap_or(profile::DevDebug::Full),
        )?)
    } else {
        None
    };

    let preset = args.preset.map(Into::into);
    let linker = args.linker.map(Into::into);
    let wrapper = match (&args.wrapper, &args.with_wrapper, args.without_wrapper) {
        (Some(WrapperArg::Kache), _, _) => Some(config::WrapperAction::Set("kache")),
        (Some(WrapperArg::Sccache), _, _) => Some(config::WrapperAction::Set("sccache")),
        (Some(WrapperArg::Off), _, _) => Some(config::WrapperAction::Remove),
        (None, Some(name), _) => Some(config::WrapperAction::Set(name)),
        (None, None, true) => Some(config::WrapperAction::Remove),
        (None, None, false) => None,
    };
    let wrapper_path = match wrapper {
        Some(config::WrapperAction::Set(name)) => {
            if name.is_empty() || name.contains('/') || name.contains('\\') {
                anyhow::bail!("--wrapper wants a plain command name, like `kache`");
            }
            Some(util::which_path(name).ok_or_else(|| {
                anyhow::anyhow!("{name} is not on PATH — install it or use --wrapper none")
            })?)
        }
        _ => None,
    };

    let memory = args
        .memory
        .as_deref()
        .map(settings::parse_memory)
        .transpose()?;
    let cargo_home_path: Option<PathBuf> = match args.cargo_home.as_deref() {
        Some("default") => {
            paths::set_cargo_home_override(None);
            None
        }
        Some(raw) => {
            let path = settings::resolve_cargo_home(raw)?;
            settings::prepare_cargo_home(&path, args.dry_run)?;
            paths::set_cargo_home_override(Some(path.clone()));
            Some(path)
        }
        None => None,
    };
    let cargo_home_action = match args.cargo_home.as_deref() {
        Some("default") => config::CargoHomeAction::Clear,
        Some(_) => config::CargoHomeAction::Set(
            cargo_home_path
                .as_deref()
                .expect("cargo home path is resolved"),
        ),
        None => config::CargoHomeAction::Keep,
    };
    let remote_url = args
        .remote_url
        .as_deref()
        .map(settings::normalize_remote_url)
        .transpose()?;
    let remote_key = args
        .remote_key
        .as_deref()
        .map(resolve_remote_key_arg)
        .transpose()?;
    let remote_tier = args.remote_tier.map(Into::into);
    if !args.remote_off {
        let existing = settings.global_remote();
        let effective_url = remote_url
            .as_deref()
            .or(existing.and_then(|remote| remote.url.as_deref()));
        let effective_key = remote_key
            .as_deref()
            .or(existing.and_then(|remote| remote.publisher_key.as_deref()));
        if effective_url.is_some() && effective_key.is_none() {
            anyhow::bail!(
                "--remote-url requires --remote-key (or an existing pinned key) — \
                 obtain it from CI/admin, never from the bucket"
            );
        }
        if effective_key.is_some() && effective_url.is_none() {
            anyhow::bail!("--remote-key requires --remote-url");
        }
    }
    let opts = config::SetupOptions {
        root_arg: args.cache_root.as_deref(),
        use_default: args.use_default,
        preset,
        linker,
        wrapper,
        memory,
        memory_text: args.memory.as_deref(),
        work_root_arg: args.work_root.as_deref(),
        cargo_home: cargo_home_action,
        remote_url: remote_url.as_deref(),
        remote_key: remote_key.as_deref(),
        remote_tier,
        remote_off: args.remote_off,
        dry_run: args.dry_run,
    };
    let report = config::setup(&opts, settings)?;

    println!(
        "{}",
        util::heading(if report.dry_run {
            "epicenter setup — dry run"
        } else {
            "epicenter setup"
        })
    );
    print_policy(&report.policy);
    if args.remote_off {
        println!("  {} off (global [remote] removed)", label("remote"));
    } else if remote_url.is_some() || remote_key.is_some() || remote_tier.is_some() {
        if let Some(url) = &remote_url {
            println!("  {} {}", label("remote URL"), url);
        }
        if let Some(key) = &remote_key {
            println!(
                "  {} {} (pinned; share via CI/admin, never the bucket)",
                label("remote key"),
                settings::remote_key_id(key)?
            );
        }
        if let Some(tier) = remote_tier {
            println!("  {} {}", label("remote tier"), tier.as_str());
        }
    }
    println!();
    let cache_note = if report.dry_run { " (not created)" } else { "" };
    println!(
        "{} shared cache {} {}{cache_note}",
        util::green(util::GLYPH_PASS),
        if report.dry_run {
            "would be"
        } else {
            "ready at"
        },
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
        if let Some(raw) = &args.cache_root {
            println!("                 {}", util::dim(raw));
        }
    } else if args.use_default {
        println!(
            "{} cache root:    back to the default template (override removed)",
            util::green(util::GLYPH_PASS)
        );
    }
    if let Some(edit) = report.wrapper_edit {
        let text = if matches!(wrapper, Some(config::WrapperAction::Remove))
            && edit == config::CargoEdit::AlreadySet
        {
            "not set"
        } else {
            edit.describe()
        };
        println!("{} rustc-wrapper: {text}", util::green(util::GLYPH_PASS));
        if let Some(name) = match wrapper {
            Some(config::WrapperAction::Set(name)) => Some(name),
            _ => None,
        } {
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
    if let Some(edit) = report.jobs_edit {
        println!(
            "{} jobs:          {} ({})",
            util::green(util::GLYPH_PASS),
            report.policy.jobs,
            edit.describe()
        );
    }
    if let Some(edit) = report.incremental_edit {
        println!(
            "{} incremental:   {} ({})",
            util::green(util::GLYPH_PASS),
            if report.policy.incremental.unwrap_or(false) {
                "true"
            } else {
                "false"
            },
            edit.describe()
        );
    }
    if let Some(linker) = &report.linker {
        let mut changed = false;
        for target in &linker.targets {
            match target.edit {
                config::CargoEdit::Inserted
                | config::CargoEdit::Appended
                | config::CargoEdit::Replaced => {
                    changed = true;
                    match linker.choice {
                        settings::LinkerChoice::Lld => {
                            println!(
                                "{} linker:        rust-lld for {}",
                                util::green(util::GLYPH_PASS),
                                target.target
                            );
                            println!("  lld:          {}", linker.binary.display());
                            println!("  rustflags:    {}", target.flags.join(" "));
                        }
                        settings::LinkerChoice::Wild => {
                            println!(
                                "{} linker:        wild for {}",
                                util::green(util::GLYPH_PASS),
                                target.target
                            );
                            println!("  wild:         {}", linker.binary.display());
                            println!("  rustflags:    {}", target.flags.join(" "));
                        }
                        settings::LinkerChoice::Mold | settings::LinkerChoice::Gold => {
                            let name = match linker.choice {
                                settings::LinkerChoice::Mold => "mold",
                                settings::LinkerChoice::Gold => "gold",
                                _ => unreachable!(),
                            };
                            println!(
                                "{} linker:        {name} for {}",
                                util::green(util::GLYPH_PASS),
                                target.target
                            );
                            println!("  {name}:         {}", linker.binary.display());
                            println!("  rustflags:    {}", target.flags.join(" "));
                        }
                        settings::LinkerChoice::System => println!(
                            "{} linker:        managed flags updated for {}",
                            util::green(util::GLYPH_PASS),
                            target.target
                        ),
                        settings::LinkerChoice::Auto => {}
                    }
                }
                config::CargoEdit::Removed => {
                    changed = true;
                    println!(
                        "{} linker:        managed flags removed for {}",
                        util::green(util::GLYPH_PASS),
                        target.target
                    );
                }
                config::CargoEdit::AlreadySet => {
                    if linker.conflict {
                        println!(
                            "{} linker:        rustflags for {} are already set — left unchanged (edit ~/.cargo/config.toml to replace them)",
                            util::warn(util::GLYPH_WARN),
                            target.target
                        );
                    } else {
                        let what = match linker.choice {
                            settings::LinkerChoice::Lld => "rust-lld",
                            settings::LinkerChoice::System => "system",
                            settings::LinkerChoice::Wild => "wild",
                            settings::LinkerChoice::Mold => "mold",
                            settings::LinkerChoice::Gold => "gold",
                            settings::LinkerChoice::Auto => "auto",
                        };
                        println!(
                            "{} linker:        already {what} for {}",
                            util::green(util::GLYPH_PASS),
                            target.target
                        );
                    }
                }
                _ => {}
            }
        }
        if changed {
            println!(
                "{} RUSTFLAGS changed — every unit re-keys; the next build repopulates the shared cache (run `epicenter store harvest` after).",
                util::warn(util::GLYPH_WARN)
            );
            if std::env::var_os("RUSTFLAGS").is_some()
                || std::env::var_os("CARGO_ENCODED_RUSTFLAGS").is_some()
            {
                println!(
                    "{} RUSTFLAGS is set in this shell — it overrides the config flags; unset it for --linker to take effect.",
                    util::warn(util::GLYPH_WARN)
                );
            }
        }
    }
    if let Some(path) = &report.backup {
        println!("  backup of previous cargo config: {}", path.display());
    }
    if let Some(path) = &report.settings_backup {
        println!("  backup of previous epicenter.toml: {}", path.display());
    }

    if let Some(profile) = &profile_report {
        print_profile(profile, args.dry_run);
    }

    if report.dry_run {
        println!();
        let cargo_path = config::cargo_config_path()?;
        print_diff(
            &cargo_path,
            report.cargo_before.as_deref(),
            &report.cargo_after,
        );
        if let Some(after) = &report.settings_after {
            print_diff(
                &report.settings_path,
                report.settings_before.as_deref(),
                after,
            );
        }
        println!();
        println!("{}", util::dim("dry run — nothing written"));
    } else {
        println!();
        println!("→ every `cargo build` on this machine now shares one cache.");
        println!("  Try `epicenter status` after your next build.");
    }

    if args.measure {
        if args.dry_run {
            println!();
            println!("{}", util::dim("measure — skipped in dry run"));
        } else {
            println!();
            println!("{}", util::heading("calibration build — cargo build"));
            let started = Instant::now();
            let mut child = util::command_for("cargo")?
                .arg("build")
                .spawn()
                .context("running calibration build")?;
            let memory = exec::ChildMemory::start(&child);
            let status = child.wait().context("running calibration build")?;
            let elapsed = started.elapsed();
            let command = ["cargo".to_string(), "build".to_string()];
            memory.record_build(&command, elapsed);
            println!(
                "  {} cargo build · {:.2}s",
                util::green(util::GLYPH_PASS),
                elapsed.as_secs_f64()
            );
            if !status.success() {
                anyhow::bail!("calibration build failed");
            }
        }
    }
    Ok(())
}

fn print_profile(profile: &profile::Report, dry_run: bool) {
    println!();
    println!(
        "{}",
        util::heading(if dry_run {
            "Cargo profile — dry run"
        } else {
            "Cargo profile"
        })
    );
    println!("  {} {}", label("manifest"), profile.path.display());
    if !profile.changed {
        println!(
            "  {} already at the recommended dev/release values",
            util::green(util::GLYPH_PASS)
        );
        return;
    }
    if dry_run {
        print_diff(&profile.path, Some(&profile.before), &profile.after);
    } else if let Some(backup) = &profile.backup {
        println!("  {} {}", label("backup"), backup.display());
    }
    let dev_debug = match profile.dev_debug {
        profile::DevDebug::Full => "debug=2",
        profile::DevDebug::Line => "debug=line-tables-only, split-debuginfo=unpacked",
        profile::DevDebug::None => "debug=false",
    };
    println!(
        "  {} {}, lto=false, codegen-units=256, incremental=true",
        label("dev"),
        dev_debug
    );
    println!(
        "  {} lto=thin, codegen-units=16, debug=false",
        label("release")
    );
}

fn print_policy(policy: &config::PolicyReport) {
    let preset = if policy.preset.as_str() == policy.effective_preset.as_str() {
        policy.preset.as_str().to_string()
    } else {
        format!(
            "{} -> {}",
            policy.preset.as_str(),
            policy.effective_preset.as_str()
        )
    };
    println!(
        "  {} {} ({})",
        label("preset"),
        preset,
        policy.preset_source.as_str()
    );
    let memory = policy
        .memory
        .map(util::human_bytes)
        .unwrap_or_else(|| "unknown".to_string());
    println!(
        "  {} {} ({})",
        label("memory"),
        memory,
        policy.memory_source.as_str()
    );
    println!(
        "  {} {} ({} cores, 2 GiB/job cap)",
        label("jobs"),
        policy.jobs,
        policy.cores
    );
    println!(
        "  {} {} ({})",
        label("linker"),
        policy.linker.as_str(),
        policy.linker_source.as_str()
    );
    println!(
        "  {} {} ({})",
        label("cargo home"),
        policy.cargo_home.display(),
        policy.cargo_home_source.as_str()
    );
    println!(
        "  {} {}",
        label("wrapper"),
        policy.wrapper.as_deref().unwrap_or("none")
    );
    println!(
        "  {} {}",
        label("store"),
        policy
            .store
            .as_deref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<build dir>/../store".to_string())
    );
    println!(
        "  {} {} ({})",
        label("work"),
        policy.work_root.display(),
        policy.work_root_source.as_str()
    );
    println!(
        "  {} compression {}, restore {}, check tier {}",
        label("policy"),
        on_off(policy.compression),
        on_off(policy.restore),
        on_off(policy.check_tier)
    );
}

fn on_off(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

fn print_diff(path: &std::path::Path, before: Option<&str>, after: &str) {
    let before = before.unwrap_or("");
    if before == after {
        println!("{} {} (no change)", util::dim("---"), path.display());
        return;
    }
    println!("{} {}", util::dim("---"), path.display());
    print!("{}", util::line_diff(before, after));
}

fn cmd_status(args: &StatusArgs) -> Result<()> {
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

fn cmd_prune(args: &PruneArgs) -> Result<()> {
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

fn cmd_overlap(args: &OverlapArgs) -> Result<()> {
    let store = vault::store_root(&config::cache_root()?);
    let packages = vault::overlap(&store)?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &packages
                    .iter()
                    .map(|package| {
                        serde_json::json!({
                            "package": package.package,
                            "profile": package.profile,
                            "units": package.units,
                            "hashes": package.hashes,
                            "bytes": package.bytes,
                            "generations": package.generations,
                        })
                    })
                    .collect::<Vec<_>>()
            )?
        );
        return Ok(());
    }
    println!(
        "{}",
        util::heading("epicenter store overlap — package/profile variants")
    );
    let multi: Vec<_> = packages
        .iter()
        .filter(|package| package.units > 1)
        .collect();
    if multi.is_empty() {
        println!("  no package has more than one stored unit variant");
        return Ok(());
    }
    println!(
        "  {:<38} {:<10} {:>6} {:>6} {:>10} {:>5}",
        util::dim("package"),
        util::dim("profile"),
        util::dim("units"),
        util::dim("hashes"),
        util::dim("bytes"),
        util::dim("gens")
    );
    for package in multi {
        println!(
            "  {:<38} {:<10} {:>6} {:>6} {:>10} {:>5}",
            package.package,
            package.profile,
            package.units,
            package.hashes,
            util::green(&util::human_bytes(package.bytes)),
            package.generations
        );
    }
    println!();
    println!(
        "  {}",
        util::dim("same package/profile with multiple hashes = feature, profile, or flag variants")
    );
    Ok(())
}

/// `epicenter doctor` printing: group checks under their section header,
/// icons colored by severity.
fn cmd_doctor(args: &DoctorArgs, settings: &settings::Settings) -> Result<()> {
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

/// A dim, aligned label column (13 chars, matching the other commands).
fn label(text: &str) -> String {
    util::dim(&format!("{text:<13}"))
}

/// `exec` hands the child's exit code to the caller unchanged, so a failing
/// job exits the process directly — the wrapper must not turn a failure into
/// a success. Nothing is buffered at this point: the command owns stdout and
/// epicenter's frame owns stderr.
fn exec_incremental(settings: &settings::Settings) -> Option<bool> {
    let (preset, _) = settings.preset();
    let (effective, _, _) = settings.effective_preset();
    let wrapper = config::cargo_configured("rustc-wrapper")
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

fn cmd_exec(
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
    if !no_remote {
        let _ = settings.remote()?;
    }
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
            let raw = path.to_string_lossy();
            if raw == "~" || raw.starts_with("~/") || raw.starts_with("~\\") {
                let rest = raw[1..].trim_start_matches(['/', '\\']);
                epicenter_cli::paths::home()?.join(rest)
            } else if path.is_absolute() {
                path.to_path_buf()
            } else {
                let base = match cwd.as_deref() {
                    Some(dir) if dir.is_absolute() => dir.to_path_buf(),
                    Some(dir) => std::env::current_dir()?.join(dir),
                    None => std::env::current_dir()?,
                };
                base.join(path)
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

fn cmd_harvest(unit: Option<&str>, dry_run: bool, no_compress: bool) -> Result<()> {
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
    let report = vault::harvest_with(
        &root,
        &vault::store_root(&root),
        unit,
        dry_run,
        None,
        None,
        !no_compress,
    )?;
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

fn cmd_restore(
    link: settings::LinkPolicy,
    into: Option<&std::path::Path>,
    unit: Option<&str>,
    no_remote: bool,
    dry_run: bool,
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
    if into.is_none() && root.is_dir() {
        util::ensure_private_dir(&root)?;
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
    let report = vault::restore_policy(&view, &store, unit, dry_run, link)?;
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

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn setup_accepts_presets_linkers_and_wrappers() {
        let cli = Cli::try_parse_from([
            "epicenter",
            "setup",
            "--preset",
            "ci",
            "--linker",
            "wild",
            "--wrapper",
            "none",
            "--dry-run",
        ])
        .unwrap();
        match cli.command {
            Command::Setup(args) => {
                assert!(matches!(args.preset, Some(PresetArg::Ci)));
                assert!(matches!(args.linker, Some(LinkerArg::Wild)));
                assert!(matches!(args.wrapper, Some(WrapperArg::Off)));
                assert!(args.dry_run);
            }
            _ => panic!("expected setup"),
        }
    }

    #[test]
    fn prune_accepts_retention_and_incremental_scope() {
        let cli = Cli::try_parse_from([
            "epicenter",
            "store",
            "prune",
            "--keep-latest",
            "2",
            "--incremental",
        ])
        .unwrap();
        match cli.command {
            Command::Store {
                command: StoreCommand::Prune(args),
            } => {
                assert_eq!(args.keep_latest, Some(2));
                assert!(args.incremental);
            }
            _ => panic!("expected store prune"),
        }
    }

    #[test]
    fn setup_and_exec_accept_a_work_root() {
        let cli = Cli::try_parse_from([
            "epicenter",
            "setup",
            "--work-root",
            "/var/lib/epicenter/work",
        ])
        .unwrap();
        match cli.command {
            Command::Setup(args) => {
                assert_eq!(args.work_root.as_deref(), Some("/var/lib/epicenter/work"))
            }
            _ => panic!("expected setup"),
        }

        let cli = Cli::try_parse_from([
            "epicenter",
            "exec",
            "--work-root",
            "/var/lib/epicenter/work",
            "--",
            "true",
        ])
        .unwrap();
        match cli.command {
            Command::Exec { work_root, .. } => {
                assert_eq!(
                    work_root.as_deref(),
                    Some(Path::new("/var/lib/epicenter/work"))
                )
            }
            _ => panic!("expected exec"),
        }
    }

    #[test]
    fn setup_accepts_remote_flags() {
        let cli = Cli::try_parse_from([
            "epicenter",
            "setup",
            "--remote-url",
            "https://cache.example/root",
            "--remote-key",
            "00",
            "--remote-tier",
            "full",
        ])
        .unwrap();
        match cli.command {
            Command::Setup(args) => {
                assert_eq!(
                    args.remote_url.as_deref(),
                    Some("https://cache.example/root")
                );
                assert_eq!(args.remote_key.as_deref(), Some("00"));
                assert!(matches!(args.remote_tier, Some(RemoteTierArg::Full)));
            }
            _ => panic!("expected setup"),
        }

        let cli = Cli::try_parse_from(["epicenter", "setup", "--remote-off"]).unwrap();
        match cli.command {
            Command::Setup(args) => assert!(args.remote_off),
            _ => panic!("expected setup"),
        }
    }

    #[test]
    fn exec_and_restore_accept_no_remote() {
        let cli = Cli::try_parse_from(["epicenter", "exec", "--no-remote", "--", "true"]).unwrap();
        match cli.command {
            Command::Exec { no_remote, .. } => assert!(no_remote),
            _ => panic!("expected exec"),
        }

        let cli = Cli::try_parse_from(["epicenter", "restore", "--no-remote"]).unwrap();
        match cli.command {
            Command::Restore(args) => assert!(args.no_remote),
            _ => panic!("expected restore"),
        }

        let cli = Cli::try_parse_from(["epicenter", "store", "restore", "--no-remote"]).unwrap();
        match cli.command {
            Command::Store {
                command: StoreCommand::Restore(args),
            } => assert!(args.no_remote),
            _ => panic!("expected store restore"),
        }
    }

    #[test]
    fn setup_accepts_measure() {
        let cli = Cli::try_parse_from(["epicenter", "setup", "--measure"]).unwrap();
        match cli.command {
            Command::Setup(args) => assert!(args.measure),
            _ => panic!("expected setup"),
        }
    }

    #[test]
    fn setup_accepts_write_profile() {
        let cli =
            Cli::try_parse_from(["epicenter", "setup", "--write-profile", "--dry-run"]).unwrap();
        match cli.command {
            Command::Setup(args) => assert!(args.write_profile && args.dry_run),
            _ => panic!("expected setup"),
        }

        let cli = Cli::try_parse_from([
            "epicenter",
            "setup",
            "--write-profile",
            "--dev-debug",
            "line",
        ])
        .unwrap();
        match cli.command {
            Command::Setup(args) => assert!(matches!(args.dev_debug, Some(DevDebugArg::Line))),
            _ => panic!("expected setup"),
        }
    }

    #[test]
    fn setup_accepts_memory_budget() {
        let cli = Cli::try_parse_from(["epicenter", "setup", "--memory-budget", "8GiB"]).unwrap();
        match cli.command {
            Command::Setup(args) => assert_eq!(args.memory.as_deref(), Some("8GiB")),
            _ => panic!("expected setup"),
        }
    }

    #[test]
    fn store_subcommands_parse() {
        let cli = Cli::try_parse_from(["epicenter", "store", "prune", "--dry-run"]).unwrap();
        match cli.command {
            Command::Store {
                command: StoreCommand::Prune(args),
            } => assert!(args.dry_run),
            _ => panic!("expected store prune"),
        }
    }

    #[test]
    fn hidden_aliases_still_parse() {
        let cli = Cli::try_parse_from(["epicenter", "harvest", "--dry-run"]).unwrap();
        assert!(matches!(cli.command, Command::Harvest(_)));
        let cli = Cli::try_parse_from(["epicenter", "check"]).is_err();
        assert!(cli, "unknown commands still fail");
    }

    #[test]
    fn fast_aliases_are_gone() {
        for alias in ["--fast", "--without-fast"] {
            let err = match Cli::try_parse_from(["epicenter", "setup", alias]) {
                Ok(_) => panic!("{alias} must not parse"),
                Err(err) => err,
            };
            assert!(
                err.to_string().contains("unexpected argument"),
                "{alias}: {err}"
            );
        }
    }

    #[test]
    fn status_units_accepts_a_filter() {
        let cli =
            Cli::try_parse_from(["epicenter", "status", "--units", "--filter", "serde"]).unwrap();
        match cli.command {
            Command::Status(args) => {
                assert!(args.units);
                assert_eq!(args.filter.as_deref(), Some("serde"));
            }
            _ => panic!("expected status"),
        }
    }

    #[test]
    fn status_flags_are_exclusive() {
        let err = match Cli::try_parse_from(["epicenter", "status", "--units", "--unit", "x"]) {
            Ok(_) => panic!("expected a conflict"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("cannot be used with"), "{err}");
    }
}
