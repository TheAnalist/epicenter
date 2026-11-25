//! Clap argument definitions for the `epicenter` binary.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use epicenter_cli::{profile, settings};

#[derive(Parser)]
#[command(
    name = "epicenter",
    version,
    about = "The state layer for Cargo builds: shared cache, durable vault, per-job dirs"
)]
pub(super) struct Cli {
    #[command(subcommand)]
    pub(super) command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(super) enum PresetArg {
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
pub(super) enum LinkerArg {
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
pub(super) enum RemoteTierArg {
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
pub(super) enum WrapperArg {
    Kache,
    Sccache,
    #[value(name = "none")]
    Off,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(super) enum DevDebugArg {
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
pub(super) struct SetupArgs {
    /// One intent instead of per-knob flags: auto (default), dev, or ci.
    #[arg(long, value_enum)]
    pub(super) preset: Option<PresetArg>,
    /// Toolchain linker: auto (keep what is configured), system, lld, wild, mold, gold.
    #[arg(long, value_enum)]
    pub(super) linker: Option<LinkerArg>,
    /// External compile cache: kache, sccache, or none (remove it).
    #[arg(long, value_enum, conflicts_with_all = ["with_wrapper", "without_wrapper"])]
    pub(super) wrapper: Option<WrapperArg>,
    /// Memory budget for the job cap (e.g. `16GiB`); same as `memory` in
    /// epicenter.toml. A bare integer is MiB.
    #[arg(long, alias = "memory-budget", value_name = "SIZE")]
    pub(super) memory: Option<String>,
    /// Use this directory for the shared cache instead of the default
    /// `{cargo-cache-home}/epicenter/build`: an absolute path, `~/…`, a
    /// relative path, or a cargo template like `{cargo-cache-home}/custom`.
    #[arg(long)]
    pub(super) cache_root: Option<String>,
    /// Drop any custom cache root and return to the default template.
    #[arg(long, conflicts_with = "cache_root")]
    pub(super) use_default: bool,
    /// Local per-VM job-dir root (absolute, `~/…`, or relative). Global-only;
    /// `default` clears the override.
    #[arg(long, value_name = "PATH")]
    pub(super) work_root: Option<String>,
    /// Global machine-level CARGO_HOME used by `exec`. Must be absolute and
    /// identical on every machine/VM that shares remote units; `default`
    /// clears the override.
    #[arg(long, value_name = "PATH")]
    pub(super) cargo_home: Option<String>,
    /// Remote endpoint: `https://…` for anonymous reads or
    /// `s3://bucket/prefix` for authenticated S3.
    #[arg(long, value_name = "URL", conflicts_with = "remote_off")]
    pub(super) remote_url: Option<String>,
    /// Pinned Ed25519 publisher public key, as 64 hex characters or a file
    /// containing it. Obtain it from CI/admin, never from the bucket.
    #[arg(long, value_name = "HEX|FILE", conflicts_with = "remote_off")]
    pub(super) remote_key: Option<String>,
    /// Remote artifact tier written to the global `[remote]` table.
    #[arg(long, value_enum, conflicts_with = "remote_off")]
    pub(super) remote_tier: Option<RemoteTierArg>,
    /// Remove the global `[remote]` policy table.
    #[arg(
        long,
        conflicts_with_all = ["remote_url", "remote_key", "remote_tier"]
    )]
    pub(super) remote_off: bool,
    /// Print the effective policy and the exact config diff; write nothing.
    #[arg(long)]
    pub(super) dry_run: bool,
    /// Explicitly write the recommended dev/release profile to the workspace
    /// Cargo.toml. Never a normal setup side effect.
    #[arg(long, conflicts_with = "revert")]
    pub(super) write_profile: bool,
    /// Debug detail for the written dev profile: full, line, or none.
    #[arg(long, value_enum, requires = "write_profile")]
    pub(super) dev_debug: Option<DevDebugArg>,
    /// After setup, run one `cargo build` and record wall time/RSS for doctor.
    #[arg(long, conflicts_with = "revert")]
    pub(super) measure: bool,
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
    pub(super) revert: bool,
    /// Legacy form of --wrapper <name> (kept for one release).
    #[arg(long, hide = true, conflicts_with = "without_wrapper")]
    pub(super) with_wrapper: Option<String>,
    /// Legacy form of --wrapper none (kept for one release).
    #[arg(long, hide = true)]
    pub(super) without_wrapper: bool,
}

#[derive(clap::Args)]
pub(super) struct StatusArgs {
    /// Machine-readable summary (not available with --units/--unit).
    #[arg(long, conflicts_with_all = ["units", "unit"])]
    pub(super) json: bool,
    /// Replace the old `who` table.
    #[arg(long, conflicts_with = "unit")]
    pub(super) units: bool,
    /// Filter the --units table by package name or dir hash fragment.
    #[arg(long, requires = "units", value_name = "QUERY")]
    pub(super) filter: Option<String>,
    /// Replace the old `why` explainer.
    #[arg(long, value_name = "NAME")]
    pub(super) unit: Option<String>,
}

#[derive(clap::Args)]
pub(super) struct PruneArgs {
    /// Remove units untouched for this long, e.g. "30d", "2w", "12h".
    #[arg(long, default_value = "30d")]
    pub(super) older_than: String,
    /// Keep the newest N groups per package/kind and remove older duplicates.
    #[arg(long, value_name = "N")]
    pub(super) keep_latest: Option<usize>,
    /// Only prune incremental state (`incremental/` and `incremental.*`).
    #[arg(long)]
    pub(super) incremental: bool,
    /// Show what would be removed, without removing anything.
    #[arg(long)]
    pub(super) dry_run: bool,
    /// Actually delete (without this flag nothing is deleted).
    #[arg(long)]
    pub(super) yes: bool,
    /// Actually delete (without this flag nothing is deleted).
    #[arg(short)]
    pub(super) y: bool,
}

#[derive(clap::Args)]
pub(super) struct OverlapArgs {
    /// Machine-readable report.
    #[arg(long)]
    pub(super) json: bool,
    /// One row per stored unit: hash, generation, age, and active marker.
    #[arg(long)]
    pub(super) detail: bool,
}

#[derive(clap::Args)]
pub(super) struct CompactArgs {
    /// Only compact generations whose key contains this string.
    #[arg(long)]
    pub(super) generation: Option<String>,
    /// Show what would be linked without changing the store.
    #[arg(long)]
    pub(super) dry_run: bool,
}

#[derive(clap::Args)]
pub(super) struct FetchArgs {
    /// Verify the pointer/body and report candidates without writing anything.
    #[arg(long)]
    pub(super) dry_run: bool,
    /// Only consider units whose name contains this string.
    #[arg(long)]
    pub(super) unit: Option<String>,
    /// Import every compatible unit when no Cargo.lock is available.
    #[arg(long)]
    pub(super) all: bool,
}

#[derive(clap::Args)]
pub(super) struct EvictArgs {
    /// Unit to remove: dir hash fragment or package name.
    #[arg(long)]
    pub(super) unit: Option<String>,
    /// All units on a stale toolchain generation.
    #[arg(long)]
    pub(super) stale: bool,
    /// All units whose rustc fingerprint identity matches this (prefix).
    #[arg(long)]
    pub(super) rustc_key: Option<String>,
    /// Delete a whole parity-key vault generation (exact key or a
    /// substring such as `1.97.1`): its units, manifest and lock.
    /// With the default `--tier all`, matching view units are unlinked too.
    #[arg(long)]
    pub(super) generation: Option<String>,
    /// Units whose artifacts are already missing (fingerprint husks).
    #[arg(long)]
    pub(super) husks: bool,
    /// Units untouched for longer than this, e.g. `30d`, `12h`.
    /// With `--work-dirs`: the max age of a job dir (default 7d).
    #[arg(long)]
    pub(super) older_than: Option<String>,
    /// Collect stale per-job working dirs under `work/` (default: older
    /// than 7 days; a dir a live build has locked is never touched).
    #[arg(long)]
    pub(super) work_dirs: bool,
    /// Remove ONE job dir now (name, `work/<id>`, or a path under `work/`):
    /// explicit choices bypass the GC age window, and a dir a live build
    /// has locked is refused.
    #[arg(long)]
    pub(super) work_dir: Option<String>,
    /// Unlink units from ONE view only (`build`, a `work/<id>` job dir,
    /// or a path): a freshness operation — the vault is never touched.
    #[arg(long)]
    pub(super) work: Option<String>,
    /// Package selector for --work (dashes and underscores both match).
    #[arg(long = "crate")]
    pub(super) crate_name: Option<String>,
    /// What an eviction touches: `all` (default: store + every view),
    /// `store` (the vault only), or `view` (build dir + job dirs only).
    #[arg(long, value_enum, default_value = "all")]
    pub(super) tier: epicenter_cli::evict::Tier,
    /// Also include current-generation units matched by bulk selectors
    /// (an explicit `--unit` is deliberate and needs no --force).
    #[arg(long)]
    pub(super) force: bool,
    /// Show what would be removed without removing it.
    #[arg(long)]
    pub(super) dry_run: bool,
    /// Actually delete (without this flag nothing is deleted).
    #[arg(long)]
    pub(super) yes: bool,
    /// Actually delete (without this flag nothing is deleted).
    #[arg(short)]
    pub(super) y: bool,
}

#[derive(clap::Args)]
pub(super) struct HarvestArgs {
    /// Only units whose name contains this (package or hash fragment).
    #[arg(long)]
    pub(super) unit: Option<String>,
    /// Store copied artifacts raw; skip gzip blobs.
    #[arg(long)]
    pub(super) no_compress: bool,
    /// Show what would be stored, without writing anything.
    #[arg(long)]
    pub(super) dry_run: bool,
    /// Sign a build dir this host did not create (a shared/network build dir).
    /// Only use it when every writer is in this trust domain.
    #[arg(long)]
    pub(super) trusted: bool,
}

#[derive(clap::Args)]
pub(super) struct PublishArgs {
    /// Override the configured remote URL. Must be `s3://bucket/prefix`.
    #[arg(long)]
    pub(super) url: Option<String>,
    /// Reader-facing URL for the printed setup handoff (defaults to --url).
    #[arg(long)]
    pub(super) reader_url: Option<String>,
    /// Publish tier; `libraries` excludes executable units.
    #[arg(long, value_enum)]
    pub(super) tier: Option<RemoteTierArg>,
    /// Generation directory in the store (default: the active parity key).
    #[arg(long)]
    pub(super) generation: Option<String>,
    /// Publish only this profile when a store generation has several.
    #[arg(long)]
    pub(super) profile: Option<String>,
    /// Rustup selector used for the build (`nightly`, `1.91.0`, ...).
    #[arg(long)]
    pub(super) toolchain: Option<String>,
    /// Explicit index sequence (must advance past the staged index).
    #[arg(long)]
    pub(super) sequence: Option<u64>,
    /// Index lifetime, e.g. 30d.
    #[arg(long, default_value = "30d")]
    pub(super) valid_for: String,
    /// Source commit recorded in publisher.json; detected from CI/git if absent.
    #[arg(long)]
    pub(super) source_commit: Option<String>,
    /// CI job identifier recorded in publisher.json.
    #[arg(long)]
    pub(super) ci_job: Option<String>,
    /// Free-form publisher note; never put credentials here.
    #[arg(long)]
    pub(super) notes: Option<String>,
    /// Pin expected publisher key id (or 64-hex public key).
    #[arg(long)]
    pub(super) expect_key_id: Option<String>,
    /// Rotate the publisher identity and print the new pin.
    #[arg(long)]
    pub(super) rotate_key: bool,
    /// Persistent directory holding the publisher identity.
    #[arg(long)]
    pub(super) publisher_state: Option<PathBuf>,
    /// Staging directory; defaults to the state directory.
    #[arg(long)]
    pub(super) out_dir: Option<PathBuf>,
    /// Path to Cargo.lock (default: nearest lock above the working directory).
    #[arg(long)]
    pub(super) lockfile: Option<PathBuf>,
    /// Fetch the current remote pointer, stage, and print the plan without writing.
    #[arg(long)]
    pub(super) dry_run: bool,
    /// Explicitly allow a missing remote index when publisher state or a prior
    /// publisher.json says this bucket was published before.
    #[arg(long)]
    pub(super) reset_sequence: bool,
}

#[derive(clap::Args)]
pub(super) struct RestoreArgs {
    /// Working dir to fill (default: the shared build dir).
    #[arg(long)]
    pub(super) into: Option<PathBuf>,
    /// Only units whose name contains this (package or hash fragment).
    #[arg(long)]
    pub(super) unit: Option<String>,
    /// Skip remote compatible-unit fetch.
    #[arg(long)]
    pub(super) no_remote: bool,
    /// Show what would be linked, without touching any file.
    #[arg(long)]
    pub(super) dry_run: bool,
}

#[derive(clap::Args)]
pub(super) struct DoctorArgs {
    /// Machine-readable checks plus the effective profile.
    #[arg(long)]
    pub(super) json: bool,
}

#[derive(Subcommand)]
pub(super) enum Command {
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
pub(super) enum StoreCommand {
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
    /// Hard-link identical files and blobs in the vault.
    Compact(CompactArgs),
    /// Verify and import compatible remote units without running a build.
    #[command(hide = true)]
    Fetch(FetchArgs),
    /// CI-only: sign one store generation and upload the immutable object tree.
    #[command(hide = true)]
    Publish(PublishArgs),
}
