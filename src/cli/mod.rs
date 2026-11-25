//! CLI: argument definitions, dispatch, and shared output helpers.

mod args;
mod build;
mod remote;
mod setup;
mod store;

#[cfg(test)]
mod tests;

use anyhow::Result;
use clap::Parser;

use epicenter_cli::{config, exec, paths, settings, util, vault};

use args::{Cli, Command, StoreCommand};
use build::{cmd_compact, cmd_doctor, cmd_exec, cmd_overlap, cmd_prune, cmd_status};
use remote::{cmd_fetch, cmd_publish, cmd_restore};
use setup::cmd_setup;
use store::{cmd_evict, cmd_harvest, cmd_vault, cmd_verify};

pub(super) fn run() -> Result<()> {
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
        Command::Harvest(args) => cmd_harvest(
            args.unit.as_deref(),
            args.dry_run,
            args.no_compress,
            args.trusted,
        ),
        Command::Restore(args) => {
            let remote = configured_remote(&settings, args.no_remote);
            cmd_restore(
                link,
                args.into.as_deref(),
                args.unit.as_deref(),
                args.no_remote,
                args.dry_run,
                remote.as_ref(),
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
        StoreCommand::Harvest(args) => cmd_harvest(
            args.unit.as_deref(),
            args.dry_run,
            args.no_compress,
            args.trusted,
        ),
        StoreCommand::Restore(args) => {
            let remote = configured_remote(settings, args.no_remote);
            cmd_restore(
                link,
                args.into.as_deref(),
                args.unit.as_deref(),
                args.no_remote,
                args.dry_run,
                remote.as_ref(),
            )
        }
        StoreCommand::Overlap(args) => cmd_overlap(&args),
        StoreCommand::Compact(args) => cmd_compact(&args),
        StoreCommand::Fetch(args) => cmd_fetch(&args, settings),
        StoreCommand::Publish(args) => cmd_publish(&args, settings),
    }
}

/// A dim, aligned label column (13 chars, matching the other commands).
pub(super) fn label(text: &str) -> String {
    util::dim(&format!("{text:<13}"))
}

pub(super) fn configured_remote(
    settings: &settings::Settings,
    no_remote: bool,
) -> Option<settings::RemotePolicy> {
    if no_remote {
        return None;
    }
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
}
