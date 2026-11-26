use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};

use epicenter_cli::{config, exec, paths, profile, settings, util};

use super::args::{SetupArgs, WrapperArg};
use super::label;

fn resolve_remote_key_arg(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if settings::is_publisher_key_hex(trimmed) {
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

/// Restore setup backups without loading the current policy: a malformed
/// policy lives in the very file this command replaces.
pub(super) fn cmd_setup_revert(args: &SetupArgs) -> Result<()> {
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
    Ok(())
}

pub(super) fn cmd_setup(args: &SetupArgs, settings: &settings::Settings) -> Result<()> {
    if args.revert {
        return cmd_setup_revert(args);
    }

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
    // Persist the resolved absolute path. Cargo resolves a bare name itself,
    // and on Windows `CreateProcess` searches the current directory before
    // PATH, so a repository-local `sccache.exe`/`kache.exe` would run.
    let wrapper_value = match (&wrapper, &wrapper_path) {
        (Some(config::WrapperAction::Set(_)), Some(path)) => {
            Some(path.to_string_lossy().into_owned())
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
        wrapper: match wrapper {
            Some(config::WrapperAction::Set(_)) => Some(config::WrapperAction::Set(
                wrapper_value
                    .as_deref()
                    .expect("a Set wrapper has a resolved path"),
            )),
            Some(config::WrapperAction::Remove) => Some(config::WrapperAction::Remove),
            None => None,
        },
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

    // The profile is a workspace file, not part of the Cargo config. Write it
    // only after every option has been validated and the config committed, so
    // an invalid flag cannot leave Cargo.toml modified.
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
    println!(
        "  {} {}, lto=false, codegen-units=256, incremental=true",
        label("dev"),
        dev_profile_label(profile.dev_debug)
    );
    println!(
        "  {} lto=thin, codegen-units=16, debug=false",
        label("release")
    );
}

/// The dev profile exactly as `profile::write_recommended` writes it. The
/// split-debuginfo key is Unix-only, so the summary must not claim it on
/// Windows.
pub(super) fn dev_profile_label(dev_debug: profile::DevDebug) -> String {
    match dev_debug {
        profile::DevDebug::Full => "debug=2".to_string(),
        profile::DevDebug::Line if cfg!(unix) => {
            "debug=line-tables-only, split-debuginfo=unpacked".to_string()
        }
        profile::DevDebug::Line => "debug=line-tables-only".to_string(),
        profile::DevDebug::None => "debug=false".to_string(),
    }
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
