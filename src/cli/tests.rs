use std::path::Path;

use clap::Parser;

use super::args::{
    Cli, Command, DevDebugArg, LinkerArg, PresetArg, RemoteTierArg, StoreCommand, WrapperArg,
};

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
fn setup_rejects_remote_off_combined_with_remote_configuration() {
    for (flag, value) in [
        ("--remote-url", "https://cache.example"),
        ("--remote-key", "key.pub"),
        ("--remote-tier", "libraries"),
    ] {
        let error = Cli::try_parse_from(["epicenter", "setup", "--remote-off", flag, value])
            .err()
            .unwrap_or_else(|| panic!("--remote-off must conflict with {flag}"));
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
}

#[test]
fn setup_requires_write_profile_for_dev_debug() {
    let error = Cli::try_parse_from(["epicenter", "setup", "--dev-debug", "line"])
        .err()
        .expect("--dev-debug requires --write-profile");
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
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
    let cli = Cli::try_parse_from(["epicenter", "setup", "--write-profile", "--dry-run"]).unwrap();
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
    let cli = Cli::try_parse_from(["epicenter", "status", "--units", "--filter", "serde"]).unwrap();
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

#[test]
fn publish_accepts_ci_flags() {
    let cli = Cli::try_parse_from([
        "epicenter",
        "store",
        "publish",
        "--url",
        "s3://bucket/prefix",
        "--reader-url",
        "https://cache.example/prefix",
        "--tier",
        "full",
        "--profile",
        "release",
        "--toolchain",
        "nightly",
        "--valid-for",
        "7d",
        "--dry-run",
        "--reset-sequence",
    ])
    .unwrap();
    match cli.command {
        Command::Store {
            command: StoreCommand::Publish(args),
        } => {
            assert_eq!(args.url.as_deref(), Some("s3://bucket/prefix"));
            assert!(matches!(args.tier, Some(RemoteTierArg::Full)));
            assert_eq!(args.profile.as_deref(), Some("release"));
            assert_eq!(args.toolchain.as_deref(), Some("nightly"));
            assert_eq!(args.valid_for, "7d");
            assert!(args.dry_run);
            assert!(args.reset_sequence);
        }
        _ => panic!("expected store publish"),
    }
}

#[test]
fn compact_accepts_generation_and_dry_run() {
    let cli = Cli::try_parse_from([
        "epicenter",
        "store",
        "compact",
        "--generation",
        "1.99",
        "--dry-run",
    ])
    .unwrap();
    match cli.command {
        Command::Store {
            command: StoreCommand::Compact(args),
        } => {
            assert_eq!(args.generation.as_deref(), Some("1.99"));
            assert!(args.dry_run);
        }
        _ => panic!("expected store compact"),
    }
}

#[test]
fn overlap_accepts_detail_and_json() {
    let cli = Cli::try_parse_from(["epicenter", "store", "overlap", "--detail", "--json"]).unwrap();
    match cli.command {
        Command::Store {
            command: StoreCommand::Overlap(args),
        } => {
            assert!(args.detail);
            assert!(args.json);
        }
        _ => panic!("expected store overlap"),
    }
}

#[test]
fn fetch_accepts_dry_run_unit_and_all() {
    let cli = Cli::try_parse_from([
        "epicenter",
        "store",
        "fetch",
        "--dry-run",
        "--unit",
        "serde",
        "--all",
    ])
    .unwrap();
    match cli.command {
        Command::Store {
            command: StoreCommand::Fetch(args),
        } => {
            assert!(args.dry_run);
            assert_eq!(args.unit.as_deref(), Some("serde"));
            assert!(args.all);
        }
        _ => panic!("expected store fetch"),
    }
}

#[test]
fn setup_revert_is_detected_before_policy_load() {
    let cli = Cli::try_parse_from(["epicenter", "setup", "--revert"]).unwrap();
    assert!(super::setup_revert(&cli.command).is_some());

    let cli = Cli::try_parse_from(["epicenter", "setup", "--dry-run"]).unwrap();
    assert!(super::setup_revert(&cli.command).is_none());
}

#[test]
fn exec_target_dir_takes_its_value_only_after_equals() {
    let cli = Cli::try_parse_from(["epicenter", "exec", "--target-dir", "cargo", "test"]).unwrap();
    match cli.command {
        Command::Exec {
            target_dir,
            command,
            ..
        } => {
            assert_eq!(target_dir.as_deref(), Some("job"));
            assert_eq!(command, vec!["cargo".to_string(), "test".to_string()]);
        }
        _ => panic!("expected exec"),
    }

    let cli = Cli::try_parse_from([
        "epicenter",
        "exec",
        "--target-dir=out",
        "--",
        "cargo",
        "test",
    ])
    .unwrap();
    match cli.command {
        Command::Exec {
            target_dir,
            command,
            ..
        } => {
            assert_eq!(target_dir.as_deref(), Some("out"));
            assert_eq!(command, vec!["cargo".to_string(), "test".to_string()]);
        }
        _ => panic!("expected exec"),
    }

    let cli = Cli::try_parse_from(["epicenter", "exec", "--target-dir", "--", "true"]).unwrap();
    match cli.command {
        Command::Exec {
            target_dir,
            command,
            ..
        } => {
            assert_eq!(target_dir.as_deref(), Some("job"));
            assert_eq!(command, vec!["true".to_string()]);
        }
        _ => panic!("expected exec"),
    }
}

#[test]
fn wrapper_from_environment_or_config_counts() {
    use std::ffi::OsString;

    let none: [Option<OsString>; 2] = [None, None];
    assert!(!super::build::wrapper_configured(&none, None));
    assert!(!super::build::wrapper_configured(&none, Some("")));
    assert!(super::build::wrapper_configured(&none, Some("sccache")));

    let env: [Option<OsString>; 2] = [Some(OsString::from("sccache")), None];
    assert!(super::build::wrapper_configured(&env, None));

    let env: [Option<OsString>; 2] = [None, Some(OsString::from("kache"))];
    assert!(super::build::wrapper_configured(&env, None));
}

#[test]
fn profile_summary_matches_the_written_dev_debug() {
    use epicenter_cli::profile::DevDebug;

    assert_eq!(super::setup::dev_profile_label(DevDebug::Full), "debug=2");
    assert_eq!(
        super::setup::dev_profile_label(DevDebug::None),
        "debug=false"
    );
    let line = super::setup::dev_profile_label(DevDebug::Line);
    if cfg!(unix) {
        assert!(line.contains("split-debuginfo=unpacked"));
    } else {
        assert!(!line.contains("split-debuginfo"));
    }
}

#[test]
fn doctor_renders_a_policy_error_as_a_check() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let global = dir.path().join("epicenter.toml");
    std::fs::write(&global, "[remote]\nurl = \"https://cache.example/root\"\n")?;
    let settings = epicenter_cli::settings::Settings::load_at(dir.path(), Some(&global))?;
    let (checks, profile) = super::build::read_policy_checks(&settings);
    assert!(profile.is_none(), "an invalid policy has no summary");
    assert_eq!(checks.len(), 1);
    assert!(matches!(
        checks[0].level,
        epicenter_cli::doctor::Level::Fail
    ));
    assert!(checks[0].message.contains("policy"));
    Ok(())
}

#[test]
fn dry_run_always_wins_over_confirmation_flags() {
    for dry_run in [false, true] {
        for yes in [false, true] {
            for y in [false, true] {
                assert_eq!(
                    super::confirmed_delete(dry_run, yes, y),
                    !dry_run && (yes || y)
                );
            }
        }
    }
    assert!(!super::confirmed_delete(true, false, true));
    assert!(!super::confirmed_delete(true, true, false));
    assert!(super::confirmed_delete(false, false, true));
    assert!(super::confirmed_delete(false, true, false));
}
