//! # epicenter
//!
//! Core library behind the `epicenter` CLI: the state layer for Cargo builds.
//! Three tiers, one manager — the durable vault (`store/`, keyed by Cargo's own
//! fingerprint hashes), the shared build cache every project compiles into
//! (`build/`, the same canonical template line in every cargo config on every
//! OS), and disposable per-job working dirs (`work/<id>/`, seeded from the
//! vault via `exec`).
//!
//! The mechanism is Cargo's own `build.build-dir` setting (stabilized in 2025):
//! `target-dir` keeps holding final artifacts (binaries, docs) while all
//! intermediate artifacts — dependency rlibs, incremental caches, build-script
//! outputs, i.e. the >95% bulk of a `target/` directory — are redirected to the
//! shared cache. Optionally a rustc-wrapper (kache or sccache) adds a second
//! layer: compile-result caching across flag/rustc changes and machines.
//!
//! On top of that foundation epicenter owns the lifecycle of build state —
//! configure, observe, reclaim, persist, execute:
//!
//! | module    | role |
//! |-----------|------|
//! | `paths`   | where things live (`$HOME`, `$CARGO_HOME`, cache root) |
//! | `config`  | epicenter's own config + editing Cargo's global `config.toml` |
//! | `prune`   | classifies artifacts into build "units" and garbage-collects them |
//! | `status`  | read-only inspection / statistics |
//! | `doctor`  | sanity checks with plain-language advice |
//! | `vault`   | durable store of unit groups + harvest / restore / verify |
//! | `exec`    | run a command against a fresh per-job dir seeded from the vault |
//! | `util`    | small formatting/parsing helpers |

pub mod config;
pub mod doctor;
pub mod evict;
pub mod exec;
pub mod fingerprint;
pub mod paths;
pub mod prune;
pub mod status;
pub mod util;
pub mod vault;
pub mod who;
