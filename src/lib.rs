//! Core library behind the `epicenter` CLI — the state layer for Cargo builds.
//!
#![doc = include_str!("../README.md")]

mod cache;
mod diagnostics;
mod support;

pub mod env;
pub mod fingerprint;
pub mod job;
pub mod remote;
pub mod util;
pub mod vault;

pub use cache::{evict, exec, prune, status, who};
pub use diagnostics::{doctor, profile};
pub use support::{config, fastlink, lockfile, paths, settings, toolchain};
