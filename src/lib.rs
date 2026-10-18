//! Core library behind the `epicenter` CLI — the state layer for Cargo builds.
//!
#![doc = include_str!("../README.md")]

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
