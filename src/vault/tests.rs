//! Vault tests, split by subject.

use super::*;

use std::fs;
#[cfg(not(unix))]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use anyhow::Result;

use crate::fingerprint;
use crate::settings::LinkPolicy;
use crate::util;
use crate::util::now_secs;
use sha2::{Digest, Sha256};

mod compact_overlap;
mod harvest;
mod import;
mod restore;
mod security;
mod support;
mod verify;
