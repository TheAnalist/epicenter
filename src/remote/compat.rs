//! Compatibility tuples and local-vs-index diagnostics.
//!
//! The exact per-unit tuple is copied from Cargo's fingerprint JSON. The
//! fleet-level tuple records the machine identity (rustc, Cargo, target,
//! cargo-home, registry source path, flags) so `doctor`/`exec` can explain a
//! likely miss before Cargo recompiles.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::path::Path;

use super::{RemoteUnit, sha256_hex};
use crate::fingerprint::FingerprintJson;

const MAX_RUSTC_TEXT: usize = 256;
const MAX_REGISTRY_NAME: usize = 256;
const MAX_REGISTRY_INDEX: usize = 4096;
const MAX_CARGO: usize = 256;
const MAX_TARGET: usize = 256;
pub(crate) const MAX_PROFILES: usize = 64;
pub(crate) const MAX_PROFILE_BYTES: usize = 128;
pub(crate) const MAX_FEATURES: usize = 4096;
pub(crate) const MAX_FEATURE_BYTES: usize = 256;
pub(crate) const MAX_FLAGS: usize = 4096;
pub(crate) const MAX_FLAG_BYTES: usize = 16 * 1024;
pub(crate) const MAX_CARGO_HOME: usize = 4096;

/// `rustc -vV` facts that name a compiler.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustcIdentity {
    pub release: String,
    pub commit: String,
    pub host: String,
    /// Empty when the toolchain does not report an LLVM version.
    pub llvm: String,
}

impl RustcIdentity {
    fn validate(&self) -> Result<()> {
        super::validate::text(&self.release, "rustc release", MAX_RUSTC_TEXT)?;
        super::validate::text(&self.commit, "rustc commit", MAX_RUSTC_TEXT)?;
        super::validate::text(&self.host, "rustc host", MAX_RUSTC_TEXT)?;
        if !self.llvm.is_empty() {
            super::validate::text(&self.llvm, "rustc LLVM version", MAX_RUSTC_TEXT)?;
        }
        Ok(())
    }
}

/// The registry identity and the absolute-path digest that Cargo folds into
/// each unit's `path` hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistryIdentity {
    pub name: String,
    /// Registry index URL, e.g. `https://github.com/rust-lang/crates.io-index`.
    pub index: String,
    /// SHA-256 of the normalized absolute `$CARGO_HOME/registry/src` path.
    /// The path itself is not published.
    pub source_path_hash: String,
}

impl RegistryIdentity {
    fn validate(&self) -> Result<()> {
        super::validate::text(&self.name, "registry name", MAX_REGISTRY_NAME)?;
        super::validate::text(&self.index, "registry index", MAX_REGISTRY_INDEX)?;
        super::validate::no_url_credentials(&self.index, "registry index")?;
        super::validate::lower_hex(&self.source_path_hash, 64, "registry source path hash")?;
        Ok(())
    }
}

/// Fleet-level compatibility tuple.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Compatibility {
    pub rustc: RustcIdentity,
    pub cargo: String,
    pub target: String,
    /// Profiles present in this index, sorted and unique.
    pub profiles: Vec<String>,
    /// Union of unit features, sorted and unique.
    pub features: Vec<String>,
    /// `crate::vault::flags_digest` (8 hex characters).
    pub rustflags_digest: String,
    /// SHA-256 over the sorted unique unit `config` hashes.
    pub config_digest: String,
    /// Absolute `CARGO_HOME` string used by the publisher.
    pub cargo_home: String,
    /// `classic`, `new`, or `mixed`.
    pub layout: String,
    pub registry: RegistryIdentity,
}

impl Compatibility {
    /// Derive the fleet tuple from a local environment and the published units.
    pub fn from_local(local: &LocalEnvironment, units: &[RemoteUnit]) -> Result<Self> {
        let mut profiles: Vec<String> = units.iter().map(|unit| unit.profile.clone()).collect();
        profiles.sort();
        profiles.dedup();

        let mut features: Vec<String> = units
            .iter()
            .flat_map(|unit| unit.compat.features.iter().cloned())
            .collect();
        features.sort();
        features.dedup();

        let mut configs: Vec<&str> = units
            .iter()
            .map(|unit| unit.compat.config.as_str())
            .collect();
        configs.sort_unstable();
        configs.dedup();
        let mut config_input = String::new();
        for config in configs {
            config_input.push_str(config);
            config_input.push('\n');
        }

        let layout = if units.is_empty() {
            local.layout.clone()
        } else if units
            .iter()
            .all(|unit| unit.layout == crate::fingerprint::UnitLayout::Classic)
        {
            "classic".to_string()
        } else if units
            .iter()
            .all(|unit| unit.layout == crate::fingerprint::UnitLayout::New)
        {
            "new".to_string()
        } else {
            "mixed".to_string()
        };

        let compatibility = Compatibility {
            rustc: local.rustc.clone(),
            cargo: local.cargo.clone(),
            target: local.target.clone(),
            profiles,
            features,
            rustflags_digest: local.rustflags_digest.clone(),
            config_digest: sha256_hex(config_input.as_bytes()),
            cargo_home: local.cargo_home.clone(),
            layout,
            registry: local.registry.clone(),
        };
        compatibility.validate()?;
        Ok(compatibility)
    }

    pub fn validate(&self) -> Result<()> {
        self.rustc.validate()?;
        super::validate::text(&self.cargo, "cargo version", MAX_CARGO)?;
        super::validate::text(&self.target, "target", MAX_TARGET)?;
        super::validate::sorted_unique(
            &self.profiles,
            "compatibility profiles",
            MAX_PROFILES,
            MAX_PROFILE_BYTES,
        )?;
        super::validate::sorted_unique(
            &self.features,
            "compatibility features",
            MAX_FEATURES,
            MAX_FEATURE_BYTES,
        )?;
        super::validate::lower_hex(&self.rustflags_digest, 8, "rustflags digest")?;
        super::validate::lower_hex(&self.config_digest, 64, "config digest")?;
        super::validate::absolute_path(&self.cargo_home, "cargo home", MAX_CARGO_HOME)?;
        ensure!(
            matches!(self.layout.as_str(), "classic" | "new" | "mixed"),
            "unknown Cargo layout; expected classic, new or mixed"
        );
        self.registry.validate()?;
        Ok(())
    }

    /// Compare the machine-level fields with this machine. Profiles, features
    /// and per-unit fingerprints are checked when the reader filters units.
    pub fn compare_local(&self, local: &LocalEnvironment) -> Vec<Mismatch> {
        let mut out = Vec::new();
        compare(
            &mut out,
            "rustc release",
            &self.rustc.release,
            &local.rustc.release,
        );
        compare(
            &mut out,
            "rustc commit",
            &self.rustc.commit,
            &local.rustc.commit,
        );
        compare(&mut out, "rustc host", &self.rustc.host, &local.rustc.host);
        if !self.rustc.llvm.is_empty() && !local.rustc.llvm.is_empty() {
            compare(&mut out, "rustc LLVM", &self.rustc.llvm, &local.rustc.llvm);
        }
        compare(&mut out, "cargo", &self.cargo, &local.cargo);
        compare(&mut out, "target", &self.target, &local.target);
        compare_path(&mut out, "cargo home", &self.cargo_home, &local.cargo_home);
        compare(
            &mut out,
            "rustflags digest",
            &self.rustflags_digest,
            &local.rustflags_digest,
        );
        // A mixed index carries units for both layouts. The per-unit filter
        // selects this reader's layout; rejecting the index outright would
        // make a valid mixed publication unusable.
        if self.layout != "mixed" {
            compare(&mut out, "Cargo layout", &self.layout, &local.layout);
        }
        compare(
            &mut out,
            "registry name",
            &self.registry.name,
            &local.registry.name,
        );
        compare(
            &mut out,
            "registry index",
            &self.registry.index,
            &local.registry.index,
        );
        compare(
            &mut out,
            "registry source path",
            &self.registry.source_path_hash,
            &local.registry.source_path_hash,
        );
        out
    }
}

/// Exact per-unit tuple copied from Cargo's fingerprint JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnitCompatibility {
    /// Cargo's opaque rustc hash.
    pub rustc: String,
    pub target: String,
    pub profile: String,
    /// Parsed from Cargo's `features` JSON string.
    pub features: Vec<String>,
    pub rustflags: Vec<String>,
    /// Cargo's opaque config hash.
    pub config: String,
    /// Cargo's opaque source-path hash.
    pub path: String,
    pub compile_kind: String,
}

impl UnitCompatibility {
    pub fn from_fingerprint(json: &FingerprintJson) -> Self {
        Self {
            rustc: json.rustc.clone(),
            target: json.target.clone(),
            profile: json.profile.clone(),
            features: json.features.clone(),
            rustflags: json.rustflags.clone(),
            config: json.config.clone(),
            path: json.path.clone(),
            compile_kind: json.compile_kind.clone(),
        }
    }

    /// Stable digest of the exact tuple, for indexing and diagnostics.
    pub fn compat_key(&self) -> Result<String> {
        Ok(sha256_hex(&serde_json::to_vec(self)?))
    }

    pub fn validate(&self) -> Result<()> {
        super::validate::decimal(&self.rustc, "unit rustc hash")?;
        super::validate::decimal(&self.target, "unit target hash")?;
        super::validate::decimal(&self.profile, "unit profile hash")?;
        super::validate::decimal(&self.config, "unit config hash")?;
        super::validate::decimal(&self.path, "unit source path hash")?;
        super::validate::decimal(&self.compile_kind, "unit compile kind")?;
        super::validate::strings(
            &self.features,
            "unit features",
            MAX_FEATURES,
            MAX_FEATURE_BYTES,
        )?;
        super::validate::strings(&self.rustflags, "unit rustflags", MAX_FLAGS, MAX_FLAG_BYTES)?;
        Ok(())
    }
}

/// One mismatch between the publisher tuple and this machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Mismatch {
    pub field: String,
    pub expected: String,
    pub actual: String,
}

impl std::fmt::Display for Mismatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}: publisher {}, local {}",
            sanitize(&self.field),
            sanitize(&self.expected),
            sanitize(&self.actual)
        )
    }
}

/// Keep control bytes out of terminal output; the JSON form stays raw.
fn sanitize(value: &str) -> Cow<'_, str> {
    if value.chars().any(char::is_control) {
        Cow::Owned(crate::util::safe_display(std::ffi::OsStr::new(value)))
    } else {
        Cow::Borrowed(value)
    }
}

/// Machine-level facts used for compatibility checks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalEnvironment {
    pub rustc: RustcIdentity,
    pub cargo: String,
    pub target: String,
    pub cargo_home: String,
    pub rustflags_digest: String,
    pub layout: String,
    pub registry: RegistryIdentity,
}

impl LocalEnvironment {
    /// Collect `rustc -vV`, `cargo -V`, the effective cargo home and the
    /// registry source-path digest. Read-only and safe for `doctor`.
    pub fn gather() -> Result<Self> {
        Self::gather_for(None)
    }

    /// Gather for a rustup selector; `exec +nightly` must compare the child
    /// toolchain, not the default one.
    pub fn gather_for(selector: Option<&str>) -> Result<Self> {
        let rustc = local_rustc(selector)?;
        let cargo = local_cargo(selector)?;
        let target = std::env::var("CARGO_BUILD_TARGET")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| rustc.host.clone());
        let cargo_home = crate::paths::cargo_home()?;
        let cargo_home_text = cargo_home.to_string_lossy().to_string();
        let layout = match crate::fingerprint::layout_for_cargo(&cargo, &[]) {
            crate::fingerprint::UnitLayout::Classic => "classic",
            crate::fingerprint::UnitLayout::New => "new",
        }
        .to_string();
        let registry = local_registry(&cargo_home);
        let environment = Self {
            rustc: rustc.clone(),
            cargo,
            target,
            cargo_home: cargo_home_text,
            rustflags_digest: crate::vault::flags_digest_of(&rustc.host, selector),
            layout,
            registry,
        };
        environment.validate()?;
        Ok(environment)
    }

    fn validate(&self) -> Result<()> {
        self.rustc.validate()?;
        super::validate::text(&self.cargo, "cargo version", MAX_CARGO)?;
        super::validate::text(&self.target, "target", MAX_TARGET)?;
        super::validate::absolute_path(&self.cargo_home, "cargo home", MAX_CARGO_HOME)?;
        super::validate::lower_hex(&self.rustflags_digest, 8, "rustflags digest")?;
        ensure!(
            matches!(self.layout.as_str(), "classic" | "new" | "mixed"),
            "unknown Cargo layout; expected classic, new or mixed"
        );
        self.registry.validate()
    }
}

/// Compare a verified index tuple with this machine and return readable
/// mismatch lines. Empty means the machine-level tuple matches.
pub fn compare_compatibility(
    compatibility: &Compatibility,
    local: &LocalEnvironment,
) -> Vec<Mismatch> {
    compatibility.compare_local(local)
}

fn local_rustc(selector: Option<&str>) -> Result<RustcIdentity> {
    let info = crate::toolchain::rustc_info(selector)?;
    Ok(RustcIdentity {
        release: info.release,
        commit: info.commit,
        host: info.host,
        llvm: info.llvm,
    })
}

fn local_cargo(selector: Option<&str>) -> Result<String> {
    crate::toolchain::cargo_version(selector)
}

/// Registry identity from Cargo's config, defaulting to crates.io.
fn local_registry(cargo_home: &Path) -> RegistryIdentity {
    let mut name = "crates-io".to_string();
    let mut index = "https://github.com/rust-lang/crates.io-index".to_string();
    if let Ok(path) = crate::config::cargo_config_path()
        && let Ok(text) = crate::util::read_trusted_config(&path, 1024 * 1024)
    {
        if let Some(replacement) =
            crate::config::read_table_key(&text, "source.crates-io", "replace-with")
        {
            name = replacement.clone();
            let table = format!("source.{replacement}");
            if let Some(url) = crate::config::read_table_key(&text, &table, "registry") {
                index = url;
            } else if let Some(url) = crate::config::read_table_key(&text, &table, "local-registry")
            {
                index = format!("local-registry+{url}");
            } else if let Some(url) = crate::config::read_table_key(&text, &table, "directory") {
                index = format!("directory+{url}");
            }
        } else if let Some(url) =
            crate::config::read_table_key(&text, "source.crates-io", "registry")
        {
            index = url;
        }
    }
    RegistryIdentity {
        name,
        index,
        source_path_hash: source_path_hash(cargo_home),
    }
}

/// SHA-256 of the normalized absolute `$CARGO_HOME/registry/src` path.
pub fn source_path_hash(cargo_home: &Path) -> String {
    let path = cargo_home.join("registry").join("src");
    sha256_hex(path_key(&path.to_string_lossy()).as_bytes())
}

fn compare(out: &mut Vec<Mismatch>, field: &str, expected: &str, actual: &str) {
    if expected != actual {
        push_mismatch(out, field, expected, actual);
    }
}

fn compare_path(out: &mut Vec<Mismatch>, field: &str, expected: &str, actual: &str) {
    if path_key(expected) != path_key(actual) {
        push_mismatch(out, field, expected, actual);
    }
}

fn push_mismatch(out: &mut Vec<Mismatch>, field: &str, expected: &str, actual: &str) {
    out.push(Mismatch {
        field: field.to_string(),
        expected: expected.to_string(),
        actual: actual.to_string(),
    });
}

fn path_key(value: &str) -> String {
    let mut text = value.replace('\\', "/");
    while text.len() > 1 && text.ends_with('/') {
        text.pop();
    }
    if cfg!(windows) {
        text.make_ascii_lowercase();
    }
    text
}
