//! Shared signed-document data types and their validation.
//!
//! The publisher and the reader both build and consume these plain data types;
//! nothing here depends back on the index, CAS or machine-comparison code.

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashSet;
use std::path::Path;

use super::{MAX_BLOB_BYTES, sha256_hex};
use crate::fingerprint::FingerprintJson;
use crate::settings::RemoteTier;

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

const EXECUTABLE_EXTENSIONS: [&str; 6] = ["exe", "dll", "dylib", "so", "dSYM", "efi"];
const MAX_REMOTE_PATH_BYTES: usize = 4096;
const MAX_SOURCE_ID_BYTES: usize = 4096;
const MAX_PACKAGE_VERSION_BYTES: usize = 128;

/// How a blob's stored bytes relate to the decoded file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Compression {
    Gzip,
    #[serde(rename = "none")]
    Raw,
}

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
            .flat_map(|unit| unit.compat.features().iter().cloned())
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

    pub fn features(&self) -> &[String] {
        &self.features
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

/// One unit group in the remote index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteUnit {
    /// `<package>-<16hex>`, exactly the Cargo fingerprint dir name.
    pub name: String,
    pub package: String,
    /// Package version recorded by Cargo's dep-info, when known. It is
    /// diagnostic only: Cargo's memo hash remains the authoritative key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub profile: String,
    /// Memo file name, e.g. `lib-serde`.
    pub memo: String,
    /// Memo hash — the authoritative 16-hex value Cargo compares.
    pub hash: String,
    /// Canonical mtime of the group (whole seconds).
    pub stamp: u64,
    pub layout: crate::fingerprint::UnitLayout,
    pub kind: RemoteUnitKind,
    pub source: UnitSource,
    pub compat: UnitCompatibility,
    pub files: Vec<RemoteFile>,
}

impl RemoteUnit {
    pub fn is_executable(&self) -> bool {
        self.kind.is_executable() || self.executable_file().is_some()
    }

    /// The reader-side tier boundary. A `libraries` reader may consume a
    /// `full` index, but it must never install an executable unit.
    pub fn importable_for(&self, reader: RemoteTier) -> bool {
        reader == RemoteTier::Full || !self.is_executable()
    }

    pub fn executable_file(&self) -> Option<&RemoteFile> {
        self.files
            .iter()
            .find(|file| file.role == FileRole::BuildTree || file.is_executable())
    }

    pub(crate) fn validate(&self) -> Result<()> {
        super::validate::component(&self.name, "remote unit name")?;
        super::validate::component(&self.package, "remote package")?;
        if let Some(version) = &self.version {
            super::validate::text(version, "remote package version", MAX_PACKAGE_VERSION_BYTES)?;
        }
        super::validate::component(&self.profile, "remote profile")?;
        super::validate::component(&self.memo, "remote memo file")?;
        let (package, suffix) = self
            .name
            .rsplit_once('-')
            .context("remote unit name must be <package>-<16hex>")?;
        ensure!(
            package == self.package,
            "remote unit name {:?} does not match package {:?}",
            self.name,
            self.package
        );
        ensure!(
            crate::fingerprint::looks_like_hash(suffix),
            "remote unit name {:?} needs a 16-hex suffix",
            self.name
        );
        ensure!(
            crate::fingerprint::looks_like_hash(&self.hash),
            "remote unit {:?} has an invalid memo hash",
            self.name
        );
        ensure!(self.stamp > 0, "remote unit {:?} has no stamp", self.name);
        let expected_kind = RemoteUnitKind::from(crate::fingerprint::classify_kind(&self.memo));
        ensure!(
            self.kind == expected_kind,
            "remote unit {:?} says {:?} but memo {:?} implies {:?}",
            self.name,
            self.kind,
            self.memo,
            expected_kind
        );
        self.source.validate()?;
        self.compat.validate()?;
        ensure!(
            !self.files.is_empty(),
            "remote unit {:?} has no files",
            self.name
        );

        let mut paths = HashSet::with_capacity(self.files.len());
        for file in &self.files {
            file.validate()?;
            ensure!(
                paths.insert(file.path.to_ascii_lowercase()),
                "duplicate case-insensitive file path {:?} in unit {:?}",
                file.path,
                self.name
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemoteUnitKind {
    Lib,
    BuildScript,
    BuildRun,
    Other,
}

impl RemoteUnitKind {
    /// Everything that is not a library unit can carry executable content
    /// (build scripts, run-build-script state, bins, tests). Proc-macro libs
    /// are caught by their shared-object file extension.
    pub fn is_executable(self) -> bool {
        !matches!(self, RemoteUnitKind::Lib)
    }
}

impl From<crate::fingerprint::UnitKind> for RemoteUnitKind {
    fn from(value: crate::fingerprint::UnitKind) -> Self {
        match value {
            crate::fingerprint::UnitKind::Lib => RemoteUnitKind::Lib,
            crate::fingerprint::UnitKind::BuildScriptCompile => RemoteUnitKind::BuildScript,
            crate::fingerprint::UnitKind::BuildScriptRun => RemoteUnitKind::BuildRun,
            crate::fingerprint::UnitKind::Other => RemoteUnitKind::Other,
        }
    }
}

/// Where a unit's source came from. Path/workspace units are always excluded
/// from a remote index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnitSource {
    pub kind: SourceKind,
    /// Registry index URL, git URL+rev, or the rejected local path.
    pub id: String,
    /// Registry checksum; `None` for git.
    pub checksum: Option<String>,
}

impl UnitSource {
    fn validate(&self) -> Result<()> {
        ensure!(
            !matches!(self.kind, SourceKind::Path | SourceKind::Workspace),
            "remote index contains a {:?} unit source; path/workspace units must never be published",
            self.kind
        );
        let what = match self.kind {
            SourceKind::Registry => "registry source",
            SourceKind::Git => "git source",
            SourceKind::Path | SourceKind::Workspace => unreachable!(),
        };
        super::validate::text(&self.id, what, MAX_SOURCE_ID_BYTES)?;
        super::validate::no_url_credentials(&self.id, what)?;

        match (self.kind, self.checksum.as_deref()) {
            (SourceKind::Registry, Some(checksum)) => {
                super::validate::lower_hex(checksum, 64, "registry checksum")?
            }
            (SourceKind::Registry, None) => {
                bail!("registry unit source needs a checksum")
            }
            (SourceKind::Git, Some(checksum)) => {
                super::validate::lower_hex(checksum, 64, "git checksum")?
            }
            (SourceKind::Git, None) => {}
            (SourceKind::Path | SourceKind::Workspace, _) => unreachable!(),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    Registry,
    Git,
    Path,
    Workspace,
}

/// What a stored file represents inside a unit group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileRole {
    Memo,
    Fingerprint,
    DepInfo,
    Artifact,
    BuildTree,
    Extra,
}

impl FileRole {
    /// The manifest spelling used by the local vault.
    pub fn as_str(self) -> &'static str {
        match self {
            FileRole::Memo => "memo",
            FileRole::Fingerprint => "fingerprint",
            FileRole::DepInfo => "dep-info",
            FileRole::Artifact => "artifact",
            FileRole::BuildTree => "build-tree",
            FileRole::Extra => "extra",
        }
    }
}

impl TryFrom<&str> for FileRole {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "memo" => Ok(FileRole::Memo),
            "fingerprint" => Ok(FileRole::Fingerprint),
            "dep-info" => Ok(FileRole::DepInfo),
            "artifact" => Ok(FileRole::Artifact),
            "build-tree" => Ok(FileRole::BuildTree),
            "extra" => Ok(FileRole::Extra),
            other => bail!("unknown remote file role {other:?}"),
        }
    }
}

/// One content-addressed file in a unit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteFile {
    /// Path inside the unit group.
    pub path: String,
    /// Path relative to the profile dir in a build dir.
    pub dest: String,
    /// Decoded size in bytes.
    pub size: u64,
    /// SHA-256 of the decoded bytes.
    pub sha256: String,
    pub role: FileRole,
    /// SHA-256 of the stored bytes; the CAS object key is `blobs/<blob>`.
    pub blob: String,
    /// Stored (possibly compressed) size in bytes.
    pub blob_size: u64,
    pub compression: Compression,
}

impl RemoteFile {
    pub fn blob_key(&self) -> Result<String> {
        super::blob_key(&self.blob)
    }

    pub fn is_executable(&self) -> bool {
        let name = self.path.rsplit('/').next().unwrap_or(&self.path);
        let Some((_, extension)) = name.rsplit_once('.') else {
            // Rustc library artifacts always have an extension; an
            // extensionless artifact in `deps/` is a binary.
            return self.role == FileRole::Artifact;
        };
        EXECUTABLE_EXTENSIONS
            .iter()
            .any(|candidate| extension.eq_ignore_ascii_case(candidate))
    }

    fn validate(&self) -> Result<()> {
        super::validate::relative_path(&self.path, "remote file path", MAX_REMOTE_PATH_BYTES)?;
        super::validate::relative_path(
            &self.dest,
            "remote destination path",
            MAX_REMOTE_PATH_BYTES,
        )?;
        ensure!(
            self.size <= MAX_BLOB_BYTES,
            "remote file {:?} is {} bytes (cap {MAX_BLOB_BYTES})",
            self.path,
            self.size
        );
        ensure!(
            self.blob_size <= MAX_BLOB_BYTES,
            "remote blob {:?} is {} bytes (cap {MAX_BLOB_BYTES})",
            self.path,
            self.blob_size
        );
        super::validate::lower_hex(&self.sha256, 64, "remote file SHA-256")?;
        super::validate::lower_hex(&self.blob, 64, "remote blob SHA-256")?;
        self.validate_blob()
    }

    fn validate_blob(&self) -> Result<()> {
        match self.compression {
            Compression::Raw => ensure!(
                self.blob == self.sha256 && self.blob_size == self.size,
                "uncompressed remote file {:?} must have blob == sha256 and \
                 blob_size == size",
                self.path
            ),
            Compression::Gzip => ensure!(
                self.blob_size > 0 && self.blob_size < self.size,
                "gzip remote file {:?} must be smaller than its decoded size",
                self.path
            ),
        }
        Ok(())
    }
}
