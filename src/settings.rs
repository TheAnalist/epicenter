//! Epicenter policy: presets, `epicenter.toml`, and safe auto-detection.
//!
//! Precedence is always **CLI > project file > global file > auto**:
//!
//! - project file: the nearest `epicenter.toml` walking up from the working
//!   directory (never outside it);
//! - global file: the OS config path (`$XDG_CONFIG_HOME`, Application Support
//!   or `%APPDATA%`), independent of `CARGO_HOME`;
//! - auto: `CI` selects the CI preset, otherwise the dev preset; memory and
//!   cores come from the machine.
//!
//! `setup` writes the **global** files only (Cargo config + this global
//! `epicenter.toml`); a project file is user-owned and read-only.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::util::metadata_nofollow;

/// Machine-level (and project-level) epicenter policy file name.
pub const FILE_NAME: &str = "epicenter.toml";

/// Conservative per-job memory footprint for the auto job cap. The measured
/// 37-dep build used ~0.25 GiB/job; 2 GiB keeps a wide machine safe without
/// starving the edit loop.
pub const JOB_FOOTPRINT: u64 = 2 * 1024 * 1024 * 1024;

/// A user intent, as written in `epicenter.toml` or passed to `setup`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Preset {
    Auto,
    Dev,
    Ci,
}

impl Preset {
    pub fn as_str(self) -> &'static str {
        match self {
            Preset::Auto => "auto",
            Preset::Dev => "dev",
            Preset::Ci => "ci",
        }
    }
}

/// The preset auto resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectivePreset {
    Dev,
    Ci,
}

impl EffectivePreset {
    pub fn as_str(self) -> &'static str {
        match self {
            EffectivePreset::Dev => "dev",
            EffectivePreset::Ci => "ci",
        }
    }
}

/// Linker selection. `Auto` keeps the existing managed state (it never
/// rewrites rustflags just because setup ran); the other values are explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkerChoice {
    Auto,
    System,
    Lld,
    Wild,
    Mold,
    Gold,
}

impl LinkerChoice {
    pub fn as_str(self) -> &'static str {
        match self {
            LinkerChoice::Auto => "auto",
            LinkerChoice::System => "system",
            LinkerChoice::Lld => "lld",
            LinkerChoice::Wild => "wild",
            LinkerChoice::Mold => "mold",
            LinkerChoice::Gold => "gold",
        }
    }
}

/// How restore installs immutable artifacts into a view.
///
/// * `auto` — reflink when the filesystem supports it; hard-link only a
///   read-only mount or a foreign immutable source; copy a writable store.
/// * `copy` — never hard-link; reflink or copy.
/// * `link` — force hard links (only valid in the global policy file).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkPolicy {
    Auto,
    Copy,
    Link,
}

impl LinkPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            LinkPolicy::Auto => "auto",
            LinkPolicy::Copy => "copy",
            LinkPolicy::Link => "link",
        }
    }

    /// Higher is stricter: a project file may tighten but never loosen the
    /// global policy.
    fn strictness(self) -> u8 {
        match self {
            LinkPolicy::Link => 0,
            LinkPolicy::Auto => 1,
            LinkPolicy::Copy => 2,
        }
    }
}

/// Where an effective value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Cli,
    Project,
    Global,
    Auto,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Cli => "cli",
            Source::Project => "project epicenter.toml",
            Source::Global => "global epicenter.toml",
            Source::Auto => "auto",
        }
    }
}

/// A memory budget: integer MiB, or a string with a unit (`8GiB`, `500M`).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Memory {
    Text(String),
    Number(u64),
}

impl Memory {
    pub fn bytes(&self) -> Result<u64> {
        match self {
            Memory::Text(raw) => parse_memory(raw),
            // A bare number in TOML is MiB: the least surprising unit for a
            // budget, and still explicit in the docs.
            Memory::Number(mib) => mib
                .checked_mul(1024 * 1024)
                .ok_or_else(|| anyhow::anyhow!("memory budget is too large")),
        }
    }
}

/// The handful of keys epicenter reads from `epicenter.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FileConfig {
    pub preset: Option<Preset>,
    pub memory: Option<Memory>,
    pub linker: Option<LinkerChoice>,
    pub link: Option<LinkPolicy>,
    pub store: Option<String>,
    pub work: Option<String>,
}

/// One resolved config file, with the directory used for relative paths.
#[derive(Debug, Clone)]
struct Loaded {
    path: PathBuf,
    preset: Option<Preset>,
    memory: Option<u64>,
    linker: Option<LinkerChoice>,
    link: Option<LinkPolicy>,
    store: Option<String>,
    work: Option<String>,
}

impl Loaded {
    fn read(path: &Path) -> Result<Option<Self>> {
        let meta = match metadata_nofollow(path) {
            Ok(meta) => meta,
            // A missing project file is normal; a missing global file means
            // "no explicit policy", not an error.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                anyhow::bail!(
                    "configuration path {} is a symlink/reparse or not a regular file",
                    path.display()
                );
            }
            Err(err) => {
                return Err(err).with_context(|| format!("inspecting {}", path.display()));
            }
        };
        if !meta.is_file() {
            anyhow::bail!(
                "configuration path {} is a symlink/reparse or not a regular file",
                path.display()
            );
        }
        let text = crate::util::read_trusted_config(path, 1024 * 1024)
            .with_context(|| format!("reading {}", path.display()))?;
        let config: FileConfig =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        Ok(Some(Self {
            path: path.to_path_buf(),
            preset: config.preset,
            memory: config.memory.map(|memory| memory.bytes()).transpose()?,
            linker: config.linker,
            link: config.link,
            store: config.store,
            work: config.work,
        }))
    }

    fn base(&self) -> &Path {
        self.path.parent().unwrap_or(Path::new("."))
    }
}

/// Project + global epicenter policy, already resolved to concrete values.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    project: Option<Loaded>,
    global: Option<Loaded>,
}

/// Convenience loader used by the CLI.
pub fn load(cwd: &Path) -> Result<Settings> {
    Settings::load(cwd)
}

impl Settings {
    /// Load the nearest project file and the global file. `cwd` is the
    /// command's working directory (`exec --cwd` uses the child's directory).
    /// The global path is resolved without consulting `CARGO_HOME`.
    pub fn load(cwd: &Path) -> Result<Self> {
        let global = crate::paths::global_config_path()?;
        Self::load_at(cwd, Some(&global))
    }

    /// Testable loader: `global` may be `None` to exercise project/auto only.
    pub fn load_at(cwd: &Path, global: Option<&Path>) -> Result<Self> {
        let cwd = if cwd.is_absolute() {
            cwd.to_path_buf()
        } else {
            std::env::current_dir()
                .context("resolving the working directory")?
                .join(cwd)
        };
        let project = match find_project(&cwd) {
            Some(path) => match Loaded::read(&path) {
                Ok(loaded) => loaded,
                Err(err) => {
                    // A malformed repository policy must not brick unrelated
                    // commands. Keep the global fallback and say why.
                    eprintln!(
                        "warning: ignoring invalid project config {}: {err:#}",
                        path.display()
                    );
                    None
                }
            },
            None => None,
        };
        let global = global.map(|path| Loaded::read(path)).transpose()?.flatten();
        Ok(Self { project, global })
    }

    pub fn preset(&self) -> (Preset, Source) {
        if let Some(value) = self.project.as_ref().and_then(|file| file.preset) {
            return (value, Source::Project);
        }
        if let Some(value) = self.global.as_ref().and_then(|file| file.preset) {
            return (value, Source::Global);
        }
        (Preset::Auto, Source::Auto)
    }

    pub fn linker(&self) -> (LinkerChoice, Source) {
        if let Some(value) = self.project.as_ref().and_then(|file| file.linker) {
            return (value, Source::Project);
        }
        if let Some(value) = self.global.as_ref().and_then(|file| file.linker) {
            return (value, Source::Global);
        }
        (LinkerChoice::Auto, Source::Auto)
    }

    /// How restore installs immutable artifacts.
    ///
    /// Precedence is by *strictness*: a project file may tighten a global
    /// policy (`auto` -> `copy`) but cannot loosen it. `link` is only valid
    /// in the global file: a repository must not force shared inodes.
    pub fn link(&self) -> Result<(LinkPolicy, Source)> {
        let project = self.project.as_ref().and_then(|file| file.link);
        if project == Some(LinkPolicy::Link) {
            bail!(
                "`link = \"link\"` is only allowed in the global epicenter.toml; \
                 a project may choose `auto` or `copy`"
            );
        }
        let global = self.global.as_ref().and_then(|file| file.link);
        let mut chosen = (LinkPolicy::Auto, Source::Auto);
        if let Some(policy) = global {
            chosen = (policy, Source::Global);
        }
        if let Some(policy) = project {
            if policy.strictness() > chosen.0.strictness() {
                chosen = (policy, Source::Project);
            } else if policy == chosen.0 && chosen.1 == Source::Global {
                chosen.1 = Source::Project;
            }
        }
        Ok(chosen)
    }

    /// Memory budget: project > global > physical RAM.
    pub fn memory_bytes(&self) -> (Option<u64>, Source) {
        if let Some(value) = self.project.as_ref().and_then(|file| file.memory) {
            return (Some(value), Source::Project);
        }
        if let Some(value) = self.global.as_ref().and_then(|file| file.memory) {
            return (Some(value), Source::Global);
        }
        (physical_memory(), Source::Auto)
    }

    /// Store path: project > global > default (`<build>/../store`).
    ///
    /// A project file is repository input, so a project-selected store is
    /// held to a stricter standard than the global one: it may not contain
    /// `..`, may not be the project directory or an ancestor of it, and an
    /// existing directory must already be a marked, private epicenter store.
    pub fn store(&self) -> Result<Option<(PathBuf, Source)>> {
        if let Some(file) = &self.project {
            if let Some(raw) = file.store.as_deref() {
                let path = resolve_path(raw, file.base())?;
                validate_project_store(&path, file.base())
                    .with_context(|| format!("project store in {}", file.path.display()))?;
                return Ok(Some((path, Source::Project)));
            }
        }
        if let Some(file) = &self.global {
            if let Some(raw) = file.store.as_deref() {
                let path = resolve_path(raw, file.base())?;
                validate_store_path(&path)?;
                return Ok(Some((path, Source::Global)));
            }
        }
        Ok(None)
    }

    /// Global-only local work root. A project file cannot redirect job dirs:
    /// `exec` creates and removes directories there, so the same rule as
    /// `store` applies. `None` means the per-user OS-local default.
    pub fn work_root(&self) -> Result<Option<(PathBuf, Source)>> {
        if self
            .project
            .as_ref()
            .and_then(|file| file.work.as_deref())
            .is_some()
        {
            bail!(
                "`work` is only allowed in the global epicenter.toml; \
                 a project must not redirect the writable work root"
            );
        }
        if let Some(file) = &self.global {
            if let Some(raw) = file.work.as_deref() {
                let path = resolve_policy_path(raw, file.base(), "work")?;
                return Ok(Some((path, Source::Global)));
            }
        }
        Ok(None)
    }

    /// Configured work root, or the OS-local default.
    pub fn work_root_or_default(&self) -> Result<(PathBuf, Source)> {
        match self.work_root()? {
            Some((path, source)) => Ok((path, source)),
            None => Ok((crate::paths::default_work_root()?, Source::Auto)),
        }
    }

    pub fn project_path(&self) -> Option<&Path> {
        self.project.as_ref().map(|file| file.path.as_path())
    }

    pub fn global_path(&self) -> Option<&Path> {
        self.global.as_ref().map(|file| file.path.as_path())
    }

    /// `auto` is dev on a workstation and ci when the environment says so.
    pub fn effective_preset(&self) -> (EffectivePreset, Preset, Source) {
        let (preset, source) = self.preset();
        (resolve_preset(preset, ci_environment()), preset, source)
    }

    /// `None` means "leave Cargo's own default alone".
    pub fn incremental(&self) -> Option<bool> {
        match self.effective_preset().0 {
            EffectivePreset::Dev => Some(true),
            EffectivePreset::Ci => Some(false),
        }
    }

    pub fn check_tier(&self) -> bool {
        self.effective_preset().0 == EffectivePreset::Ci
    }

    /// Copied artifacts are gzip-compressed at harvest; library outputs are
    /// stored raw. `store harvest --no-compress` opts out for CPU-starved hosts.
    pub fn compression(&self) -> bool {
        true
    }

    pub fn restore(&self) -> bool {
        true
    }
}

/// Nearest `epicenter.toml`, but never above the workspace root. A shared
/// parent directory can be written by a co-tenant; an ancestor policy file
/// must not be able to redirect the store or the profile.
fn find_project(cwd: &Path) -> Option<PathBuf> {
    let stop = workspace_root(cwd).unwrap_or_else(|| cwd.to_path_buf());
    for dir in cwd.ancestors() {
        let candidate = dir.join(FILE_NAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        if dir == stop {
            break;
        }
    }
    None
}

/// The nearest directory that marks a workspace (`.git` or `Cargo.toml`).
fn workspace_root(cwd: &Path) -> Option<PathBuf> {
    for dir in cwd.ancestors() {
        if dir.join(".git").exists() || dir.join("Cargo.toml").is_file() {
            return Some(dir.to_path_buf());
        }
    }
    None
}

/// Reject a project-selected store before any write/deletion can reach it.
fn validate_project_store(path: &Path, project_dir: &Path) -> Result<()> {
    validate_store_path(path)?;
    // `store = ".."` / `"."` would make the sweep and chmod target the
    // project or its parent. A store may live inside the project (a marked
    // local vault) but never contain it.
    if project_dir.starts_with(path) {
        bail!(
            "store {} must not be the project directory or an ancestor of it",
            path.display()
        );
    }
    match crate::util::metadata_nofollow(path) {
        Ok(meta) => {
            if !meta.is_dir() {
                bail!("store {} is not a real directory", path.display());
            }
            if !crate::util::owned_by_us(path, &meta) {
                bail!("store {} is owned by another user", path.display());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if meta.mode() & 0o077 != 0 {
                    bail!(
                        "project store {} is accessible by other users (mode {:o}); a project-selected store must be 0700",
                        path.display(),
                        meta.mode() & 0o777
                    );
                }
            }
            let marker = path.join(crate::vault::STORE_MARKER);
            if !marker.is_file() {
                // An empty directory is a fresh store: the writer creates and
                // marks it. A non-empty unmarked directory is the dangerous
                // case (`store = "~/.cargo"`, `store = "~/.config"`).
                let empty = std::fs::read_dir(path)
                    .map(|mut entries| entries.next().is_none())
                    .unwrap_or(false);
                if !empty {
                    bail!(
                        "store {} is not an epicenter store (missing {}); use the global store or an empty directory",
                        path.display(),
                        crate::vault::STORE_MARKER
                    );
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            bail!("store {} is not a real directory", path.display());
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).with_context(|| format!("inspecting {}", path.display())),
    }
    Ok(())
}

/// Paths that must never be used as a store, regardless of source.
fn validate_store_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("store path {} must be absolute", path.display());
    }
    if path.parent().is_none() {
        bail!(
            "store path {} must not be a filesystem root",
            path.display()
        );
    }
    if let Ok(home) = crate::paths::home() {
        if path == home || home.starts_with(path) {
            bail!(
                "store path {} must not be the home directory or its ancestor",
                path.display()
            );
        }
    }
    let temp = std::env::temp_dir();
    if path == temp || temp.starts_with(path) {
        bail!(
            "store path {} must not be the temporary directory or its ancestor",
            path.display()
        );
    }
    // Reject a symlinked final component even when the target is benign: the
    // store is a deletion root, so its identity must be the directory itself.
    match crate::util::metadata_nofollow(path) {
        Ok(meta) => {
            if !meta.is_dir() {
                bail!("store path {} is not a real directory", path.display());
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            bail!("store path {} is not a real directory", path.display());
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).with_context(|| format!("inspecting {}", path.display())),
    }
    Ok(())
}

/// Resolve a configured path: `~`, absolute, or relative to the config file.
fn resolve_policy_path(raw: &str, base: &Path, what: &str) -> Result<PathBuf> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("`{what}` must not be empty");
    }
    if Path::new(raw)
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!("`{what}` must not contain `..`; use an absolute or home-relative path");
    }
    if raw == "~" || raw.starts_with("~/") || raw.starts_with("~\\") {
        let rest = raw[1..].trim_start_matches(['/', '\\']);
        return Ok(crate::paths::home()?.join(rest));
    }
    let path = PathBuf::from(raw);
    Ok(normalize(if path.is_absolute() {
        path
    } else {
        base.join(path)
    }))
}

fn resolve_path(raw: &str, base: &Path) -> Result<PathBuf> {
    resolve_policy_path(raw, base, "store")
}

/// Lexically remove `.`/`..` so reported store paths are stable.
fn normalize(path: PathBuf) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Parse `512MiB`, `8GiB`, `2T`, or `500M`; a bare number is MiB.
pub fn parse_memory(raw: &str) -> Result<u64> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("memory value must not be empty");
    }
    let number: String = raw
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == '.')
        .collect();
    if number.is_empty() {
        bail!("memory value {raw:?} must start with a number");
    }
    let unit = raw[number.len()..].trim().to_ascii_lowercase();
    let multiplier: u64 = match unit.as_str() {
        "" | "mib" | "m" | "mb" => 1024 * 1024,
        "gib" | "g" | "gb" => 1024 * 1024 * 1024,
        "kib" | "k" | "kb" => 1024,
        "tib" | "t" | "tb" => 1024u64 * 1024 * 1024 * 1024,
        "b" => 1,
        other => bail!("unknown memory unit {other:?} (use KiB/MiB/GiB/TiB)"),
    };
    let value: f64 = number
        .parse()
        .with_context(|| format!("parsing memory value {raw:?}"))?;
    let bytes = value * multiplier as f64;
    if !bytes.is_finite() || bytes < 0.0 || bytes > u64::MAX as f64 {
        bail!("memory value {raw:?} is out of range");
    }
    Ok(bytes as u64)
}

/// Auto preset: CI when `CI` is truthy, dev otherwise.
pub fn resolve_preset(preset: Preset, ci: bool) -> EffectivePreset {
    match preset {
        Preset::Dev => EffectivePreset::Dev,
        Preset::Ci => EffectivePreset::Ci,
        Preset::Auto if ci => EffectivePreset::Ci,
        Preset::Auto => EffectivePreset::Dev,
    }
}

/// Common CI markers (`CI=true`, `CI=1`, ...).
pub fn ci_environment() -> bool {
    std::env::var_os("CI")
        .map(|value| {
            !matches!(
                value.to_string_lossy().to_ascii_lowercase().as_str(),
                "" | "0" | "false" | "no"
            )
        })
        .unwrap_or(false)
}

/// Logical cores, at least one.
pub fn available_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Workers for vault file copies. One per core up to eight: a two-core laptop
/// gets two, a many-core workstation gets eight without thrashing the disk.
pub fn copy_workers() -> usize {
    available_cores().clamp(1, 8)
}

/// Jobs = cores, capped by the memory budget; 2 GiB per job.
pub fn job_cap(cores: usize, memory: Option<u64>) -> usize {
    let cores = cores.max(1);
    let by_memory = memory
        .map(|bytes| (bytes / JOB_FOOTPRINT).max(1) as usize)
        .unwrap_or(usize::MAX);
    cores.min(by_memory).max(1)
}

/// Physical RAM, or `None` when the platform has no cheap query.
#[cfg(unix)]
pub fn physical_memory() -> Option<u64> {
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if pages > 0 && page_size > 0 {
        Some((pages as u64).saturating_mul(page_size as u64))
    } else {
        None
    }
}

#[cfg(windows)]
pub fn physical_memory() -> Option<u64> {
    #[repr(C)]
    #[allow(non_snake_case)]
    struct MemoryStatusEx {
        length: u32,
        memory_load: u32,
        total_phys: u64,
        avail_phys: u64,
        total_page_file: u64,
        avail_page_file: u64,
        total_virtual: u64,
        avail_virtual: u64,
        avail_extended_virtual: u64,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GlobalMemoryStatusEx(buffer: *mut MemoryStatusEx) -> i32;
    }

    let mut status = MemoryStatusEx {
        length: std::mem::size_of::<MemoryStatusEx>() as u32,
        memory_load: 0,
        total_phys: 0,
        avail_phys: 0,
        total_page_file: 0,
        avail_page_file: 0,
        total_virtual: 0,
        avail_virtual: 0,
        avail_extended_virtual: 0,
    };
    let ok = unsafe { GlobalMemoryStatusEx(&mut status) };
    (ok != 0).then_some(status.total_phys)
}

#[cfg(not(any(unix, windows)))]
pub fn physical_memory() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, text: &str) {
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn missing_global_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let global = dir.path().join("missing.toml");
        let settings = Settings::load_at(dir.path(), Some(&global)).unwrap();
        assert!(settings.global_path().is_none());
    }

    #[test]
    fn non_regular_global_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let global = dir.path().join("global-dir");
        std::fs::create_dir(&global).unwrap();
        let err = Settings::load_at(dir.path(), Some(&global)).unwrap_err();
        assert!(format!("{err:#}").contains("not a regular file"), "{err:#}");
    }

    #[cfg(unix)]
    #[test]
    fn project_symlink_is_ignored_and_global_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.toml");
        write(&real, "preset = \"ci\"\n");
        let project_link = dir.path().join(FILE_NAME);
        symlink(&real, &project_link).unwrap();
        let settings = Settings::load_at(dir.path(), None).unwrap();
        assert!(
            settings.project_path().is_none(),
            "a symlinked project policy must not be read"
        );

        let global_link = dir.path().join("global-link.toml");
        symlink(&real, &global_link).unwrap();
        let err = Settings::load_at(dir.path(), Some(&global_link)).unwrap_err();
        assert!(format!("{err:#}").contains("symlink/reparse"), "{err:#}");
    }

    #[test]
    fn global_config_path_is_absolute_and_named() {
        let path = crate::paths::global_config_path().unwrap();
        assert!(path.is_absolute(), "{} must be absolute", path.display());
        assert_eq!(path.file_name(), Some(std::ffi::OsStr::new(FILE_NAME)));
        assert_eq!(
            path.parent().and_then(Path::file_name),
            Some(std::ffi::OsStr::new("epicenter"))
        );
    }

    #[test]
    fn memory_units_parse() {
        assert_eq!(parse_memory("8GiB").unwrap(), 8 * 1024 * 1024 * 1024);
        assert_eq!(parse_memory("8192MiB").unwrap(), 8 * 1024 * 1024 * 1024);
        assert_eq!(parse_memory("8G").unwrap(), 8 * 1024 * 1024 * 1024);
        assert_eq!(parse_memory("512").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_memory("1.5GiB").unwrap(), 3 * 1024 * 1024 * 1024 / 2);
        assert_eq!(parse_memory("2TiB").unwrap(), 2 * 1024u64.pow(4));
        assert!(parse_memory("lots").is_err());
        assert!(parse_memory("8XiB").is_err());
        assert!(parse_memory("").is_err());
    }

    #[test]
    fn project_file_wins_over_global() {
        let project = tempfile::tempdir().unwrap();
        write(
            &project.path().join(FILE_NAME),
            "preset = \"ci\"\nlinker = \"wild\"\nmemory = \"4GiB\"\nstore = \"vault\"\n",
        );
        let global = tempfile::tempdir().unwrap();
        let global_file = global.path().join(FILE_NAME);
        write(&global_file, "preset = \"dev\"\nlinker = \"lld\"\n");

        let settings = Settings::load_at(project.path(), Some(&global_file)).unwrap();
        assert_eq!(settings.preset(), (Preset::Ci, Source::Project));
        assert_eq!(settings.linker(), (LinkerChoice::Wild, Source::Project));
        assert_eq!(
            settings.memory_bytes(),
            (Some(4 * 1024 * 1024 * 1024), Source::Project)
        );
        let (store, source) = settings.store().unwrap().unwrap();
        assert_eq!(store, project.path().join("vault"));
        assert_eq!(source, Source::Project);
        assert_eq!(settings.effective_preset().0, EffectivePreset::Ci);
        assert_eq!(settings.incremental(), Some(false));
        assert!(settings.check_tier());
    }

    #[test]
    fn global_file_is_the_fallback() {
        let project = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let global_file = global.path().join(FILE_NAME);
        write(
            &global_file,
            "preset = \"dev\"\nlinker = \"lld\"\nmemory = 2048\n",
        );

        let settings = Settings::load_at(project.path(), Some(&global_file)).unwrap();
        assert_eq!(settings.preset(), (Preset::Dev, Source::Global));
        assert_eq!(settings.linker(), (LinkerChoice::Lld, Source::Global));
        assert_eq!(
            settings.memory_bytes(),
            (Some(2 * 1024 * 1024 * 1024), Source::Global)
        );
        assert!(settings.store().unwrap().is_none());
    }

    #[test]
    fn auto_preset_follows_ci() {
        assert_eq!(resolve_preset(Preset::Auto, false), EffectivePreset::Dev);
        assert_eq!(resolve_preset(Preset::Auto, true), EffectivePreset::Ci);
        assert_eq!(resolve_preset(Preset::Dev, true), EffectivePreset::Dev);
        assert_eq!(resolve_preset(Preset::Ci, false), EffectivePreset::Ci);
    }

    #[test]
    fn copy_workers_is_bounded() {
        let workers = copy_workers();
        assert!(
            (1..=8).contains(&workers),
            "unexpected copy pool size {workers}"
        );
    }

    #[test]
    fn job_cap_is_conservative() {
        assert_eq!(job_cap(16, Some(8 * 1024 * 1024 * 1024)), 4);
        assert_eq!(job_cap(16, Some(32 * 1024 * 1024 * 1024)), 16);
        assert_eq!(job_cap(4, Some(64 * 1024 * 1024 * 1024)), 4);
        assert_eq!(job_cap(0, None), 1);
        assert_eq!(job_cap(16, Some(1)), 1);
    }

    #[test]
    fn work_root_is_global_only_and_resolves_from_the_global_file() {
        let dir = tempfile::tempdir().unwrap();
        let global = dir.path().join("global.toml");
        write(&global, "work = \"local-work\"\n");
        let settings = Settings::load_at(dir.path(), Some(&global)).unwrap();
        let (work, source) = settings.work_root().unwrap().unwrap();
        assert_eq!(work, dir.path().join("local-work"));
        assert_eq!(source, Source::Global);

        write(
            &dir.path().join(FILE_NAME),
            "work = \"/tmp/project-work\"\n",
        );
        let settings = Settings::load_at(dir.path(), Some(&global)).unwrap();
        let err = settings.work_root().unwrap_err();
        assert!(err.to_string().contains("global"), "{err}");
    }

    #[test]
    fn relative_store_resolves_against_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(FILE_NAME);
        write(&file, "store = \"vault\"\n");
        let settings = Settings::load_at(dir.path(), None).unwrap();
        let (store, _) = settings.store().unwrap().unwrap();
        assert_eq!(store, dir.path().join("vault"));
    }

    #[test]
    fn link_policy_defaults_project_tightens_and_link_is_global_only() {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::load_at(dir.path(), None).unwrap();
        assert_eq!(settings.link().unwrap(), (LinkPolicy::Auto, Source::Auto));

        let global = dir.path().join("global.toml");
        write(&global, "link = \"link\"\n");
        let project = dir.path().join("project.toml");
        write(&project, "link = \"copy\"\n");
        let settings = Settings::load_at(dir.path(), Some(&global)).unwrap();
        assert_eq!(settings.link().unwrap(), (LinkPolicy::Link, Source::Global));
        // A project file can tighten a global link policy to copy.
        let project_file = Settings {
            project: Some(Loaded::read(&project).unwrap().unwrap()),
            global: Some(Loaded::read(&global).unwrap().unwrap()),
        };
        assert_eq!(
            project_file.link().unwrap(),
            (LinkPolicy::Copy, Source::Project)
        );

        // A project cannot loosen a global copy policy to auto.
        write(&global, "link = \"copy\"\n");
        write(&project, "link = \"auto\"\n");
        let settings = Settings {
            project: Some(Loaded::read(&project).unwrap().unwrap()),
            global: Some(Loaded::read(&global).unwrap().unwrap()),
        };
        assert_eq!(settings.link().unwrap(), (LinkPolicy::Copy, Source::Global));

        // Forcing links from a repository is refused.
        write(&project, "link = \"link\"\n");
        let settings = Settings {
            project: Some(Loaded::read(&project).unwrap().unwrap()),
            global: None,
        };
        assert!(settings.link().is_err());
    }

    #[test]
    fn unknown_link_policy_is_rejected_in_global_but_project_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join(FILE_NAME), "link = \"all\"\n");
        let settings = Settings::load_at(dir.path(), None).unwrap();
        assert!(settings.project_path().is_none());

        let global = dir.path().join("global.toml");
        write(&global, "link = \"all\"\n");
        assert!(Settings::load_at(dir.path(), Some(&global)).is_err());
    }

    #[test]
    fn project_store_rejects_parent_and_dot() {
        for raw in ["..", "../vault", "."] {
            let dir = tempfile::tempdir().unwrap();
            write(&dir.path().join(FILE_NAME), &format!("store = \"{raw}\"\n"));
            let settings = Settings::load_at(dir.path(), None).unwrap();
            assert!(settings.store().is_err(), "store = {raw:?} must be refused");
        }
    }

    #[test]
    fn project_store_requires_a_marker_for_a_nonempty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("vault");
        std::fs::create_dir(&store).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        write(&store.join("not-a-store"), "x");
        write(&dir.path().join(FILE_NAME), "store = \"vault\"\n");
        let settings = Settings::load_at(dir.path(), None).unwrap();
        let err = settings.store().unwrap_err();
        assert!(
            format!("{err:#}").contains("not an epicenter store"),
            "{err:#}"
        );

        write(
            &store.join(crate::vault::STORE_MARKER),
            "epicenter-store-v1\n",
        );
        let settings = Settings::load_at(dir.path(), None).unwrap();
        assert!(settings.store().is_ok(), "a marked store is accepted");
    }

    #[test]
    fn ancestor_policy_file_above_the_workspace_is_ignored() {
        let parent = tempfile::tempdir().unwrap();
        write(&parent.path().join(FILE_NAME), "store = \"vault\"\n");
        let project = parent.path().join("repo");
        std::fs::create_dir(&project).unwrap();
        write(&project.join("Cargo.toml"), "[package]\nname = \"x\"\n");
        let settings = Settings::load_at(&project, None).unwrap();
        assert!(settings.project_path().is_none(), "ancestor file ignored");
    }

    #[test]
    fn malformed_project_file_is_ignored_but_malformed_global_fails() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join(FILE_NAME), "preset = \"turbo\"\n");
        let settings = Settings::load_at(dir.path(), None).unwrap();
        assert!(settings.project_path().is_none());

        let global = dir.path().join("global.toml");
        write(&global, "preset = \"turbo\"\n");
        let err = Settings::load_at(dir.path(), Some(&global)).unwrap_err();
        assert!(err.to_string().contains("global.toml"), "{err:#}");
    }
}
