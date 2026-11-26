//! Editing epicenter's **global** state: Cargo's `config.toml` and the
//! machine-level `epicenter.toml`.
//!
//! The shared-cache decision lives in `$CARGO_HOME/config.toml` as the
//! `[build] build-dir` key, where cargo (and any other tool) can read it.
//! Policy intent (preset/linker) lives in the OS config path, independent of
//! `CARGO_HOME`; project `epicenter.toml` files are read-only inputs.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use toml_edit::{DocumentMut, Item, Table, value};

use crate::paths::{self, DEFAULT_BUILD_DIR};
use crate::settings::{self, LinkerChoice, Preset, RemoteTier, Settings, Source};
use crate::util::metadata_nofollow;

/// The effective shared-cache root: **only** the global
/// `$CARGO_HOME/config.toml` (or the canonical default). Project configs are
/// never consulted for state; `cargo metadata` is deliberately not executed.
pub fn cache_root() -> Result<PathBuf> {
    let root = trusted_cache_root()?;
    if root.exists() {
        return crate::util::validate_state_root(&root, "cache root");
    }
    crate::util::ensure_windows_user_path(&root, "cache root")?;
    Ok(root)
}

/// The trusted root: the global `$CARGO_HOME/config.toml` `build-dir` value,
/// or the canonical default template. Never reads a project config and never
/// executes `cargo metadata`.
pub fn trusted_cache_root() -> Result<PathBuf> {
    let value = cargo_build_dir()?.unwrap_or_else(|| DEFAULT_BUILD_DIR.to_string());
    paths::resolve_template(&value)
}

/// The `[build] build-dir` value from the **global** `$CARGO_HOME/config.toml`.
/// This is the only trusted source for epicenter state. A relative config path,
/// or a symlinked `config.toml`, is refused.
pub fn cargo_build_dir() -> Result<Option<String>> {
    cargo_build_dir_in(&paths::cargo_home()?)
}

fn cargo_build_dir_in(cargo_home: &Path) -> Result<Option<String>> {
    let config_path = cargo_config_path_in(cargo_home)?;
    if !config_path.exists() {
        return Ok(None);
    }
    let text = crate::util::read_trusted_config(&config_path, 1024 * 1024)
        .with_context(|| format!("reading {}", config_path.display()))?;
    Ok(read_table_key(&text, "build", "build-dir").filter(|value| !value.trim().is_empty()))
}

/// Config values are written inside single-quoted TOML strings. Reject the
/// characters that can break out of the literal or start a new key/line.
fn validate_config_value(value: &str, what: &str) -> Result<()> {
    if value.contains(['\n', '\r', '\0', '\'']) {
        anyhow::bail!("{what} contains a forbidden character (newline, NUL or single quote)");
    }
    Ok(())
}

/// A TOML key with its optional quoting removed, so `"jobs"` matches `jobs`.
fn bare_key(candidate: &str) -> &str {
    let key = candidate.trim();
    key.strip_prefix('"')
        .and_then(|key| key.strip_suffix('"'))
        .or_else(|| {
            key.strip_prefix('\'')
                .and_then(|key| key.strip_suffix('\''))
        })
        .unwrap_or(key)
}

fn key_matches(candidate: &str, key: &str) -> bool {
    bare_key(candidate) == key
}

/// Cargo's *global* config file: `$CARGO_HOME/config.toml`.
/// Settings there apply to every project on the machine.
pub fn cargo_config_path() -> Result<PathBuf> {
    cargo_config_path_in(&paths::cargo_home()?)
}

/// Cargo's global config for an explicit home. Setup resolves a previewed home
/// locally and passes it here instead of installing it process-wide.
fn cargo_config_path_in(cargo_home: &Path) -> Result<PathBuf> {
    if cargo_home.is_relative() {
        anyhow::bail!(
            "CARGO_HOME is relative ({}) — set an absolute CARGO_HOME",
            cargo_home.display()
        );
    }
    // The config file is only as trustworthy as its directory: a
    // group/world-writable $CARGO_HOME lets another user swap the file after
    // any path-only check. Check the directory, then the file; the actual
    // read uses fstat on the opened descriptor (util::read_trusted_config).
    crate::util::check_trusted_path(
        cargo_home,
        crate::util::PathKind::Dir,
        crate::util::TrustPolicy::NoForeignWrite,
        "CARGO_HOME",
    )?;
    let path = cargo_home.join("config.toml");
    if path.is_relative() {
        anyhow::bail!(
            "global cargo config path is relative ({}) — set an absolute CARGO_HOME",
            path.display()
        );
    }
    crate::util::ensure_windows_user_path(&path, "global cargo config")?;
    crate::util::check_trusted_path(
        &path,
        crate::util::PathKind::File,
        crate::util::TrustPolicy::NoForeignWrite,
        "global cargo config",
    )?;
    Ok(path)
}

/// What an edit to Cargo's config changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CargoEdit {
    /// The file did not exist and was created.
    Created,
    /// The key was added to an existing `[build]` table.
    Inserted,
    /// The key existed with a different value and was replaced.
    Replaced,
    /// The key existed and was deleted.
    Removed,
    /// Nothing needed changing.
    AlreadySet,
    /// The key was appendend at the end of the toml file
    Appended,
    /// Revert config file to the last backup
    Reverted,
}

impl CargoEdit {
    pub fn describe(&self) -> &'static str {
        match self {
            CargoEdit::Created => "created the file",
            CargoEdit::Inserted => "added",
            CargoEdit::Replaced => "updated",
            CargoEdit::Removed => "removed",
            CargoEdit::AlreadySet => "already set, unchanged",
            CargoEdit::Appended => "appended line at the EOF",
            CargoEdit::Reverted => "config file reverted to last backup",
        }
    }
}

/// Sets `key = 'value'` (or `key = value` for booleans) inside the `[build]`
/// table of a Cargo config, as pure text surgery so user comments and
/// formatting survive untouched. Mutates `text` in place; the return value
/// only describes what changed.
fn set_build_key(text: &mut String, key: &str, value: &str, is_bool: bool) -> CargoEdit {
    let wanted = if is_bool {
        format!("{key} = {value}")
    } else {
        format!("{key} = '{value}'")
    };
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();

    // Exact header match (whitespace-insensitive) — `.contains("[build]")`
    // would also match comments or sub-table names.
    let header = lines
        .iter()
        .position(|l| l.trim().replace([' ', '\t'], "") == "[build]");

    match header {
        Some(i) => {
            // Scan to the next table header: that is the whole [build] table.
            let mut j = i + 1;
            while j < lines.len() {
                let t = lines[j].trim();
                if t.starts_with('[') && t.ends_with(']') {
                    break;
                }
                if t.split_once('=').is_some_and(|(k, _)| key_matches(k, key)) {
                    if t == wanted {
                        return CargoEdit::AlreadySet;
                    }
                    lines[j] = wanted;
                    *text = lines.join("\n") + "\n";
                    return CargoEdit::Replaced;
                }
                j += 1;
            }
            lines.insert(i + 1, wanted);
            *text = lines.join("\n") + "\n";
            CargoEdit::Inserted
        }
        None => {
            let needs_blank = lines.last().map_or(false, |l| !l.trim().is_empty());
            if needs_blank {
                lines.push(String::new());
            }
            lines.push("[build]".to_string());
            lines.push(wanted);
            *text = lines.join("\n") + "\n";
            CargoEdit::Appended
        }
    }
}

/// Delete `key = ...` from the `[build]` table, if present. Mutates `text`;
/// leaves it untouched when the key is absent.
fn remove_build_key(text: &mut String, key: &str) -> CargoEdit {
    let mut out: Vec<String> = Vec::new();
    let mut in_build = false;
    let mut removed = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_build = trimmed.replace([' ', '\t'], "") == "[build]";
            out.push(line.to_string());
            continue;
        }
        if in_build
            && trimmed
                .split_once('=')
                .map_or(false, |(candidate, _)| key_matches(candidate, key))
        {
            removed = true;
            continue;
        }
        out.push(line.to_string());
    }
    if removed {
        *text = out.join("\n") + "\n";
        CargoEdit::Removed
    } else {
        CargoEdit::AlreadySet
    }
}
/// Parse the value of `key` out of the `[build]` table.
fn read_build_key(text: &str, key: &str) -> Option<String> {
    read_table_key(text, "build", key)
}

/// Is this line the `[target.<triple>]` header (plain or TOML-quoted)?
fn is_target_header(line: &str, target: &str) -> bool {
    let compact = line.trim().replace([' ', '\t'], "");
    compact == format!("[target.{target}]")
        || compact == format!("[target.\"{target}\"]")
        || compact == format!("[target.'{target}']")
}

/// The triple from a `[target.<triple>]` header (plain or quoted), if any.
fn target_table_name(line: &str) -> Option<String> {
    let compact = line.trim().replace([' ', '\t'], "");
    let rest = compact.strip_prefix("[target.")?.strip_suffix(']')?;
    Some(rest.trim_matches('"').trim_matches('\'').to_string())
}

/// Does this `rustflags` value consist solely of flags epicenter wrote?
///
/// Ownership is structural, never a substring: the value must parse as a TOML
/// array of `-C <flag>` pairs and every flag must be one of the shapes this
/// tool emits. A user array that merely contains `-fuse-ld=lld` next to their
/// own `target-cpu` is therefore left alone.
fn is_managed_linker_flags(value: &str) -> bool {
    // Callers hand over the bare right-hand side of `rustflags = ...`, which is
    // an array value, not a document. Wrap it in a one-key table so TOML parses
    // it, and reject anything that smuggles extra keys into the wrapper.
    let Ok(toml::Value::Table(mut document)) =
        format!("rustflags = {value}").parse::<toml::Value>()
    else {
        return false;
    };
    if document.len() != 1 {
        return false;
    }
    let Some(toml::Value::Array(items)) = document.remove("rustflags") else {
        return false;
    };
    let mut flags = Vec::new();
    let mut items = items.iter();
    while let Some(prefix) = items.next() {
        let Some(flag) = items.next() else {
            return false;
        };
        if prefix.as_str() != Some("-C") {
            return false;
        }
        let Some(flag) = flag.as_str() else {
            return false;
        };
        flags.push(flag);
    }
    if flags.is_empty() {
        return false;
    }
    let mut marker = false;
    for flag in flags {
        match managed_linker_flag(flag) {
            Some(is_marker) => marker |= is_marker,
            None => return false,
        }
    }
    marker
}

/// Last path component, accepting both separators (config paths are
/// forward-slashed, but be liberal when reading).
fn file_name_any(path: &str) -> &str {
    path.trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
}

/// Recognise one flag from an epicenter-managed linker plan. Returns `None`
/// for a user flag, `Some(false)` for a neutral part (`linker=clang`) and
/// `Some(true)` for a flag that proves the array came from a managed plan.
fn managed_linker_flag(flag: &str) -> Option<bool> {
    const LINKERS: &[&str] = &["lld", "wild", "mold", "gold", "ld.gold", "ld.lld"];
    if let Some(rest) = flag.strip_prefix("link-arg=-fuse-ld=") {
        if LINKERS.contains(&rest) || LINKERS.contains(&file_name_any(rest)) {
            return Some(true);
        }
        return None;
    }
    if let Some(rest) = flag.strip_prefix("link-arg=--ld-path=") {
        // Legacy releases wrote the bare name; newer ones write the resolved
        // path. Only Wild is ours, never an arbitrary user `--ld-path`.
        if rest == "wild" || matches!(file_name_any(rest), "wild" | "wild.exe") {
            return Some(true);
        }
        return None;
    }
    if let Some(dir) = flag.strip_prefix("link-arg=-B") {
        return dir
            .trim_end_matches(['/', '\\'])
            .ends_with("gcc-ld")
            .then_some(true);
    }
    if let Some(linker) = flag.strip_prefix("linker=") {
        let name = file_name_any(linker);
        if matches!(
            name,
            "rust-lld" | "rust-lld.exe" | "lld-link" | "lld-link.exe" | "wild" | "wild.exe"
        ) {
            return Some(true);
        }
        // `linker=clang` is only part of a managed plan when another flag
        // (an ld-path or -fuse-ld) marks it; alone it is the user's choice.
        return (name == "clang").then_some(false);
    }
    if flag == "linker-flavor=wasm-ld" {
        return Some(true);
    }
    None
}

/// Insert `rustflags = ...` into `[target.<target>]`, preserving every other
/// line and comment. Existing `rustflags` are **never** overwritten, except
/// literals in `stale` (written by an older release), which are migrated.
/// The second return value reports a real conflict instead.
fn set_target_rustflags(
    text: &mut String,
    target: &str,
    literal: &str,
    stale: &[String],
) -> (CargoEdit, bool) {
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    if let Some(header) = lines.iter().position(|line| is_target_header(line, target)) {
        let mut end = header + 1;
        while end < lines.len() {
            let trimmed = lines[end].trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                break;
            }
            if let Some((key, value)) = trimmed.split_once('=') {
                if key_matches(key, "rustflags") {
                    let value = clean_toml_value(value);
                    if value == literal {
                        return (CargoEdit::AlreadySet, false);
                    }
                    if stale.iter().any(|old| value == old.as_str())
                        || is_managed_linker_flags(&value)
                    {
                        lines[end] = format!("rustflags = {literal}");
                        *text = lines.join("\n") + "\n";
                        return (CargoEdit::Replaced, false);
                    }
                    return (CargoEdit::AlreadySet, true);
                }
            }
            end += 1;
        }
        lines.insert(end, format!("rustflags = {literal}"));
        *text = lines.join("\n") + "\n";
        (CargoEdit::Inserted, false)
    } else {
        let needs_blank = lines.last().map_or(false, |line| !line.trim().is_empty());
        if needs_blank {
            lines.push(String::new());
        }
        lines.push(format!("[target.{target}]"));
        lines.push(format!("rustflags = {literal}"));
        *text = lines.join("\n") + "\n";
        (CargoEdit::Appended, false)
    }
}

/// Remove epicenter-managed linker `rustflags` from `[target.<target>]` only
/// when the value matches what this version or an older release wrote.
/// Anything else is left alone.
fn remove_target_rustflags(
    text: &mut String,
    target: &str,
    literal: &str,
    stale: &[String],
) -> (CargoEdit, bool) {
    let mut out: Vec<String> = Vec::new();
    let mut in_table = false;
    let mut removed = false;
    let mut conflict = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_table = is_target_header(line, target);
            out.push(line.to_string());
            continue;
        }
        if in_table {
            if let Some((key, value)) = trimmed.split_once('=') {
                if key_matches(key, "rustflags") {
                    let value = clean_toml_value(value);
                    if value == literal
                        || stale.iter().any(|old| value == old.as_str())
                        || is_managed_linker_flags(&value)
                    {
                        removed = true;
                        continue;
                    }
                    conflict = true;
                }
            }
        }
        out.push(line.to_string());
    }
    if removed {
        *text = out.join("\n") + "\n";
        (CargoEdit::Removed, false)
    } else if conflict {
        (CargoEdit::AlreadySet, true)
    } else {
        (CargoEdit::AlreadySet, false)
    }
}

/// Every target table whose `rustflags` are entirely setup-managed. Used by
/// `--linker system` so stale flags are found in the file itself, without
/// probing for Mold/Gold/Wild executables that may already be uninstalled.
fn managed_targets(text: &str) -> Vec<String> {
    let mut targets = std::collections::BTreeSet::new();
    let mut current = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current = target_table_name(trimmed);
            continue;
        }
        let Some(target) = current.as_ref() else {
            continue;
        };
        if let Some((key, value)) = trimmed.split_once('=')
            && key_matches(key, "rustflags")
            && is_managed_linker_flags(&clean_toml_value(value))
        {
            targets.insert(target.clone());
        }
    }
    targets.into_iter().collect()
}

/// Enable Cargo incremental compilation in `[build]`. Setup only does this
/// when no `rustc-wrapper` remains: wrapper caches and incremental state work
/// against each other.
fn set_incremental(text: &mut String, enabled: bool) -> CargoEdit {
    set_build_key(
        text,
        "incremental",
        if enabled { "true" } else { "false" },
        true,
    )
}

/// Strip a trailing `#` comment while respecting single/double quoted values.
fn strip_toml_comment(value: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (index, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match quote {
            Some(q) => {
                if ch == '\\' && q == '"' {
                    escaped = true;
                } else if ch == q {
                    quote = None;
                }
            }
            None => {
                if ch == '#' {
                    return &value[..index];
                }
                if ch == '"' || ch == '\'' {
                    quote = Some(ch);
                }
            }
        }
    }
    value
}

/// Parse `key = value` out of any `[table]` of a cargo config text.
///
/// Only the exact table is scanned (until the next header line); a trailing
/// comment is stripped and surrounding quotes are removed.
pub fn read_table_key(text: &str, table: &str, key: &str) -> Option<String> {
    let header = format!("[{table}]");
    let dotted = format!("{table}.{key}");
    let mut in_table = false;
    let mut at_root = true;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            at_root = false;
            in_table = trimmed.replace([' ', '\t'], "") == header;
            continue;
        }
        let candidate = trimmed.split_once('=').map(|(k, _)| k.trim());
        // TOML allows `build.build-dir = ...` at the document root.
        if at_root
            && candidate.is_some_and(|candidate| bare_key(candidate) == dotted)
            && let Some((_, value)) = trimmed.split_once('=')
        {
            return Some(clean_toml_value(value));
        }
        if !in_table {
            continue;
        }
        if let Some((candidate, value)) = trimmed.split_once('=') {
            if !key_matches(candidate, key) {
                continue;
            }
            return Some(clean_toml_value(value));
        }
    }
    None
}

fn clean_toml_value(value: &str) -> String {
    let value = strip_toml_comment(value).trim();
    let value = value
        .strip_prefix('\'')
        .and_then(|v| v.strip_suffix('\''))
        .or_else(|| value.strip_prefix('"').and_then(|v| v.strip_suffix('"')))
        .unwrap_or(value);
    value.trim().to_string()
}

/// Look up a key in any table of Cargo's *global* config file.
pub fn cargo_configured_in(table: &str, key: &str) -> Result<Option<String>> {
    let path = cargo_config_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let text = crate::util::read_trusted_config(&path, 1024 * 1024)?;
    Ok(read_table_key(&text, table, key))
}

/// Read a `[build]` key from ANY cargo config file — doctor uses this to scan
/// the ancestor `.cargo/config.toml` chain for shadowing values. Read-only.
pub fn read_build_table_key(path: &Path, key: &str) -> Option<String> {
    let text = crate::util::read_small_text(path, 1024 * 1024).ok()?;
    read_build_key(&text, key)
}

pub struct SetupReport {
    /// Where the shared cache now lives.
    pub root: PathBuf,
    /// What happened to the `build-dir` setting.
    pub build_dir_edit: CargoEdit,
    /// What happened to the `rustc-wrapper` (kache/sccache) setting, if touched.
    pub wrapper_edit: Option<CargoEdit>,
    /// What happened to `[build] jobs`, if touched.
    pub jobs_edit: Option<CargoEdit>,
    /// What happened to `[build] incremental`, if touched.
    pub incremental_edit: Option<CargoEdit>,
    /// What happened to the linker flags, if touched.
    pub linker: Option<LinkerSetupReport>,
    /// Backup of the previous cargo config, if it was modified.
    pub backup: Option<PathBuf>,
    /// Backup of the previous global epicenter.toml, if it was modified.
    pub settings_backup: Option<PathBuf>,
    /// Is the override mode active (vs the canonical template)?
    pub using_override: bool,
    /// Effective policy, explained by `doctor` and printed by `--dry-run`.
    pub policy: PolicyReport,
    pub dry_run: bool,
    /// Cargo config before/after; `before` is None for a new file.
    pub cargo_before: Option<String>,
    pub cargo_after: String,
    /// Global epicenter.toml before/after, when a policy key was written.
    pub settings_before: Option<String>,
    pub settings_after: Option<String>,
    pub settings_path: PathBuf,
}

/// The resolved policy behind one setup/doctor run.
pub struct PolicyReport {
    pub preset: Preset,
    pub effective_preset: settings::EffectivePreset,
    pub preset_source: Source,
    pub memory: Option<u64>,
    pub memory_source: Source,
    pub cores: usize,
    pub jobs: usize,
    pub incremental: Option<bool>,
    pub check_tier: bool,
    pub compression: bool,
    pub restore: bool,
    pub linker: LinkerChoice,
    pub linker_source: Source,
    pub wrapper: Option<String>,
    /// Effective Cargo home and where it came from.
    pub cargo_home: PathBuf,
    pub cargo_home_source: Source,
    pub store: Option<PathBuf>,
    pub work_root: PathBuf,
    pub work_root_source: Source,
}

/// The linker outcome: bundled LLD, Wild, or removal of managed flags.
pub struct LinkerSetupReport {
    pub choice: LinkerChoice,
    /// `ld.lld` / `rust-lld.exe` / `wild`.
    pub binary: PathBuf,
    pub targets: Vec<LinkerTargetReport>,
    /// At least one target had competing custom rustflags.
    pub conflict: bool,
}

pub struct LinkerTargetReport {
    pub target: String,
    pub flags: Vec<String>,
    pub edit: CargoEdit,
}

/// What `--wrapper` asked for.
#[derive(Debug, Clone, Copy)]
pub enum WrapperAction<'a> {
    Set(&'a str),
    Remove,
}

/// What `--cargo-home` asked for. `Keep` leaves the policy file untouched.
#[derive(Debug, Clone, Copy)]
pub enum CargoHomeAction<'a> {
    Keep,
    Set(&'a Path),
    Clear,
}

/// Inputs that come from the CLI; file values are layered underneath.
pub struct SetupOptions<'a> {
    pub root_arg: Option<&'a str>,
    pub use_default: bool,
    pub preset: Option<Preset>,
    pub linker: Option<LinkerChoice>,
    pub wrapper: Option<WrapperAction<'a>>,
    /// CLI memory budget in bytes, and its original text for persistence.
    pub memory: Option<u64>,
    pub memory_text: Option<&'a str>,
    pub work_root_arg: Option<&'a str>,
    pub cargo_home: CargoHomeAction<'a>,
    /// Resolved, normalized remote values; `None` leaves each field alone.
    pub remote_url: Option<&'a str>,
    pub remote_key: Option<&'a str>,
    pub remote_tier: Option<RemoteTier>,
    pub remote_off: bool,
    pub dry_run: bool,
}

/// Normalize a user-provided `--cache-root` value.
///
/// - cargo template strings (`{…}`) pass through untouched — they resolve at
///   build time via cargo, exactly like the default template;
/// - `~` expands to the home directory;
/// - relative paths resolve against the current directory;
/// - absolute paths stay as-is.
fn toml_string(value: &str) -> String {
    toml::Value::String(value.to_string()).to_string()
}

pub fn normalize_root_input(raw: &str) -> Result<PathBuf> {
    let raw = raw.trim();
    anyhow::ensure!(!raw.is_empty(), "--cache-root must not be empty");
    if raw.contains('{') && raw.contains('}') {
        return Ok(PathBuf::from(raw)); // template passthrough
    }
    let path = crate::util::expand_tilde(raw)?;
    if path.is_absolute() {
        return Ok(path);
    }
    let cwd = std::env::current_dir().context("resolving a relative --cache-root")?;
    Ok(cwd.join(path))
}

/// Expand `{cargo-cache-home}` with an explicit home. Setup resolves the
/// effective home for the run and must not install it process-wide.
fn resolve_template_in(value: &str, cargo_home: &Path) -> Result<PathBuf> {
    let expanded = value.replace("{cargo-cache-home}", &cargo_home.to_string_lossy());
    paths::resolve_template(&expanded)
}

/// Apply one setup decision to the **global** Cargo config, and persist the
/// explicit policy keys in the global epicenter.toml.
///
/// The filesystem side effects are skipped under `dry_run`, but every edit is
/// still computed so the caller can print the exact diff.
pub fn setup(opts: &SetupOptions<'_>, settings: &Settings) -> Result<SetupReport> {
    let (file_preset, file_preset_source) = settings.preset();
    let preset = opts.preset.unwrap_or(file_preset);
    let preset_source = if opts.preset.is_some() {
        Source::Cli
    } else {
        file_preset_source
    };
    let effective_preset = settings::resolve_preset(preset, settings::ci_environment());

    let (linker, linker_source) = match opts.linker {
        Some(value) => (value, Source::Cli),
        None => settings.linker(),
    };
    let (memory, memory_source) = match opts.memory {
        Some(bytes) => (Some(bytes), Source::Cli),
        None => settings.memory_bytes(),
    };
    let (cargo_home, cargo_home_source) = match opts.cargo_home {
        CargoHomeAction::Set(path) => (path.to_path_buf(), Source::Cli),
        CargoHomeAction::Clear => (paths::ambient_cargo_home()?, Source::Cli),
        CargoHomeAction::Keep => settings.cargo_home()?,
    };
    let cores = settings::available_cores();
    let jobs = settings::job_cap(cores, memory);
    let store = settings.store()?.map(|(path, _)| path);
    let (work_root, work_root_source) = match opts.work_root_arg {
        Some("default") => (crate::paths::default_work_root()?, Source::Auto),
        Some(raw) => {
            let path = normalize_root_input(raw)?;
            if path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            {
                anyhow::bail!("--work-root must not contain `..`");
            }
            (path, Source::Cli)
        }
        None => settings.work_root_or_default()?,
    };
    // Decision precedence: CLI root > the value already in cargo's config >
    // the canonical default template. `--cache-root` / `--use-default`
    // REWRITE the cargo-config decision; without them it stays untouched.
    let build_dir_value: String = if let Some(raw) = opts.root_arg {
        normalize_root_input(raw)?.to_string_lossy().into_owned()
    } else if opts.use_default {
        DEFAULT_BUILD_DIR.to_string()
    } else {
        cargo_build_dir_in(&cargo_home)?.unwrap_or_else(|| DEFAULT_BUILD_DIR.to_string())
    };
    validate_config_value(&build_dir_value, "build-dir")?;
    if let Some(name) = match opts.wrapper {
        Some(WrapperAction::Set(name)) => Some(name),
        _ => None,
    } {
        validate_config_value(name, "rustc-wrapper")?;
    }

    // The filesystem view must always be RESOLVED (a template is not a path).
    let root = resolve_template_in(&build_dir_value, &cargo_home)?;
    let effective_store = store
        .clone()
        .unwrap_or_else(|| crate::paths::store_root(&root));
    if work_root.starts_with(&effective_store) || effective_store.starts_with(&work_root) {
        anyhow::bail!(
            "work root {} overlaps the vault {} — choose a separate local directory",
            work_root.display(),
            effective_store.display()
        );
    }
    if opts.work_root_arg.is_some() && !opts.dry_run {
        crate::util::ensure_windows_user_path(&work_root, "work root")?;
        crate::util::create_private_dir_all(&work_root)?;
        let canonical_work = crate::util::validate_state_root(&work_root, "work root")?;
        if let Ok(canonical_store) = effective_store.canonicalize() {
            if canonical_work.starts_with(&canonical_store)
                || canonical_store.starts_with(&canonical_work)
            {
                anyhow::bail!(
                    "work root {} resolves inside the vault {} — choose a separate local directory",
                    work_root.display(),
                    effective_store.display()
                );
            }
        }
    }
    crate::util::ensure_windows_user_path(&root, "cache root")?;
    if !opts.dry_run {
        crate::util::create_private_dir_all(&root)
            .with_context(|| format!("creating cache dir {}", root.display()))?;
        crate::util::validate_state_root(&root, "cache root")?;
    }

    let cargo_cfg = cargo_config_path_in(&cargo_home)?;
    let existed = cargo_cfg.is_file();
    let mut text = if existed {
        crate::util::read_trusted_config(&cargo_cfg, 1024 * 1024)
            .with_context(|| format!("reading {}", cargo_cfg.display()))?
    } else {
        "[build]\n".to_string()
    };
    let cargo_before = existed.then(|| text.clone());

    let mut build_dir_edit = set_build_key(&mut text, "build-dir", &build_dir_value, false);
    if !existed {
        build_dir_edit = CargoEdit::Created;
    }
    let wrapper_edit = match opts.wrapper {
        Some(WrapperAction::Set(name)) => {
            Some(set_build_key(&mut text, "rustc-wrapper", name, false))
        }
        Some(WrapperAction::Remove) => Some(remove_build_key(&mut text, "rustc-wrapper")),
        None => None,
    };
    let wrapper = read_build_key(&text, "rustc-wrapper");

    // Presets own the incremental/jobs policy. Auto never overwrites an
    // explicit `build.jobs`; dev/ci are explicit and do.
    let incremental = match preset {
        Preset::Auto => None,
        Preset::Ci => Some(false),
        // A wrapper cache and Cargo's incremental state work against each
        // other; an explicit dev preset turns incremental off rather than
        // silently leaving a previous `true` behind.
        Preset::Dev if wrapper.is_some() => Some(false),
        Preset::Dev => Some(true),
    };
    let incremental_edit = incremental.map(|enabled| set_incremental(&mut text, enabled));
    // Auto respects an explicit `build.jobs`, but an explicit CLI memory
    // budget is a request to re-derive it.
    let jobs_edit = if preset == Preset::Auto
        && opts.memory.is_none()
        && read_build_key(&text, "jobs").is_some()
    {
        None
    } else {
        Some(set_build_key(&mut text, "jobs", &jobs.to_string(), true))
    };

    let (linker_report, linker_edit) = apply_linker(&mut text, linker)?;

    let changed = !existed
        || build_dir_edit != CargoEdit::AlreadySet
        || wrapper_edit.is_some_and(|edit| edit != CargoEdit::AlreadySet)
        || jobs_edit.is_some_and(|edit| edit != CargoEdit::AlreadySet)
        || incremental_edit.is_some_and(|edit| edit != CargoEdit::AlreadySet)
        || linker_edit.is_some_and(|edit| edit != CargoEdit::AlreadySet);

    // Persist only the keys the user explicitly selected. The project file is
    // never written; the global file lives in the OS config directory so it
    // can be read before the effective Cargo home is known.
    let settings_path = paths::global_config_path()?;
    let settings_existed = settings_path.is_file();
    let mut settings_text = if settings_existed {
        crate::util::read_trusted_config(&settings_path, 1024 * 1024)
            .with_context(|| format!("reading {}", settings_path.display()))?
    } else {
        String::new()
    };
    let settings_before = settings_existed.then(|| settings_text.clone());
    let mut settings_changed = false;
    if let Some(value) = opts.preset {
        settings_changed |= set_top_key(
            &mut settings_text,
            "preset",
            &format!("\"{}\"", value.as_str()),
        );
    }
    if let Some(value) = opts.linker {
        settings_changed |= set_top_key(
            &mut settings_text,
            "linker",
            &format!("\"{}\"", value.as_str()),
        );
    }
    if let Some(value) = opts.memory_text {
        settings_changed |= set_top_key(
            &mut settings_text,
            "memory",
            &format!("\"{}\"", value.trim()),
        );
    }
    if let Some(raw) = opts.work_root_arg {
        if raw == "default" {
            settings_changed |= remove_top_key(&mut settings_text, "work");
        } else {
            settings_changed |= set_top_key(
                &mut settings_text,
                "work",
                &toml_string(&work_root.to_string_lossy()),
            );
        }
    }
    match opts.cargo_home {
        CargoHomeAction::Keep => {}
        CargoHomeAction::Set(path) => {
            settings_changed |= set_top_key(
                &mut settings_text,
                "cargo_home",
                &toml_string(&path.to_string_lossy()),
            );
        }
        CargoHomeAction::Clear => {
            settings_changed |= remove_top_key(&mut settings_text, "cargo_home");
        }
    }
    if opts.remote_off {
        settings_changed |= remove_remote_table(&mut settings_text)?;
    } else {
        if let Some(tier) = opts.remote_tier {
            settings_changed |= set_remote_key(&mut settings_text, "tier", tier.as_str())?;
        }
        if let Some(url) = opts.remote_url {
            settings_changed |= set_remote_key(&mut settings_text, "url", url)?;
        }
        if let Some(key) = opts.remote_key {
            settings_changed |= set_remote_key(&mut settings_text, "publisher_key", key)?;
        }
        if opts.remote_url.is_some() || opts.remote_key.is_some() {
            let parsed: settings::FileConfig = toml::from_str(&settings_text)
                .context("parsing the global epicenter.toml after the remote edit")?;
            let remote = parsed.remote.unwrap_or_default();
            if let Some(url) = remote.url.as_deref() {
                settings::normalize_remote_url(url)?;
            }
            if let Some(key) = remote.publisher_key.as_deref() {
                settings::normalize_remote_publisher_key(key)?;
            }
            if remote.url.is_some() && remote.publisher_key.is_none() {
                anyhow::bail!(
                    "`[remote] url` requires a pinned `publisher_key`; \
                     pass `--remote-key` for the first setup"
                );
            }
        }
    }

    // Validate both plans before writing either file: a rejected remote policy
    // must leave the Cargo config exactly as it was.
    let cargo_plan = (changed && !opts.dry_run).then_some(PendingWrite {
        path: cargo_cfg.as_path(),
        existed,
        text: text.as_str(),
    });
    let settings_plan = (settings_changed && !opts.dry_run).then_some(PendingWrite {
        path: settings_path.as_path(),
        existed: settings_existed,
        text: settings_text.as_str(),
    });
    let (backup, settings_backup) = commit_plans(cargo_plan, settings_plan)?;
    let policy = PolicyReport {
        preset,
        effective_preset,
        preset_source,
        memory,
        memory_source,
        cores,
        jobs,
        incremental,
        check_tier: effective_preset == settings::EffectivePreset::Ci,
        compression: settings.compression(),
        restore: settings.restore(),
        linker,
        linker_source,
        wrapper: wrapper.clone(),
        cargo_home,
        cargo_home_source,
        store,
        work_root,
        work_root_source,
    };

    Ok(SetupReport {
        root,
        build_dir_edit,
        wrapper_edit,
        jobs_edit,
        incremental_edit,
        linker: linker_report,
        backup,
        settings_backup,
        using_override: build_dir_value != DEFAULT_BUILD_DIR,
        policy,
        dry_run: opts.dry_run,
        cargo_before,
        cargo_after: text,
        settings_before,
        settings_after: settings_changed.then_some(settings_text),
        settings_path,
    })
}

/// Apply the selected linker, returning the report and the Cargo edit that
/// participated in the `changed` decision.
fn apply_linker(
    text: &mut String,
    choice: LinkerChoice,
) -> Result<(Option<LinkerSetupReport>, Option<CargoEdit>)> {
    match choice {
        LinkerChoice::Auto => Ok((None, None)),
        LinkerChoice::Lld | LinkerChoice::Wild | LinkerChoice::Mold | LinkerChoice::Gold => {
            let linker = match choice {
                LinkerChoice::Lld => crate::fastlink::detect()?,
                LinkerChoice::Wild => crate::fastlink::detect_wild()?,
                LinkerChoice::Mold => crate::fastlink::detect_mold()?,
                LinkerChoice::Gold => crate::fastlink::detect_gold()?,
                _ => unreachable!(),
            };
            let mut targets = Vec::new();
            let mut conflict = false;
            for plan in linker.plans() {
                let (edit, target_conflict) =
                    set_target_rustflags(text, &plan.target, &plan.literal, &plan.legacy);
                conflict |= target_conflict;
                targets.push(LinkerTargetReport {
                    target: plan.target,
                    flags: plan.flags,
                    edit,
                });
            }
            let changed = targets
                .iter()
                .any(|target| target.edit != CargoEdit::AlreadySet);
            Ok((
                Some(LinkerSetupReport {
                    choice,
                    binary: linker.linker.clone(),
                    targets,
                    conflict,
                }),
                Some(if changed {
                    CargoEdit::Replaced
                } else {
                    CargoEdit::AlreadySet
                }),
            ))
        }
        LinkerChoice::System => {
            // Removal is structural: every `[target.*]` table whose rustflags
            // are entirely managed is cleared, regardless of which binary (or
            // whether it still exists) wrote them. This catches stale Mold,
            // Gold and Wild host flags plus Wild's wasm target.
            let mut targets = Vec::new();
            let mut conflict = false;
            for target in managed_targets(text) {
                let (edit, target_conflict) = remove_target_rustflags(text, &target, "", &[]);
                conflict |= target_conflict;
                targets.push(LinkerTargetReport {
                    target,
                    flags: Vec::new(),
                    edit,
                });
            }
            let changed = targets
                .iter()
                .any(|target| target.edit == CargoEdit::Removed);
            Ok((
                Some(LinkerSetupReport {
                    choice,
                    binary: PathBuf::new(),
                    targets,
                    conflict,
                }),
                Some(if changed {
                    CargoEdit::Removed
                } else {
                    CargoEdit::AlreadySet
                }),
            ))
        }
    }
}

/// Set a top-level key in `epicenter.toml`, preserving comments and tables.
/// Returns whether the text changed.
fn set_top_key(text: &mut String, key: &str, wanted: &str) -> bool {
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut first_table = lines.len();
    let mut found = None;
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            first_table = index;
            break;
        }
        if let Some((candidate, _)) = trimmed.split_once('=') {
            if key_matches(candidate, key) {
                found = Some(index);
                break;
            }
        }
    }
    let wanted_line = format!("{key} = {wanted}");
    match found {
        Some(index) if lines[index].trim() == wanted_line => false,
        Some(index) => {
            lines[index] = wanted_line;
            *text = lines.join("\n") + "\n";
            true
        }
        None => {
            lines.insert(first_table, wanted_line);
            *text = lines.join("\n") + "\n";
            true
        }
    }
}

/// Remove a top-level key from `epicenter.toml`, preserving comments/tables.
fn remove_top_key(text: &mut String, key: &str) -> bool {
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut found = None;
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            break;
        }
        if let Some((candidate, _)) = trimmed.split_once('=') {
            if key_matches(candidate, key) {
                found = Some(index);
                break;
            }
        }
    }
    let Some(index) = found else {
        return false;
    };
    lines.remove(index);
    *text = lines.join("\n") + "\n";
    true
}

/// Set a key inside the `[remote]` table, preserving unrelated tables and
/// comments. Returns whether the text changed.
fn set_remote_key(text: &mut String, key: &str, wanted: &str) -> Result<bool> {
    let before = text.clone();
    let mut doc: DocumentMut = text.parse().context("parsing the global epicenter.toml")?;
    let remote = doc
        .as_table_mut()
        .entry("remote")
        .or_insert(Item::Table(Table::new()));
    let remote = remote
        .as_table_mut()
        .context("`[remote]` must be a table, not an inline value")?;
    remote.insert(key, value(wanted));
    *text = doc.to_string();
    Ok(*text != before)
}

/// Remove the whole `[remote]` table. Returns whether the text changed.
fn remove_remote_table(text: &mut String) -> Result<bool> {
    let before = text.clone();
    let mut doc: DocumentMut = text.parse().context("parsing the global epicenter.toml")?;
    let removed = doc.as_table_mut().remove("remote").is_some();
    if removed {
        *text = doc.to_string();
    }
    Ok(*text != before)
}

/// One file edit, validated before either setup file is written.
struct PendingWrite<'a> {
    path: &'a Path,
    existed: bool,
    text: &'a str,
}

/// Validate both setup plans, then commit the Cargo config and the policy
/// file. Nothing is written when either plan is not valid TOML.
fn commit_plans(
    cargo: Option<PendingWrite<'_>>,
    settings: Option<PendingWrite<'_>>,
) -> Result<(Option<PathBuf>, Option<PathBuf>)> {
    for plan in [cargo.as_ref(), settings.as_ref()].into_iter().flatten() {
        plan.text
            .parse::<DocumentMut>()
            .with_context(|| format!("validating {}", plan.path.display()))?;
    }
    Ok((commit_plan(cargo)?, commit_plan(settings)?))
}

fn commit_plan(plan: Option<PendingWrite<'_>>) -> Result<Option<PathBuf>> {
    let Some(plan) = plan else {
        return Ok(None);
    };
    if let Some(parent) = plan.path.parent() {
        crate::util::create_private_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let backup = plan.existed.then(|| backup_file(plan.path)).transpose()?;
    crate::util::write_atomic_private(plan.path, plan.text.as_bytes())?;
    Ok(backup)
}

/// `<config>.epicenter-bak` (suffix 0).
fn backup_base(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".epicenter-bak");
    path.with_file_name(name)
}

/// Setup backups for a config path, oldest to newest.
///
/// Suffixes are monotonic (`…-bak`, `…-bak.1`, `…-bak.2`, …), so the newest
/// backup is always the highest suffix — never mtime (copies can carry any
/// timestamp) and never "first free" (a gap would break the ordering).
fn backups(path: &Path) -> Result<Vec<(u64, PathBuf)>> {
    let base = backup_base(path);
    let Some(parent) = base.parent() else {
        return Ok(Vec::new());
    };
    let base_name = base
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err).with_context(|| format!("reading {}", parent.display())),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let suffix = if name == base_name {
            0
        } else if let Some(rest) = name.strip_prefix(&base_name) {
            match rest.strip_prefix('.').and_then(|n| n.parse::<u64>().ok()) {
                Some(number) => number,
                None => continue, // `…-bak.2.tmp`, `…-bak.old`
            }
        } else {
            continue;
        };
        // Follow no links here: a backup is a plain file next to the config.
        // A vanished entry is not a candidate; neither is a link replacing
        // one while we scan.
        let meta = match metadata_nofollow(&entry.path()) {
            Ok(meta) => meta,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
                ) =>
            {
                continue;
            }
            // One unreadable candidate must not block a setup that can still
            // use the older, readable backups.
            Err(_) => continue,
        };
        if !meta.is_file() {
            continue;
        }
        out.push((suffix, entry.path()));
    }
    out.sort_by_key(|(suffix, _)| *suffix);
    Ok(out)
}

/// The newest setup backup for a config path, if any.
fn latest_backup(path: &Path) -> Result<Option<PathBuf>> {
    Ok(backups(path)?.pop().map(|(_, path)| path))
}

/// Copy `path` to the next numbered backup before modifying it.
pub(crate) fn backup_file(path: &Path) -> Result<PathBuf> {
    let base = backup_base(path);
    let next = backups(path)?
        .last()
        .map(|(suffix, _)| suffix + 1)
        .unwrap_or(0);
    let mut name = base.file_name().unwrap_or_default().to_os_string();
    if next > 0 {
        name.push(format!(".{next}"));
    }
    let backup = base.with_file_name(name);
    // Create the backup with O_EXCL; the source is opened O_NOFOLLOW by
    // copy_file_hashed so a swapped symlink cannot redirect the copy.
    let source = path.to_path_buf();
    crate::util::copy_file_hashed(&source, &backup)
        .with_context(|| format!("backing up {}", path.display()))?;
    if let Ok(meta) = fs::metadata(&source) {
        let _ = fs::set_permissions(&backup, meta.permissions());
    }
    Ok(backup)
}

/// Restored config + the backup it came from.
#[derive(Debug)]
pub struct RevertReport {
    pub config: PathBuf,
    pub backup: PathBuf,
}

/// Restore the global cargo config from its newest setup backup.
pub fn revert_config() -> Result<RevertReport> {
    let config = cargo_config_path()?;
    revert_config_at(&config)
}

/// Restore the newest backup of the global Cargo config and the global
/// epicenter.toml. Returns one report per file that had a backup.
pub fn revert_backups(dry_run: bool) -> Result<Vec<RevertReport>> {
    let mut out = Vec::new();
    for path in [cargo_config_path()?, paths::global_config_path()?] {
        let Some(backup) = latest_backup(&path)? else {
            continue;
        };
        if !dry_run {
            let text = crate::util::read_trusted_config(&backup, 1024 * 1024)
                .with_context(|| format!("reading backup {}", backup.display()))?;
            crate::util::write_atomic_private(&path, text.as_bytes())
                .with_context(|| format!("restoring {}", path.display()))?;
        }
        out.push(RevertReport {
            config: path,
            backup,
        });
    }
    if out.is_empty() {
        anyhow::bail!("no setup backups found — run `epicenter setup` after a change first");
    }
    Ok(out)
}

/// Restore `config` from its newest backup: trusted read, atomic write.
fn revert_config_at(config: &Path) -> Result<RevertReport> {
    let Some(backup) = latest_backup(config)? else {
        anyhow::bail!(
            "no setup backup found next to {} — run `epicenter setup` after a change first",
            config.display()
        );
    };
    let text = crate::util::read_trusted_config(&backup, 1024 * 1024)
        .with_context(|| format!("reading backup {}", backup.display()))?;
    crate::util::write_atomic_private(config, text.as_bytes())
        .with_context(|| format!("restoring {}", config.display()))?;
    Ok(RevertReport {
        config: config.to_path_buf(),
        backup,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaced_line_keeps_the_rest_of_the_file() {
        // Regression test for the split_inclusive `Replaced` bug: the kache
        // line and the [net] table had to survive the replacement.
        let mut src =
            "[build]\nbuild-dir = '/old'\nrustc-wrapper = \"kache\"\n\n[net]\nx = 1\n".to_string();
        let edit = set_build_key(&mut src, "build-dir", "/cache", false);
        assert_eq!(edit, CargoEdit::Replaced);
        assert!(
            src.contains("rustc-wrapper = \"kache\""),
            "tail deleted:\n{src}"
        );
        assert!(src.contains("[net]"), "tail deleted:\n{src}");
        let dir = src.find("build-dir = '/cache'").unwrap();
        let net = src.find("[net]").unwrap();
        assert!(dir < net, "replaced value must stay inside [build]:\n{src}");
    }
    #[test]
    fn backups_are_numbered_and_latest_wins() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config = dir.path().join("config.toml");
        fs::write(&config, "[build]\nbuild-dir = '/one'\n")?;

        let first = backup_file(&config)?;
        assert_eq!(
            first.file_name().unwrap(),
            "config.toml.epicenter-bak",
            "the first backup has no suffix"
        );
        fs::write(&config, "[build]\nbuild-dir = '/two'\n")?;
        let second = backup_file(&config)?;
        assert_eq!(
            second.file_name().unwrap(),
            "config.toml.epicenter-bak.1",
            "suffixes are monotonic"
        );
        assert_eq!(latest_backup(&config)?, Some(second.clone()));
        assert_eq!(
            fs::read_to_string(&first)?,
            "[build]\nbuild-dir = '/one'\n",
            "the older backup is untouched"
        );
        Ok(())
    }

    #[test]
    fn revert_restores_the_newest_backup() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config = dir.path().join("config.toml");
        fs::write(&config, "one\n")?;
        let first = backup_file(&config)?;
        fs::write(&config, "two\n")?;
        let second = backup_file(&config)?;
        fs::write(&config, "current\n")?;

        let report = revert_config_at(&config)?;
        assert_eq!(report.config, config.clone());
        assert_eq!(report.backup, second);
        assert_eq!(fs::read_to_string(&config)?, "two\n");
        assert!(first.is_file() && second.is_file(), "backups are kept");

        // Reverting again is idempotent: the newest backup is still the same.
        let again = revert_config_at(&config)?;
        assert_eq!(again.backup, second);
        assert_eq!(fs::read_to_string(&config)?, "two\n");
        Ok(())
    }

    #[test]
    fn revert_without_a_backup_is_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let err = revert_config_at(&config).unwrap_err();
        assert!(err.to_string().contains("no setup backup"), "{err}");
    }

    #[test]
    fn remote_table_edits_preserve_other_tables() -> Result<()> {
        let mut text =
            "preset = \"dev\"\n\n[remote]\ntier = \"libraries\"\n\n[net]\noffline = true\n"
                .to_string();
        assert!(set_remote_key(
            &mut text,
            "url",
            "https://cache.example/root"
        )?);
        assert!(set_remote_key(&mut text, "publisher_key", "ab")?);
        assert!(text.contains("[net]\noffline = true"), "{text}");
        assert!(text.contains("tier = \"libraries\""), "{text}");

        assert!(remove_remote_table(&mut text)?);
        assert!(!text.contains("[remote]"), "{text}");
        assert!(text.contains("[net]"), "{text}");
        assert!(text.contains("preset = \"dev\""), "{text}");
        Ok(())
    }

    #[test]
    fn inserts_lld_flags_into_an_existing_target_table() {
        let mut src = "[build]\nbuild-dir = '/c'\n\n[target.x86_64-unknown-linux-gnu]\nlinker = \"clang\"\n\n[net]\nx = 1\n".to_string();
        let literal = r#"[\"-C\", \"link-arg=-fuse-ld=lld\", \"-C\", \"link-arg=-B/tmp/gcc-ld\"]"#;
        let (edit, conflict) =
            set_target_rustflags(&mut src, "x86_64-unknown-linux-gnu", literal, &[]);
        assert_eq!(edit, CargoEdit::Inserted);
        assert!(!conflict);
        assert!(
            src.contains("linker = \"clang\""),
            "existing key lost:\n{src}"
        );
        let target = src.find("[target.").unwrap();
        let flags = src.find("rustflags").unwrap();
        let net = src.find("[net]").unwrap();
        assert!(
            target < flags && flags < net,
            "flags escaped the table:\n{src}"
        );
        assert!(src.contains(literal));
    }
    #[test]
    fn lld_flags_are_never_overwritten() {
        let mut src =
            "[target.x86_64-unknown-linux-gnu]\nrustflags = [\"-C\", \"custom\"]\n".to_string();
        let original = src.clone();
        let (edit, conflict) = set_target_rustflags(
            &mut src,
            "x86_64-unknown-linux-gnu",
            "[\"-C\", \"ours\"]",
            &[],
        );
        assert_eq!(edit, CargoEdit::AlreadySet);
        assert!(conflict);
        assert_eq!(src, original, "existing flags untouched");

        // Re-running the same linker choice is a clean no-op.
        let mut same =
            "[target.x86_64-unknown-linux-gnu]\nrustflags = [\"-C\", \"ours\"]\n".to_string();
        let original = same.clone();
        let (edit, conflict) = set_target_rustflags(
            &mut same,
            "x86_64-unknown-linux-gnu",
            "[\"-C\", \"ours\"]",
            &[],
        );
        assert_eq!(edit, CargoEdit::AlreadySet);
        assert!(!conflict);
        assert_eq!(same, original);
    }
    #[test]
    fn removes_only_our_lld_flags() {
        let literal = r#"[\"-C\", \"link-arg=-fuse-ld=lld\"]"#;
        let mut src = format!(
            "[target.x86_64-unknown-linux-gnu]\nlinker = \"clang\"\nrustflags = {literal}\n\n[net]\nx = 1\n"
        );
        let (edit, conflict) =
            remove_target_rustflags(&mut src, "x86_64-unknown-linux-gnu", literal, &[]);
        assert_eq!(edit, CargoEdit::Removed);
        assert!(!conflict);
        assert!(!src.contains("rustflags"), "flags not removed:\n{src}");
        assert!(
            src.contains("linker = \"clang\""),
            "other keys kept:\n{src}"
        );

        let mut custom =
            "[target.x86_64-unknown-linux-gnu]\nrustflags = [\"-C\", \"custom\"]\n".to_string();
        let original = custom.clone();
        let (edit, conflict) = remove_target_rustflags(
            &mut custom,
            "x86_64-unknown-linux-gnu",
            "[\"-C\", \"ours\"]",
            &[],
        );
        assert_eq!(edit, CargoEdit::AlreadySet);
        assert!(conflict);
        assert_eq!(custom, original, "custom flags untouched");
    }
    #[test]
    fn lld_flags_create_the_target_table_when_missing() {
        let literal = r#"[\"-C\", \"link-arg=-fuse-ld=lld\"]"#;
        let mut src = "[build]\nbuild-dir = '/c'\n".to_string();
        let (edit, conflict) =
            set_target_rustflags(&mut src, "x86_64-unknown-linux-gnu", literal, &[]);
        assert_eq!(edit, CargoEdit::Appended);
        assert!(!conflict);
        assert!(
            src.contains("[target.x86_64-unknown-linux-gnu]\nrustflags = "),
            "got:\n{src}"
        );
    }
    #[test]
    fn appends_table_without_merging_lines() {
        // Regression test for the collect::<String> `Appended` bug: joining
        // without separators fused `[net]` and `foo = 1` into one line.
        let mut src = "[net]\nfoo = 1\n".to_string();
        let edit = set_build_key(&mut src, "build-dir", "/cache", false);
        assert_eq!(edit, CargoEdit::Appended);
        assert!(!src.contains("[net]foo"), "lines merged:\n{src}");
        assert!(src.contains("foo = 1"));
        let net = src.find("[net]").unwrap();
        let build = src.rfind("[build]").unwrap();
        assert!(net < build);
    }
    #[test]
    fn appends_build_table_when_missing() {
        let mut src = "[net]\nfoo = 1\n".to_string();
        let edit = set_build_key(&mut src, "build-dir", "/cache", false);
        assert_eq!(edit, CargoEdit::Appended);
        assert!(src.contains("[build]\nbuild-dir = '/cache'"), "got:\n{src}");
    }
    #[test]
    fn inserts_into_existing_build_table() {
        let mut src = "[build]\nrustflags = []\n\n[net]\nx = 1\n".to_string();
        let edit = set_build_key(&mut src, "build-dir", "/cache", false);
        assert_eq!(edit, CargoEdit::Inserted);
        // build-dir must land inside [build], i.e. after the header but before [net].
        let build = src.find("[build]").unwrap();
        let dir = src.find("build-dir").unwrap();
        let net = src.find("[net]").unwrap();
        assert!(build < dir && dir < net, "got:\n{src}");
    }
    #[test]
    fn replaces_old_value() {
        let mut src = "[build]\nbuild-dir = '/old'\n".to_string();
        let edit = set_build_key(&mut src, "build-dir", "/cache", false);
        assert_eq!(edit, CargoEdit::Replaced);
        assert!(src.contains("build-dir = '/cache'"));
        assert!(!src.contains("/old"));
    }
    #[test]
    fn already_set_is_a_no_op() {
        let mut src = "[build]\nbuild-dir = '/cache'\n".to_string();
        let original = src.clone();
        let edit = set_build_key(&mut src, "build-dir", "/cache", false);
        assert_eq!(edit, CargoEdit::AlreadySet);
        assert_eq!(src, original);
    }
    #[test]
    fn removes_wrapper_line() {
        let mut src = "[build]\nbuild-dir = '/cache'\nrustc-wrapper = 'sccache'\n".to_string();
        let edit = remove_build_key(&mut src, "rustc-wrapper");
        assert_eq!(edit, CargoEdit::Removed);
        assert!(src.contains("build-dir"), "build-dir must survive:\n{src}");
        assert!(!src.contains("rustc-wrapper"));
    }
    #[test]
    fn remove_is_a_no_op_when_absent() {
        let mut src = "[build]\nbuild-dir = '/cache'\n".to_string();
        let original = src.clone();
        let edit = remove_build_key(&mut src, "rustc-wrapper");
        assert_eq!(edit, CargoEdit::AlreadySet);
        assert_eq!(src, original);
    }
    #[test]
    fn reads_key_from_build_table() {
        assert_eq!(
            read_build_key("[build]\nbuild-dir = '/cache' # comment\n", "build-dir"),
            Some("/cache".to_string()),
        );
        assert_eq!(read_build_key("[build]\nother = 1\n", "build-dir"), None);
        // A build-dir under some OTHER table must not be picked up.
        assert_eq!(
            read_build_key("[net]\nbuild-dir = '/x'\n", "build-dir"),
            None
        );
    }

    #[test]
    fn reads_generic_table_keys() {
        let text = "[unstable]\nfine-grain-locking = true # concurrent builds\n\n[build]\nbuild-dir = '/x'\n";
        assert_eq!(
            read_table_key(text, "unstable", "fine-grain-locking"),
            Some("true".to_string())
        );
        assert_eq!(read_table_key(text, "build", "fine-grain-locking"), None);
        assert_eq!(
            read_table_key(text, "build", "build-dir"),
            Some("/x".to_string())
        );
        // A key mentioned in a comment elsewhere must not leak.
        assert_eq!(
            read_table_key(
                "[other]\n# fine-grain-locking = true\n",
                "unstable",
                "fine-grain-locking"
            ),
            None
        );
    }

    #[test]
    fn config_writes_reject_injection() {
        assert!(validate_config_value("x'\nrustc-wrapper = '/tmp/evil' #", "build-dir").is_err());
        assert!(validate_config_value("x\r\ny", "build-dir").is_err());
        assert!(validate_config_value("x\0y", "build-dir").is_err());
        assert!(validate_config_value("/tmp/cache", "build-dir").is_ok());
    }

    #[test]
    fn removal_is_scoped_to_the_build_table() {
        let mut src =
            "[build]\nbuild-dir = '/x'\n\n[target.x]\nrustc-wrapper = 'keep'\n".to_string();
        let edit = remove_build_key(&mut src, "rustc-wrapper");
        assert_eq!(edit, CargoEdit::AlreadySet);
        assert!(src.contains("rustc-wrapper = 'keep'"));
    }
    #[test]
    fn dotted_build_dir_is_detected() {
        assert_eq!(
            read_build_key("build.build-dir = '/tmp/dotted'\n", "build-dir"),
            Some("/tmp/dotted".to_string())
        );
    }

    #[test]
    fn comments_inside_quoted_values_are_preserved() {
        assert_eq!(
            read_build_key("[build]\nbuild-dir = '/tmp/a#b' # tail\n", "build-dir"),
            Some("/tmp/a#b".to_string())
        );
    }

    #[test]
    fn cache_root_input_is_normalized() {
        // Cargo templates pass through untouched.
        assert_eq!(
            normalize_root_input("{cargo-cache-home}/custom").unwrap(),
            PathBuf::from("{cargo-cache-home}/custom"),
        );
        // Absolute stays absolute (use a host-absolute path).
        let absolute = if cfg!(windows) {
            r"C:\cache"
        } else {
            "/tmp/cache"
        };
        assert_eq!(
            normalize_root_input(absolute).unwrap(),
            PathBuf::from(absolute),
        );
        // `~` expands to the home directory.
        let home = paths::home().unwrap();
        assert_eq!(normalize_root_input("~/cache").unwrap(), home.join("cache"));
        // Relative resolves against the current directory.
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(
            normalize_root_input("cache/build").unwrap(),
            cwd.join("cache/build"),
        );
    }

    #[test]
    fn incremental_is_written_as_a_bool() {
        let mut text = "[build]\nbuild-dir = '/cache'\n".to_string();
        let edit = set_incremental(&mut text, true);
        assert_eq!(edit, CargoEdit::Inserted);
        assert!(text.contains("incremental = true"), "got:\n{text}");
        assert!(!text.contains("incremental = 'true'"), "got:\n{text}");

        let again = set_incremental(&mut text, true);
        assert_eq!(again, CargoEdit::AlreadySet);
        assert_eq!(text.matches("incremental =").count(), 1, "got:\n{text}");
    }

    #[test]
    fn incremental_replaces_false() {
        let mut text = "[build]\nincremental = false\n".to_string();
        let edit = set_incremental(&mut text, true);
        assert_eq!(edit, CargoEdit::Replaced);
        assert!(text.contains("incremental = true"));
        assert!(!text.contains("incremental = false"));
    }

    #[test]
    fn migrates_the_old_msvc_lld_link_flags() {
        let target = "x86_64-pc-windows-msvc";
        let old = r#"["-C", "linker=C:/rust/gcc-ld/lld-link.exe"]"#;
        let new = r#"["-C", "linker=C:/rust/bin/rust-lld.exe"]"#;
        let mut src = format!("[target.{target}]\nrustflags = {old}\n");
        let (edit, conflict) = set_target_rustflags(&mut src, target, new, &[old.to_string()]);
        assert_eq!(edit, CargoEdit::Replaced);
        assert!(!conflict);
        assert!(src.contains(new));
        assert!(!src.contains("lld-link.exe"));
    }

    #[test]
    fn system_removes_the_old_msvc_lld_link_flags() {
        let target = "x86_64-pc-windows-msvc";
        let old = r#"["-C", "linker=C:/rust/gcc-ld/lld-link.exe"]"#;
        let new = r#"["-C", "linker=C:/rust/bin/rust-lld.exe"]"#;
        let mut src = format!("[target.{target}]\nrustflags = {old}\n");
        let (edit, conflict) = remove_target_rustflags(&mut src, target, new, &[old.to_string()]);
        assert_eq!(edit, CargoEdit::Removed);
        assert!(!conflict);
        assert!(!src.contains("rustflags"), "{src}");
    }
    #[test]
    fn migrates_managed_wild_shape() {
        let target = "x86_64-unknown-linux-gnu";
        let old = r#"["-C", "link-arg=-fuse-ld=wild"]"#;
        let new = r#"["-C", "linker=clang", "-C", "link-arg=--ld-path=wild"]"#;
        let mut src = format!("[target.{target}]\nrustflags = {old}\n");
        let (edit, conflict) = set_target_rustflags(&mut src, target, new, &[]);
        assert_eq!(edit, CargoEdit::Replaced);
        assert!(!conflict, "a managed wild shape is not a user conflict");
        assert!(src.contains(new), "{src}");
    }

    #[test]
    fn removes_managed_wild_shape() {
        let target = "x86_64-unknown-linux-gnu";
        let old = r#"["-C", "link-arg=-fuse-ld=wild", "-C", "link-arg=-B/tmp/gcc-ld"]"#;
        let new = r#"["-C", "linker=clang", "-C", "link-arg=--ld-path=wild"]"#;
        let mut src = format!("[target.{target}]\nrustflags = {old}\n");
        let (edit, conflict) = remove_target_rustflags(&mut src, target, new, &[]);
        assert_eq!(edit, CargoEdit::Removed);
        assert!(!conflict);
        assert!(!src.contains("rustflags"), "{src}");
    }

    #[test]
    fn quoted_build_keys_are_updated_and_removed_in_place() {
        let mut src =
            "[build]\n\"incremental\" = false\n\"jobs\" = 1\n\"build-dir\" = '/old'\n".to_string();
        assert_eq!(set_incremental(&mut src, true), CargoEdit::Replaced);
        assert_eq!(
            set_build_key(&mut src, "jobs", "8", true),
            CargoEdit::Replaced
        );
        assert_eq!(src.matches("incremental =").count(), 1, "{src}");
        assert!(!src.contains("\"incremental\""), "{src}");
        assert_eq!(src.matches("jobs =").count(), 1, "{src}");
        assert!(!src.contains("\"jobs\""), "{src}");
        assert_eq!(remove_build_key(&mut src, "build-dir"), CargoEdit::Removed);
        assert!(!src.contains("build-dir"), "{src}");
        src.parse::<DocumentMut>().expect("valid toml");
        assert_eq!(
            read_build_key("[build]\n\"build-dir\" = '/quoted'\n", "build-dir"),
            Some("/quoted".to_string())
        );
    }

    #[test]
    fn quoted_policy_keys_are_updated_in_place() {
        let mut text =
            "\"preset\" = \"auto\"\n\"linker\" = \"auto\"\n\n[remote]\ntier = \"libraries\"\n"
                .to_string();
        assert!(set_top_key(&mut text, "preset", "\"dev\""));
        assert!(set_top_key(&mut text, "linker", "\"lld\""));
        assert_eq!(text.matches("preset =").count(), 1, "{text}");
        assert!(!text.contains("\"preset\""), "{text}");
        assert_eq!(text.matches("linker =").count(), 1, "{text}");
        assert!(
            text.find("preset").unwrap() < text.find("[remote]").unwrap(),
            "{text}"
        );
        text.parse::<DocumentMut>().expect("valid toml");

        assert!(remove_top_key(&mut text, "preset"));
        assert!(!text.contains("preset ="), "{text}");
        text.parse::<DocumentMut>().expect("valid toml");
    }

    #[test]
    fn custom_rustflags_that_mention_managed_flags_are_kept() {
        let target = "x86_64-unknown-linux-gnu";
        let custom = r#"["-C", "target-cpu=native", "-C", "link-arg=-fuse-ld=lld"]"#;
        let mut src = format!("[target.{target}]\nrustflags = {custom}\n");
        let literal = r#"["-C", "link-arg=-fuse-ld=lld"]"#;
        let (edit, conflict) = set_target_rustflags(&mut src, target, literal, &[]);
        assert_eq!(edit, CargoEdit::AlreadySet);
        assert!(conflict);
        assert!(src.contains("target-cpu=native"), "{src}");
    }

    #[test]
    fn managed_linker_ownership_is_structural() {
        assert!(is_managed_linker_flags(
            r#"["-C", "link-arg=-fuse-ld=lld"]"#
        ));
        assert!(is_managed_linker_flags(
            r#"["-C", "linker=clang", "-C", "link-arg=-fuse-ld=/usr/bin/mold"]"#
        ));
        assert!(is_managed_linker_flags(
            r#"["-C", "link-arg=--ld-path=/home/u/.cargo/bin/wild"]"#
        ));
        assert!(!is_managed_linker_flags(
            r#"["-C", "link-arg=--ld-path=/usr/bin/mold"]"#
        ));
        assert!(!is_managed_linker_flags(
            r#"["-C", "link-arg=-fuse-ld=lld-next"]"#
        ));
        assert!(!is_managed_linker_flags(r#"["-C", "target-cpu=native"]"#));
    }

    #[test]
    fn migrates_the_legacy_wild_literal_to_the_resolved_path() {
        let target = "x86_64-unknown-linux-gnu";
        let old = r#"["-C", "link-arg=-fuse-ld=wild"]"#;
        let new = r#"["-C", "link-arg=--ld-path=/home/u/.cargo/bin/wild"]"#;
        let mut src = format!("[target.{target}]\nrustflags = {old}\n");
        let (edit, conflict) = set_target_rustflags(&mut src, target, new, &[]);
        assert_eq!(edit, CargoEdit::Replaced);
        assert!(!conflict);
        assert!(src.contains("--ld-path=/home/u/.cargo/bin/wild"), "{src}");
    }

    #[test]
    fn system_removes_every_managed_linker_shape_without_probing() {
        let mut src = "\
[target.x86_64-unknown-linux-gnu]
rustflags = [\"-C\", \"linker=clang\", \"-C\", \"link-arg=-fuse-ld=/usr/bin/mold\"]

[target.aarch64-unknown-linux-gnu]
rustflags = [\"-C\", \"linker=clang\", \"-C\", \"link-arg=-fuse-ld=/usr/bin/ld.gold\"]

[target.wasm32-unknown-unknown]
rustflags = [\"-C\", \"linker=/home/u/.cargo/bin/wild\", \"-C\", \"linker-flavor=wasm-ld\"]

[target.thumbv7em-none-eabihf]
rustflags = [\"-C\", \"target-cpu=cortex-m4\"]
"
        .to_string();
        let (report, edit) = apply_linker(&mut src, LinkerChoice::System).unwrap();
        assert_eq!(edit, Some(CargoEdit::Removed));
        let report = report.expect("a system report");
        assert_eq!(report.targets.len(), 3, "{src}");
        assert!(!src.contains("mold"), "{src}");
        assert!(!src.contains("ld.gold"), "{src}");
        assert!(!src.contains("wasm-ld"), "{src}");
        assert!(src.contains("target-cpu=cortex-m4"), "{src}");
        src.parse::<DocumentMut>().expect("valid toml");
    }

    #[test]
    fn system_removes_a_resolved_wild_ld_path() {
        let mut src = "[target.x86_64-unknown-linux-gnu]\nrustflags = [\"-C\", \"link-arg=--ld-path=/opt/wild/bin/wild\"]\n"
            .to_string();
        let (_, edit) = apply_linker(&mut src, LinkerChoice::System).unwrap();
        assert_eq!(edit, Some(CargoEdit::Removed));
        assert!(!src.contains("rustflags"), "{src}");
    }

    #[test]
    fn invalid_settings_plan_commits_neither_file() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let cargo = dir.path().join("config.toml");
        let settings = dir.path().join("epicenter.toml");
        fs::write(&cargo, "[build]\nbuild-dir = '/old'\n")?;
        fs::write(&settings, "preset = \"auto\"\n")?;
        let err = commit_plans(
            Some(PendingWrite {
                path: &cargo,
                existed: true,
                text: "[build]\nbuild-dir = '/new'\n",
            }),
            Some(PendingWrite {
                path: &settings,
                existed: true,
                text: "preset = \"dev\n",
            }),
        )
        .unwrap_err();
        assert!(err.to_string().contains("validating"), "{err}");
        assert_eq!(fs::read_to_string(&cargo)?, "[build]\nbuild-dir = '/old'\n");
        assert_eq!(fs::read_to_string(&settings)?, "preset = \"auto\"\n");
        assert_eq!(backups(&cargo)?.len(), 0, "no backup before validation");
        Ok(())
    }

    #[test]
    fn preview_cargo_home_is_not_installed_process_wide() -> Result<()> {
        let before = paths::cargo_home()?;
        let home = tempfile::tempdir()?;
        assert_eq!(
            cargo_config_path_in(home.path())?,
            home.path().join("config.toml")
        );
        assert_eq!(
            resolve_template_in("{cargo-cache-home}/epicenter/build", home.path())?,
            home.path().join("epicenter").join("build")
        );
        assert_eq!(paths::cargo_home()?, before, "the preview leaked");
        Ok(())
    }
}
