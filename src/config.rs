//! Editing Cargo's global `config.toml` — the single source of truth.
//!
//! epicenter keeps NO state file of its own: the shared-cache decision lives
//! in `$CARGO_HOME/config.toml` as the `[build] build-dir` key, where cargo
//! (and any other tool) can read it. epicenter writes that key (`setup`),
//! reads it back, and verifies it (`doctor`).

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::paths::{self, DEFAULT_BUILD_DIR};

/// The effective shared-cache root: **only** the global
/// `$CARGO_HOME/config.toml` (or the canonical default). Project configs are
/// never consulted for state; `cargo metadata` is deliberately not executed.
pub fn cache_root() -> Result<PathBuf> {
    let root = trusted_cache_root()?;
    crate::util::ensure_windows_user_path(&root, "cache root")?;
    Ok(root)
}

/// The trusted root: the global `$CARGO_HOME/config.toml` `build-dir` value,
/// or the canonical default template. Never reads a project config and never
/// executes `cargo metadata`.
pub fn trusted_cache_root() -> Result<PathBuf> {
    let value = paths::cargo_build_dir()?.unwrap_or_else(|| DEFAULT_BUILD_DIR.to_string());
    paths::resolve_template(&value)
}

/// Config values are written inside single-quoted TOML strings. Reject the
/// characters that can break out of the literal or start a new key/line.
fn validate_config_value(value: &str, what: &str) -> Result<()> {
    if value.contains(['\n', '\r', '\0', '\'']) {
        anyhow::bail!("{what} contains a forbidden character (newline, NUL or single quote)");
    }
    Ok(())
}

/// Cargo's *global* config file: `$CARGO_HOME/config.toml`.
/// Settings there apply to every project on the machine.
pub fn cargo_config_path() -> Result<PathBuf> {
    let cargo_home = paths::cargo_home()?;
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
    match fs::symlink_metadata(&cargo_home) {
        Ok(meta) => {
            if !meta.is_dir() || meta.file_type().is_symlink() {
                anyhow::bail!(
                    "CARGO_HOME {} is a symlink or not a directory",
                    cargo_home.display()
                );
            }
            if !crate::util::owned_by_us(&meta) {
                anyhow::bail!(
                    "CARGO_HOME {} is owned by another user",
                    cargo_home.display()
                );
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if meta.mode() & 0o022 != 0 {
                    anyhow::bail!(
                        "CARGO_HOME {} is group/world-writable (mode {:o})",
                        cargo_home.display(),
                        meta.mode() & 0o777
                    );
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| format!("inspecting {}", cargo_home.display()));
        }
    }
    let path = cargo_home.join("config.toml");
    if path.is_relative() {
        anyhow::bail!(
            "global cargo config path is relative ({}) — set an absolute CARGO_HOME",
            path.display()
        );
    }
    crate::util::ensure_windows_user_path(&path, "global cargo config")?;
    match fs::symlink_metadata(&path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_file() {
                anyhow::bail!(
                    "global cargo config {} is a symlink or not a regular file",
                    path.display()
                );
            }
            if !crate::util::owned_by_us(&meta) {
                anyhow::bail!(
                    "global cargo config {} is owned by another user",
                    path.display()
                );
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if meta.mode() & 0o022 != 0 {
                    anyhow::bail!(
                        "global cargo config {} is group/world-writable (mode {:o})",
                        path.display(),
                        meta.mode() & 0o777
                    );
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| format!("inspecting {}", path.display()));
        }
    }
    Ok(path)
}

/// What an edit to Cargo's config changed.
#[derive(Debug, PartialEq, Eq)]
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
        }
    }
}

/// Sets `key = 'value'` inside the `[build]` table of a Cargo config,
/// as pure text surgery so user comments and formatting survive untouched.
fn set_build_key(text: &str, key: &str, value: &str) -> (String, CargoEdit) {
    let wanted = format!("{key} = '{value}'");
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
                if t.split_once('=').map_or(false, |(k, _)| k.trim() == key) {
                    if t == wanted {
                        return (text.to_string(), CargoEdit::AlreadySet);
                    }
                    lines[j] = wanted;
                    return (lines.join("\n") + "\n", CargoEdit::Replaced);
                }
                j += 1;
            }
            lines.insert(i + 1, wanted);
            (lines.join("\n") + "\n", CargoEdit::Inserted)
        }
        None => {
            let needs_blank = lines.last().map_or(false, |l| !l.trim().is_empty());
            if needs_blank {
                lines.push(String::new());
            }
            lines.push("[build]".to_string());
            lines.push(wanted);
            (lines.join("\n") + "\n", CargoEdit::Appended)
        }
    }
}

/// delete `key = ...` from the `[build]` table, if present.
fn remove_build_key(text: &str, key: &str) -> (String, CargoEdit) {
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
                .map_or(false, |(candidate, _)| candidate.trim() == key)
        {
            removed = true;
            continue;
        }
        out.push(line.to_string());
    }
    if removed {
        (out.join("\n") + "\n", CargoEdit::Removed)
    } else {
        (text.to_string(), CargoEdit::AlreadySet)
    }
}
/// Parse the value of `key` out of the `[build]` table.
fn read_build_key(text: &str, key: &str) -> Option<String> {
    read_table_key(text, "build", key)
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
        if at_root && candidate == Some(dotted.as_str()) {
            if let Some((_, value)) = trimmed.split_once('=') {
                return Some(clean_toml_value(value));
            }
        }
        if !in_table {
            continue;
        }
        if let Some((candidate, value)) = trimmed.split_once('=') {
            if candidate.trim() != key {
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

/// Look up a `[build]` key in Cargo's *global* config file on disk.
pub fn cargo_configured(key: &str) -> Result<Option<String>> {
    let path = cargo_config_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let text = crate::util::read_trusted_config(&path, 1024 * 1024)?;
    Ok(read_build_key(&text, key))
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
    /// Backup of the previous cargo config, if it was modified.
    pub backup: Option<PathBuf>,
    /// Is the override mode active (vs the canonical template)?
    pub using_override: bool,
}

/// The full `epicenter setup` orchestration: compute the decision, make the
/// directory, and write/merge the cargo config.
/// Normalize a user-provided `--cache-root` value.
///
/// - cargo template strings (`{…}`) pass through untouched — they resolve at
///   build time via cargo, exactly like the default template;
/// - `~` expands to the home directory;
/// - relative paths resolve against the current directory;
/// - absolute paths stay as-is.
pub fn normalize_root_input(raw: &str) -> Result<PathBuf> {
    let raw = raw.trim();
    anyhow::ensure!(!raw.is_empty(), "--cache-root must not be empty");
    if raw.contains('{') && raw.contains('}') {
        return Ok(PathBuf::from(raw)); // template passthrough
    }
    let home = paths::home()?;
    if raw == "~" || raw.starts_with("~/") || raw.starts_with("~\\") {
        let rest = raw[1..].trim_start_matches(['/', '\\']);
        return Ok(home.join(rest));
    }
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        return Ok(path);
    }
    let cwd = std::env::current_dir().context("resolving a relative --cache-root")?;
    Ok(cwd.join(path))
}

/// Priority: CLI root > stored override (`~/.epicenter/config.toml`) > default
/// template. `--cache-root` and `--use-default` rewrite the stored decision;
/// without them the stored decision (if any) stays untouched.
pub fn setup(
    root_arg: Option<&str>,
    use_default: bool,
    with_wrapper: Option<&str>,
    without_wrapper: bool,
) -> Result<SetupReport> {
    // Decision precedence: CLI root > the value already in cargo's config >
    // the canonical default template. `--cache-root` / `--use-default`
    // REWRITE the cargo-config decision; without them it stays untouched.
    // There is no epicenter side-file — `~/.cargo/config.toml` is the state.
    let build_dir_value: String = if let Some(raw) = root_arg {
        normalize_root_input(raw)?.to_string_lossy().into_owned()
    } else if use_default {
        DEFAULT_BUILD_DIR.to_string()
    } else {
        paths::cargo_build_dir()?.unwrap_or_else(|| DEFAULT_BUILD_DIR.to_string())
    };

    validate_config_value(&build_dir_value, "build-dir")?;
    if let Some(name) = with_wrapper {
        validate_config_value(name, "rustc-wrapper")?;
    }

    // The filesystem view must always be RESOLVED (a template is not a path).
    let root = paths::resolve_template(&build_dir_value)?;
    crate::util::ensure_windows_user_path(&root, "cache root")?;
    crate::util::create_private_dir_all(&root)
        .with_context(|| format!("creating cache dir {}", root.display()))?;

    // No epicenter side-file: the decision itself is the cargo config below.
    let cargo_cfg = cargo_config_path()?;
    let (build_dir_edit, wrapper_edit, backup) = if !cargo_cfg.exists() {
        if let Some(parent) = cargo_cfg.parent() {
            crate::util::create_private_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut text = format!("[build]\nbuild-dir = '{build_dir_value}'\n");
        let wrapper_edit = if let Some(name) = with_wrapper {
            text.push_str(&format!("rustc-wrapper = '{name}'\n"));
            Some(CargoEdit::Inserted)
        } else {
            None
        };
        crate::util::write_atomic_private(&cargo_cfg, text.as_bytes())?;
        (CargoEdit::Created, wrapper_edit, None)
    } else {
        let text = crate::util::read_trusted_config(&cargo_cfg, 1024 * 1024)
            .with_context(|| format!("reading {}", cargo_cfg.display()))?;
        let (text, build_dir_edit) = set_build_key(&text, "build-dir", &build_dir_value);
        let (text, wrapper_edit) = match with_wrapper {
            Some(name) => {
                let (text, edit) = set_build_key(&text, "rustc-wrapper", name);
                (text, Some(edit))
            }
            None if without_wrapper => {
                let (text, edit) = remove_build_key(&text, "rustc-wrapper");
                (text, Some(edit))
            }
            None => (text, None),
        };
        let mut backup = None;
        let changed = build_dir_edit != CargoEdit::AlreadySet
            || wrapper_edit
                .as_ref()
                .is_some_and(|e| *e != CargoEdit::AlreadySet);
        if changed {
            backup = Some(backup_file(&cargo_cfg)?);
            crate::util::write_atomic_private(&cargo_cfg, text.as_bytes())?;
        }
        (build_dir_edit, wrapper_edit, backup)
    };

    Ok(SetupReport {
        root,
        build_dir_edit,
        wrapper_edit,
        backup,
        using_override: build_dir_value != DEFAULT_BUILD_DIR,
    })
}

/// Copy `path` to `path.epicenter-bak` before modifying it.
fn backup_file(path: &Path) -> Result<PathBuf> {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".epicenter-bak");
    let base = path.with_file_name(name);
    // Never write through a pre-existing symlink; pick a fresh name instead.
    let mut backup = base.clone();
    let mut suffix = 0u32;
    while fs::symlink_metadata(&backup).is_ok() {
        suffix += 1;
        let mut name = base.file_name().unwrap_or_default().to_os_string();
        name.push(format!(".{suffix}"));
        backup = base.with_file_name(name);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaced_line_keeps_the_rest_of_the_file() {
        // Regression test for the split_inclusive `Replaced` bug: the kache
        // line and the [net] table had to survive the replacement.
        let src = "[build]\nbuild-dir = '/old'\nrustc-wrapper = \"kache\"\n\n[net]\nx = 1\n";
        let (out, edit) = set_build_key(src, "build-dir", "/cache");
        assert_eq!(edit, CargoEdit::Replaced);
        assert!(
            out.contains("rustc-wrapper = \"kache\""),
            "tail deleted:\n{out}"
        );
        assert!(out.contains("[net]"), "tail deleted:\n{out}");
        let dir = out.find("build-dir = '/cache'").unwrap();
        let net = out.find("[net]").unwrap();
        assert!(dir < net, "replaced value must stay inside [build]:\n{out}");
    }

    #[test]
    fn appends_table_without_merging_lines() {
        // Regression test for the collect::<String> `Appended` bug: joining
        // without separators fused `[net]` and `foo = 1` into one line.
        let (out, edit) = set_build_key("[net]\nfoo = 1\n", "build-dir", "/cache");
        assert_eq!(edit, CargoEdit::Appended);
        assert!(!out.contains("[net]foo"), "lines merged:\n{out}");
        assert!(out.contains("foo = 1"));
        let net = out.find("[net]").unwrap();
        let build = out.rfind("[build]").unwrap();
        assert!(net < build);
    }

    #[test]
    fn appends_build_table_when_missing() {
        let (out, edit) = set_build_key("[net]\nfoo = 1\n", "build-dir", "/cache");
        assert_eq!(edit, CargoEdit::Appended);
        assert!(out.contains("[build]\nbuild-dir = '/cache'"), "got:\n{out}");
    }

    #[test]
    fn inserts_into_existing_build_table() {
        let (out, edit) = set_build_key(
            "[build]\nrustflags = []\n\n[net]\nx = 1\n",
            "build-dir",
            "/cache",
        );
        assert_eq!(edit, CargoEdit::Inserted);
        // build-dir must land inside [build], i.e. after the header but before [net].
        let build = out.find("[build]").unwrap();
        let dir = out.find("build-dir").unwrap();
        let net = out.find("[net]").unwrap();
        assert!(build < dir && dir < net, "got:\n{out}");
    }

    #[test]
    fn replaces_old_value() {
        let (out, edit) = set_build_key("[build]\nbuild-dir = '/old'\n", "build-dir", "/cache");
        assert_eq!(edit, CargoEdit::Replaced);
        assert!(out.contains("build-dir = '/cache'"));
        assert!(!out.contains("/old"));
    }

    #[test]
    fn already_set_is_a_no_op() {
        let src = "[build]\nbuild-dir = '/cache'\n";
        let (out, edit) = set_build_key(src, "build-dir", "/cache");
        assert_eq!(edit, CargoEdit::AlreadySet);
        assert_eq!(out, src);
    }

    #[test]
    fn removes_wrapper_line() {
        let src = "[build]\nbuild-dir = '/cache'\nrustc-wrapper = 'sccache'\n";
        let (out, edit) = remove_build_key(src, "rustc-wrapper");
        assert_eq!(edit, CargoEdit::Removed);
        assert!(out.contains("build-dir"), "build-dir must survive:\n{out}");
        assert!(!out.contains("rustc-wrapper"));
    }

    #[test]
    fn remove_is_a_no_op_when_absent() {
        let src = "[build]\nbuild-dir = '/cache'\n";
        let (out, edit) = remove_build_key(src, "rustc-wrapper");
        assert_eq!(edit, CargoEdit::AlreadySet);
        assert_eq!(out, src);
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
        let src = "[build]\nbuild-dir = '/x'\n\n[target.x]\nrustc-wrapper = 'keep'\n";
        let (out, edit) = remove_build_key(src, "rustc-wrapper");
        assert_eq!(edit, CargoEdit::AlreadySet);
        assert!(out.contains("rustc-wrapper = 'keep'"));
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
}
