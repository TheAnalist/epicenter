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

/// The effective shared-cache root: cargo's own runtime answer
/// (`cargo metadata` merges every config layer exactly like a real build),
/// falling back to the configured build-dir value (or the canonical default)
/// when cargo cannot be asked.
pub fn cache_root() -> Result<PathBuf> {
    if let Some(dir) = paths::cargo_metadata_build_dir() {
        return Ok(paths::normalize_host_separators(dir));
    }
    let value = cargo_configured("build-dir")?
        .unwrap_or_else(|| DEFAULT_BUILD_DIR.to_string());
    paths::resolve_template(&value)
}

/// Cargo's *global* config file: `$CARGO_HOME/config.toml`.
/// Settings there apply to every project on the machine.
pub fn cargo_config_path() -> Result<PathBuf> {
    Ok(paths::cargo_home()?.join("config.toml"))
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
    if text.contains("[build]") && text.contains(key) {
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        lines.retain(|line| !line.contains(key));
        (lines.join("\n") + "\n", CargoEdit::Removed)
    } else {
        (text.to_string(), CargoEdit::AlreadySet)
    }
}

/// Parse the value of `key` out of the `[build]` table.
fn read_build_key(text: &str, key: &str) -> Option<String> {
    read_table_key(text, "build", key)
}

/// Parse `key = value` out of any `[table]` of a cargo config text.
///
/// Only the exact table is scanned (until the next header line); a trailing
/// comment is stripped and surrounding quotes are removed.
pub fn read_table_key(text: &str, table: &str, key: &str) -> Option<String> {
    let header = format!("[{table}]");
    let mut in_table = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_table = trimmed.replace([' ', '\t'], "") == header;
            continue;
        }
        if !in_table {
            continue;
        }
        if let Some((candidate, value)) = trimmed.split_once('=') {
            if candidate.trim() != key {
                continue;
            }
            let value = value.split('#').next().unwrap_or("").trim();
            return Some(value.trim_matches(['"', '\'']).trim().to_string());
        }
    }
    None
}

/// Look up a key in any table of Cargo's *global* config file.
pub fn cargo_configured_in(table: &str, key: &str) -> Result<Option<String>> {
    let path = cargo_config_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path)?;
    Ok(read_table_key(&text, table, key))
}

/// Look up a `[build]` key in Cargo's *global* config file on disk.
pub fn cargo_configured(key: &str) -> Result<Option<String>> {
    let path = cargo_config_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path)?;
    Ok(read_build_key(&text, key))
}

/// Read a `[build]` key from ANY cargo config file — doctor uses this to scan
/// the ancestor `.cargo/config.toml` chain for shadowing values. Read-only.
pub fn read_build_table_key(path: &Path, key: &str) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
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
        cargo_configured("build-dir")?.unwrap_or_else(|| DEFAULT_BUILD_DIR.to_string())
    };

    // The filesystem view must always be RESOLVED (a template is not a path).
    let root = if root_arg.is_some() || use_default {
        paths::resolve_template(&build_dir_value)?
    } else {
        paths::resolve_template(&build_dir_value)
            .or_else(|_| paths::cargo_resolved_build_dir())?
    };
    fs::create_dir_all(&root).with_context(|| format!("creating cache dir {}", root.display()))?;

    // No epicenter side-file: the decision itself is the cargo config below.
    let cargo_cfg = cargo_config_path()?;
    let (build_dir_edit, wrapper_edit, backup) = if !cargo_cfg.exists() {
        if let Some(parent) = cargo_cfg.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut text = format!("[build]\nbuild-dir = '{build_dir_value}'\n");
        let wrapper_edit = if let Some(name) = with_wrapper {
            text.push_str(&format!("rustc-wrapper = '{name}'\n"));
            Some(CargoEdit::Inserted)
        } else {
            None
        };
        fs::write(&cargo_cfg, text)?;
        (CargoEdit::Created, wrapper_edit, None)
    } else {
        let text = fs::read_to_string(&cargo_cfg)
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
            fs::write(&cargo_cfg, text)
                .with_context(|| format!("writing {}", cargo_cfg.display()))?;
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
    let backup = path.with_file_name(name);
    fs::copy(path, &backup).with_context(|| format!("backing up {}", path.display()))?;
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
            read_table_key("[other]\n# fine-grain-locking = true\n", "unstable", "fine-grain-locking"),
            None
        );
    }

    #[test]
    fn cache_root_input_is_normalized() {
        // Cargo templates pass through untouched.
        assert_eq!(
            normalize_root_input("{cargo-cache-home}/custom").unwrap(),
            PathBuf::from("{cargo-cache-home}/custom"),
        );
        // Absolute stays absolute.
        assert_eq!(
            normalize_root_input("/tmp/cache").unwrap(),
            PathBuf::from("/tmp/cache"),
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
