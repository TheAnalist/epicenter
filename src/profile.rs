//! Explicit Cargo profile writing.
//!
//! Compiler knobs belong in `Cargo.toml`; this module only writes the
//! recommendations `doctor` reports, and only when `setup --write-profile`
//! asks for it.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use toml_edit::{DocumentMut, Item, Table, value};

/// How much debug information the dev profile should keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevDebug {
    Full,
    Line,
    None,
}

/// What the explicit profile write did.
pub struct Report {
    pub path: PathBuf,
    /// Previous manifest backup, when the file changed.
    pub backup: Option<PathBuf>,
    pub before: String,
    pub after: String,
    pub changed: bool,
    pub dev_debug: DevDebug,
}

/// Write the recommended dev/release profile to the current workspace.
pub fn write_recommended(dry_run: bool, dev_debug: DevDebug) -> Result<Report> {
    let root = crate::doctor::workspace_root()
        .context("no Cargo workspace found from this directory — run setup in the project")?;
    write_manifest(&root.join("Cargo.toml"), dry_run, dev_debug)
}

fn apply(text: &str, dev_debug: DevDebug) -> Result<(String, bool)> {
    let before = text.to_string();
    let mut doc: DocumentMut = text.parse().context("parsing Cargo.toml")?;

    {
        let dev = profile_table(&mut doc, "dev")?;
        match dev_debug {
            DevDebug::Full => {
                dev["debug"] = value(2i64);
            }
            DevDebug::Line => {
                dev["debug"] = value("line-tables-only");
                #[cfg(unix)]
                {
                    dev["split-debuginfo"] = value("unpacked");
                }
            }
            DevDebug::None => {
                dev["debug"] = value(false);
            }
        }
        dev["lto"] = value(false);
        dev["codegen-units"] = value(256i64);
        dev["incremental"] = value(true);
    }
    {
        let release = profile_table(&mut doc, "release")?;
        release["lto"] = value("thin");
        release["codegen-units"] = value(16i64);
        release["debug"] = value(false);
    }

    let after = doc.to_string();
    Ok((after.clone(), after != before))
}

fn profile_table<'a>(doc: &'a mut DocumentMut, name: &str) -> Result<&'a mut Table> {
    let mut implicit = Table::new();
    implicit.set_implicit(true);
    let profile = doc
        .as_table_mut()
        .entry("profile")
        .or_insert(Item::Table(implicit));
    let profile = profile
        .as_table_mut()
        .context("[profile] must be a table, not an inline value")?;
    let table = profile.entry(name).or_insert(Item::Table(Table::new()));
    table
        .as_table_mut()
        .with_context(|| format!("[profile.{name}] must be a table"))
}

fn write_manifest(path: &Path, dry_run: bool, dev_debug: DevDebug) -> Result<Report> {
    let meta = match crate::util::metadata_nofollow(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            anyhow::bail!("refusing symlinked Cargo.toml: {}", path.display());
        }
        Err(err) => {
            return Err(err).with_context(|| format!("inspecting {}", path.display()));
        }
    };
    if !meta.is_file() {
        anyhow::bail!("{} is not a regular file", path.display());
    }
    let before = crate::util::read_small_text(path, 4 * 1024 * 1024)
        .with_context(|| format!("reading {}", path.display()))?;
    let (after, changed) = apply(&before, dev_debug)?;

    let mut backup = None;
    if changed && !dry_run {
        backup = Some(crate::config::backup_file(path)?);
        let permissions = meta.permissions();
        crate::util::write_atomic_private(path, after.as_bytes())
            .with_context(|| format!("writing {}", path.display()))?;
        fs::set_permissions(path, permissions)
            .with_context(|| format!("preserving permissions on {}", path.display()))?;
    }

    Ok(Report {
        path: path.to_path_buf(),
        backup,
        before,
        after,
        changed,
        dev_debug,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_recommendations_and_preserves_other_keys() -> Result<()> {
        let source = r#"[package]
name = "demo"
version = "0.1.0"

[profile.release]
lto = true
debug = 2
opt-level = 3

[profile.dev]
opt-level = 1
"#;
        let (after, changed) = apply(source, DevDebug::Full)?;
        assert!(changed);
        let parsed: toml::Value = toml::from_str(&after)?;
        let dev = &parsed["profile"]["dev"];
        assert_eq!(dev["debug"].as_integer(), Some(2));
        assert_eq!(dev["lto"].as_bool(), Some(false));
        assert_eq!(dev["codegen-units"].as_integer(), Some(256));
        assert_eq!(dev["incremental"].as_bool(), Some(true));
        assert_eq!(
            dev["opt-level"].as_integer(),
            Some(1),
            "custom key preserved"
        );

        let release = &parsed["profile"]["release"];
        assert_eq!(release["lto"].as_str(), Some("thin"));
        assert_eq!(release["codegen-units"].as_integer(), Some(16));
        assert_eq!(release["debug"].as_bool(), Some(false));
        assert_eq!(
            release["opt-level"].as_integer(),
            Some(3),
            "custom key preserved"
        );

        let (again, changed) = apply(&after, DevDebug::Full)?;
        assert!(!changed, "second write is a no-op");
        assert_eq!(again, after);
        Ok(())
    }

    #[test]
    fn dev_debug_line_sets_unpacked_on_unix() -> Result<()> {
        let source = "[package]\nname = \"demo\"\n";
        let (after, _) = apply(source, DevDebug::Line)?;
        let parsed: toml::Value = toml::from_str(&after)?;
        assert_eq!(
            parsed["profile"]["dev"]["debug"].as_str(),
            Some("line-tables-only")
        );
        #[cfg(unix)]
        assert_eq!(
            parsed["profile"]["dev"]["split-debuginfo"].as_str(),
            Some("unpacked")
        );
        Ok(())
    }

    #[test]
    fn dev_debug_none_disables_debug() -> Result<()> {
        let source = "[package]\nname = \"demo\"\n";
        let (after, _) = apply(source, DevDebug::None)?;
        let parsed: toml::Value = toml::from_str(&after)?;
        assert_eq!(parsed["profile"]["dev"]["debug"].as_bool(), Some(false));
        Ok(())
    }

    #[test]
    fn dry_run_reports_without_writing() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("Cargo.toml");
        fs::write(&path, "[package]\nname = \"demo\"\n")?;
        let before = fs::read_to_string(&path)?;
        let report = write_manifest(&path, true, DevDebug::Full)?;
        assert!(report.changed);
        assert!(report.backup.is_none());
        assert_eq!(fs::read_to_string(&path)?, before);
        Ok(())
    }

    #[test]
    fn changed_manifest_is_backed_up() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("Cargo.toml");
        fs::write(&path, "[package]\nname = \"demo\"\n")?;
        let report = write_manifest(&path, false, DevDebug::Full)?;
        assert!(report.changed);
        let backup = report.backup.expect("backup");
        assert!(backup.is_file());
        assert_ne!(fs::read_to_string(&path)?, report.before);
        Ok(())
    }
}
