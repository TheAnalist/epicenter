//! `Cargo.lock` as a restore filter.
//!
//! A stored unit is only seeded into a project that resolves the exact package
//! version it was compiled from. The lock is parsed once per command and every
//! unit check is a hash-map lookup, so binding restore to the lock adds one
//! small file read, not a per-unit scan.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::util;

/// One `[[package]]` entry from a lock file.
#[derive(Debug, Clone)]
pub struct LockPackage {
    pub version: String,
    /// Registry checksum or git URL+rev; empty for path packages.
    pub source: String,
}

/// Package names and versions a project resolves to.
#[derive(Debug, Clone, Default)]
pub struct LockIndex {
    packages: HashMap<String, Vec<LockPackage>>,
}

impl LockIndex {
    /// Nearest `Cargo.lock` at or above `cwd` (or above `manifest`).
    ///
    /// `None` means "cannot tell" — no lock, unreadable, or empty — and the
    /// caller keeps the whole-generation seed.
    pub fn load(cwd: &Path, manifest: Option<&Path>) -> Option<Self> {
        let mut dir = match manifest {
            Some(manifest) => {
                let manifest = if manifest.is_absolute() {
                    manifest.to_path_buf()
                } else {
                    cwd.join(manifest)
                };
                manifest
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| cwd.to_path_buf())
            }
            None => cwd.to_path_buf(),
        };
        loop {
            let lock = dir.join("Cargo.lock");
            if lock.is_file() {
                return Self::parse(&lock);
            }
            dir = dir.parent()?.to_path_buf();
        }
    }

    /// Parse one lock file. A symlinked or oversized lock is "cannot tell".
    pub fn parse(path: &Path) -> Option<Self> {
        let text = util::read_small_text(path, 4 * 1024 * 1024).ok()?;
        let lock: toml::Value = text.parse().ok()?;
        let mut packages: HashMap<String, Vec<LockPackage>> = HashMap::new();
        for package in lock.get("package")?.as_array()? {
            let (Some(name), Some(version)) = (
                package.get("name").and_then(toml::Value::as_str),
                package.get("version").and_then(toml::Value::as_str),
            ) else {
                continue;
            };
            if name.is_empty() || version.is_empty() {
                continue;
            }
            packages
                .entry(name.to_string())
                .or_default()
                .push(LockPackage {
                    version: version.to_string(),
                    source: package
                        .get("source")
                        .and_then(toml::Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                });
        }
        (!packages.is_empty()).then_some(Self { packages })
    }

    /// Does the project resolve this package at all?
    pub fn contains(&self, name: &str) -> bool {
        self.packages.contains_key(name)
    }

    /// Does the project resolve `name` at `version`?
    ///
    /// `version == None` means the unit did not record one (a git checkout, a
    /// path crate, or a build dir without a `.d` side file); keep the old
    /// name-only match rather than dropping the unit.
    pub fn matches(&self, name: &str, version: Option<&str>) -> bool {
        let Some(packages) = self.packages.get(name) else {
            return false;
        };
        match version {
            None => true,
            Some(wanted) => packages.iter().any(|package| package.version == wanted),
        }
    }

    pub fn len(&self) -> usize {
        self.packages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }
}

/// `--manifest-path <p>` or `--manifest-path=<p>` from a child's argv.
pub fn manifest_arg(command: &[String]) -> Option<PathBuf> {
    let mut args = command.iter();
    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--manifest-path=") {
            return Some(PathBuf::from(value));
        }
        if arg == "--manifest-path" {
            return args.next().map(PathBuf::from);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock(text: &str) -> Option<LockIndex> {
        let dir = tempfile::tempdir().ok()?;
        let path = dir.path().join("Cargo.lock");
        std::fs::write(&path, text).ok()?;
        LockIndex::parse(&path)
    }

    #[test]
    fn parses_names_and_versions() {
        let index = lock(
            "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.219\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n\
             [[package]]\nname = \"syn\"\nversion = \"1.0.109\"\n\n\
             [[package]]\nname = \"syn\"\nversion = \"2.0.100\"\n",
        )
        .expect("lock parses");
        assert_eq!(index.len(), 2);
        assert!(index.contains("serde"));
        assert!(index.matches("serde", Some("1.0.219")));
        assert!(!index.matches("serde", Some("1.0.218")));
        assert!(index.matches("syn", Some("1.0.109")));
        assert!(index.matches("syn", Some("2.0.100")));
        assert!(!index.matches("syn", Some("3.0.0")));
        assert!(!index.contains("tokio"));
    }

    #[test]
    fn an_unrecorded_version_falls_back_to_the_name() {
        let index = lock("version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.219\"\n")
            .expect("lock parses");
        assert!(index.matches("serde", None));
        assert!(!index.matches("other", None));
    }

    #[test]
    fn a_symlinked_lock_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.lock");
        std::fs::write(&real, "version = 4\n").unwrap();
        let link = dir.path().join("Cargo.lock");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();
        #[cfg(windows)]
        {
            // A file symlink needs SeCreateSymbolicLinkPrivilege (Developer
            // Mode or elevation). The no-follow path is covered on Unix; skip
            // the fixture when the OS denies it.
            if let Err(err) = std::os::windows::fs::symlink_file(&real, &link) {
                if err.raw_os_error() == Some(1314)
                    || err.kind() == std::io::ErrorKind::PermissionDenied
                {
                    return;
                }
                panic!("creating a symlink: {err}");
            }
        }
        assert!(LockIndex::parse(&link).is_none());
    }
}
