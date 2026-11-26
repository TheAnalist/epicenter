//! `Cargo.lock` as a restore filter.
//!
//! A stored unit is only seeded into a project that resolves the exact package
//! version it was compiled from. The lock is parsed once per command and every
//! unit check is a hash-map lookup, so binding restore to the lock adds one
//! small file read, not a per-unit scan.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail, ensure};

use crate::util;

/// One `[[package]]` entry from a lock file.
#[derive(Debug, Clone)]
pub struct LockPackage {
    pub version: String,
    /// Registry index or git URL+rev; empty for path packages.
    pub source: String,
    /// Registry checksum; absent for git/path packages.
    pub checksum: Option<String>,
}

/// A source resolved from `Cargo.lock` for one stored unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockSource {
    /// A registry index and the crate checksum Cargo records.
    Registry { index: String, checksum: String },
    /// A git URL+revision, including Cargo's `git+` prefix.
    Git { id: String },
    /// A path/workspace package; never publishable remotely.
    Path,
}

/// Package names and versions a project resolves to.
#[derive(Debug, Clone, Default)]
pub struct LockIndex {
    packages: HashMap<String, Vec<LockPackage>>,
}

impl LockIndex {
    /// The lock Cargo resolves the project against.
    ///
    /// A workspace member is built against the workspace root's lock, not a
    /// member-local `Cargo.lock` left over from a standalone checkout, so the
    /// root wins whenever one is found. `None` means "cannot tell" — no lock,
    /// unreadable, or empty — and the caller keeps the whole-generation seed.
    pub fn load(cwd: &Path, manifest: Option<&Path>) -> Option<Self> {
        let start = match manifest {
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
        if let Some(root) = workspace_root(&start) {
            // The workspace root owns the lockfile: an absent lock is "cannot
            // tell", never a fallback to a member-local file Cargo ignores.
            return Self::parse(&root.join("Cargo.lock"));
        }
        let mut dir = start;
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
                    checksum: package
                        .get("checksum")
                        .and_then(toml::Value::as_str)
                        .filter(|checksum| !checksum.is_empty())
                        .map(str::to_string),
                });
        }
        (!packages.is_empty()).then_some(Self { packages })
    }

    /// Does the project resolve this package at all?
    pub fn contains(&self, name: &str) -> bool {
        self.packages.contains_key(name)
    }

    /// Does the lock contain `name` at `version`?
    ///
    /// This is a pure presence check; vault seeding also requires a registry
    /// or git source via [`Self::seedable`].
    ///
    /// `version == None` matches any recorded version.
    pub fn matches(&self, name: &str, version: Option<&str>) -> bool {
        let Some(packages) = self.packages.get(name) else {
            return false;
        };
        match version {
            None => true,
            Some(wanted) => packages.iter().any(|package| package.version == wanted),
        }
    }

    /// Resolve one publishable source. `Ok(None)` means the package is not in
    /// the lock (a workspace member that was not resolved as a dependency).
    ///
    /// Ambiguity is an error: two named packages at the same version with
    /// different sources cannot be mapped to one stored unit.
    pub fn resolve(&self, name: &str, version: Option<&str>) -> Result<Option<LockSource>> {
        let Some(first) = self.unique_package(name, version)? else {
            return Ok(None);
        };
        if first.source.is_empty() || first.source.starts_with("path+") {
            return Ok(Some(LockSource::Path));
        }
        if let Some(index) = first
            .source
            .strip_prefix("registry+")
            .or_else(|| first.source.strip_prefix("sparse+"))
        {
            let checksum = first.checksum.as_deref().ok_or_else(|| {
                anyhow::anyhow!("Cargo.lock has no checksum for registry package {name}")
            })?;
            ensure!(
                checksum.len() == 64 && checksum.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "Cargo.lock checksum for {name} is not 64 hex characters"
            );
            return Ok(Some(LockSource::Registry {
                index: index.to_string(),
                checksum: checksum.to_ascii_lowercase(),
            }));
        }
        if first.source.starts_with("git+") {
            return Ok(Some(LockSource::Git {
                id: first.source.clone(),
            }));
        }
        bail!(
            "Cargo.lock source {:?} for {name} is not a registry, git or path source",
            first.source
        )
    }

    /// One package entry for `name`/`version`, or an ambiguity error.
    fn unique_package(&self, name: &str, version: Option<&str>) -> Result<Option<&LockPackage>> {
        let Some(packages) = self.packages.get(name) else {
            return Ok(None);
        };
        let mut candidates = packages
            .iter()
            .filter(|package| version.is_none_or(|wanted| package.version == wanted));
        let Some(first) = candidates.next() else {
            return Ok(None);
        };
        for package in candidates {
            ensure!(
                package.source == first.source && package.checksum == first.checksum,
                "Cargo.lock resolves {name} {:?} to multiple sources; refusing an ambiguous unit",
                version.unwrap_or("<unrecorded>")
            );
        }
        Ok(Some(first))
    }

    /// Whether a stored unit may be seeded from the local vault.
    ///
    /// Only registry and git packages carry a source identity that survives a
    /// project boundary. Path/workspace units are skipped: their name and
    /// version do not identify the checkout, so a unit from another project
    /// could be seeded by accident. An absent, ambiguous or malformed entry
    /// also falls back to a local build rather than guessing.
    ///
    /// This is the hot path during restore, so it scans the package's entries
    /// without allocating.
    pub fn seedable(&self, name: &str, version: Option<&str>) -> bool {
        let Ok(Some(package)) = self.unique_package(name, version) else {
            return false;
        };
        if package.source.is_empty() || package.source.starts_with("path+") {
            return false;
        }
        if package.source.starts_with("registry+") || package.source.starts_with("sparse+") {
            return package.checksum.as_deref().is_some_and(|checksum| {
                checksum.len() == 64 && checksum.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
        }
        package.source.starts_with("git+")
    }

    pub fn len(&self) -> usize {
        self.packages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }
}

/// The nearest `Cargo.toml` at or above `start` that declares a `[workspace]`.
/// Cargo resolves members against that root's `Cargo.lock`, not against a
/// member-local file. A symlinked, oversized or unreadable manifest is not a
/// workspace marker.
fn workspace_root(start: &Path) -> Option<PathBuf> {
    for dir in start.ancestors() {
        let manifest = dir.join("Cargo.toml");
        let Ok(text) = util::read_small_text(&manifest, 4 * 1024 * 1024) else {
            continue;
        };
        if let Ok(value) = toml::from_str::<toml::Value>(&text)
            && value.get("workspace").is_some()
        {
            return Some(dir.to_path_buf());
        }
    }
    None
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
    fn resolves_registry_git_and_path_sources() {
        let index = lock(
            "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.219\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB\"\n\n\
             [[package]]\nname = \"gitdep\"\nversion = \"0.1.0\"\n\
             source = \"git+https://github.com/example/gitdep?rev=abc#deadbeef\"\n\n\
             [[package]]\nname = \"local\"\nversion = \"0.1.0\"\n",
        )
        .expect("lock parses");
        assert_eq!(
            index.resolve("serde", Some("1.0.219")).unwrap(),
            Some(LockSource::Registry {
                index: "https://github.com/rust-lang/crates.io-index".to_string(),
                checksum: "ab".repeat(32),
            })
        );
        assert_eq!(
            index.resolve("gitdep", Some("0.1.0")).unwrap(),
            Some(LockSource::Git {
                id: "git+https://github.com/example/gitdep?rev=abc#deadbeef".to_string(),
            })
        );
        assert_eq!(
            index.resolve("local", Some("0.1.0")).unwrap(),
            Some(LockSource::Path)
        );
        assert!(index.resolve("missing", None).unwrap().is_none());
    }

    #[test]
    fn seedable_requires_a_registry_or_git_source() {
        let index = lock(
            "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.219\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"abababababababababababababababababababababababababababababababab\"\n\n\
             [[package]]\nname = \"gitdep\"\nversion = \"0.1.0\"\n\
             source = \"git+https://github.com/example/gitdep?rev=abc#deadbeef\"\n\n\
             [[package]]\nname = \"local\"\nversion = \"0.1.0\"\n\n\
             [[package]]\nname = \"pathed\"\nversion = \"0.1.0\"\n\
             source = \"path+file:///work/pathed\"\n",
        )
        .expect("lock parses");
        assert!(index.seedable("serde", Some("1.0.219")));
        assert!(index.seedable("gitdep", Some("0.1.0")));
        assert!(!index.seedable("local", Some("0.1.0")));
        assert!(!index.seedable("pathed", Some("0.1.0")));
        assert!(!index.seedable("missing", None));
        assert!(!index.seedable("serde", Some("9.9.9")));
    }

    #[test]
    fn seedable_skips_an_ambiguous_or_malformed_entry() {
        let index = lock(
            "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.219\"\n\
             source = \"registry+https://one.example/index\"\n\
             checksum = \"abababababababababababababababababababababababababababababababab\"\n\n\
             [[package]]\nname = \"serde\"\nversion = \"1.0.219\"\n\
             source = \"git+https://example/git?rev=abc\"\n\n\
             [[package]]\nname = \"broken\"\nversion = \"0.1.0\"\n\
             source = \"registry+https://two.example/index\"\n",
        )
        .expect("lock parses");
        assert!(!index.seedable("serde", Some("1.0.219")));
        assert!(!index.seedable("broken", Some("0.1.0")));
    }

    #[test]
    fn registry_checksum_is_required() {
        let index = lock(
            "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.219\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
        )
        .expect("lock parses");
        assert!(index.resolve("serde", Some("1.0.219")).is_err());
    }

    #[test]
    fn ambiguous_sources_are_refused() {
        let index = lock(
            "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.219\"\n\
             source = \"registry+https://one.example/index\"\n\
             checksum = \"abababababababababababababababababababababababababababababababab\"\n\n\
             [[package]]\nname = \"serde\"\nversion = \"1.0.219\"\n\
             source = \"git+https://example/git?rev=abc\"\n",
        )
        .expect("lock parses");
        assert!(index.resolve("serde", Some("1.0.219")).is_err());
    }

    #[test]
    fn a_symlinked_lock_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.lock");
        std::fs::write(
            &real,
            "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.219\"\n",
        )
        .unwrap();
        assert!(
            LockIndex::parse(&real).is_some(),
            "the fixture must itself be a readable lockfile"
        );
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

    fn write(path: &Path, text: &str) {
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn a_workspace_member_uses_the_workspace_lock() {
        let root = tempfile::tempdir().unwrap();
        let member = root.path().join("crates/member");
        std::fs::create_dir_all(&member).unwrap();
        write(
            &root.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/member\"]\n",
        );
        write(
            &root.path().join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.219\"\n",
        );
        write(
            &member.join("Cargo.toml"),
            "[package]\nname = \"member\"\nversion = \"0.1.0\"\n",
        );
        // A standalone-era lock in the member must not filter the restore.
        write(
            &member.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"0.9.0\"\n",
        );

        let index = LockIndex::load(&member, None).expect("workspace lock");
        assert!(index.matches("serde", Some("1.0.219")));
        assert!(!index.matches("serde", Some("0.9.0")));

        let manifest = member.join("Cargo.toml");
        let index = LockIndex::load(root.path(), Some(&manifest)).expect("workspace lock");
        assert!(index.matches("serde", Some("1.0.219")));
    }

    #[test]
    fn a_workspace_without_a_lock_is_cannot_tell() {
        let root = tempfile::tempdir().unwrap();
        let member = root.path().join("member");
        std::fs::create_dir_all(&member).unwrap();
        write(
            &root.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"member\"]\n",
        );
        write(
            &member.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"0.9.0\"\n",
        );

        assert!(
            LockIndex::load(&member, None).is_none(),
            "the workspace root owns the lock, so a member-local file is ignored"
        );
    }

    #[test]
    fn a_standalone_package_still_uses_its_own_lock() {
        let root = tempfile::tempdir().unwrap();
        write(
            &root.path().join("Cargo.toml"),
            "[package]\nname = \"solo\"\nversion = \"0.1.0\"\n",
        );
        write(
            &root.path().join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"solo\"\nversion = \"0.1.0\"\n",
        );

        let index = LockIndex::load(root.path(), None).expect("standalone lock");
        assert!(index.matches("solo", Some("0.1.0")));
    }
}
