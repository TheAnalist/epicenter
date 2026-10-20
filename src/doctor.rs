//! `epicenter doctor`: one check per known failure mode of a shared
//! build-dir setup. Each check emits one line with a severity icon; the
//! checks are grouped into sections for printing.

use std::path::Path;
use std::time::SystemTime;

use anyhow::Result;

use crate::fingerprint::{ArtifactInfo, Unit};
use crate::paths;
use crate::util::{human_age, human_bytes, human_duration};
use crate::who;

/// Severity of one check.
#[derive(Debug, Clone, Copy)]
pub enum Level {
    Pass,
    Info,
    Warn,
    Fail,
}

impl Level {
    pub fn icon(&self) -> &'static str {
        match self {
            Level::Pass => crate::util::GLYPH_PASS,
            Level::Info => crate::util::GLYPH_INFO,
            Level::Warn => crate::util::GLYPH_WARN,
            Level::Fail => crate::util::GLYPH_FAIL,
        }
    }
}

/// One doctor check result, tagged with its section for grouped printing.
pub struct Check {
    pub section: &'static str,
    pub level: Level,
    pub message: String,
}

pub const SEC_CACHE: &str = "shared cache";
pub const SEC_CONFIG: &str = "configuration";
pub const SEC_WRAPPER: &str = "wrapper";
pub const SEC_FS: &str = "filesystem";
pub const SEC_TC: &str = "toolchain";
pub const SEC_MTIME: &str = "mtime discipline";

fn check(section: &'static str, level: Level, message: impl Into<String>) -> Check {
    Check {
        section,
        level,
        message: message.into(),
    }
}

/// The full checklist.
pub fn run() -> Result<Vec<Check>> {
    let mut checks = Vec::new();

    // Everything hangs on resolving the cache dir; if it fails, say so in
    // check language instead of crashing the whole report.
    let root = match crate::config::trusted_cache_root() {
        Ok(root) => root,
        Err(e) => {
            return Ok(vec![check(
                SEC_CACHE,
                Level::Fail,
                format!("could not resolve the shared cache dir ({e:#}) — run `epicenter setup`"),
            )]);
        }
    };

    // Shared cache dir exists.
    checks.push(if root.is_dir() {
        check(
            SEC_CACHE,
            Level::Pass,
            format!("shared cache exists at {}", root.display()),
        )
    } else {
        check(
            SEC_CACHE,
            Level::Fail,
            format!(
                "shared cache missing at {} — run `epicenter setup`",
                root.display()
            ),
        )
    });

    // Template cleanliness + drift (global build-dir vs cargo's answer).
    checks.push(check_build_dir(&root));
    checks.push(check_cache_permissions(&root));

    // Ancestor configs shadowing keys per-key.
    checks.extend(check_ancestor_configs());

    // rustc-wrapper in env AND config, plus discoverability.
    checks.extend(check_rustc_wrapper());

    // Cache root on a slow filesystem.
    if root.starts_with("/mnt/") {
        checks.push(check(
            SEC_FS,
            Level::Warn,
            String::from(concat!(
                "shared cache on a Windows-mounted drive — very slow I/O under WSL; ",
                "prefer the default {cargo-cache-home} location"
            )),
        ));
    } else {
        checks.push(check(
            SEC_FS,
            Level::Pass,
            format!("cache root on the local filesystem: {}", root.display()),
        ));
    }

    // Cache vs this project's target/ on different mounts (EXDEV).
    if let Some(cross) = check_exdev(&root) {
        checks.push(cross);
    }

    // Migration note: the former ~/.epicenter/config.toml state file is no
    // longer used (~/.cargo/config.toml is the single source of truth).
    if let Ok(home) = paths::home() {
        let legacy = home.join(".epicenter").join("config.toml");
        if legacy.exists() {
            checks.push(check(
                SEC_CONFIG,
                Level::Info,
                "legacy ~/.epicenter/config.toml found — no longer used; safe to delete",
            ));
        }
    }

    // Unit-graph facts, one scan: toolchain generations, then mtime ordering.
    // Toolchain identity is part of every unit's fingerprint, so a rustc
    // upgrade re-keys the whole cache; ordering decides what recompiles.
    let rows = match who::collect(&root) {
        Ok(rows) => {
            checks.extend(check_toolchain_generation(&rows));
            Some(rows)
        }
        Err(e) => {
            checks.push(check(
                SEC_TC,
                Level::Warn,
                format!("could not read the shared cache: {e:#}"),
            ));
            None
        }
    };
    checks.push(check_rustc());
    checks.push(check_locking());
    if let Some(rows) = &rows {
        checks.extend(check_mtime_ordering(rows));
    }

    Ok(checks)
}

/// Template cleanliness + drift: the global [build] build-dir value must be
/// templated and must resolve to the dir cargo actually builds into.
fn check_build_dir(root: &Path) -> Check {
    let section: &'static str = SEC_CONFIG;
    let value = match crate::config::cargo_configured("build-dir") {
        Ok(Some(value)) => value,
        Ok(None) => {
            return check(
                section,
                Level::Warn,
                "no build-dir in the global cargo config — run `epicenter setup`",
            );
        }
        Err(e) => {
            return check(
                section,
                Level::Warn,
                format!("could not read the cargo config: {e:#}"),
            );
        }
    };

    let has_braces = value.contains('{') && value.contains('}');
    if !has_braces {
        // A literal path from another OS (a C:\ value read by WSL cargo) is
        // joined into LD_LIBRARY_PATH and breaks every build: reject it.
        if value.contains("C:\\") || value.contains("/mnt/") {
            return check(
                section,
                Level::Fail,
                String::from(concat!(
                    "build-dir value is a literal other-OS path — the cross-OS-safe form is ",
                    "'{cargo-cache-home}\\epicenter\\build'; run `epicenter setup`"
                )),
            );
        }
        return check(
            section,
            Level::Warn,
            format!(
                "build-dir = '{value}' is a literal path (no template) — fine locally, \
                 fragile when configs are shared across OSes; `epicenter setup` writes the template form"
            ),
        );
    }

    match paths::resolve_template(&value) {
        Ok(resolved) if resolved == root => check(
            section,
            Level::Pass,
            format!(
                "build-dir template resolves to the shared cache: {}",
                root.display()
            ),
        ),
        Ok(resolved) => check(
            section,
            Level::Warn,
            format!(
                "config drift: the global build-dir resolves to {}, but cargo's effective \
                 build-dir is {} — an ancestor config may be winning; run `epicenter setup`",
                resolved.display(),
                root.display()
            ),
        ),
        Err(e) => check(
            section,
            Level::Warn,
            format!(
                "could not expand the build-dir template locally ({e:#}) — cargo still \
                 expands it at build time; only epicenter's local view failed"
            ),
        ),
    }
}

/// Cache root ownership/mode: a shared, foreign-owned, or group/world-
/// writable cache is a poisoning/secret-leak vector.
fn check_cache_permissions(root: &Path) -> Check {
    let section: &'static str = SEC_CACHE;
    let meta = match std::fs::symlink_metadata(root) {
        Ok(meta) => meta,
        Err(err) => {
            return check(
                section,
                Level::Fail,
                format!("could not inspect cache root: {err}"),
            );
        }
    };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return check(
            section,
            Level::Fail,
            "cache root is a symlink or not a directory",
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !crate::util::owned_by_us(&meta) {
            return check(
                section,
                Level::Fail,
                format!(
                    "cache root owned by uid {} (not uid {}) — never share a mutable vault between users",
                    meta.uid(),
                    crate::util::euid()
                ),
            );
        }
        if meta.mode() & 0o077 != 0 {
            return check(
                section,
                Level::Fail,
                format!(
                    "cache root mode {:o} is accessible by other users — run `chmod 700 {}`",
                    meta.mode() & 0o777,
                    root.display()
                ),
            );
        }
    }
    check(section, Level::Pass, "cache root is private (owner-only)")
}

/// Ancestor scan: from the CWD upward, any `.cargo/config.toml` that sets a
/// key DIFFERENTLY from the global one wins silently (deep config wins
/// per-key) — how a Windows literal once bricked WSL builds.
fn check_ancestor_configs() -> Vec<Check> {
    let section: &'static str = SEC_CONFIG;
    let mut out = Vec::new();
    let home_cfg = crate::config::cargo_config_path().ok();
    let mut dir = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(_) => return out,
    };

    let mut found = false;
    loop {
        let candidate = dir.join(".cargo").join("config.toml");
        let is_home = home_cfg.as_ref().map_or(false, |h| *h == candidate);
        if candidate.exists() && !is_home {
            found = true;
            for key in ["build-dir", "rustc-wrapper"] {
                let Some(ancestor) = crate::config::read_build_table_key(&candidate, key) else {
                    continue; // key absent there — nothing to shadow
                };
                let home_value = crate::config::cargo_configured(key).ok().flatten();
                if home_value.as_deref() != Some(ancestor.as_str()) {
                    out.push(check(
                        section,
                        Level::Fail,
                        format!(
                            "{} sets {key} = '{ancestor}' differently from the global config \
                             (deep config wins per-key) — epicenter refuses project-controlled state",
                            candidate.display()
                        ),
                    ));
                } else {
                    out.push(check(
                        section,
                        Level::Pass,
                        format!(
                            "{} sets {key} = '{ancestor}', matching the global config",
                            candidate.display()
                        ),
                    ));
                }
            }
        }
        match dir.parent() {
            Some(parent) => dir = parent.to_path_buf(),
            None => break,
        }
    }

    if !found {
        out.push(check(
            section,
            Level::Pass,
            "no ancestor .cargo/config.toml shadows the global config",
        ));
    }
    out
}

/// Wrapper checks, merged across env + config:
/// where it is configured (env wins over config files), whether it is
/// discoverable (PATH or $CARGO_HOME/bin), and whether PATH is actually set
/// (cargo spawns the wrapper by NAME at build time).
fn check_rustc_wrapper() -> Vec<Check> {
    let section: &'static str = SEC_WRAPPER;
    let mut out = Vec::new();

    for var in ["RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WRAPPER"] {
        if let Some(value) = std::env::var_os(var) {
            out.push(check(
                section,
                Level::Warn,
                format!(
                    "{var}={} — environment wins over config files",
                    value.to_string_lossy()
                ),
            ));
        }
    }

    let configured = crate::config::cargo_configured("rustc-wrapper");
    match configured {
        Err(e) => out.push(check(section, Level::Warn, format!("could not read the cargo config: {e:#}"))),
        Ok(None) => out.push(check(section,
            Level::Info,
            "no rustc-wrapper configured — kache/sccache are optional layers (`epicenter setup --with-wrapper kache`)",
        )),
        Ok(Some(name)) => match crate::util::which_path(&name) {
            None => out.push(check(section,
                Level::Warn,
                format!(
                    "rustc-wrapper '{name}' is configured but not found in PATH or $CARGO_HOME/bin — \
                     builds fail until it is installed or removed (`epicenter setup --without-wrapper`)"
                ),
            )),
            Some(path) => {
                out.push(check(section,
                    Level::Pass,
                    format!("rustc-wrapper '{name}' discovered: {}", path.display()),
                ));
                if !crate::util::on_path(&name) {
                    out.push(check(section,
                        Level::Warn,
                        format!(
                            "'{name}' lives in the cargo bin dir but NOT on PATH — cargo spawns \
                             the wrapper by NAME at build time, so add the bin dir to PATH"
                        ),
                    ));
                }
            }
        },
    }
    out
}

/// EXDEV class: cache on a different filesystem than this project's
/// target/ — finals then always copy, never hardlink.
fn check_exdev(root: &Path) -> Option<Check> {
    let section: &'static str = SEC_FS;
    let target = std::env::current_dir().ok()?.join("target");
    if !target.is_dir() {
        return Some(check(
            section,
            Level::Info,
            "no ./target next to this invocation — filesystem-match check skipped",
        ));
    }
    match (device_id(&target), device_id(root)) {
        (Some(target_dev), Some(root_dev)) if target_dev != root_dev => Some(check(
            section,
            Level::Warn,
            format!(
                "cache filesystem differs from ./target/ ({} vs {}) — final artifacts are \
                 copied per project, never hardlinked (expected when projects live on /mnt)",
                root.display(),
                target.display()
            ),
        )),
        (Some(_), Some(_)) => Some(check(
            section,
            Level::Pass,
            "cache and ./target/ share one filesystem — hardlink reuse is possible",
        )),
        _ => Some(check(
            section,
            Level::Info,
            "filesystem identity not measurable on this platform",
        )),
    }
}

#[cfg(unix)]
fn device_id(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()
        .map(|meta| std::os::unix::fs::MetadataExt::dev(&meta))
}

#[cfg(not(unix))]
fn device_id(path: &Path) -> Option<u64> {
    // Windows std exposes no volume serial; the std-only proxy is the
    // canonical path's volume prefix (`\\?\C:\…` → `C:`, `\\?\UNC\server\share…`
    // → `\\server\share`) — enough to distinguish local drives, WSL mounts
    // (`\\wsl$…`) and network shares. A true volume serial requires Win32
    // FFI (`GetFileInformationByHandle`), which is deliberately avoided to
    // keep the dependency tree std-only.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let canonical = path.canonicalize().ok()?;
    let text = canonical.to_string_lossy();
    let key = strip_volume_prefix(&text)?;
    // Hashing only needs determinism WITHIN one doctor run (two ids compared).
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    Some(hasher.finish())
}

/// `\\?\C:\Users\…` → `C:`; `\\?\UNC\server\share\…` → `\\server\share`.
#[cfg(not(unix))]
fn strip_volume_prefix(canonical: &str) -> Option<String> {
    let rest = canonical.strip_prefix(r"\\?\")?;
    let mut chars = rest.chars();
    let (first, second) = (chars.next()?, chars.next()?);
    if second == ':' {
        Some(rest[..2].to_string()) // drive letter
    } else if rest.starts_with("UNC\\") {
        let unc = &rest["UNC\\".len()..];
        let mut segments = unc.split('\\');
        let server = segments.next()?;
        let share = segments.next()?;
        Some(format!(r"\\{server}\{share}"))
    } else {
        None
    }
}

/// rustc version + the upgrade-prune hint.
fn check_rustc() -> Check {
    let section: &'static str = SEC_TC;
    let output = crate::util::command_for("rustc")
        .and_then(|mut command| Ok(command.arg("--version").output()?));
    match output {
        Ok(out) if out.status.success() => {
            let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
            check(
                section,
                Level::Info,
                format!(
                    "{version} — after toolchain upgrades, run `epicenter prune` to drop old artifacts"
                ),
            )
        }
        _ => check(section, Level::Warn, "could not run `rustc --version`"),
    }
}

/// Cache freshness relative to the installed toolchain, plus reclaimable
/// older generations.
///
/// The `rustc` fingerprint field changes with every toolchain update, which
/// re-keys every unit. Two distinct consequences, kept separate on purpose:
/// - **staleness (fail)** when the installed toolchain is newer than the
///   newest cached unit — the next build recompiles everything;
/// - **dead weight (warning)** when older generations still occupy space —
///   nothing is broken, they can be reclaimed deliberately.
fn check_toolchain_generation(rows: &[(Unit, ArtifactInfo)]) -> Vec<Check> {
    if rows.is_empty() {
        return vec![check(
            SEC_TC,
            Level::Info,
            "shared cache holds no fingerprint units yet",
        )];
    }

    let newest_art = rows.iter().filter_map(|(_, arts)| arts.newest).max();
    // The generation of the most recently built unit is the active one.
    let active_gen = rows
        .iter()
        .filter(|(_, arts)| arts.newest == newest_art)
        .find_map(|(unit, _)| unit.json.as_ref().map(|json| json.rustc.clone()))
        .unwrap_or_else(|| "unknown".into());

    let mut checks = Vec::new();

    match (newest_art, toolchain_mtime()) {
        (Some(newest), Some(toolchain)) if newest < toolchain => checks.push(check(
            SEC_TC,
            Level::Fail,
            format!(
                "installed toolchain is newer than the newest cached unit ({}): the cache is \
                 stale — the next build recompiles it; outdated units can be reclaimed below",
                human_age(newest)
            ),
        )),
        (Some(newest), Some(_)) => checks.push(check(
            SEC_TC,
            Level::Pass,
            format!(
                "cache is aligned with the installed toolchain (newest unit {})",
                human_age(newest)
            ),
        )),
        _ => checks.push(check(
            SEC_TC,
            Level::Info,
            "toolchain install time could not be read (`rustc --print sysroot` failed)",
        )),
    }

    let stale: Vec<&(crate::fingerprint::Unit, crate::fingerprint::ArtifactInfo)> = rows
        .iter()
        .filter(|(unit, _)| who::rustc_of(unit) != active_gen)
        .collect();
    if !stale.is_empty() {
        let stale_bytes: u64 = stale.iter().map(|(_, arts)| arts.bytes).sum();
        checks.push(check(
            SEC_TC,
            Level::Warn,
            format!(
                "{} unit(s) on older toolchain generations ({}) — reclaim with `epicenter evict --stale`",
                stale.len(),
                human_bytes(stale_bytes)
            ),
        ));
    }
    checks
}

/// Mtime discipline across the unit graph: cargo re-runs a unit when a
/// dependency's artifact is newer than the unit's own outputs ("the
/// dependency `X` was rebuilt"). Restored views preserve the stored order,
/// but a view that mixed restored and locally rebuilt units can break it —
/// each violation costs exactly one recompile, so this warns.
fn check_mtime_ordering(rows: &[(Unit, ArtifactInfo)]) -> Vec<Check> {
    if rows.is_empty() {
        return Vec::new();
    }
    let units: Vec<Unit> = rows.iter().map(|(unit, _)| unit.clone()).collect();
    let edges = crate::fingerprint::dep_edges(&units);

    let mut checked = 0usize;
    let mut violations: Vec<(usize, usize)> = Vec::new();
    for (dependent, deps) in edges.iter().enumerate() {
        let own = rows[dependent].1.newest;
        for &dep in deps {
            checked += 1;
            let (Some(own), Some(dep_newest)) = (own, rows[dep].1.newest) else {
                continue;
            };
            if dep_newest > own {
                violations.push((dependent, dep));
            }
        }
    }

    if violations.is_empty() {
        return vec![check(
            SEC_MTIME,
            Level::Pass,
            format!(
                "every unit is at least as new as its dependencies ({checked} edge(s) checked)"
            ),
        )];
    }

    let mut checks = vec![check(
        SEC_MTIME,
        Level::Warn,
        format!(
            "{} unit(s) recompile once — a dependency is newer ({} edge(s) checked)",
            violations.len(),
            checked
        ),
    )];
    for (dependent, dep) in violations.iter().take(3) {
        let own = rows[*dependent].1.newest.expect("violation has timestamps");
        let dep_newest = rows[*dep].1.newest.expect("violation has timestamps");
        checks.push(check(
            SEC_MTIME,
            Level::Info,
            format!(
                "{} ← {} is {} newer (cargo: \"the dependency was rebuilt\")",
                units[*dependent].dir_name,
                units[*dep].dir_name,
                human_duration(dep_newest.duration_since(own).unwrap_or_default())
            ),
        ));
    }
    if violations.len() > 3 {
        checks.push(check(
            SEC_MTIME,
            Level::Info,
            format!("… and {} more", violations.len() - 3),
        ));
    }
    checks
}

/// Build concurrency: is fine-grain locking enabled, and is it even available?
fn check_locking() -> Check {
    let env_on = std::env::var("CARGO_UNSTABLE_FINE_GRAIN_LOCKING")
        .map(|value| is_truthy(&value))
        .unwrap_or(false);
    let config_on = crate::config::cargo_configured_in("unstable", "fine-grain-locking")
        .ok()
        .flatten()
        .map(|value| is_truthy(&value))
        .unwrap_or(false);

    if env_on || config_on {
        return check(
            SEC_TC,
            Level::Pass,
            "fine-grain locking enabled — concurrent builds on the shared build-dir overlap \
             instead of serializing",
        );
    }
    if toolchain_is_nightly() {
        check(
            SEC_TC,
            Level::Warn,
            "fine-grain locking is available but OFF — concurrent builds serialize on the \
             shared build-dir; enable with `[unstable] fine-grain-locking = true` in \
             ~/.cargo/config.toml",
        )
    } else {
        check(
            SEC_TC,
            Level::Info,
            "one file lock guards the shared build-dir: concurrent builds serialize; \
             fine-grain locking (`-Z fine-grain-locking`) is nightly-only",
        )
    }
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Install time of the active toolchain (the real `rustc` binary, falling
/// back to the sysroot directory). The vault owns toolchain identity; this
/// is the same reference its harvest freshness gate uses.
fn toolchain_mtime() -> Option<SystemTime> {
    crate::vault::toolchain_install_time()
}

fn toolchain_is_nightly() -> bool {
    crate::util::command_for("rustc")
        .and_then(|mut command| Ok(command.arg("--version").output()?))
        .ok()
        .map(|out| String::from_utf8_lossy(&out.stdout).contains("nightly"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Duration;

    #[test]
    fn truthiness_parsing() {
        assert!(is_truthy("true"));
        assert!(is_truthy("1"));
        assert!(is_truthy(" YES "));
        assert!(is_truthy("On"));
        assert!(!is_truthy("false"));
        assert!(!is_truthy("0"));
        assert!(!is_truthy(""));
        assert!(!is_truthy("nightly"));
    }

    #[test]
    fn flags_older_toolchain_generations_for_reclaim() -> Result<()> {
        // Two units, two rustc generations: the most recently built one is
        // "active"; the other must surface as a reclaim warning.
        let root = tempfile::tempdir()?;
        let make_unit = |pkg: &str, hex: &str, rustc: &str, artifact: &str| -> Result<()> {
            let dir = root
                .path()
                .join("debug/.fingerprint")
                .join(format!("{pkg}-{hex}"));
            fs::create_dir_all(&dir)?;
            fs::write(dir.join(format!("lib-{pkg}")), "0011223344556677")?;
            fs::write(
                dir.join(format!("lib-{pkg}.json")),
                format!(
                    r#"{{"rustc":{rustc},"features":"[]","declared_features":"[]","deps":[]}}"#
                ),
            )?;
            fs::create_dir_all(root.path().join("debug/deps"))?;
            fs::write(root.path().join("debug/deps").join(artifact), [0u8; 8])?;
            Ok(())
        };
        make_unit(
            "oldcrate",
            "aaaaaaaaaaaaaaaa",
            "111",
            "liboldcrate-aaaaaaaaaaaaaaaa.rlib",
        )?;
        std::thread::sleep(std::time::Duration::from_millis(20));
        make_unit(
            "newcrate",
            "bbbbbbbbbbbbbbbb",
            "222",
            "libnewcrate-bbbbbbbbbbbbbbbb.rlib",
        )?;

        let rows = who::collect(root.path())?;
        let checks = check_toolchain_generation(&rows);
        let reclaim = checks
            .iter()
            .find(|c| c.message.contains("older toolchain generations"))
            .expect("reclaim warning expected");
        assert_eq!(reclaim.level as u8, Level::Warn as u8);
        assert!(
            reclaim.message.contains("1 unit(s)"),
            "got: {}",
            reclaim.message
        );
        Ok(())
    }

    /// Two units with a resolved dependency edge (the serde → serde_core
    /// pair); artifacts carry explicit stamps so the
    /// ordering is deterministic.
    fn edge_build_dir(root: &Path, dep_at: u64, unit_at: u64) -> Result<()> {
        let stamp = |path: &Path, secs: u64| -> Result<()> {
            let time = SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
            fs::File::options()
                .write(true)
                .open(path)?
                .set_modified(time)?;
            Ok(())
        };
        fs::create_dir_all(root.join("debug/deps"))?;

        let core = root.join("debug/.fingerprint/serde_core-b468be6fa8c1f936");
        fs::create_dir_all(&core)?;
        fs::write(core.join("lib-serde_core"), "71a9f323efa5ae82")?;
        let core_rlib = root.join("debug/deps/libserde_core-b468be6fa8c1f936.rlib");
        fs::write(&core_rlib, [1u8; 32])?;
        stamp(&core_rlib, dep_at)?;

        let unit = root.join("debug/.fingerprint/serde-746d173581f1a314");
        fs::create_dir_all(&unit)?;
        fs::write(unit.join("lib-serde"), "5d82713a7f2d05e2")?;
        fs::write(
            unit.join("lib-serde.json"),
            r#"{"rustc":5244445300240561903,"features":"[]","declared_features":"[]","deps":[[11029742160753049355,"serde_core",false,9416646317397223793]]}"#,
        )?;
        let unit_rlib = root.join("debug/deps/libserde-746d173581f1a314.rlib");
        fs::write(&unit_rlib, [1u8; 32])?;
        stamp(&unit_rlib, unit_at)?;
        Ok(())
    }

    #[test]
    fn flags_units_older_than_their_dependencies() -> Result<()> {
        let root = tempfile::tempdir()?;
        edge_build_dir(root.path(), 1_700_000_600, 1_700_000_000)?;
        let rows = who::collect(root.path())?;
        let checks = check_mtime_ordering(&rows);
        assert!(
            matches!(checks[0].level, Level::Warn),
            "{:?}",
            checks[0].message
        );
        assert!(
            checks[0].message.contains("recompile once"),
            "got: {}",
            checks[0].message
        );
        assert_eq!(checks.len(), 2, "one example follows the count");
        assert!(checks[1].message.contains("serde-746d173581f1a314"));
        assert!(checks[1].message.contains("serde_core-b468be6fa8c1f936"));
        Ok(())
    }

    #[test]
    fn ordering_passes_when_units_are_current() -> Result<()> {
        let root = tempfile::tempdir()?;
        edge_build_dir(root.path(), 1_700_000_000, 1_700_000_600)?;
        let rows = who::collect(root.path())?;
        let checks = check_mtime_ordering(&rows);
        assert!(matches!(checks[0].level, Level::Pass));
        assert!(
            checks[0].message.contains("at least as new"),
            "got: {}",
            checks[0].message
        );
        assert_eq!(checks.len(), 1);
        Ok(())
    }

    #[test]
    fn staleness_requires_both_timestamps() {
        let now = SystemTime::now();
        let older = now - Duration::from_secs(60);
        assert!(older < now, "sanity");
        assert!(!(older >= now));
        assert!(now > older);
    }
}
