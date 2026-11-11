//! `epicenter doctor`: one check per known failure mode of a shared
//! build-dir setup. Each check emits one line with a severity icon; the
//! checks are grouped into sections for printing.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Result;

use crate::fingerprint::{ArtifactInfo, Unit};
use crate::paths;
use crate::settings::{self, Settings};
use crate::util::{human_age, human_bytes, human_duration, metadata_nofollow};
use crate::who;
use walkdir::WalkDir;

/// Severity of one check.
#[derive(Debug, Clone, Copy)]
pub enum Level {
    Pass,
    Info,
    Warn,
    Fail,
}

impl Level {
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Pass => "pass",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Fail => "fail",
        }
    }

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

    let work_root = crate::exec::work_root(&root);
    checks.push(check(
        SEC_CACHE,
        Level::Info,
        format!("work root: {}", work_root.display()),
    ));
    #[cfg(target_os = "linux")]
    if work_root.to_string_lossy().starts_with("/mnt/") {
        checks.push(check(
            SEC_CACHE,
            Level::Warn,
            format!(
                "work root {} is on a Windows-mounted WSL path — keep job dirs on ext4/local disk",
                work_root.display()
            ),
        ));
    }
    if work_root.starts_with(&root) || root.starts_with(&work_root) {
        checks.push(check(
            SEC_CACHE,
            Level::Warn,
            format!(
                "work root {} overlaps the shared cache root {} — choose a separate local directory",
                work_root.display(),
                root.display()
            ),
        ));
    }

    let store_root = crate::vault::store_root(&root);
    if store_root.is_dir() {
        let pubkey = store_root.join(crate::vault::PUBKEY_FILE);
        checks.push(if pubkey.is_file() {
            check(
                SEC_CACHE,
                Level::Info,
                format!("vault public key: {}", pubkey.display()),
            )
        } else {
            check(
                SEC_CACHE,
                Level::Warn,
                format!(
                    "vault has no Ed25519 public key at {} — re-harvest on the writer for multi-VM sharing",
                    pubkey.display()
                ),
            )
        });
    }

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
    checks.extend(check_incremental_state(
        &root,
        rows.as_deref().unwrap_or(&[]),
    ));
    if let Some(rows) = &rows {
        checks.extend(check_mtime_ordering(rows));
    }

    Ok(checks)
}

/// Template cleanliness + drift: the global [build] build-dir value must be
/// templated and must resolve to the dir cargo actually builds into.
fn check_build_dir(root: &Path) -> Check {
    let section: &'static str = SEC_CONFIG;
    let value = match crate::paths::cargo_build_dir() {
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
    let meta = match metadata_nofollow(root) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return check(section, Level::Fail, "cache root does not exist");
        }
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            return check(
                section,
                Level::Fail,
                "cache root is a symlink/reparse point",
            );
        }
        Err(err) => {
            return check(
                section,
                Level::Fail,
                format!("could not inspect cache root: {err}"),
            );
        }
    };
    if !meta.is_dir() {
        return check(section, Level::Fail, "cache root is not a directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !crate::util::owned_by_us(root, &meta) {
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
    #[cfg(windows)]
    {
        if let Err(err) = crate::util::ensure_windows_user_path(root, "cache root") {
            return check(section, Level::Fail, format!("{err:#}"));
        }
        if !crate::util::owned_by_us(root, &meta) {
            return check(
                section,
                Level::Fail,
                "cache root is owned by another user — never share a mutable vault between principals",
            );
        }
        return match crate::util::windows_acl_is_private(root) {
            Some(true) => check(
                section,
                Level::Pass,
                "cache root is private (write access is owner/SYSTEM/Administrators only)",
            ),
            Some(false) => check(
                section,
                Level::Fail,
                "cache root DACL grants write access to another principal — use `icacls` to make it owner-only or choose a private local directory",
            ),
            None => check(
                section,
                Level::Fail,
                "cache root DACL could not be inspected — choose a private local directory with an owner-only ACL",
            ),
        };
    }
    #[cfg(not(windows))]
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
        for name in ["config.toml", "config"] {
            let candidate = dir.join(".cargo").join(name);
            let is_home = home_cfg.as_ref().map_or(false, |h| *h == candidate)
                || home_cfg
                    .as_ref()
                    .and_then(|h| h.parent())
                    .map(|p| p.join("config") == candidate)
                    .unwrap_or(false);
            if !candidate.exists() || is_home {
                continue;
            }
            found = true;
            for key in ["build-dir", "rustc-wrapper"] {
                let Some(ancestor) = crate::config::read_build_table_key(&candidate, key) else {
                    continue; // key absent there — nothing to shadow
                };
                let home_value = crate::config::cargo_configured(key).ok().flatten();
                if home_value.as_deref() != Some(ancestor.as_str()) {
                    out.push(check(
                        section,
                        Level::Warn,
                        format!(
                            "{} sets {key} = '{ancestor}' differently from the global config \
                             (cargo applies it to builds) — epicenter ignores it for its own state",
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
            "no ancestor .cargo/config(.toml) shadows the global config",
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
    let (_first, second) = (chars.next()?, chars.next()?);
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

/// Stale vault generations occupy space even when the build view is aligned
/// with the installed toolchain. They are safe to remove as whole generations.
fn check_store_generations(store: &Path) -> Vec<Check> {
    if !store.is_dir() {
        return Vec::new();
    }
    match crate::vault::generations(store) {
        Ok(generations) => {
            let stale: Vec<_> = generations
                .iter()
                .filter(|generation| !generation.active)
                .collect();
            if stale.is_empty() {
                return Vec::new();
            }
            let units: usize = stale.iter().map(|generation| generation.units).sum();
            let bytes: u64 = stale.iter().map(|generation| generation.bytes).sum();
            vec![check(
                SEC_TC,
                Level::Warn,
                format!(
                    "{} stale vault generation(s) hold {} unit(s) · {} — reclaim with `epicenter store evict --generation <key>`",
                    stale.len(),
                    units,
                    human_bytes(bytes)
                ),
            )]
        }
        Err(err) => vec![check(
            SEC_TC,
            Level::Warn,
            format!("could not inspect vault generations: {err:#}"),
        )],
    }
}

/// Incremental directories are not fingerprinted by the vault. Older rustc
/// session directories can outlive the unit that created them; wrapper
/// `incremental.*` state is opaque but reclaimable as a family.
fn check_incremental_state(root: &Path, rows: &[(Unit, ArtifactInfo)]) -> Vec<Check> {
    let live: std::collections::HashSet<String> = rows
        .iter()
        .map(|(unit, _)| unit.package.replace('-', "_"))
        .collect();
    let mut orphan_dirs = 0usize;
    let mut orphan_bytes = 0u64;
    let mut wrapper_dirs = 0usize;
    let mut checks = Vec::new();

    let Ok(profiles) = fs::read_dir(root) else {
        return checks;
    };
    for profile in profiles.flatten() {
        if !profile
            .file_type()
            .map(|kind| kind.is_dir())
            .unwrap_or(false)
        {
            continue;
        }
        let Ok(entries) = fs::read_dir(profile.path()) else {
            continue;
        };
        for entry in entries.flatten() {
            if !entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "incremental" {
                let Ok(sessions) = fs::read_dir(entry.path()) else {
                    continue;
                };
                for session in sessions.flatten() {
                    if !session
                        .file_type()
                        .map(|kind| kind.is_dir())
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    let cookie = session.file_name().to_string_lossy().into_owned();
                    let package = cookie
                        .rsplit_once('-')
                        .map(|(package, _)| package.replace('-', "_"))
                        .unwrap_or(cookie);
                    if !live.contains(&package) {
                        orphan_dirs += 1;
                        orphan_bytes += directory_bytes(&session.path());
                    }
                }
            } else if name.starts_with("incremental") {
                wrapper_dirs += 1;
            }
        }
    }

    if orphan_dirs > 0 {
        checks.push(check(
            SEC_CACHE,
            Level::Warn,
            format!(
                "{orphan_dirs} incremental session(s) without a live fingerprint ({}): reclaim with `epicenter prune --incremental`",
                human_bytes(orphan_bytes)
            ),
        ));
    }
    if wrapper_dirs > 0 {
        checks.push(check(
            SEC_CACHE,
            Level::Info,
            format!(
                "{wrapper_dirs} wrapper incremental tree(s) present (`incremental.*`) — `epicenter prune --incremental` handles them by age or keep-latest"
            ),
        ));
    }
    checks
}

fn directory_bytes(root: &Path) -> u64 {
    WalkDir::new(root)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.metadata().ok())
        .filter(|meta| meta.is_file())
        .map(|meta| meta.len())
        .sum()
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

pub const SEC_POLICY: &str = "policy";
pub const SEC_PROFILE: &str = "profile";
pub const SEC_SYSTEM: &str = "system";
pub const SEC_NIGHTLY: &str = "nightly hints";

/// Effective Cargo profile values, as far as epicenter can read them.
#[derive(Debug, Clone)]
pub struct ProfileValues {
    pub opt_level: String,
    pub debug: String,
    pub lto: String,
    pub codegen_units: String,
    pub split_debuginfo: String,
    pub incremental: String,
}

impl Default for ProfileValues {
    fn default() -> Self {
        Self {
            opt_level: "3".to_string(),
            debug: "false".to_string(),
            lto: "false".to_string(),
            codegen_units: "16".to_string(),
            split_debuginfo: "default".to_string(),
            incremental: "false".to_string(),
        }
    }
}

/// Everything `doctor --json` and the policy section report.
#[derive(Debug, Clone)]
pub struct ProfileSummary {
    pub preset: String,
    pub effective_preset: String,
    pub preset_source: String,
    pub linker: String,
    pub linker_source: String,
    pub link: String,
    pub link_source: String,
    pub active_linker: String,
    pub wrapper: Option<String>,
    pub memory_bytes: Option<u64>,
    pub memory_source: String,
    pub cores: usize,
    pub jobs: usize,
    pub jobs_source: String,
    pub job_cap: usize,
    pub global_config: String,
    pub store: String,
    pub project: Option<String>,
    pub dev: ProfileValues,
    pub release: ProfileValues,
    pub package_overrides: bool,
    /// Reserved for a measured build; epicenter does not record one yet.
    pub last_build: Option<String>,
}

impl ProfileSummary {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "preset": self.preset,
            "effective_preset": self.effective_preset,
            "preset_source": self.preset_source,
            "linker": self.linker,
            "linker_source": self.linker_source,
            "link": self.link,
            "link_source": self.link_source,
            "active_linker": self.active_linker,
            "wrapper": self.wrapper,
            "memory_bytes": self.memory_bytes,
            "memory_source": self.memory_source,
            "cores": self.cores,
            "jobs": self.jobs,
            "jobs_source": self.jobs_source,
            "job_cap": self.job_cap,
            "global_config": self.global_config,
            "store": self.store,
            "project": self.project,
            "dev": {
                "opt_level": self.dev.opt_level,
                "debug": self.dev.debug,
                "lto": self.dev.lto,
                "codegen_units": self.dev.codegen_units,
                "split_debuginfo": self.dev.split_debuginfo,
                "incremental": self.dev.incremental,
            },
            "release": {
                "opt_level": self.release.opt_level,
                "debug": self.release.debug,
                "lto": self.release.lto,
                "codegen_units": self.release.codegen_units,
                "split_debuginfo": self.release.split_debuginfo,
                "incremental": self.release.incremental,
            },
            "package_overrides": self.package_overrides,
            "last_build": self.last_build,
        })
    }
}

/// Build the profile summary for the effective epicenter policy.
pub fn profile(settings: &Settings) -> Result<ProfileSummary> {
    let (preset, preset_source) = settings.preset();
    let (effective, _, _) = settings.effective_preset();
    let (linker, linker_source) = settings.linker();
    let (memory, memory_source) = settings.memory_bytes();
    let cores = settings::available_cores();
    let job_cap = settings::job_cap(cores, memory);
    let (jobs, jobs_source) = effective_jobs(cores, job_cap);
    let (link, link_source) = settings.link()?;
    let (active_linker, _) = active_linker();
    let wrapper = crate::config::cargo_configured("rustc-wrapper")?;
    let build_root = crate::config::cache_root().ok();
    let store = match settings.store()? {
        Some((path, _)) => path,
        None => crate::vault::store_root(build_root.as_deref().unwrap_or_else(|| Path::new("."))),
    };
    let project = workspace_root();
    let (dev, release, package_overrides) = project
        .as_deref()
        .and_then(profiles)
        .unwrap_or_else(|| (ProfileValues::default(), ProfileValues::default(), false));

    Ok(ProfileSummary {
        preset: preset.as_str().to_string(),
        effective_preset: effective.as_str().to_string(),
        preset_source: preset_source.as_str().to_string(),
        linker: linker.as_str().to_string(),
        linker_source: linker_source.as_str().to_string(),
        link: link.as_str().to_string(),
        link_source: link_source.as_str().to_string(),
        active_linker,
        wrapper,
        memory_bytes: memory,
        memory_source: memory_source.as_str().to_string(),
        cores,
        jobs,
        jobs_source,
        job_cap,
        global_config: crate::paths::global_config_path()?.display().to_string(),
        store: store.display().to_string(),
        project: project.map(|path| path.display().to_string()),
        dev,
        release,
        package_overrides,
        last_build: read_last_build(),
    })
}

/// Policy/profile checks for the doctor, in the same shape as the store
/// checks. All of them are read-only.
pub fn policy_checks(settings: &Settings) -> Result<(Vec<Check>, ProfileSummary)> {
    let profile = profile(settings)?;
    let mut checks = Vec::new();
    let global_path = crate::paths::global_config_path()?;
    checks.push(check(
        SEC_CONFIG,
        if settings.global_path().is_some() {
            Level::Info
        } else {
            Level::Warn
        },
        if settings.global_path().is_some() {
            format!("global policy: {}", global_path.display())
        } else {
            format!(
                "no global policy at {} — defaults apply; run `epicenter setup` to persist intent",
                global_path.display()
            )
        },
    ));
    // The old location is never read as policy. Keep the hint concrete so a
    // user can move the file without guessing the new OS path.
    if let Ok(legacy) = crate::paths::legacy_global_config_path() {
        if legacy != global_path && legacy.exists() {
            let parent = global_path.parent().unwrap_or_else(|| Path::new("."));
            let move_hint = if cfg!(windows) {
                format!(
                    "mkdir \"{}\" && move \"{}\" \"{}\"",
                    parent.display(),
                    legacy.display(),
                    global_path.display()
                )
            } else {
                format!(
                    "mkdir -p '{}' && mv -n '{}' '{}'",
                    parent.display(),
                    legacy.display(),
                    global_path.display()
                )
            };
            checks.push(check(
                SEC_CONFIG,
                Level::Warn,
                format!(
                    "legacy global policy {} is no longer read; make relative `store`/`work` absolute, then move it: {move_hint}",
                    legacy.display()
                ),
            ));
        }
    }
    let memory_label = if profile.memory_source == "auto" {
        "physical memory"
    } else {
        "memory budget"
    };
    checks.push(check(
        SEC_SYSTEM,
        Level::Info,
        format!(
            "{} {}, {} cores; safe job cap {} (2 GiB/job)",
            profile
                .memory_bytes
                .map(human_bytes)
                .unwrap_or_else(|| "unknown".to_string()),
            memory_label,
            profile.cores,
            profile.job_cap
        ),
    ));
    if profile.job_cap < profile.cores {
        checks.push(check(
            SEC_SYSTEM,
            Level::Info,
            format!(
                "{memory_label} caps jobs from {} cores to {}; set `memory` or CARGO_BUILD_JOBS to change it",
                profile.cores, profile.job_cap
            ),
        ));
    }
    checks.push(check(
        SEC_POLICY,
        Level::Pass,
        format!(
            "preset: {} -> {} ({})",
            profile.preset, profile.effective_preset, profile.preset_source
        ),
    ));
    checks.push(check(
        SEC_POLICY,
        if profile.jobs > profile.job_cap {
            Level::Warn
        } else {
            Level::Pass
        },
        format!(
            "jobs: {} ({}){}",
            profile.jobs,
            profile.jobs_source,
            if profile.jobs > profile.job_cap {
                format!(" — above the memory cap {}", profile.job_cap)
            } else {
                String::new()
            }
        ),
    ));
    checks.push(check(
        SEC_POLICY,
        if profile.linker == "auto"
            || profile.active_linker == profile.linker
            || profile.active_linker == "custom"
        {
            Level::Pass
        } else {
            Level::Warn
        },
        format!(
            "linker: intent {} ({}), active {}",
            profile.linker, profile.linker_source, profile.active_linker
        ),
    ));
    checks.push(check(
        SEC_POLICY,
        Level::Info,
        format!(
            "link policy: {} ({}) — a writable network/shared store is copied; auto links only immutable archive outputs in a private local store",
            profile.link, profile.link_source
        ),
    ));
    checks.push(check(
        SEC_POLICY,
        Level::Info,
        match &profile.wrapper {
            Some(wrapper) => format!("rustc-wrapper: {wrapper}"),
            None => "rustc-wrapper: none".to_string(),
        },
    ));
    if let Some(wrapper) = &profile.wrapper {
        if profile.dev.incremental == "true" {
            checks.push(check(
                SEC_POLICY,
                Level::Warn,
                format!(
                    "rustc-wrapper {wrapper} is active but dev incremental is on — wrapper caches and incremental state fight; set incremental=false or remove the wrapper"
                ),
            ));
        }
    }
    checks.push(check(
        SEC_POLICY,
        Level::Info,
        format!("store: {}", profile.store),
    ));
    checks.extend(check_store_generations(Path::new(&profile.store)));
    if let Some(last) = &profile.last_build {
        checks.push(check(
            SEC_POLICY,
            Level::Info,
            format!("last build: {last}"),
        ));
    }
    if let Some(project) = &profile.project {
        checks.push(check(
            SEC_PROFILE,
            Level::Info,
            format!("workspace: {project}"),
        ));
        checks.push(check(
            SEC_PROFILE,
            Level::Info,
            format!(
                "dev: opt-level={}, debug={}, lto={}, codegen-units={}, split-debuginfo={}, incremental={}",
                profile.dev.opt_level,
                profile.dev.debug,
                profile.dev.lto,
                profile.dev.codegen_units,
                profile.dev.split_debuginfo,
                profile.dev.incremental
            ),
        ));
        checks.push(check(
            SEC_PROFILE,
            Level::Info,
            format!(
                "release: opt-level={}, debug={}, lto={}, codegen-units={}, split-debuginfo={}",
                profile.release.opt_level,
                profile.release.debug,
                profile.release.lto,
                profile.release.codegen_units,
                profile.release.split_debuginfo
            ),
        ));
        checks.push(check(
            SEC_PROFILE,
            Level::Info,
            "recommend dev: debug=2, lto=false, codegen-units=256, incremental=true — edit Cargo.toml; epicenter never rewrites a profile automatically",
        ));
        checks.push(check(
            SEC_PROFILE,
            Level::Info,
            "recommend release: lto=\"thin\", codegen-units=16, debug=false — thin LTO measured 4.84→2.99 MiB binary and 760→729 MiB build",
        ));
        checks.push(check(
            SEC_PROFILE,
            Level::Info,
            "with full debug, split-debuginfo=unpacked trims the binary and linker RSS (not total disk; Windows/MSVC semantics differ)",
        ));
        if profile.dev.lto != "false" && profile.dev.lto != "off" {
            checks.push(check(
                SEC_PROFILE,
                Level::Warn,
                format!(
                    "dev lto={} — thin/fat LTO makes warm edits slower; keep LTO for release",
                    profile.dev.lto
                ),
            ));
        }
        if profile.dev.codegen_units != "256" {
            checks.push(check(
                SEC_PROFILE,
                Level::Warn,
                format!(
                    "dev codegen-units={} (Cargo default 256) — raising CGU without measurement was 5–17% slower in screening",
                    profile.dev.codegen_units
                ),
            ));
        }
        if profile.dev.debug == "false" {
            checks.push(check(
                SEC_PROFILE,
                Level::Warn,
                "dev debug=false — no debuginfo for incident investigation; use line-tables-only if size is the goal",
            ));
        }
        if profile.package_overrides {
            checks.push(check(
                SEC_PROFILE,
                Level::Info,
                "profile package overrides present — the values above are the top-level profile, not per-package",
            ));
        }
    } else {
        checks.push(check(
            SEC_PROFILE,
            Level::Info,
            "no Cargo project here — profile audit skipped",
        ));
    }
    if nightly_available() {
        for (flag, effect) in [
            (
                "-Zdebuginfo-compression=zstd",
                "−25% build time / −69% binary, neutral time",
            ),
            (
                "-Zcodegen-backend=cranelift",
                "−12% wall / −9% build (preview backend)",
            ),
            ("-Zshare-generics", "neutral on the 37-dep screen"),
            ("-Zmir-opt-level=0", "~3% faster builds; runtime cost"),
        ] {
            checks.push(check(
                SEC_NIGHTLY,
                Level::Info,
                format!("nightly hint: `{flag}` — {effect}; optional, never applied automatically"),
            ));
        }
    }
    Ok((checks, profile))
}

fn read_last_build() -> Option<String> {
    let path = crate::paths::cargo_home()
        .ok()?
        .join("epicenter")
        .join("last-build.json");
    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    let command = value.get("command")?.as_str()?;
    let seconds = value.get("elapsed_secs")?.as_f64()?;
    let rss = value.get("peak_rss_bytes")?.as_u64()?;
    Some(format!(
        "`{command}` — {seconds:.1}s, peak RSS {}",
        human_bytes(rss)
    ))
}

fn effective_jobs(cores: usize, cap: usize) -> (usize, String) {
    if let Some(raw) = std::env::var_os("CARGO_BUILD_JOBS") {
        if let Some(jobs) = parse_jobs(&raw.to_string_lossy(), cores) {
            return (jobs, "CARGO_BUILD_JOBS".to_string());
        }
    }
    if let Some(raw) = project_cargo_jobs() {
        if let Some(jobs) = parse_jobs(&raw, cores) {
            return (jobs, "project .cargo/config.toml".to_string());
        }
    }
    if let Ok(Some(raw)) = crate::config::cargo_configured("jobs") {
        if let Some(jobs) = parse_jobs(&raw, cores) {
            return (jobs, "global cargo config".to_string());
        }
    }
    (cap, "auto memory cap".to_string())
}

fn parse_jobs(raw: &str, cores: usize) -> Option<usize> {
    let value: i64 = raw.trim().parse().ok()?;
    Some(if value > 0 {
        value as usize
    } else if value < 0 {
        (cores as i64 + value).max(1) as usize
    } else {
        1
    })
}

fn project_cargo_jobs() -> Option<String> {
    let cwd = std::env::current_dir().ok()?;
    for ancestor in cwd.ancestors() {
        let path = ancestor.join(".cargo").join("config.toml");
        if path.is_file() {
            if let Some(value) = crate::config::read_build_table_key(&path, "jobs") {
                return Some(value);
            }
        }
    }
    None
}

fn host_triple() -> Option<String> {
    let output = crate::util::command_for("rustc")
        .ok()?
        .arg("-vV")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(|host| host.trim().to_string())
}

fn active_linker() -> (String, Option<String>) {
    let Some(host) = host_triple() else {
        return ("unknown".to_string(), None);
    };
    let key = format!("target.{host}");
    let raw = crate::config::cargo_configured_in(&key, "rustflags")
        .ok()
        .flatten();
    let active = match raw.as_deref() {
        Some(value) if value.contains("--ld-path=wild") || value.contains("-fuse-ld=wild") => {
            "wild"
        }
        Some(value)
            if value.contains("-fuse-ld=lld")
                || value.contains("rust-lld")
                || value.contains("lld-link") =>
        {
            "lld"
        }
        Some(_) => "custom",
        None => "system",
    };
    (active.to_string(), raw)
}

pub(crate) fn workspace_root() -> Option<PathBuf> {
    let output = crate::util::command_for("cargo")
        .ok()?
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    json.get("workspace_root")
        .and_then(|value| value.as_str())
        .map(PathBuf::from)
}

fn profiles(root: &Path) -> Option<(ProfileValues, ProfileValues, bool)> {
    let text = crate::util::read_small_text(&root.join("Cargo.toml"), 4 * 1024 * 1024).ok()?;
    let value: toml::Value = toml::from_str(&text).ok()?;
    let profile = value.get("profile");
    let dev = profile.and_then(|profile| profile.get("dev"));
    let release = profile.and_then(|profile| profile.get("release"));
    let package_overrides = dev.and_then(|dev| dev.get("package")).is_some()
        || release.and_then(|release| release.get("package")).is_some();
    Some((
        profile_values(dev, false),
        profile_values(release, true),
        package_overrides,
    ))
}

fn profile_values(profile: Option<&toml::Value>, release: bool) -> ProfileValues {
    let get = |key: &str| profile.and_then(|profile| profile.get(key));
    ProfileValues {
        opt_level: render(get("opt-level"), if release { "3" } else { "0" }),
        debug: render(get("debug"), if release { "false" } else { "true" }),
        lto: render(get("lto"), "false"),
        codegen_units: render(get("codegen-units"), if release { "16" } else { "256" }),
        split_debuginfo: render(get("split-debuginfo"), "default"),
        incremental: render(get("incremental"), if release { "false" } else { "true" }),
    }
}

fn render(value: Option<&toml::Value>, default: &str) -> String {
    match value {
        Some(toml::Value::String(value)) => value.clone(),
        Some(toml::Value::Boolean(value)) => value.to_string(),
        Some(toml::Value::Integer(value)) => value.to_string(),
        Some(toml::Value::Float(value)) => value.to_string(),
        Some(value) => value.to_string(),
        None => default.to_string(),
    }
}

fn nightly_available() -> bool {
    crate::util::command_for("rustc")
        .ok()
        .and_then(|mut command| command.args(["+nightly", "--version"]).output().ok())
        .map(|output| output.status.success())
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
    fn flags_orphan_incremental_state() -> Result<()> {
        let root = tempfile::tempdir()?;
        let orphan = root.path().join("debug/incremental/orphan-abc123");
        fs::create_dir_all(orphan.join("session"))?;
        fs::write(orphan.join("session/file"), [0u8; 7])?;
        let wrapper = root.path().join("debug/incremental.kache-auto/v1/hash");
        fs::create_dir_all(&wrapper)?;
        fs::write(wrapper.join("state"), [0u8; 5])?;

        let rows: Vec<(Unit, ArtifactInfo)> = Vec::new();
        let checks = check_incremental_state(root.path(), &rows);
        let messages: Vec<&str> = checks.iter().map(|check| check.message.as_str()).collect();
        assert!(
            messages
                .iter()
                .any(|message| message.contains("incremental session")),
            "{messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("incremental.*")),
            "{messages:?}"
        );
        Ok(())
    }

    #[test]
    fn flags_stale_vault_generations() -> Result<()> {
        let store = tempfile::tempdir()?;
        let old = store.path().join("old-generation").join("units/foo-abc");
        fs::create_dir_all(&old)?;
        fs::write(old.join("artifact"), [0u8; 9])?;
        let checks = check_store_generations(store.path());
        let found: Vec<&str> = checks
            .iter()
            .filter(|check| matches!(check.level, Level::Warn))
            .map(|check| check.message.as_str())
            .collect();
        assert!(
            found.iter().any(|message| message.contains("stale vault")),
            "stale generation must be visible: {found:?}"
        );
        assert!(check_store_generations(&store.path().join("missing")).is_empty());
        Ok(())
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
