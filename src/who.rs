//! `epicenter who` / `epicenter why` — unit ownership forensics over the
//! shared build dir. Ground truth source: `.fingerprint/`
//! unit dirs (via the [`crate::fingerprint`] reader), artifacts attached by
//! suffix, staleness reasoned with the mtime rule.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::fingerprint::{ArtifactInfo, DepRef, Unit, UnitKind, artifacts_for, read_units};
use crate::util::{self, human_age, human_bytes};

/// Fully attached unit list, sorted by size (largest first).
pub(crate) fn collect(build_root: &Path) -> Result<Vec<(Unit, ArtifactInfo)>> {
    let mut rows: Vec<(Unit, ArtifactInfo)> = read_units(build_root)?
        .into_iter()
        .map(|unit| {
            let arts = artifacts_for(build_root, &unit);
            (unit, arts)
        })
        .collect();
    rows.sort_by_key(|(_, arts)| std::cmp::Reverse(arts.bytes));
    Ok(rows)
}

/// The rustc identity used by most units counts as the current toolchain
/// generation; every other cohort is stale.
pub(crate) fn rustc_cohorts(rows: &[(Unit, ArtifactInfo)]) -> BTreeMap<String, usize> {
    let mut cohorts: BTreeMap<String, usize> = BTreeMap::new();
    for (unit, _) in rows {
        let id = unit
            .json
            .as_ref()
            .map(|json| json.rustc.clone())
            .unwrap_or_else(|| "unknown".into());
        *cohorts.entry(id).or_default() += 1;
    }
    cohorts
}

pub(crate) fn rustc_of(unit: &Unit) -> String {
    unit.json
        .as_ref()
        .map(|json| json.rustc.clone())
        .unwrap_or_else(|| "unknown".into())
}

fn deps_of(unit: &Unit) -> usize {
    unit.json.as_ref().map_or(0, |json| json.deps.len())
}

/// `epicenter who [query]` — units grouped by package, sorted by size.
pub fn run(build_root: &Path, filter: Option<&str>) -> Result<()> {
    let rows = collect(build_root).context("reading fingerprint units")?;
    if rows.is_empty() {
        println!("no fingerprint units found under {}", build_root.display());
        return Ok(());
    }

    let cohorts = rustc_cohorts(&rows);
    let current = cohorts
        .iter()
        .max_by_key(|(_, count)| **count)
        .map(|(id, _)| id.clone())
        .unwrap_or_default();

    // Group by package (only matched rows), order packages by total size.
    let mut packages: BTreeMap<String, Vec<(&Unit, &ArtifactInfo)>> = BTreeMap::new();
    let mut shown = 0usize;
    let mut stale_count = 0usize;
    for (unit, arts) in &rows {
        let matches = filter.map_or(true, |query| {
            unit.dir_name.contains(query)
                || unit.package.contains(query)
                || unit.dir_suffix.contains(query)
        });
        if !matches {
            continue;
        }
        shown += 1;
        if rustc_of(unit) != current {
            stale_count += 1;
        }
        packages
            .entry(unit.package.clone())
            .or_default()
            .push((unit, arts));
    }

    let mut package_rows: Vec<(String, u64, Vec<(&Unit, &ArtifactInfo)>)> = packages
        .into_iter()
        .map(|(pkg, units)| {
            let total = units.iter().map(|(_, arts)| arts.bytes).sum();
            (pkg, total, units)
        })
        .collect();
    package_rows.sort_by_key(|(_, total, _)| std::cmp::Reverse(*total));

    // Summary header.
    let current_short = short(&current, 10);
    let stale_list: Vec<String> = cohorts
        .iter()
        .filter(|(id, _)| **id != current)
        .map(|(id, count)| format!("{} ({} unit(s))", short(id, 10), count))
        .collect();
    println!(
        "{}",
        util::heading(&format!(
            "epicenter who — {} unit(s) in {} package(s) · {} on a STALE toolchain generation",
            shown,
            package_rows.len(),
            stale_count
        ))
    );
    println!(
        "  {} {} — current rustc {}",
        util::dim("toolchain generations:"),
        cohorts.len(),
        util::green(&current_short)
    );
    if !stale_list.is_empty() {
        println!(
            "  {} {}",
            util::dim("stale:"),
            util::warn(&stale_list.join(", "))
        );
    }

    for (pkg, total, units) in &package_rows {
        println!();
        println!(
            "{} {}",
            util::green(pkg),
            util::dim(&format!(
                "— {} unit(s), {}",
                units.len(),
                human_bytes(*total)
            ))
        );
        for (unit, arts) in units {
            let stale = rustc_of(unit) != current;
            let age = arts.newest.map(human_age).unwrap_or_else(|| "?".into());
            let deps = format!(
                "{} dep{}",
                deps_of(unit),
                if deps_of(unit) == 1 { "" } else { "s" }
            );
            let tag = if stale {
                util::warn("[STALE]")
            } else {
                util::green("[current]")
            };
            println!(
                "  {} {} {:>9}  {:>9} old  {}  {}",
                util::dim(&format!("{:<10}", unit.kind.label())),
                unit.dir_suffix,
                human_bytes(arts.bytes),
                age,
                util::dim(&format!("{deps:>6}")),
                tag,
            );
            if arts.paths.is_empty() {
                println!(
                    "  {} {}",
                    util::warn(util::GLYPH_WARN),
                    util::warn("artifacts missing — would recompile")
                );
            }
        }
    }

    println!();
    println!(
        "{}",
        util::dim(
            "legend: current = rustc generation in use · STALE = older toolchain or config era \
             (evictable) — details: epicenter why <dir hash>"
        )
    );
    Ok(())
}

/// Does a unit match a user query (dir name, dir hash, or package name)?
pub(crate) fn unit_matches(unit: &Unit, query: &str) -> bool {
    unit.dir_name == query
        || unit.dir_suffix == query
        || unit.package == query
        || unit.dir_name.contains(query)
        || unit.package.contains(query)
}

/// `epicenter why <query>` — the surgical single-unit report.
pub fn explain(build_root: &Path, query: &str) -> Result<()> {
    let rows = collect(build_root).context("reading fingerprint units")?;

    let matches: Vec<&(Unit, ArtifactInfo)> = rows
        .iter()
        .filter(|(unit, _)| unit_matches(unit, query))
        .collect();

    match matches.len() {
        0 => bail!("no unit matches {query:?} — run `epicenter who` to list units"),
        // Single match: the surgical report.
        1 => explain_one(&rows, matches[0]),
        n => {
            let cohorts = rustc_cohorts(&rows);
            let current = cohorts
                .iter()
                .max_by_key(|(_, count)| **count)
                .map(|(id, _)| id.clone())
                .unwrap_or_default();

            // For a package query, the unit cargo actually uses as a
            // dependency is the CURRENT-generation lib. Explain it
            // surgically; everything else becomes an evict-candidate list.
            let preferred = matches
                .iter()
                .filter(|(unit, _)| {
                    unit.kind == UnitKind::Lib
                        && unit
                            .json
                            .as_ref()
                            .map_or(false, |json| json.rustc == current)
                })
                .max_by_key(|(_, arts)| arts.newest);

            if let Some(&preferred) = preferred {
                explain_one(&rows, preferred)?;

                let cur_key = (preferred.0.dir_name.as_str(), preferred.0.profile.as_str());
                let evictables: Vec<&(Unit, ArtifactInfo)> = matches
                    .iter()
                    .copied()
                    .filter(|(unit, _)| (unit.dir_name.as_str(), unit.profile.as_str()) != cur_key)
                    .collect();
                let evictable_bytes: u64 = evictables.iter().map(|(_, arts)| arts.bytes).sum();
                if !evictables.is_empty() {
                    println!();
                    println!(
                        "{} other fingerprint dir(s) — {} {}:",
                        evictables.len(),
                        util::dim("evict candidates"),
                        util::green(&human_bytes(evictable_bytes)),
                    );
                    for (unit, arts) in &evictables {
                        println!(
                            "  {} · {} · {} · {}",
                            unit.dir_name,
                            util::dim(unit.kind.label()),
                            arts.newest.map(human_age).unwrap_or_else(|| "?".into()),
                            if arts.paths.is_empty() {
                                util::warn("artifacts MISSING (husk)")
                            } else {
                                util::dim("artifacts present")
                            },
                        );
                    }
                    println!(
                        "  {} {}",
                        util::dim("evict individually:"),
                        util::green("epicenter evict --unit <hash> --yes")
                    );
                }
            } else {
                println!(
                    "{n} matches for {query:?} — none on the current toolchain \
                     generation; narrow to a dir hash (latest ages first):"
                );
                for (unit, arts) in &matches {
                    let rustc_id = unit
                        .json
                        .as_ref()
                        .map(|json| json.rustc.clone())
                        .unwrap_or_else(|| "unknown".into());
                    println!(
                        "  {} · {} · {} · rustc {}",
                        unit.dir_name,
                        unit.kind.label(),
                        arts.newest.map(human_age).unwrap_or_else(|| "?".into()),
                        &rustc_id[..rustc_id.len().min(8)],
                    );
                }
            }
            Ok(())
        }
    }
}

fn explain_one(all: &[(Unit, ArtifactInfo)], picked: &(Unit, ArtifactInfo)) -> Result<()> {
    let (unit, arts) = picked;
    let json = unit
        .json
        .as_ref()
        .context("unit has no readable fingerprint JSON")?;

    let cohorts = rustc_cohorts(all);
    let current = cohorts
        .iter()
        .max_by_key(|(_, count)| **count)
        .map(|(id, _)| id.clone())
        .unwrap_or_default();
    let stale_id = json.rustc != current;

    // (dependency unit index, reason) for stale deps; `usize::MAX` for the
    // unit-level reasons that belong to no edge.
    let units: Vec<Unit> = all.iter().map(|(unit, _)| unit.clone()).collect();
    let index = crate::fingerprint::memo_index(&units);
    let mut reasons: Vec<(usize, String)> = why_stale(all, unit, arts, &json.deps, &index);
    if stale_id {
        reasons.push((usize::MAX, "stale toolchain generation (rustc key differs)".into()));
    }
    if arts.paths.is_empty() {
        reasons.push((usize::MAX, "no artifacts on disk".into()));
    }

    println!(
        "{} {} — {} · profile {}",
        util::green("unit"),
        util::heading(&unit.dir_name),
        unit.kind.label(),
        util::dim(&unit.profile)
    );
    println!();
    println!("  {}", util::green("identity"));
    println!(
        "    {} {}",
        util::dim(&format!("{:<13}", "dir suffix")),
        unit.dir_suffix
    );
    println!(
        "    {} {}  {}",
        util::dim(&format!("{:<13}", "memo hash")),
        unit.memo_hash.as_deref().unwrap_or("?"),
        util::dim("(authoritative — different hash role than the dir suffix)")
    );
    println!(
        "    {} {}  {}",
        util::dim(&format!("{:<13}", "rustc")),
        json.rustc,
        if stale_id {
            util::warn("[STALE generation]")
        } else {
            util::green("[current generation]")
        }
    );
    println!();
    println!("  {}", util::green("configuration"));
    println!(
        "    {} {}",
        util::dim(&format!("{:<13}", "features")),
        display_features(&json.features)
    );
    println!(
        "    {} {}",
        util::dim(&format!("{:<13}", "declared")),
        display_features(&json.declared_features)
    );
    println!(
        "    {} target {} · profile {} · path {} · config {} · compile_kind {}",
        util::dim(&format!("{:<13}", "opaque hashes")),
        short(&json.target, 10),
        short(&json.profile, 10),
        short(&json.path, 10),
        short(&json.config, 10),
        json.compile_kind
    );
    if !json.rustflags.is_empty() {
        println!(
            "    {} {}",
            util::dim(&format!("{:<13}", "rustflags")),
            json.rustflags.join(" ")
        );
    }
    println!();
    println!("  {}", util::green("artifacts"));
    if arts.paths.is_empty() {
        println!(
            "    {} none on disk — this unit would recompile",
            util::warn(util::GLYPH_WARN)
        );
    } else {
        for (path, size, mtime) in arts.paths.iter().take(8) {
            println!(
                "    {:<42} {:>9}  {}",
                path.file_name().map_or_else(
                    || path.display().to_string(),
                    |n| n.to_string_lossy().into_owned()
                ),
                human_bytes(*size),
                util::dim(&format!(
                    "{:>10} old",
                    mtime.map(human_age).unwrap_or_else(|| "?".into())
                ))
            );
        }
        if arts.paths.len() > 8 {
            println!("    … {} more", arts.paths.len() - 8);
        }
    }
    let dep_info = unit.dep_info.as_ref().map(|p| {
        p.file_name().map_or_else(
            || p.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        )
    });
    println!(
        "    {} {}",
        util::dim(&format!("{:<13}", "dep-info")),
        dep_info.as_deref().map_or_else(
            || util::warn("MISSING (mandatory for freshness)"),
            |name| name.to_string()
        )
    );
    println!();
    println!(
        "  {} {}",
        util::green("dependencies"),
        util::dim("(freshness: dep's newest output mtime vs this unit's)")
    );
    if reasons.is_empty() && json.deps.is_empty() {
        println!("    (none declared)");
    }
    for dep in &json.deps {
        let target = crate::fingerprint::resolve_dep(&index, dep);
        let clean = !reasons
            .iter()
            .any(|(at, _)| target.is_some() && Some(*at) == target);
        println!(
            "    {} {}  {}",
            if clean {
                util::green(util::GLYPH_PASS)
            } else {
                util::warn(util::GLYPH_WARN)
            },
            dep.name,
            if clean {
                util::dim("(fresh)")
            } else {
                util::warn("(drives this rebuild)")
            }
        );
    }
    println!();
    println!("  {}", util::green("verdict"));
    if reasons.is_empty() {
        println!(
            "    {} {}",
            util::heading("FRESH"),
            util::dim("— nothing would rebuild for this unit")
        );
    } else {
        println!(
            "    {} {}",
            util::warn("DIRTY"),
            util::dim("— would recompile because:")
        );
        for (_, reason) in &reasons {
            println!("      {} {reason}", util::dim("·"));
        }
    }
    Ok(())
}

/// Freshness rule (cargo's `DependencyRebuilt`): *a dependency's newest
/// artifact is newer than this unit's newest artifact ⇒ dirty*. Edges join
/// by memo hash — the package name alone is ambiguous (several units of one
/// crate coexist) and extern names flip `-`/`_`. Returns the offending
/// dependency's unit index with each reason, so callers can mark exact rows.
fn why_stale(
    all: &[(Unit, ArtifactInfo)],
    self_unit: &Unit,
    own_arts: &crate::fingerprint::ArtifactInfo,
    deps: &[DepRef],
    index: &std::collections::HashMap<String, usize>,
) -> Vec<(usize, String)> {
    let Some(own_newest) = own_arts.newest else {
        return vec![(usize::MAX, "no artifacts on disk (missing unit)".into())];
    };

    let mut reasons = Vec::new();
    for dep in deps {
        let Some(target) = crate::fingerprint::resolve_dep(index, dep) else {
            continue; // dependency not present in this build dir
        };
        let (dep_unit, dep_arts) = &all[target];
        if dep_unit.dir_name == self_unit.dir_name {
            continue;
        }
        if let Some(newest) = dep_arts.newest {
            if newest > own_newest {
                reasons.push((
                    target,
                    format!(
                        "dependency {} has outputs newer than this unit (StaleDependency, {} old)",
                        dep_unit.dir_name,
                        human_age(newest)
                    ),
                ));
            }
        }
    }
    reasons
}

fn display_features(features: &[String]) -> String {
    if features.is_empty() {
        "- (none)".into()
    } else {
        features.join(", ")
    }
}

/// Truncate a hash for display: first `width` chars.
fn short(hash: &str, width: usize) -> String {
    hash.chars().take(width).collect()
}
