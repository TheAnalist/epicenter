//! Small formatting/parsing helpers shared by the other modules.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use anyhow::Result;

// ── terminal colors ─────────────────────────────────────────────────────────
//
// Palette: one brand green (#92D293) for headers/accents, dim gray for labels,
// amber strictly for warnings, red only for failures — calm by default, loud
// only when something is wrong. Colors auto-disable when stdout is not a
// terminal, when `NO_COLOR` is set, and force-enable with `CLICOLOR_FORCE`.

const GREEN: &str = "38;2;146;210;147"; // #92D293 — headers, success, accents
const WARN: &str = "38;2;230;180;85"; // #E6B455 — warnings only
const FAIL: &str = "38;2;224;108;117"; // #E06C75 — failures only
const INFO: &str = "38;2;126;166;224"; // #7EA6E0 — neutral tips
const DIM: &str = "2"; // labels, legends, secondary detail

fn colors_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        if std::env::var_os("NO_COLOR").is_some() {
            return false;
        }
        if let Some(force) = std::env::var_os("CLICOLOR_FORCE") {
            if force != "0" && !force.is_empty() {
                return true;
            }
        }
        std::io::stdout().is_terminal()
    })
}

fn paint(enabled: bool, code: &str, text: &str) -> String {
    if enabled {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// Brand-green text (`#92D293`) — section titles and success accents.
pub fn green(text: &str) -> String {
    paint(colors_enabled(), GREEN, text)
}

/// Bold brand green — top-level headings.
pub fn heading(text: &str) -> String {
    paint(colors_enabled(), &format!("1;{GREEN}"), text)
}

/// Amber — warnings.
pub fn warn(text: &str) -> String {
    paint(colors_enabled(), WARN, text)
}

/// Red — failures.
pub fn fail(text: &str) -> String {
    paint(colors_enabled(), FAIL, text)
}

/// Calm blue — neutral info.
pub fn info(text: &str) -> String {
    paint(colors_enabled(), INFO, text)
}

/// Dimmed — labels, legends, secondary detail.
pub fn dim(text: &str) -> String {
    paint(colors_enabled(), DIM, text)
}

// ── status glyphs ───────────────────────────────────────────────────────────
//
// Geometric, single-width, emoji-free: ✓ pass · ▲ warning · ✕ failure · ◆ info.

/// `✓`
pub const GLYPH_PASS: &str = "✓";
/// `▲`
pub const GLYPH_WARN: &str = "▲";
/// `✕`
pub const GLYPH_FAIL: &str = "✕";
/// `◆`
pub const GLYPH_INFO: &str = "◆";

/// `1234567` -> `"1.2 MiB"` style, compact.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Parse `"30d"`, `"2w"`, `"12h"`, `"90m"`, `"45s"` or plain seconds `"45"`.
pub fn parse_duration(text: &str) -> Result<Duration> {
    let text = text.trim();
    let split = text
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap_or(text.len());
    let (num, unit) = text.split_at(split);
    // Build the message explicitly: the raw integer-parse error ("cannot parse
    // integer from empty string") is noise for a CLI user.
    let n: u64 = num.parse().map_err(|_| {
        anyhow::anyhow!("invalid duration {text:?} (expected e.g. 30d, 2w, 12h)")
    })?;
    let secs = match unit.to_ascii_lowercase().as_str() {
        "" | "s" => n,
        "m" => n * 60,
        "h" => n * 3_600,
        "d" => n * 86_400,
        "w" => n * 604_800,
        other => anyhow::bail!("unknown time unit {other:?} in {text:?} (use s, m, h, d or w)"),
    };
    Ok(Duration::from_secs(secs))
}

/// Age of a timestamp, human-readable ("3.4 days").
pub fn human_age(at: SystemTime) -> String {
    match SystemTime::now().duration_since(at) {
        Ok(age) => human_duration(age),
        Err(_) => "in the future".to_string(),
    }
}

/// One failure rendered in the tool's visual language: a red `✕` line, the
/// message's own continuation lines indented beneath it, then any `anyhow`
/// causes as dim rows. Plain glyphs when colors are off.
pub fn error_block(err: &anyhow::Error) -> String {
    let mut chain = err.chain();
    let headline = chain
        .next()
        .map(|cause| cause.to_string())
        .unwrap_or_else(|| "unknown error".to_string());
    let mut lines = headline.lines();
    let mut out = format!("{} {}", fail(GLYPH_FAIL), lines.next().unwrap_or(""));
    for line in lines {
        out.push_str("\n  ");
        out.push_str(line);
    }
    for cause in chain {
        out.push_str(&format!("\n  {} {cause}", dim("caused by:")));
    }
    out
}

/// Compact duration for humans ("3.4 s", "1.2 min", "2.1 h").
pub fn human_duration(duration: Duration) -> String {
    let secs = duration.as_secs_f64();
    if secs >= 86_400.0 {
        format!("{:.1} days", secs / 86_400.0)
    } else if secs >= 3_600.0 {
        format!("{:.1} h", secs / 3_600.0)
    } else if secs >= 60.0 {
        format!("{:.1} min", secs / 60.0)
    } else {
        format!("{} s", duration.as_secs())
    }
}

/// Candidate executables for `program`. Cargo installs `kache` as
/// `kache.exe` on Windows, so the suffix must be considered there.
fn exe_candidates(program: &str) -> Vec<String> {
    let mut names = vec![program.to_string()];
    if cfg!(windows) {
        names.push(format!("{program}.exe"));
    }
    names
}

/// Is `program` reachable through `PATH`? (bare `which`, no extra crate)
pub fn on_path(program: &str) -> bool {
    let names = exe_candidates(program);
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path)
        .any(|dir| names.iter().any(|name| dir.join(name).is_file()))
}

/// Absolute path of `program` if discoverable — first on `PATH`, then as a
/// fallback in Cargo's own bin dir (`$CARGO_HOME/bin`, e.g.
/// `C:\Users\<user>\.cargo\bin`), which rustup tools live in but isn't on
/// PATH in every shell. Returns `None` when not found anywhere.
pub fn which_path(program: &str) -> Option<PathBuf> {
    let names = exe_candidates(program);
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            for name in &names {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    let cargo_bin = crate::paths::cargo_home().ok()?.join("bin");
    names
        .iter()
        .map(|name| cargo_bin.join(name))
        .find(|candidate| candidate.is_file())
}

/// Is `program` installed at all (PATH or cargo bin dir)?
pub fn which(program: &str) -> bool {
    which_path(program).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn parses_time_units() {
        assert_eq!(parse_duration("30d").unwrap(), Duration::from_secs(30 * 86_400));
        assert_eq!(parse_duration("2w").unwrap(), Duration::from_secs(2 * 604_800));
        assert_eq!(parse_duration("12h").unwrap(), Duration::from_secs(12 * 3_600));
        assert_eq!(parse_duration("45").unwrap(), Duration::from_secs(45));
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("5x").is_err());
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(3 * 1_048_576 + 200_000), "3.2 MiB");
    }

    #[test]
    fn exe_candidates_is_platform_aware() {
        let names = exe_candidates("kache");
        assert!(names.contains(&"kache".to_string()));
        #[cfg(windows)]
        assert!(names.contains(&"kache.exe".to_string()));
        #[cfg(not(windows))]
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn paint_is_pure() {
        assert_eq!(paint(false, "38;2;146;210;147", "hi"), "hi");
        assert_eq!(paint(true, "1", "hi"), "\x1b[1mhi\x1b[0m");
    }

    #[test]
    fn error_blocks_render_a_glyph_indent_and_causes() {
        let plain = anyhow::anyhow!("nothing selected — pass one selector:\n--stale   older toolchains");
        let block = error_block(&plain);
        assert_eq!(block, "✕ nothing selected — pass one selector:\n  --stale   older toolchains");

        let chained = Err::<(), _>(anyhow::anyhow!("inner detail")).context("outer headline");
        let block = error_block(&chained.unwrap_err());
        assert_eq!(block, "✕ outer headline\n  caused by: inner detail");
    }
}
