//! Small formatting, parsing and filesystem helpers shared by the other
//! modules.
//!
//! This parent module carries the terminal UI helpers (colors, glyphs, human
//! formatting); the rest is split by concern across child modules: `time`
//! (durations and ages), `proc` (tool discovery), `text` (textual validation
//! and bounded reads), `platform` (identity, ownership, ACL, reparse and
//! no-follow probes), `nofollow` (handle-based traversal), `fs` (path privacy,
//! installs, hashing, copying), `scan` (bounded walks) and `lock` (file
//! locks). The re-exports keep every item at its historical `crate::util::*`
//! path.

use std::io::IsTerminal;
use std::sync::OnceLock;
use std::time::Duration;

mod fs;
mod lock;
mod nofollow;
mod platform;
mod proc;
mod scan;
mod text;
mod time;

#[cfg(test)]
mod tests;

#[cfg(not(unix))]
pub(crate) use self::fs::decompress_file_verified;
#[cfg(unix)]
pub use self::fs::try_link_file_hashed;
#[cfg(windows)]
pub(crate) use self::fs::windows_file_identity;
pub(crate) use self::fs::{
    COMPRESS_MIN_BYTES, account_files, compress_file_hashed, copy_capped, copy_verified,
    create_temp_dir, decompress_file_hashed, file_identity, link_temp, replace_file, temp_nonce,
    verify_file_hash, with_temp_file,
};
pub use self::fs::{
    Privacy, check_private_dir, check_regular_chain, copy_file_hashed, copy_file_verified,
    copy_file_verified_unowned, create_private_dir_all, expand_tilde, force_remove_dir,
    reject_protected_path, resolve_from, sha256_file, validate_private_dir, validate_state_root,
    write_atomic_private,
};
#[cfg(unix)]
pub(crate) use self::fs::{copy_fd_verified, link_fallback, sha256_file_fd};

pub use self::lock::FileLock;
pub(crate) use self::lock::open_lock_file;

pub use self::nofollow::{DirChainGuard, create_dir_chain_nofollow};
#[cfg(unix)]
pub(crate) use self::nofollow::{open_dir_chain_at, open_file_nofollow, set_stamp_fd};
pub(crate) use self::nofollow::{open_regular, remove_empty_dir, remove_file, remove_tree};

pub(crate) use self::platform::{
    PathKind, Probed, TrustPolicy, check_trusted_path, probe_dir, probe_file, probe_kind,
    probe_lenient,
};
pub use self::platform::{
    ensure_windows_user_path, euid, io_error, is_not_found, is_reparse_point, is_windows_reserved,
    metadata_nofollow, owned_by_us, probe,
};
#[cfg(windows)]
pub use self::platform::{windows_acl_is_private, windows_acl_is_secret};

pub use self::proc::{command_for, on_path, tool_path, which, which_path};

pub use self::scan::MAX_FILE_BYTES;
pub(crate) use self::scan::{MAX_SCAN_FILES, SafeWalk, ScanBudget, has_reparse_component};

pub(crate) use self::text::{hex_decode, hex_encode, is_unsafe_format};
pub use self::text::{
    read_private_text, read_small_text, read_text_prefix, read_trusted_config, validate_component,
    validate_rel,
};

pub use self::time::{human_age, now_secs, parse_duration};

// ── ui: terminal colors, status glyphs and human formatting ────────────────
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

// ── status glyphs ──────────────────────────────────────────────────────────
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

/// `1234567` -> `"1.2 MB"` style, compact decimal units.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Render an untrusted name for a terminal without ANSI/control injection.
pub fn safe_display(value: &std::ffi::OsStr) -> String {
    value
        .to_string_lossy()
        .chars()
        .flat_map(|ch| {
            if ch.is_control() {
                ch.escape_default().collect::<Vec<_>>()
            } else {
                vec![ch]
            }
        })
        .collect()
}

/// One failure rendered in the tool's visual language: a red `✕` line, the
/// message's own continuation lines indented beneath it, then any `anyhow`
/// causes as dim rows. Plain glyphs when colors are off.
pub fn error_block(err: &anyhow::Error) -> String {
    error_block_with(colors_enabled(), err)
}

/// Pure form of [`error_block`] so tests never depend on a TTY.
fn error_block_with(enabled: bool, err: &anyhow::Error) -> String {
    let mut chain = err.chain();
    let headline = chain
        .next()
        .map(|cause| cause.to_string())
        .unwrap_or_else(|| "unknown error".to_string());
    let mut lines = headline.lines();
    let mut out = format!(
        "{} {}",
        paint(enabled, FAIL, GLYPH_FAIL),
        lines.next().unwrap_or("")
    );
    for line in lines {
        out.push_str("\n  ");
        out.push_str(line);
    }
    for cause in chain {
        out.push_str(&format!(
            "\n  {} {cause}",
            paint(enabled, DIM, "caused by:")
        ));
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

/// Minimal line diff for `setup --dry-run`: unchanged lines are prefixed with
/// two spaces, removals with `- `, additions with `+ `.
///
/// Config files are tiny, so the O(n·m) LCS is simpler than pulling in a diff
/// dependency and produces stable, readable output.
pub fn line_diff(before: &str, after: &str) -> String {
    let a: Vec<&str> = before.lines().collect();
    let b: Vec<&str> = after.lines().collect();
    let mut lcs = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }

    let mut out = String::new();
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if a[i] == b[j] {
            out.push_str("  ");
            out.push_str(a[i]);
            out.push('\n');
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push_str("- ");
            out.push_str(a[i]);
            out.push('\n');
            i += 1;
        } else {
            out.push_str("+ ");
            out.push_str(b[j]);
            out.push('\n');
            j += 1;
        }
    }
    while i < a.len() {
        out.push_str("- ");
        out.push_str(a[i]);
        out.push('\n');
        i += 1;
    }
    while j < b.len() {
        out.push_str("+ ");
        out.push_str(b[j]);
        out.push('\n');
        j += 1;
    }
    out
}
