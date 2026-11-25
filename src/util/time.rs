// ── time: duration parsing and human-readable ages ──

use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};

use super::human_duration;

/// Parse `"30d"`, `"2w"`, `"12h"`, `"90m"`, `"45s"` or plain seconds `"45"`.
pub fn parse_duration(text: &str) -> Result<Duration> {
    let text = text.trim();
    let split = text
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap_or(text.len());
    let (num, unit) = text.split_at(split);
    // Build the message explicitly: the raw integer-parse error ("cannot parse
    // integer from empty string") is noise for a CLI user.
    let n: u64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration {text:?} (expected e.g. 30d, 2w, 12h)"))?;
    let secs = match unit.to_ascii_lowercase().as_str() {
        "" | "s" => Some(n),
        "m" => n.checked_mul(60),
        "h" => n.checked_mul(3_600),
        "d" => n.checked_mul(86_400),
        "w" => n.checked_mul(604_800),
        other => anyhow::bail!("unknown time unit {other:?} in {text:?} (use s, m, h, d or w)"),
    }
    .with_context(|| format!("duration {text:?} is too large"))?;
    Ok(Duration::from_secs(secs))
}

/// Unix seconds, saturating at zero for clocks before the epoch.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Age of a timestamp, human-readable ("3.4 days").
pub fn human_age(at: SystemTime) -> String {
    match SystemTime::now().duration_since(at) {
        Ok(age) => human_duration(age),
        Err(_) => "in the future".to_string(),
    }
}
