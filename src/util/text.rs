// ── text: bounded trusted reads and textual validation ──

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Result;

use super::nofollow::open_regular;
use super::platform::{is_windows_reserved, owned_by_us};
#[cfg(windows)]
use super::platform::{windows_acl_is_private, windows_acl_is_secret};

/// One path component: no separators, no `.`/`..`, no NUL, no Windows
/// drive/ADS separator, no trailing dot/space, no reserved device stem.
/// Use for manifest fields that must be one directory or file name
/// (`name`, `profile`, `memo`, parity keys).
pub fn validate_component(value: &str, what: &str) -> Result<()> {
    if value.is_empty()
        || value != value.trim_end_matches([' ', '.'])
        || value.trim_end_matches([' ', '.']) == "."
        || value.trim_end_matches([' ', '.']) == ".."
        || value.contains(['/', '\\', '\0', ':'])
        || value.chars().any(char::is_control)
        || is_windows_reserved(value)
    {
        anyhow::bail!("invalid {what} {value:?}: expected one plain path component");
    }
    Ok(())
}

/// A **relative** path with only normal components. Rejects absolute paths,
/// `..`, `.`, NUL, drive prefixes, backslash/forward-slash tricks, and
/// non-canonical spellings: an empty interior component (`deps//x`) or an
/// explicit `.` component (`./x`, `deps/./x`) never reaches `Path`
/// normalization, which would silently rewrite both. This is the single gate
/// for every manifest path that reaches the filesystem.
pub fn validate_rel(value: &str, what: &str) -> Result<PathBuf> {
    if value.is_empty() || value.contains('\0') || value.ends_with(['/', '\\']) {
        anyhow::bail!("invalid {what} {value:?}: empty or trailing separator");
    }
    let mut out = PathBuf::new();
    // Split the raw text: `Path::components` would fold `.` and repeated
    // separators away before any check could see them.
    for part in value.split(['/', '\\']) {
        if part.is_empty() {
            anyhow::bail!("invalid {what} {value:?}: empty path component");
        }
        validate_component(part, what)?;
        out.push(part);
    }
    Ok(out)
}

fn read_capped(file: File, max_bytes: u64, message: &'static str) -> std::io::Result<String> {
    // Take one byte past the cap so a file that grew after the metadata
    // check, or reports a bogus length, still cannot exceed the limit.
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            message,
        ));
    }
    String::from_utf8(bytes)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

/// Read at most `max_bytes` from the start of a regular file, without
/// following a symlink/reparse point and without blocking on FIFOs/devices.
/// Use this for a bounded prefix of a file that may legitimately be large.
pub fn read_text_prefix(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    let file = open_regular(path, false)?;
    let mut text = String::new();
    file.take(max_bytes).read_to_string(&mut text)?;
    Ok(text)
}

/// Read a small regular file without following a symlink and without
/// blocking on FIFOs/devices. Returns an error on non-regular or oversized
/// inputs.
pub fn read_small_text(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    read_capped(
        open_regular(path, false)?,
        max_bytes,
        "not a small regular file",
    )
}

/// Read a global config file from an already-open-like trusted path:
/// O_NOFOLLOW, regular-file-only, owned by the current euid, and not
/// group/world-writable. The ownership/mode checks use fstat on the opened
/// descriptor, so a symlink/file swap between a path check and this read
/// cannot redirect the trust anchor.
pub fn read_trusted_config(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    read_trusted_text(path, max_bytes, false)
}

/// Read a private secret file: no-follow, regular-file-only, owner-only
/// (`0600` on Unix, private DACL on Windows), and bounded in size.
pub fn read_private_text(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    read_trusted_text(path, max_bytes, true)
}

fn read_trusted_text(path: &Path, max_bytes: u64, private: bool) -> std::io::Result<String> {
    #[cfg(not(unix))]
    let _ = private;
    let file = open_regular(path, false)?;
    let meta = file.metadata()?;
    if meta.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a small regular config file",
        ));
    }
    if !owned_by_us(path, &meta) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "config file is owned by an untrusted principal",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mask = if private { 0o077 } else { 0o022 };
        if meta.mode() & mask != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                if private {
                    "private file is accessible by other users"
                } else {
                    "config file is group/world-writable"
                },
            ));
        }
    }
    #[cfg(windows)]
    {
        // Ordinary config cares about mutation; secrets must not be readable
        // by another principal either.
        let ok = if private {
            windows_acl_is_secret(path)
        } else {
            windows_acl_is_private(path)
        };
        if ok != Some(true) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                if private {
                    "private file DACL grants read or write access to an untrusted principal"
                } else {
                    "config file DACL grants write access to an untrusted principal"
                },
            ));
        }
    }
    let text = read_capped(file, max_bytes, "not a small regular config file")?;
    Ok(text)
}

/// Unicode format characters used for bidi spoofing or invisible names.
pub(crate) fn is_unsafe_format(ch: char) -> bool {
    matches!(
        ch,
        '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2028}'..='\u{2029}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub(crate) fn hex_decode(text: &str, what: &str) -> Result<Vec<u8>> {
    let text = text.trim();
    if text.len() % 2 != 0 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("{what} is not a valid hex string");
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(pair).expect("hex pair is ASCII");
        out.push(u8::from_str_radix(pair, 16).expect("validated hex pair"));
    }
    Ok(out)
}
