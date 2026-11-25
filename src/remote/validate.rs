//! Small validation primitives shared by the remote schema and policy.
//!
//! The signed index is untrusted input until the pointer signature and body
//! hash have been verified. These helpers keep the per-field limits in one
//! place and reject control characters before any value reaches a log or a
//! terminal.

use anyhow::{Result, ensure};
use std::path::Path;

use crate::util::validate_component;

/// One plain path component (no separators, no traversal, no reserved name).
pub(crate) fn component(value: &str, what: &str) -> Result<()> {
    validate_component(value, what)?;
    ensure!(value.len() <= 255, "{what} {:?} exceeds 255 bytes", value);
    ensure!(
        !value.chars().any(is_unsafe_format),
        "{what} must not contain bidi or zero-width formatting characters"
    );
    Ok(())
}

/// A single-line value: non-empty, no control characters, bounded.
pub(crate) fn text(value: &str, what: &str, max_bytes: usize) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{what} must not be empty");
    ensure!(
        !value
            .chars()
            .any(|ch| ch.is_control() || is_unsafe_format(ch)),
        "{what} must not contain control or formatting characters"
    );
    ensure!(value.len() <= max_bytes, "{what} exceeds {max_bytes} bytes");
    Ok(())
}

/// A value that may contain newlines/tabs but no other control characters.
pub(crate) fn multiline(value: &str, what: &str, max_bytes: usize) -> Result<()> {
    ensure!(
        !value
            .chars()
            .any(|ch| (ch.is_control() && ch != '\n' && ch != '\t') || is_unsafe_format(ch)),
        "{what} must not contain control or formatting characters"
    );
    ensure!(value.len() <= max_bytes, "{what} exceeds {max_bytes} bytes");
    Ok(())
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

/// Exactly `length` lowercase hex characters.
pub(crate) fn lower_hex(value: &str, length: usize, what: &str) -> Result<()> {
    ensure!(
        value.len() == length && value.bytes().all(is_lower_hex),
        "{what} must be {length} lowercase hex characters"
    );
    Ok(())
}

/// A non-empty decimal hash (Cargo's opaque fingerprint values).
pub(crate) fn decimal(value: &str, what: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 32 && value.bytes().all(|byte| byte.is_ascii_digit()),
        "{what} must be a non-empty decimal hash"
    );
    Ok(())
}

/// A relative path with normal components only, bounded in total and per
/// component.
pub(crate) fn relative_path(value: &str, what: &str, max_bytes: usize) -> Result<()> {
    let path = crate::util::validate_rel(value, what)?;
    ensure!(value.len() <= max_bytes, "{what} exceeds {max_bytes} bytes");
    for component in path.components() {
        let part = component.as_os_str().to_string_lossy();
        ensure!(
            part.len() <= 255,
            "{what} contains a component longer than 255 bytes"
        );
        ensure!(
            !part.chars().any(is_unsafe_format),
            "{what} must not contain bidi or zero-width formatting characters"
        );
    }
    Ok(())
}

/// A bounded list of non-empty single-line strings.
pub(crate) fn strings(
    values: &[String],
    what: &str,
    max_items: usize,
    max_item_bytes: usize,
) -> Result<()> {
    ensure!(
        values.len() <= max_items,
        "{what} has {} entries (cap {max_items})",
        values.len()
    );
    for value in values {
        text(value, what, max_item_bytes)?;
    }
    Ok(())
}

/// A sorted, duplicate-free list of bounded strings.
pub(crate) fn sorted_unique(
    values: &[String],
    what: &str,
    max_items: usize,
    max_item_bytes: usize,
) -> Result<()> {
    strings(values, what, max_items, max_item_bytes)?;
    ensure!(
        values.windows(2).all(|pair| pair[0] < pair[1]),
        "{what} must be sorted and unique"
    );
    Ok(())
}

/// An absolute path string with no control characters.
pub(crate) fn absolute_path(value: &str, what: &str, max_bytes: usize) -> Result<()> {
    text(value, what, max_bytes)?;
    ensure!(
        Path::new(value).is_absolute(),
        "{what} must be an absolute path"
    );
    Ok(())
}

pub(crate) use crate::util::is_unsafe_format;

/// Reject URL userinfo unless it is the conventional SSH `git` user. A
/// registry/git URL is published in the index; credentials must stay in the
/// Cargo credential provider.
pub(crate) fn no_url_credentials(value: &str, what: &str) -> Result<()> {
    let Some((_, rest)) = value.split_once("://") else {
        return Ok(());
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if let Some((userinfo, _)) = authority.rsplit_once('@') {
        ensure!(
            userinfo == "git",
            "{what} must not embed credentials; use the environment/credential provider"
        );
    }
    Ok(())
}

/// A bounded count.
pub(crate) fn count(len: usize, max: usize, what: &str) -> Result<()> {
    ensure!(len <= max, "{what} has {len} entries (cap {max})");
    Ok(())
}
