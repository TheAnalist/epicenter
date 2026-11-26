//! URL encoding shared by endpoint mapping and SigV4 canonicalization.

/// RFC 3986 encoding used by SigV4 (space is `%20`, never `+`).
pub(crate) fn aws_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_query_values_without_plus() {
        assert_eq!(aws_encode("a b"), "a%20b");
        assert_eq!(aws_encode("upload+id"), "upload%2Bid");
        assert_eq!(aws_encode("a/b"), "a%2Fb");
    }
}
