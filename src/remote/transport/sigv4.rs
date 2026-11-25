//! Minimal AWS Signature Version 4 for S3 requests.

use anyhow::Result;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::SystemTime;
use time::OffsetDateTime;

use super::http::{Body, HttpRequest};
use super::{Credentials, ErrorKind, TransportError};

type HmacSha256 = Hmac<Sha256>;

pub struct SigV4Signer {
    access_key: String,
    secret_key: String,
    session_token: Option<String>,
    region: String,
}

impl SigV4Signer {
    pub fn new(credentials: &Credentials, region: &str) -> Self {
        Self {
            access_key: credentials.access_key().expose().to_string(),
            secret_key: credentials.secret_key().expose().to_string(),
            session_token: credentials
                .session_token()
                .map(|value| value.expose().to_string()),
            region: region.to_string(),
        }
    }

    pub fn sign(&self, request: &mut HttpRequest) -> Result<(), TransportError> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        self.sign_at(request, now)
    }

    pub fn with_region(&self, region: &str) -> Self {
        Self {
            access_key: self.access_key.clone(),
            secret_key: self.secret_key.clone(),
            session_token: self.session_token.clone(),
            region: region.to_string(),
        }
    }

    pub fn sign_at(&self, request: &mut HttpRequest, now: u64) -> Result<(), TransportError> {
        let payload = match (&request.body, &request.payload_sha256) {
            (_, Some(hash)) => hash.clone(),
            (Body::Empty, None) => hex_sha256(&[]),
            (Body::Bytes(bytes), None) => hex_sha256(bytes),
            (Body::File(_), None) => {
                return Err(TransportError::new(
                    ErrorKind::Config,
                    "a file upload needs its SHA-256 before SigV4 signing",
                ));
            }
        };
        let (date_stamp, amz_date) = amz_dates(now)?;
        request
            .headers
            .push(("x-amz-content-sha256".to_string(), payload.clone()));
        request
            .headers
            .push(("x-amz-date".to_string(), amz_date.clone()));
        if let Some(token) = &self.session_token {
            request
                .headers
                .push(("x-amz-security-token".to_string(), token.clone()));
        }

        let host = host_header(&request.url)?;
        let mut headers: Vec<(String, String)> = request
            .headers
            .iter()
            .filter(|(name, _)| !name.eq_ignore_ascii_case("authorization"))
            .map(|(name, value)| (name.to_ascii_lowercase(), canonical_value(value)))
            .collect();
        headers.push(("host".to_string(), host));
        headers.sort_by(|left, right| left.0.cmp(&right.0));
        let signed_headers = headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let canonical_headers = headers
            .iter()
            .map(|(name, value)| format!("{name}:{value}\n"))
            .collect::<String>();
        let canonical_uri = if request.url.path().is_empty() {
            "/".to_string()
        } else {
            request.url.path().to_string()
        };
        let canonical_query = canonical_query(&request.query);
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method_name(request.method),
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload
        );
        let scope = format!("{date_stamp}/{}/s3/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex_sha256(canonical_request.as_bytes())
        );
        let signature = self.signature(&date_stamp, &string_to_sign)?;
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key
        );
        request
            .headers
            .push(("authorization".to_string(), authorization));
        request.payload_sha256 = Some(payload);
        Ok(())
    }

    fn signature(&self, date_stamp: &str, string_to_sign: &str) -> Result<String, TransportError> {
        let mut date = hmac(
            format!("AWS4{}", self.secret_key).as_bytes(),
            date_stamp.as_bytes(),
        )?;
        date = hmac(&date, self.region.as_bytes())?;
        date = hmac(&date, b"s3")?;
        date = hmac(&date, b"aws4_request")?;
        let signature = hmac(&date, string_to_sign.as_bytes())?;
        Ok(hex_encode(&signature))
    }
}

fn hmac(key: &[u8], value: &[u8]) -> Result<Vec<u8>, TransportError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| TransportError::new(ErrorKind::Config, "invalid SigV4 HMAC key"))?;
    mac.update(value);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn method_name(method: super::http::Method) -> &'static str {
    match method {
        super::http::Method::Get => "GET",
        super::http::Method::Head => "HEAD",
        super::http::Method::Put => "PUT",
        super::http::Method::Post => "POST",
        super::http::Method::Delete => "DELETE",
    }
}

fn host_header(url: &url::Url) -> Result<String, TransportError> {
    let host = url
        .host_str()
        .ok_or_else(|| TransportError::new(ErrorKind::Config, "request URL has no host"))?;
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn canonical_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn canonical_query(pairs: &[(String, String)]) -> String {
    let mut pairs: Vec<(String, String)> = pairs
        .iter()
        .map(|(key, value)| (aws_encode(key), aws_encode(value)))
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

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

fn amz_dates(now: u64) -> Result<(String, String), TransportError> {
    let timestamp = i64::try_from(now)
        .map_err(|_| TransportError::new(ErrorKind::Config, "system clock is out of range"))?;
    let date = OffsetDateTime::from_unix_timestamp(timestamp)
        .map_err(|_| TransportError::new(ErrorKind::Config, "system clock is out of range"))?;
    let date_stamp = format!(
        "{:04}{:02}{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    );
    let amz_date = format!(
        "{date_stamp}T{:02}{:02}{:02}Z",
        date.hour(),
        date.minute(),
        date.second()
    );
    Ok((date_stamp, amz_date))
}

pub(crate) fn hex_sha256(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::transport::http::{HttpRequest, Method};
    use url::Url;

    #[test]
    fn matches_the_aws_s3_get_example() -> Result<()> {
        let mut request = HttpRequest::new(
            Method::Get,
            Url::parse("https://examplebucket.s3.amazonaws.com/test.txt")?,
        );
        request.headers.push(("range".into(), "bytes=0-9".into()));
        let signer = SigV4Signer {
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
            region: "us-east-1".into(),
        };
        signer.sign_at(&mut request, 1_369_353_600)?;
        let authorization = request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.as_str())
            .expect("authorization header");
        assert!(
            authorization.contains(
                "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
            ),
            "{authorization}"
        );
        assert!(authorization.contains("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date"));
        Ok(())
    }

    #[test]
    fn encodes_query_values_without_plus() {
        assert_eq!(aws_encode("a b"), "a%20b");
        assert_eq!(aws_encode("upload+id"), "upload%2Bid");
        assert_eq!(aws_encode("a/b"), "a%2Fb");
    }
}
