//! Network transport for remote distribution.
//!
//! `https://` endpoints are anonymous GET sources. `s3://` endpoints are
//! mapped to an HTTPS S3 endpoint and every request is SigV4-signed. The
//! transport layer is deliberately synchronous: callers already use rayon for
//! parallel work, and a blocking client keeps the dependency surface small.

mod credentials;
mod fetch;
mod http;
mod https;
mod s3;
mod sigv4;
mod url;

pub use credentials::{CredentialSource, Credentials};
pub use fetch::{FetchedPointer, RemoteSource};
pub use https::HttpsSource;
pub use s3::{S3Client, S3Sink, S3Source};

use ::url::Url;
use anyhow::{Context, Result, bail, ensure};
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use self::url::aws_encode;
use crate::settings::{RemotePolicy, RemoteTransport};

/// One resolved remote endpoint.
#[derive(Debug, Clone)]
pub enum Endpoint {
    Https(HttpsEndpoint),
    S3(S3Endpoint),
}

/// Anonymous HTTPS base URL.
#[derive(Debug, Clone)]
pub struct HttpsEndpoint {
    base: Url,
}

/// Authenticated S3 endpoint.
#[derive(Debug, Clone)]
pub struct S3Endpoint {
    pub bucket: String,
    pub prefix: Vec<String>,
    pub region: String,
    pub addressing: S3Addressing,
    /// `AWS_ENDPOINT_URL_S3` selected this endpoint; automatic AWS region
    /// discovery must not rewrite its host or path.
    custom: bool,
    /// Base URL without the bucket/prefix/key path.
    base: Url,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3Addressing {
    VirtualHosted,
    PathStyle,
}

/// TLS settings. System roots are loaded through `rustls-native-certs`, which
/// also honors `SSL_CERT_FILE`/`SSL_CERT_DIR`. `ca_file` exists for tests and
/// for callers that already resolved an explicit bundle.
#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    pub ca_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub connect: Duration,
    pub response: Duration,
    pub read: Duration,
    pub write: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            response: Duration::from_secs(30),
            read: Duration::from_secs(60),
            write: Duration::from_secs(120),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub attempts: u32,
    pub base: Duration,
    pub max: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: 3,
            base: Duration::from_millis(200),
            max: Duration::from_secs(5),
        }
    }
}

/// Everything one command needs to construct a transport.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub endpoint: Endpoint,
    pub credentials: Option<Credentials>,
    pub tls: TlsConfig,
    pub timeouts: Timeouts,
    pub retry: RetryPolicy,
}

impl TransportConfig {
    /// Build from the machine-level remote policy. Environment credentials are
    /// read here, at the command boundary, never deep in a worker.
    pub fn from_policy(policy: &RemotePolicy) -> Result<Self> {
        let url = policy
            .url
            .as_deref()
            .context("remote policy has no endpoint")?;
        match policy.transport {
            RemoteTransport::AnonymousHttps => Ok(Self {
                endpoint: Endpoint::Https(HttpsEndpoint::parse(url)?),
                credentials: None,
                tls: TlsConfig::default(),
                timeouts: Timeouts::default(),
                retry: RetryPolicy::default(),
            }),
            RemoteTransport::S3 => {
                let region = policy
                    .region
                    .clone()
                    .context("the S3 transport requires AWS_REGION or AWS_DEFAULT_REGION")?;
                Self::for_s3(url, &region)
            }
        }
    }

    /// Build an S3 transport for an explicit URL (`store publish --url`).
    pub fn for_s3(url: &str, region: &str) -> Result<Self> {
        let credentials = Credentials::load()?;
        Ok(Self {
            endpoint: Endpoint::S3(S3Endpoint::parse(url, region, custom_endpoint()?)?),
            credentials: Some(credentials),
            tls: TlsConfig::default(),
            timeouts: Timeouts::default(),
            retry: RetryPolicy::default(),
        })
    }

    pub fn with_ca_file(mut self, ca_file: Option<PathBuf>) -> Self {
        self.tls.ca_file = ca_file;
        self
    }

    pub fn is_s3(&self) -> bool {
        matches!(self.endpoint, Endpoint::S3(_))
    }
}

impl Endpoint {
    pub fn url_for(&self, key: &str) -> Result<Url> {
        match self {
            Endpoint::Https(endpoint) => endpoint.url_for(key),
            Endpoint::S3(endpoint) => endpoint.url_for(key),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Endpoint::Https(endpoint) => endpoint.base.origin().ascii_serialization(),
            Endpoint::S3(endpoint) => endpoint.origin(),
        }
    }
}

impl HttpsEndpoint {
    pub fn parse(raw: &str) -> Result<Self> {
        let base = parse_https_endpoint(raw, "remote URL")?;
        Ok(Self { base })
    }

    pub fn url_for(&self, key: &str) -> Result<Url> {
        let mut url = self.base.clone();
        append_key(&mut url, key)?;
        Ok(url)
    }
}

impl S3Endpoint {
    pub fn parse(raw: &str, region: &str, custom: Option<Url>) -> Result<Self> {
        validate_region(region)?;
        let scheme_end = raw
            .find("://")
            .with_context(|| format!("S3 endpoint {raw:?} must start with s3://"))?;
        ensure!(
            raw[..scheme_end].eq_ignore_ascii_case("s3"),
            "S3 endpoint {raw:?} must start with s3://"
        );
        let rest = &raw[scheme_end + 3..];
        let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
        let prefix = prefix.strip_suffix('/').unwrap_or(prefix);
        let mut prefix_parts = Vec::new();
        if !prefix.is_empty() {
            for part in prefix.split('/') {
                validate_key_segment(part, "S3 prefix")?;
                prefix_parts.push(part.to_string());
            }
        }
        let custom_endpoint = custom;
        let is_custom = custom_endpoint.is_some();
        validate_bucket(bucket, is_custom)?;
        let (base, addressing) = match custom_endpoint {
            Some(base) => (base, S3Addressing::PathStyle),
            None if bucket.contains('.') => (
                Url::parse(&format!("https://s3.{region}.amazonaws.com/"))?,
                S3Addressing::PathStyle,
            ),
            None => (
                Url::parse(&format!("https://{bucket}.s3.{region}.amazonaws.com/"))?,
                S3Addressing::VirtualHosted,
            ),
        };
        Ok(Self {
            bucket: bucket.to_string(),
            prefix: prefix_parts,
            region: region.to_string(),
            addressing,
            custom: is_custom,
            base,
        })
    }

    pub(crate) fn origin(&self) -> String {
        self.base.origin().ascii_serialization()
    }

    pub(crate) fn base_host(&self) -> Option<&str> {
        self.base.host_str()
    }

    pub fn url_for(&self, key: &str) -> Result<Url> {
        // Build the path with the same RFC 3986 encoding SigV4 canonicalizes.
        // `Url` leaves some characters (`!`, `'`, `(`, `)`, `*`) literal that
        // SigV4 encodes, which would otherwise invalidate the signature.
        let mut path = self.base.path().trim_end_matches('/').to_string();
        let mut push = |segment: &str| {
            path.push('/');
            path.push_str(&aws_encode(segment));
        };
        if self.addressing == S3Addressing::PathStyle {
            push(&self.bucket);
        }
        for part in &self.prefix {
            push(part);
        }
        for part in key.split('/') {
            validate_key_segment(part, "S3 object key")?;
            push(part);
        }
        let raw = format!("{}{}", self.base.origin().ascii_serialization(), path);
        Url::parse(&raw).with_context(|| format!("building S3 object URL {raw:?}"))
    }

    /// Rebuild the endpoint for another region. `region` may come from the
    /// `x-amz-bucket-region` response header, so it is validated before it is
    /// interpolated into a host name.
    pub fn with_region(&self, region: &str) -> Result<Self> {
        validate_region(region)?;
        let mut next = self.clone();
        next.region = region.to_string();
        if self.addressing == S3Addressing::VirtualHosted {
            next.base = Url::parse(&format!(
                "https://{}.s3.{region}.amazonaws.com/",
                self.bucket
            ))?;
            ensure!(
                next.base
                    .host_str()
                    .is_some_and(|host| host.ends_with(".amazonaws.com")),
                "S3 region {region:?} does not produce an AWS endpoint"
            );
        } else if self.base.host_str() == Some("s3.amazonaws.com")
            || self
                .base
                .host_str()
                .is_some_and(|host| host.starts_with("s3.") && host.ends_with(".amazonaws.com"))
        {
            next.base = Url::parse(&format!("https://s3.{region}.amazonaws.com/"))?;
        }
        Ok(next)
    }
}

fn validate_region(region: &str) -> Result<()> {
    ensure!(
        !region.is_empty()
            && region.len() <= 64
            && region
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "S3 region is not a safe AWS region name"
    );
    Ok(())
}

fn custom_endpoint() -> Result<Option<Url>> {
    let Some(raw) = std::env::var_os("AWS_ENDPOINT_URL_S3").filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let raw = raw
        .into_string()
        .map_err(|_| anyhow::anyhow!("AWS_ENDPOINT_URL_S3 is not valid UTF-8"))?;
    let url = parse_https_endpoint(&raw, "AWS_ENDPOINT_URL_S3")?;
    // The SigV4 canonical URI uses this base path verbatim. Only accept
    // segments that are already in SigV4's canonical form so the signed and
    // sent paths cannot diverge.
    if let Some(segments) = url.path_segments() {
        for segment in segments {
            ensure!(
                aws_encode(segment) == segment,
                "AWS_ENDPOINT_URL_S3 path segments must be plain URL-safe characters \
                 (letters, digits, `-`, `.`, `_`, `~`)"
            );
        }
    }
    Ok(Some(url))
}

fn parse_https_endpoint(raw: &str, what: &str) -> Result<Url> {
    // Trim once and validate exactly the string that is parsed: a raw check on
    // untrimmed input would miss traversal that `Url::parse` then normalizes.
    let trimmed = raw.trim();
    let url = parse_https_url(trimmed, what)?;
    let rest = raw_after_scheme(trimmed, "https://")
        .with_context(|| format!("{what} must use https://"))?;
    validate_authority(rest, &url, what)?;
    validate_path_prefix(rest, what)?;
    validate_parsed_path(&url, what)?;
    Ok(url)
}

fn parse_https_url(raw: &str, what: &str) -> Result<Url> {
    ensure!(
        !raw.is_empty() && !raw.chars().any(|ch| ch.is_control() || ch.is_whitespace()),
        "{what} must be a single non-empty URL"
    );
    let url = Url::parse(raw).with_context(|| format!("parsing {what}"))?;
    ensure!(url.scheme() == "https", "{what} must use https://");
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "{what} must not embed credentials"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "{what} must not contain a query or fragment"
    );
    ensure!(url.host_str().is_some(), "{what} is missing a host");
    Ok(url)
}

/// The authority written in the raw endpoint must resolve to the origin the
/// parsed URL would send the request to.
fn validate_authority(rest: &str, url: &Url, what: &str) -> Result<()> {
    let authority = rest.split('/').next().unwrap_or_default();
    let probe = Url::parse(&format!("https://{authority}/"))
        .with_context(|| format!("{what} has an invalid authority"))?;
    ensure!(
        probe.origin().ascii_serialization() == url.origin().ascii_serialization(),
        "{what} authority is inconsistent with the parsed endpoint"
    );
    Ok(())
}

/// Reject traversal that only appears after URL normalization or percent
/// decoding, so the signed/sent path cannot diverge from the validated one.
fn validate_parsed_path(url: &Url, what: &str) -> Result<()> {
    let Some(segments) = url.path_segments() else {
        bail!("{what} cannot be a base URL");
    };
    for segment in segments {
        if segment.is_empty() {
            continue;
        }
        let lower = segment.to_ascii_lowercase();
        ensure!(
            segment != "."
                && segment != ".."
                && !lower.contains("%2e")
                && !lower.contains("%2f")
                && !lower.contains("%5c"),
            "{what} path contains traversal after normalization"
        );
    }
    Ok(())
}

fn raw_after_scheme<'a>(raw: &'a str, scheme: &str) -> Option<&'a str> {
    raw.get(..scheme.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(scheme))
        .map(|_| &raw[scheme.len()..])
}

/// Validate the raw path prefix before `url` normalizes `..` away.
fn validate_path_prefix(rest: &str, what: &str) -> Result<()> {
    ensure!(!rest.contains('\\'), "{what} must not contain `\\`");
    let path = rest
        .split_once('/')
        .map(|(_, path)| path)
        .unwrap_or_default();
    ensure!(
        !path.starts_with('/'),
        "{what} path must not begin with an empty component"
    );
    let path = path.strip_suffix('/').unwrap_or(path);
    if path.is_empty() {
        return Ok(());
    }
    for part in path.split('/') {
        ensure!(
            !part.is_empty() && part != "." && part != "..",
            "{what} path must not contain empty, `.` or `..` components"
        );
        let lower = part.to_ascii_lowercase();
        ensure!(
            !lower.contains("%2e")
                && !lower.contains("%2f")
                && !lower.contains("%5c")
                && !part
                    .chars()
                    .any(|ch| ch.is_control() || crate::remote::validate::is_unsafe_format(ch)),
            "{what} path contains an encoded traversal or control character"
        );
    }
    Ok(())
}

fn append_key(url: &mut Url, key: &str) -> Result<()> {
    let mut segments = url
        .path_segments_mut()
        .map_err(|_| anyhow::anyhow!("remote URL cannot be a base URL"))?;
    // A base path ending in `/` has an empty trailing segment; pushing onto it
    // would produce `//`, so drop that one slash first.
    segments.pop_if_empty();
    for part in key.split('/') {
        validate_key_segment(part, "remote object key")?;
        segments.push(part);
    }
    drop(segments);
    url.set_query(None);
    url.set_fragment(None);
    Ok(())
}

fn validate_key_segment(value: &str, what: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value != "." && value != "..",
        "{what} must not contain empty, `.` or `..` components"
    );
    ensure!(
        !value.contains(['\\', '\0'])
            && !value
                .chars()
                .any(|ch| ch.is_control() || crate::remote::validate::is_unsafe_format(ch)),
        "{what} contains a control character or backslash"
    );
    ensure!(value.len() <= 255, "{what} component exceeds 255 bytes");
    Ok(())
}

fn validate_bucket(bucket: &str, custom: bool) -> Result<()> {
    ensure!(!bucket.is_empty(), "S3 URL is missing a bucket");
    ensure!(
        bucket != "." && bucket != ".." && !bucket.contains(['/', '\\', '@']),
        "S3 bucket {bucket:?} is not valid"
    );
    if custom {
        ensure!(
            bucket.len() <= 255
                && bucket
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')),
            "S3 bucket {bucket:?} contains unsupported characters"
        );
        return Ok(());
    }
    ensure!(
        (3..=63).contains(&bucket.len())
            && bucket.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'-'))
            && bucket
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && bucket
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            && !bucket.contains(".."),
        "S3 bucket {bucket:?} does not follow AWS bucket naming rules; use AWS_ENDPOINT_URL_S3 for a compatible store"
    );
    Ok(())
}

// ── errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Missing,
    Unauthorized,
    Forbidden,
    Conflict,
    Precondition,
    RateLimited,
    Server,
    Redirect,
    Network,
    Timeout,
    Tls,
    Protocol,
    TooLarge,
    Config,
}

#[derive(Debug)]
pub struct TransportError {
    pub kind: ErrorKind,
    pub status: Option<u16>,
    pub retryable: bool,
    pub message: String,
    pub request_id: Option<String>,
}

impl TransportError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            status: None,
            retryable: matches!(
                kind,
                ErrorKind::Network
                    | ErrorKind::Timeout
                    | ErrorKind::RateLimited
                    | ErrorKind::Server
            ),
            message: message.into(),
            request_id: None,
        }
    }

    pub fn status(status: u16, message: impl Into<String>) -> Self {
        let kind = match status {
            401 => ErrorKind::Unauthorized,
            403 => ErrorKind::Forbidden,
            404 => ErrorKind::Missing,
            408 => ErrorKind::Timeout,
            409 => ErrorKind::Conflict,
            412 => ErrorKind::Precondition,
            429 => ErrorKind::RateLimited,
            300..=399 => ErrorKind::Redirect,
            500..=599 => ErrorKind::Server,
            _ => ErrorKind::Protocol,
        };
        Self {
            kind,
            status: Some(status),
            retryable: matches!(status, 408 | 429 | 500..=599),
            message: message.into(),
            request_id: None,
        }
    }

    pub fn with_request_id(mut self, request_id: Option<String>) -> Self {
        self.request_id = request_id;
        self
    }

    pub fn is_miss(&self) -> bool {
        self.kind == ErrorKind::Missing
    }

    pub fn retryable(&self) -> bool {
        self.retryable
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(status) = self.status {
            write!(f, "HTTP {status}: {}", self.message)?;
        } else {
            write!(f, "{}", self.message)?;
        }
        if let Some(request_id) = &self.request_id {
            write!(f, " (request {request_id})")?;
        }
        Ok(())
    }
}

impl std::error::Error for TransportError {}

impl From<std::io::Error> for TransportError {
    fn from(err: std::io::Error) -> Self {
        let kind = match err.kind() {
            std::io::ErrorKind::TimedOut => ErrorKind::Timeout,
            _ => ErrorKind::Network,
        };
        Self::new(kind, err.to_string())
    }
}

pub(crate) fn is_miss(err: &anyhow::Error) -> bool {
    err.downcast_ref::<TransportError>()
        .is_some_and(TransportError::is_miss)
}

#[cfg(all(test, unix))]
mod mock_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_aws_s3_to_virtual_hosted_or_path_style() -> Result<()> {
        let plain = S3Endpoint::parse("s3://bucket/prefix", "us-east-1", None)?;
        assert_eq!(
            plain.url_for("blobs/abc")?.as_str(),
            "https://bucket.s3.us-east-1.amazonaws.com/prefix/blobs/abc"
        );
        let dotted = S3Endpoint::parse("s3://a.b/prefix", "us-east-1", None)?;
        assert_eq!(
            dotted.url_for("index.json")?.as_str(),
            "https://s3.us-east-1.amazonaws.com/a.b/prefix/index.json"
        );
        Ok(())
    }

    #[test]
    fn custom_endpoint_is_path_style() -> Result<()> {
        let base = Url::parse("https://minio.example/s3")?;
        let endpoint = S3Endpoint::parse("s3://Bucket_name/prefix", "us-east-1", Some(base))?;
        assert_eq!(
            endpoint.url_for("blobs/abc")?.as_str(),
            "https://minio.example/s3/Bucket_name/prefix/blobs/abc"
        );
        Ok(())
    }

    #[test]
    fn encodes_object_keys_like_sigv4_canonical_uris() -> Result<()> {
        let endpoint = S3Endpoint::parse("s3://bucket/a!b(c)*d", "us-east-1", None)?;
        let url = endpoint.url_for("blobs/x")?;
        assert_eq!(url.path(), "/a%21b%28c%29%2Ad/blobs/x");
        assert_eq!(
            url.as_str(),
            "https://bucket.s3.us-east-1.amazonaws.com/a%21b%28c%29%2Ad/blobs/x"
        );
        Ok(())
    }

    #[test]
    fn validates_region_switches() -> Result<()> {
        let endpoint = S3Endpoint::parse("s3://bucket/prefix", "us-east-1", None)?;
        let next = endpoint.with_region("eu-west-1")?;
        assert_eq!(
            next.url_for("index.json")?.as_str(),
            "https://bucket.s3.eu-west-1.amazonaws.com/prefix/index.json"
        );
        assert!(endpoint.with_region("evil.amazonaws.com@attacker").is_err());
        assert!(endpoint.with_region("us-east-1/x").is_err());
        assert!(endpoint.with_region("us east 1").is_err());
        assert!(endpoint.with_region("").is_err());
        Ok(())
    }

    #[test]
    fn rejects_prefix_traversal_and_bad_aws_buckets() {
        assert!(HttpsEndpoint::parse("https://cache.example/a/../b").is_err());
        assert!(HttpsEndpoint::parse("https://cache.example/%2e%2e/b").is_err());
        assert!(HttpsEndpoint::parse("https://cache.example/../b").is_err());
        assert!(S3Endpoint::parse("s3://Bad_Bucket/prefix", "us-east-1", None).is_err());
        assert!(S3Endpoint::parse("s3://bucket/a/../b", "us-east-1", None).is_err());
    }

    #[test]
    fn trailing_slash_and_bare_prefix_resolve_identically() -> Result<()> {
        for raw in [
            "https://cache.example/deps",
            "https://cache.example/deps/",
            "  https://cache.example/deps/  ",
        ] {
            let endpoint = HttpsEndpoint::parse(raw)?;
            assert_eq!(
                endpoint.url_for("index.json")?.as_str(),
                "https://cache.example/deps/index.json",
                "endpoint {raw:?}"
            );
        }
        for raw in ["https://cache.example", "https://cache.example/"] {
            let endpoint = HttpsEndpoint::parse(raw)?;
            assert_eq!(
                endpoint.url_for("blobs/abc")?.as_str(),
                "https://cache.example/blobs/abc",
                "endpoint {raw:?}"
            );
        }
        for raw in ["s3://bucket/prefix", "s3://bucket/prefix/"] {
            let endpoint = S3Endpoint::parse(raw, "us-east-1", None)?;
            assert_eq!(
                endpoint.url_for("blobs/abc")?.as_str(),
                "https://bucket.s3.us-east-1.amazonaws.com/prefix/blobs/abc",
                "endpoint {raw:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn endpoint_traversal_is_rejected_after_trimming_and_normalization() {
        for raw in [
            "https://cache.example/a/../deps",
            " https://cache.example/a/../deps",
            "https://cache.example/a/../deps\n",
            "https://cache.example/%2e%2e/deps",
            " https://cache.example/%2E%2E/deps",
            "https://cache.example/a/%2e/deps",
            "https://cache.example/a%2f..%2fdeps",
            "https://cache.example/a/..%5c/deps",
        ] {
            assert!(HttpsEndpoint::parse(raw).is_err(), "endpoint {raw:?}");
        }
    }

    #[test]
    fn endpoint_authority_must_match_the_parsed_origin() {
        assert!(HttpsEndpoint::parse("https:///deps").is_err());
        assert!(HttpsEndpoint::parse("https://cache.example@evil.example/deps").is_err());
        assert!(HttpsEndpoint::parse(" https://CACHE.example/deps/ ").is_ok());
    }
}
