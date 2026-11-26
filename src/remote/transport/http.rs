//! Blocking HTTP client: TLS roots, proxy, timeouts, caps and retries.

use anyhow::{Context, Result, bail, ensure};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

use super::url::aws_encode;
use super::{ErrorKind, RetryPolicy, TlsConfig, TransportConfig, TransportError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Put,
    Post,
    Delete,
}

#[derive(Debug, Clone)]
pub enum Body {
    Empty,
    Bytes(Vec<u8>),
    File(PathBuf),
}

#[derive(Clone)]
pub struct HttpRequest {
    pub method: Method,
    pub url: Url,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Body,
    /// Known SHA-256 of the exact request body. SigV4 requires this for PUT.
    pub payload_sha256: Option<String>,
}

impl HttpRequest {
    pub fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            query: Vec::new(),
            headers: Vec::new(),
            body: Body::Empty,
            payload_sha256: None,
        }
    }
}

pub struct HttpResponse {
    pub status: u16,
    headers: Vec<(String, String)>,
    body: ureq::Body,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status)
    }

    pub fn read_vec(self, max_bytes: u64) -> Result<Vec<u8>, TransportError> {
        if let Some(length) = self
            .header("content-length")
            .and_then(|value| value.parse::<u64>().ok())
            && length > max_bytes
        {
            return Err(TransportError::new(
                ErrorKind::TooLarge,
                format!("remote object is {length} bytes (cap {max_bytes})"),
            ));
        }
        let bytes = self
            .body
            .into_with_config()
            .limit(max_bytes)
            .read_to_vec()
            .map_err(|err| {
                if let ureq::Error::BodyExceedsLimit(_) = &err {
                    TransportError::new(
                        ErrorKind::TooLarge,
                        format!("remote object exceeds the {max_bytes}-byte cap"),
                    )
                } else {
                    map_ureq(err)
                }
            })?;
        Ok(bytes)
    }

    pub fn copy_to<W: Write + ?Sized>(
        self,
        writer: &mut W,
        max_bytes: u64,
    ) -> Result<u64, TransportError> {
        if let Some(length) = self
            .header("content-length")
            .and_then(|value| value.parse::<u64>().ok())
            && length > max_bytes
        {
            return Err(TransportError::new(
                ErrorKind::TooLarge,
                format!("remote object is {length} bytes (cap {max_bytes})"),
            ));
        }
        let mut reader = self.body.into_with_config().limit(max_bytes).reader();
        let mut total = 0u64;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = reader.read(&mut buf).map_err(|err| {
                let too_large = err
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<ureq::Error>())
                    .is_some_and(|inner| matches!(inner, ureq::Error::BodyExceedsLimit(_)));
                if too_large {
                    TransportError::new(
                        ErrorKind::TooLarge,
                        format!("remote object exceeds the {max_bytes}-byte cap"),
                    )
                } else {
                    TransportError::from(err)
                }
            })?;
            if n == 0 {
                break;
            }
            total = total.saturating_add(n as u64);
            writer.write_all(&buf[..n]).map_err(TransportError::from)?;
        }
        Ok(total)
    }

    /// Map a non-2xx status to a classified error. `304 Not Modified` is not a
    /// success here: an unconditional request never sends a validator, so a
    /// caller handling a conditional GET must inspect the status explicitly.
    pub fn ensure_success(self, what: &str) -> Result<Self, TransportError> {
        if self.is_success() {
            return Ok(self);
        }
        let status = self.status;
        let request_id = self.header("x-amz-request-id").map(str::to_string);
        let code = self.read_error_code();
        Err(TransportError::status(
            status,
            format!(
                "{what} failed{}",
                code.as_deref()
                    .map(|code| format!(" ({code})"))
                    .unwrap_or_default()
            ),
        )
        .with_request_id(request_id))
    }

    fn read_error_code(self) -> Option<String> {
        // The body is already consumed lazily; bound the read and only use a
        // short alphanumeric code in the message.
        let text = self
            .body
            .into_with_config()
            .limit(8 * 1024)
            .read_to_vec()
            .ok()?;
        let text = String::from_utf8_lossy(&text);
        let start = text.find("<Code>")? + 6;
        let end = text[start..].find("</Code>")? + start;
        let code = &text[start..end];
        (code.len() <= 64
            && code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
        .then(|| code.to_string())
    }
}

#[derive(Clone)]
pub struct HttpClient {
    agent: ureq::Agent,
    retry: RetryPolicy,
}

impl HttpClient {
    pub fn new(config: &TransportConfig) -> Result<Self> {
        #[cfg(windows)]
        let provider = ureq::tls::TlsProvider::NativeTls;
        #[cfg(not(windows))]
        let provider = ureq::tls::TlsProvider::Rustls;
        #[cfg(windows)]
        let roots = if config.tls.ca_file.is_some()
            || std::env::var_os("SSL_CERT_FILE").is_some_and(|value| !value.is_empty())
        {
            ureq::tls::RootCerts::Specific(load_roots(&config.tls)?)
        } else {
            ureq::tls::RootCerts::PlatformVerifier
        };
        #[cfg(not(windows))]
        let roots = ureq::tls::RootCerts::Specific(load_roots(&config.tls)?);
        let tls = ureq::tls::TlsConfig::builder()
            .provider(provider)
            .root_certs(roots)
            .build();
        let proxy = load_proxy()?;
        let agent = ureq::Agent::config_builder()
            .https_only(true)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .http_status_as_error(false)
            .accept_encoding("identity")
            .user_agent(format!("epicenter/{}", env!("CARGO_PKG_VERSION")))
            .tls_config(tls)
            .proxy(proxy)
            .timeout_connect(Some(config.timeouts.connect))
            .timeout_recv_response(Some(config.timeouts.response))
            .timeout_recv_body(Some(config.timeouts.read))
            .timeout_send_body(Some(config.timeouts.write))
            .max_idle_connections(8)
            .max_idle_connections_per_host(8)
            .build()
            .new_agent();
        Ok(Self {
            agent,
            retry: config.retry,
        })
    }

    /// Execute a request, retrying only replayable failures. A returned 4xx/5xx
    /// response is not an error here; callers use `ensure_success`.
    pub fn execute(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError> {
        let mut attempt = 0u32;
        loop {
            match self.send_once(request) {
                Ok(response) => {
                    if matches!(response.status, 408 | 429 | 500..=599)
                        && attempt + 1 < self.retry.attempts
                    {
                        let wait =
                            retry_after(&response).unwrap_or_else(|| backoff(self.retry, attempt));
                        std::thread::sleep(wait);
                        attempt += 1;
                        continue;
                    }
                    return Ok(response);
                }
                Err(err) if err.retryable() && attempt + 1 < self.retry.attempts => {
                    std::thread::sleep(backoff(self.retry, attempt));
                    attempt += 1;
                }
                Err(err) => return Err(err),
            }
        }
    }

    fn send_once(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError> {
        let response = match request.method {
            Method::Get | Method::Head | Method::Delete => {
                let builder = match request.method {
                    Method::Get => self.agent.get(request.url.as_str()),
                    Method::Head => self.agent.head(request.url.as_str()),
                    Method::Delete => self.agent.delete(request.url.as_str()),
                    _ => unreachable!(),
                };
                let builder = apply_request(builder, request);
                if !matches!(request.body, Body::Empty) {
                    return Err(TransportError::new(
                        ErrorKind::Config,
                        "GET/HEAD/DELETE cannot carry a body",
                    ));
                }
                builder.call()
            }
            Method::Put | Method::Post => {
                let builder = match request.method {
                    Method::Put => self.agent.put(request.url.as_str()),
                    Method::Post => self.agent.post(request.url.as_str()),
                    _ => unreachable!(),
                };
                let builder = apply_request(builder, request);
                match &request.body {
                    Body::Empty => builder.send_empty(),
                    Body::Bytes(bytes) => builder.send(bytes.as_slice()),
                    Body::File(path) => {
                        let file =
                            crate::util::open_regular(path, false).map_err(TransportError::from)?;
                        builder.send(file)
                    }
                }
            }
        }
        .map_err(map_ureq)?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_ascii_lowercase(), value.to_string()))
            })
            .collect();
        if status == 304 {
            return Ok(HttpResponse {
                status,
                headers,
                body: response.into_body(),
            });
        }
        if let Some(encoding) = headers
            .iter()
            .find(|(name, _)| name == "content-encoding")
            .map(|(_, value)| value.as_str())
            && !encoding.eq_ignore_ascii_case("identity")
        {
            return Err(TransportError::new(
                ErrorKind::Protocol,
                "remote server applied a content encoding; refusing ‘{encoding}’",
            ));
        }
        Ok(HttpResponse {
            status,
            headers,
            body: response.into_body(),
        })
    }
}

fn apply_request<B>(
    mut builder: ureq::RequestBuilder<B>,
    request: &HttpRequest,
) -> ureq::RequestBuilder<B> {
    if !request.query.is_empty() {
        // The wire query must use exactly the SigV4 canonical encoding. ureq's
        // `query_pairs` uses a different escape set (for example it leaves `*`
        // literal where SigV4 encodes it), which would invalidate the
        // signature for such values.
        builder = builder.query_pairs_raw(
            request
                .query
                .iter()
                .map(|(key, value)| (aws_encode(key), aws_encode(value))),
        );
    }
    for (name, value) in &request.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder
}

fn load_roots(tls: &TlsConfig) -> Result<Arc<Vec<ureq::tls::Certificate<'static>>>> {
    let native = rustls_native_certs::load_native_certs();
    let mut certs = Vec::with_capacity(native.certs.len() + 4);
    for cert in native.certs {
        certs.push(ureq::tls::Certificate::from_der(cert.as_ref()).to_owned());
    }
    if let Some(path) = &tls.ca_file {
        let text = crate::util::read_small_text(path, 16 * 1024 * 1024)
            .with_context(|| format!("reading CA bundle {}", path.display()))?;
        let mut cursor = std::io::Cursor::new(text.as_bytes());
        let mut loaded = 0usize;
        for cert in rustls_pemfile::certs(&mut cursor) {
            let cert = cert.context("parsing a CA certificate")?;
            certs.push(ureq::tls::Certificate::from_der(cert.as_ref()).to_owned());
            loaded += 1;
        }
        ensure!(
            loaded > 0,
            "CA bundle {} contains no certificates",
            path.display()
        );
    }
    ensure!(
        !certs.is_empty(),
        "no TLS root certificates were found; set SSL_CERT_FILE or configure an explicit CA bundle"
    );
    Ok(Arc::new(certs))
}

fn load_proxy() -> Result<Option<ureq::Proxy>> {
    let configured = [
        "ALL_PROXY",
        "all_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()));
    if !configured {
        return Ok(None);
    }
    match ureq::Proxy::try_from_env() {
        Some(proxy) => Ok(Some(proxy)),
        None => bail!("a proxy environment variable is set but its URL is not valid"),
    }
}

fn retry_after(response: &HttpResponse) -> Option<Duration> {
    let value = response.header("retry-after")?;
    value
        .trim()
        .parse::<u64>()
        .ok()
        .map(|seconds| Duration::from_secs(seconds.min(60)))
}

fn backoff(policy: RetryPolicy, attempt: u32) -> Duration {
    let factor = 1u32.checked_shl(attempt.min(8)).unwrap_or(1);
    let base = policy.base.saturating_mul(factor).min(policy.max);
    // Deterministic jitter derived from the clock; no extra RNG dependency.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos())
        .unwrap_or(0);
    let jitter = Duration::from_millis(u64::from(nanos % 100));
    (base + jitter).min(policy.max)
}

fn map_ureq(err: ureq::Error) -> TransportError {
    match err {
        ureq::Error::StatusCode(status) => TransportError::status(status, "HTTP request"),
        ureq::Error::Timeout(_) => TransportError::new(ErrorKind::Timeout, "request timed out"),
        ureq::Error::HostNotFound => TransportError::new(ErrorKind::Network, "host not found"),
        ureq::Error::Io(err) if err.kind() == std::io::ErrorKind::TimedOut => {
            TransportError::new(ErrorKind::Timeout, "network request timed out")
        }
        ureq::Error::Io(_) | ureq::Error::ConnectionFailed => {
            TransportError::new(ErrorKind::Network, "network request failed")
        }
        ureq::Error::Tls(_) | ureq::Error::Pem(_) => {
            TransportError::new(ErrorKind::Tls, "TLS validation failed")
        }
        #[cfg(not(windows))]
        ureq::Error::Rustls(_) => TransportError::new(ErrorKind::Tls, "TLS validation failed"),
        ureq::Error::BadUri(_) => TransportError::new(ErrorKind::Config, "invalid request URL"),
        ureq::Error::Protocol(_) => TransportError::new(ErrorKind::Protocol, "HTTP protocol error"),
        ureq::Error::TooManyRedirects | ureq::Error::RedirectFailed => {
            TransportError::new(ErrorKind::Redirect, "redirect refused")
        }
        _ => TransportError::new(ErrorKind::Protocol, "HTTP request failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u16) -> HttpResponse {
        HttpResponse {
            status,
            headers: Vec::new(),
            body: ureq::Body::builder().data(Vec::new()),
        }
    }

    #[test]
    fn unconditional_get_and_head_reject_304() {
        for what in ["HTTPS GET", "HTTPS blob GET", "S3 GET", "S3 HEAD"] {
            let err = response(304)
                .ensure_success(what)
                .err()
                .expect("a 304 must not pass ensure_success");
            assert_eq!(err.status, Some(304));
            assert_eq!(err.kind, ErrorKind::Redirect);
        }
    }

    #[test]
    fn unconditional_get_and_head_accept_only_2xx() {
        for status in [200, 201, 204] {
            assert!(response(status).ensure_success("HTTPS GET").is_ok());
        }
        let err = response(302)
            .ensure_success("HTTPS GET")
            .err()
            .expect("a redirect must not pass ensure_success");
        assert_eq!(err.kind, ErrorKind::Redirect);
    }
}
