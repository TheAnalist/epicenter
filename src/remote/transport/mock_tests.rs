//! Local TLS tests for the anonymous HTTPS and signed S3 paths.

use super::s3::{MAX_MULTIPART_PARTS, MultipartPlan};
use super::*;
use crate::remote::sink::{Precondition, PutStatus, RemoteSink};
use crate::remote::{RemoteSource, Upload, UploadKind, UploadMode, sha256_hex};
use ::url::Url;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

#[derive(Clone)]
struct MockRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl MockRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

struct MockResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl MockResponse {
    fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    fn not_found() -> Self {
        Self {
            status: 404,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

struct TestServer {
    addr: SocketAddr,
    ca: PathBuf,
    _dir: TempDir,
}

fn start_server(
    handler: impl Fn(&MockRequest) -> MockResponse + Send + Sync + 'static,
) -> anyhow::Result<TestServer> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)?,
    );
    let dir = tempfile::tempdir()?;
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, cert.pem())?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let handler = Arc::new(handler);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let config = config.clone();
            let handler = handler.clone();
            std::thread::spawn(move || {
                let _ = serve(stream, config, handler);
            });
        }
    });
    Ok(TestServer {
        addr,
        ca,
        _dir: dir,
    })
}

fn serve(
    stream: TcpStream,
    config: Arc<rustls::ServerConfig>,
    handler: Arc<dyn Fn(&MockRequest) -> MockResponse + Send + Sync>,
) -> anyhow::Result<()> {
    let conn = rustls::ServerConnection::new(config)?;
    let mut tls = rustls::StreamOwned::new(conn, stream);
    let request = read_request(&mut tls)?;
    let response = handler(&request);
    write_response(
        &mut tls,
        response,
        request.method.eq_ignore_ascii_case("HEAD"),
    )?;
    Ok(())
}

fn read_request<R: Read>(reader: &mut R) -> anyhow::Result<MockRequest> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = reader.read(&mut chunk)?;
        anyhow::ensure!(n > 0, "connection closed before headers");
        raw.extend_from_slice(&chunk[..n]);
        if let Some(at) = find(&raw, b"\r\n\r\n") {
            break at + 4;
        }
        anyhow::ensure!(raw.len() <= 128 * 1024, "request headers too large");
    };
    let head = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let mut headers = Vec::new();
    let mut content_length = 0usize;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_string();
        if name == "content-length" {
            content_length = value.parse().unwrap_or(0);
        }
        headers.push((name, value));
    }
    let mut body = raw[header_end..].to_vec();
    while body.len() < content_length {
        let n = reader.read(&mut chunk)?;
        anyhow::ensure!(n > 0, "connection closed before body");
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    Ok(MockRequest {
        method,
        path,
        headers,
        body,
    })
}

fn write_response<W: Write>(
    writer: &mut W,
    response: MockResponse,
    head: bool,
) -> anyhow::Result<()> {
    let reason = match response.status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        403 => "Forbidden",
        404 => "Not Found",
        412 => "Precondition Failed",
        500 => "Internal Server Error",
        _ => "Status",
    };
    write!(writer, "HTTP/1.1 {} {reason}\r\n", response.status)?;
    for (name, value) in &response.headers {
        write!(writer, "{name}: {value}\r\n")?;
    }
    let has_length = response
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-length"));
    if !has_length {
        write!(writer, "content-length: {}\r\n", response.body.len())?;
    }
    write!(writer, "connection: close\r\n\r\n")?;
    if !head {
        writer.write_all(&response.body)?;
    }
    writer.flush()?;
    Ok(())
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn config_with_ca(endpoint: Endpoint, ca: &std::path::Path) -> TransportConfig {
    TransportConfig {
        endpoint,
        credentials: Some(Credentials::from_parts(
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None,
        )),
        tls: TlsConfig {
            ca_file: Some(ca.to_path_buf()),
        },
        timeouts: Timeouts::default(),
        retry: RetryPolicy::default(),
    }
}

#[test]
fn anonymous_https_streams_a_blob() -> anyhow::Result<()> {
    let server = start_server(|request| {
        if request.path == "/prefix/blobs/abc" {
            MockResponse::ok(b"blob bytes".to_vec())
        } else {
            MockResponse::not_found()
        }
    })?;
    let endpoint = HttpsEndpoint::parse(&format!("https://{}/prefix", server.addr))?;
    let mut config = TransportConfig {
        endpoint: Endpoint::Https(endpoint),
        credentials: None,
        tls: TlsConfig {
            ca_file: Some(server.ca.clone()),
        },
        timeouts: Timeouts::default(),
        retry: RetryPolicy::default(),
    };
    config.retry.attempts = 1;
    let source = HttpsSource::new(&config)?;
    let mut out = Vec::new();
    source.fetch_blob("abc", 1024, &mut out)?;
    assert_eq!(out, b"blob bytes");
    Ok(())
}

#[test]
fn s3_get_is_signed_and_mapped_to_https() -> anyhow::Result<()> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let capture = seen.clone();
    let server = start_server(move |request| {
        capture.lock().unwrap().push(request.clone());
        if request.path == "/bucket/prefix/index.json" {
            MockResponse::ok(b"pointer".to_vec())
        } else {
            MockResponse::not_found()
        }
    })?;
    let endpoint = S3Endpoint::parse(
        "s3://bucket/prefix",
        "us-east-1",
        Some(Url::parse(&format!("https://{}", server.addr))?),
    )?;
    let config = config_with_ca(Endpoint::S3(endpoint), &server.ca);
    let source = S3Source::new(&config)?;
    assert_eq!(source.fetch_pointer()?, b"pointer");
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "GET");
    assert!(
        seen[0]
            .header("authorization")
            .is_some_and(|value| value.starts_with("AWS4-HMAC-SHA256 "))
    );
    assert!(seen[0].header("x-amz-date").is_some());
    assert!(seen[0].header("x-amz-content-sha256").is_some());
    Ok(())
}

#[test]
fn s3_missing_pointer_is_a_clean_miss_but_forbidden_is_not() -> anyhow::Result<()> {
    let missing = start_server(|_| MockResponse::not_found())?;
    let endpoint = S3Endpoint::parse(
        "s3://bucket/prefix",
        "us-east-1",
        Some(Url::parse(&format!("https://{}", missing.addr))?),
    )?;
    let source = S3Source::new(&config_with_ca(Endpoint::S3(endpoint), &missing.ca))?;
    assert!(source.fetch_pointer_optional()?.is_none());

    let forbidden = start_server(|_| MockResponse {
        status: 403,
        headers: Vec::new(),
        body: Vec::new(),
    })?;
    let endpoint = S3Endpoint::parse(
        "s3://bucket/prefix",
        "us-east-1",
        Some(Url::parse(&format!("https://{}", forbidden.addr))?),
    )?;
    let source = S3Source::new(&config_with_ca(Endpoint::S3(endpoint), &forbidden.ca))?;
    assert!(source.fetch_pointer_optional().is_err());
    Ok(())
}

#[test]
fn s3_put_uses_if_none_match() -> anyhow::Result<()> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let capture = seen.clone();
    let server = start_server(move |request| {
        capture.lock().unwrap().push(request.clone());
        if request.method == "PUT" {
            let mut response = MockResponse::ok(Vec::new());
            response.status = 201;
            response.headers.push(("etag".into(), "\"abc\"".into()));
            response
        } else {
            MockResponse::not_found()
        }
    })?;
    let endpoint = S3Endpoint::parse(
        "s3://bucket/prefix",
        "us-east-1",
        Some(Url::parse(&format!("https://{}", server.addr))?),
    )?;
    let config = config_with_ca(Endpoint::S3(endpoint), &server.ca);
    let sink = S3Sink::new(&config)?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("blob");
    let bytes = b"payload".to_vec();
    std::fs::write(&path, &bytes)?;
    let upload = Upload {
        key: format!("blobs/{}", sha256_hex(&bytes)),
        source: path,
        sha256: sha256_hex(&bytes),
        size: bytes.len() as u64,
        mode: UploadMode::PutIfAbsent,
        kind: UploadKind::Blob,
    };
    let outcome = sink.put(&upload, Precondition::IfAbsent)?;
    assert_eq!(outcome.status, PutStatus::Created);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "PUT");
    assert_eq!(seen[0].header("if-none-match"), Some("*"));
    assert_eq!(seen[0].body, bytes);
    Ok(())
}

#[test]
fn multipart_upload_creates_parts_and_completes_last() -> anyhow::Result<()> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let capture = seen.clone();
    let server = start_server(move |request| {
        capture.lock().unwrap().push(request.clone());
        if request.method == "HEAD" {
            MockResponse::not_found()
        } else if request.method == "POST" && request.path.contains("uploads=") {
            MockResponse::ok(b"<UploadId>a*b!(c)~d</UploadId>".to_vec())
        } else if request.method == "PUT" && request.path.contains("partNumber=") {
            let mut response = MockResponse::ok(Vec::new());
            response.headers.push(("etag".into(), "\"part-1\"".into()));
            response
        } else if request.method == "POST" && request.path.contains("uploadId=") {
            let mut response = MockResponse::ok(Vec::new());
            response.headers.push(("etag".into(), "\"done\"".into()));
            response
        } else {
            MockResponse::not_found()
        }
    })?;
    let endpoint = S3Endpoint::parse(
        "s3://bucket/prefix",
        "us-east-1",
        Some(Url::parse(&format!("https://{}", server.addr))?),
    )?;
    let config = config_with_ca(Endpoint::S3(endpoint), &server.ca);
    let client = S3Client::new(&config)?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("blob");
    let bytes = vec![7u8; 1024 * 1024];
    std::fs::write(&path, &bytes)?;
    let upload = Upload {
        key: format!("blobs/{}", sha256_hex(&bytes)),
        source: path,
        sha256: sha256_hex(&bytes),
        size: bytes.len() as u64,
        mode: UploadMode::PutIfAbsent,
        kind: UploadKind::Blob,
    };
    let outcome = client.put_multipart(&upload, Precondition::IfAbsent)?;
    assert_eq!(outcome.status, PutStatus::Created);
    let seen = seen.lock().unwrap();
    assert_eq!(
        seen.len(),
        4,
        "{:?}",
        seen.iter()
            .map(|r| (&r.method, &r.path))
            .collect::<Vec<_>>()
    );
    assert_eq!(seen[0].method, "HEAD");
    assert!(seen[1].method == "POST" && seen[1].path.contains("uploads="));
    assert!(seen[2].method == "PUT" && seen[2].path.contains("partNumber=1"));
    // The wire query must match the SigV4 canonical encoding, including `*`,
    // `!`, `(`, `)` and `~` in the server-provided upload id.
    assert!(
        seen[2].path.contains("uploadId=a%2Ab%21%28c%29~d"),
        "{}",
        seen[2].path
    );
    assert!(seen[3].method == "POST" && seen[3].path.contains("uploadId="));
    assert_eq!(seen[3].header("if-none-match"), Some("*"));
    Ok(())
}

#[test]
fn multipart_skips_a_present_blob_without_creating_an_upload() -> anyhow::Result<()> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let capture = seen.clone();
    let size = 100 * 1024 * 1024u64;
    let server = start_server(move |request| {
        capture.lock().unwrap().push(request.clone());
        if request.method == "HEAD" {
            let mut response = MockResponse::ok(Vec::new());
            response
                .headers
                .push(("content-length".into(), size.to_string()));
            response
        } else {
            MockResponse::not_found()
        }
    })?;
    let endpoint = S3Endpoint::parse(
        "s3://bucket/prefix",
        "us-east-1",
        Some(Url::parse(&format!("https://{}", server.addr))?),
    )?;
    let config = config_with_ca(Endpoint::S3(endpoint), &server.ca);
    let client = S3Client::new(&config)?;
    let upload = Upload {
        key: "blobs/large".into(),
        source: PathBuf::from("/nonexistent"),
        sha256: "ab".repeat(32),
        size,
        mode: UploadMode::PutIfAbsent,
        kind: UploadKind::Blob,
    };
    let outcome = client.put_multipart(&upload, Precondition::IfAbsent)?;
    assert_eq!(outcome.status, PutStatus::AlreadyExists);
    let seen = seen.lock().unwrap();
    assert_eq!(
        seen.len(),
        1,
        "{:?}",
        seen.iter().map(|r| &r.method).collect::<Vec<_>>()
    );
    assert_eq!(seen[0].method, "HEAD");
    Ok(())
}

#[test]
fn multipart_aborts_after_a_lost_conditional_complete() -> anyhow::Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let seen = Arc::new(Mutex::new(Vec::new()));
    let capture = seen.clone();
    let heads = Arc::new(AtomicUsize::new(0));
    let head_count = heads.clone();
    let size = 1024 * 1024u64;
    let server = start_server(move |request| {
        capture.lock().unwrap().push(request.clone());
        if request.method == "HEAD" {
            // First HEAD is the preflight (a miss); the second is issued while
            // resolving the 412 and reports the object that won the race.
            if head_count.fetch_add(1, Ordering::SeqCst) == 0 {
                return MockResponse::not_found();
            }
            let mut response = MockResponse::ok(Vec::new());
            response
                .headers
                .push(("content-length".into(), size.to_string()));
            return response;
        }
        if request.method == "POST" && request.path.contains("uploads=") {
            MockResponse::ok(b"<UploadId>upload-1</UploadId>".to_vec())
        } else if request.method == "PUT" && request.path.contains("partNumber=") {
            let mut response = MockResponse::ok(Vec::new());
            response.headers.push(("etag".into(), "\"part-1\"".into()));
            response
        } else if request.method == "POST" && request.path.contains("uploadId=") {
            MockResponse {
                status: 412,
                headers: Vec::new(),
                body: Vec::new(),
            }
        } else if request.method == "DELETE" && request.path.contains("uploadId=") {
            MockResponse {
                status: 204,
                headers: Vec::new(),
                body: Vec::new(),
            }
        } else {
            MockResponse::not_found()
        }
    })?;
    let endpoint = S3Endpoint::parse(
        "s3://bucket/prefix",
        "us-east-1",
        Some(Url::parse(&format!("https://{}", server.addr))?),
    )?;
    let config = config_with_ca(Endpoint::S3(endpoint), &server.ca);
    let client = S3Client::new(&config)?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("blob");
    let bytes = vec![7u8; size as usize];
    std::fs::write(&path, &bytes)?;
    let upload = Upload {
        key: format!("blobs/{}", sha256_hex(&bytes)),
        source: path,
        sha256: sha256_hex(&bytes),
        size,
        mode: UploadMode::PutIfAbsent,
        kind: UploadKind::Blob,
    };
    let outcome = client.put_multipart(&upload, Precondition::IfAbsent)?;
    assert_eq!(outcome.status, PutStatus::AlreadyExists);
    let seen = seen.lock().unwrap();
    assert!(
        seen.iter()
            .any(|r| r.method == "DELETE" && r.path.contains("uploadId=")),
        "losing multipart uploads must be aborted: {:?}",
        seen.iter()
            .map(|r| (&r.method, &r.path))
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn multipart_plan_uses_more_than_one_part_and_stays_bounded() -> anyhow::Result<()> {
    let upload = Upload {
        key: "blobs/large".into(),
        source: PathBuf::from("/nonexistent"),
        sha256: "ab".repeat(32),
        size: 100 * 1024 * 1024,
        mode: UploadMode::PutIfAbsent,
        kind: UploadKind::Blob,
    };
    let plan = MultipartPlan::for_upload(&upload)?;
    assert!(plan.parts.len() > 1);
    assert!(
        plan.parts
            .iter()
            .all(|part| part.number > 0 && part.len > 0)
    );
    let large = Upload {
        size: 16 * 1024 * 1024 * 1024,
        ..upload
    };
    let plan = MultipartPlan::for_upload(&large)?;
    assert!(plan.parts.len() as u64 <= MAX_MULTIPART_PARTS);
    Ok(())
}

#[test]
fn https_refuses_a_plain_http_server() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
        }
    });
    let endpoint = HttpsEndpoint::parse(&format!("https://{addr}/prefix"))?;
    let mut config = TransportConfig {
        endpoint: Endpoint::Https(endpoint),
        credentials: None,
        tls: TlsConfig::default(),
        timeouts: Timeouts::default(),
        retry: RetryPolicy::default(),
    };
    config.retry.attempts = 1;
    let source = HttpsSource::new(&config)?;
    assert!(source.fetch_pointer().is_err());
    Ok(())
}

#[test]
fn rejects_a_content_encoded_response() -> anyhow::Result<()> {
    let server = start_server(|_| {
        let mut response = MockResponse::ok(b"compressed".to_vec());
        response
            .headers
            .push(("content-encoding".into(), "gzip".into()));
        response
    })?;
    let endpoint = HttpsEndpoint::parse(&format!("https://{}/prefix", server.addr))?;
    let mut config = TransportConfig {
        endpoint: Endpoint::Https(endpoint),
        credentials: None,
        tls: TlsConfig {
            ca_file: Some(server.ca.clone()),
        },
        timeouts: Timeouts::default(),
        retry: RetryPolicy::default(),
    };
    config.retry.attempts = 1;
    let source = HttpsSource::new(&config)?;
    assert!(source.fetch_pointer().is_err());
    Ok(())
}

#[test]
fn a_server_error_is_not_a_miss() -> anyhow::Result<()> {
    let server = start_server(|_| MockResponse {
        status: 500,
        headers: Vec::new(),
        body: Vec::new(),
    })?;
    let endpoint = S3Endpoint::parse(
        "s3://bucket/prefix",
        "us-east-1",
        Some(Url::parse(&format!("https://{}", server.addr))?),
    )?;
    let mut config = config_with_ca(Endpoint::S3(endpoint), &server.ca);
    config.retry.attempts = 1;
    let source = S3Source::new(&config)?;
    assert!(source.fetch_pointer_optional().is_err());
    Ok(())
}

#[test]
fn a_read_timeout_is_reported() -> anyhow::Result<()> {
    let server = start_server(|_| {
        std::thread::sleep(std::time::Duration::from_millis(300));
        MockResponse::ok(Vec::new())
    })?;
    let endpoint = HttpsEndpoint::parse(&format!("https://{}/prefix", server.addr))?;
    let mut config = TransportConfig {
        endpoint: Endpoint::Https(endpoint),
        credentials: None,
        tls: TlsConfig {
            ca_file: Some(server.ca.clone()),
        },
        timeouts: Timeouts::default(),
        retry: RetryPolicy::default(),
    };
    config.timeouts.response = std::time::Duration::from_millis(50);
    config.timeouts.read = std::time::Duration::from_millis(50);
    config.retry.attempts = 1;
    let source = HttpsSource::new(&config)?;
    assert!(source.fetch_pointer().is_err());
    Ok(())
}

#[test]
fn lenient_head_treats_forbidden_as_absent_but_not_server_errors() -> anyhow::Result<()> {
    let forbidden = start_server(|_| MockResponse {
        status: 403,
        headers: Vec::new(),
        body: Vec::new(),
    })?;
    let endpoint = S3Endpoint::parse(
        "s3://bucket/prefix",
        "us-east-1",
        Some(Url::parse(&format!("https://{}", forbidden.addr))?),
    )?;
    let client = S3Client::new(&config_with_ca(Endpoint::S3(endpoint), &forbidden.ca))?;
    assert!(client.head("blobs/missing").is_err());
    assert!(client.head_lenient("blobs/missing")?.is_none());

    let failing = start_server(|_| MockResponse {
        status: 500,
        headers: Vec::new(),
        body: Vec::new(),
    })?;
    let endpoint = S3Endpoint::parse(
        "s3://bucket/prefix",
        "us-east-1",
        Some(Url::parse(&format!("https://{}", failing.addr))?),
    )?;
    let mut config = config_with_ca(Endpoint::S3(endpoint), &failing.ca);
    config.retry.attempts = 1;
    let client = S3Client::new(&config)?;
    assert!(client.head_lenient("blobs/x").is_err());
    Ok(())
}
