//! S3-compatible transport: endpoint mapping, SigV4 requests, conditional
//! writes and multipart uploads.

use anyhow::{Context, Result, bail, ensure};
use rayon::{ThreadPool, prelude::*};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

use super::http::{Body, HttpClient, HttpRequest, HttpResponse, Method};
use super::sigv4::{SigV4Signer, hex_sha256};
use super::{
    Endpoint, ErrorKind, FetchedPointer, RemoteSource, S3Endpoint, TransportConfig, TransportError,
};
use crate::remote::sink::{ObjectMeta, Precondition, PutOutcome, PutStatus, RemoteSink};
use crate::remote::{
    INDEX_FILE, MAX_INDEX_BODY_BYTES, MAX_INDEX_POINTER_BYTES, Upload, UploadKind,
};

const MULTIPART_THRESHOLD: u64 = 100 * 1024 * 1024;
const MULTIPART_MIN_PART: u64 = 16 * 1024 * 1024;
const MULTIPART_MAX_PART: u64 = 64 * 1024 * 1024;
pub(super) const MAX_MULTIPART_PARTS: u64 = 10_000;
const MIB: u64 = 1024 * 1024;
const MAX_UPLOAD_ID_BYTES: usize = 2048;

#[derive(Clone)]
pub struct S3Client {
    http: HttpClient,
    endpoint: S3Endpoint,
    signer: Arc<SigV4Signer>,
    part_pool: Option<Arc<ThreadPool>>,
}

impl S3Client {
    pub fn new(config: &TransportConfig) -> Result<Self> {
        Self::build(config, true)
    }

    pub fn new_reader(config: &TransportConfig) -> Result<Self> {
        Self::build(config, false)
    }

    fn build(config: &TransportConfig, with_parts: bool) -> Result<Self> {
        let Endpoint::S3(endpoint) = &config.endpoint else {
            bail!("S3 client requires an s3:// endpoint");
        };
        let credentials = config
            .credentials
            .as_ref()
            .context("the S3 transport requires credentials")?;
        let part_pool = if with_parts {
            Some(Arc::new(
                rayon::ThreadPoolBuilder::new()
                    .num_threads(4)
                    .thread_name(|index| format!("s3-part-{index}"))
                    .build()
                    .context("building the S3 multipart pool")?,
            ))
        } else {
            None
        };
        Ok(Self {
            http: HttpClient::new(config)?,
            endpoint: endpoint.clone(),
            signer: Arc::new(SigV4Signer::new(credentials, &endpoint.region)),
            part_pool,
        })
    }

    fn with_region(&self, region: &str) -> Result<Self> {
        Ok(Self {
            http: self.http.clone(),
            endpoint: self.endpoint.with_region(region)?,
            signer: Arc::new(self.signer.with_region(region)),
            part_pool: self.part_pool.clone(),
        })
    }

    fn request(
        &self,
        method: Method,
        key: &str,
        query: Vec<(String, String)>,
        headers: Vec<(String, String)>,
        body: Body,
        payload: Option<String>,
    ) -> Result<HttpRequest, TransportError> {
        let url = self.endpoint.url_for(key).map_err(|err| {
            TransportError::new(
                ErrorKind::Config,
                format!("building S3 object URL: {err:#}"),
            )
        })?;
        let mut request = HttpRequest::new(method, url);
        request.query = query;
        request.headers = headers;
        request.body = body;
        request.payload_sha256 = payload;
        self.signer.sign(&mut request)?;
        Ok(request)
    }

    fn send(
        &self,
        method: Method,
        key: &str,
        query: Vec<(String, String)>,
        headers: Vec<(String, String)>,
        body: Body,
        payload: Option<String>,
    ) -> Result<HttpResponse, TransportError> {
        self.send_inner(method, key, query, headers, body, payload, true)
    }

    #[allow(clippy::too_many_arguments)]
    fn send_inner(
        &self,
        method: Method,
        key: &str,
        query: Vec<(String, String)>,
        headers: Vec<(String, String)>,
        body: Body,
        payload: Option<String>,
        allow_region_redirect: bool,
    ) -> Result<HttpResponse, TransportError> {
        let request = self.request(
            method,
            key,
            query.clone(),
            headers.clone(),
            body.clone(),
            payload.clone(),
        )?;
        let response = self.http.execute(&request)?;
        if allow_region_redirect
            && !self.endpoint.custom
            && (response.is_redirect() || response.status == 400)
            && self
                .endpoint
                .base_host()
                .is_some_and(|host| host.ends_with("amazonaws.com"))
            && let Some(region) = response.header("x-amz-bucket-region")
            && region != self.endpoint.region
        {
            let alt = self.with_region(region).map_err(|err| {
                TransportError::new(ErrorKind::Config, format!("switching S3 region: {err:#}"))
            })?;
            return alt.send_inner(method, key, query, headers, body, payload, false);
        }
        Ok(response)
    }

    pub fn get_response(&self, key: &str) -> Result<HttpResponse, TransportError> {
        let response = self.send(Method::Get, key, Vec::new(), Vec::new(), Body::Empty, None)?;
        response.ensure_success("S3 GET")
    }

    pub fn get(&self, key: &str, max_bytes: u64) -> Result<Vec<u8>, TransportError> {
        self.get_response(key)?.read_vec(max_bytes)
    }

    pub fn get_with_etag(
        &self,
        key: &str,
        max_bytes: u64,
    ) -> Result<FetchedPointer, TransportError> {
        let response = self.get_response(key)?;
        let etag = response.header("etag").map(str::to_string);
        let bytes = response.read_vec(max_bytes)?;
        Ok(FetchedPointer { bytes, etag })
    }

    pub fn head(&self, key: &str) -> Result<Option<ObjectMeta>, TransportError> {
        let response = self.send(Method::Head, key, Vec::new(), Vec::new(), Body::Empty, None)?;
        if response.status == 404 {
            return Ok(None);
        }
        let response = response.ensure_success("S3 HEAD")?;
        let size = response
            .header("content-length")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        Ok(Some(ObjectMeta {
            size,
            etag: response.header("etag").map(str::to_string),
            checksum_sha256: response.header("x-amz-checksum-sha256").map(str::to_string),
        }))
    }

    /// HEAD for an optional preflight. A 403 is how S3 reports a missing key
    /// when the caller lacks `s3:ListBucket`, so it is treated like a miss
    /// here. Callers still rely on the conditional write, never on this probe,
    /// to decide whether an object exists.
    pub fn head_lenient(&self, key: &str) -> Result<Option<ObjectMeta>, TransportError> {
        match self.head(key) {
            Ok(meta) => Ok(meta),
            Err(err) if err.kind == ErrorKind::Forbidden => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn put_single(&self, upload: &Upload, precondition: Precondition) -> Result<PutOutcome> {
        let mut headers = put_headers(&precondition);
        // Have the store record a whole-object SHA-256 so a later HEAD can
        // prove the existing bytes before a name is reused.
        headers.push((
            "x-amz-checksum-sha256".to_string(),
            checksum_sha256(&upload.sha256)
                .context("upload SHA-256 is not a 64-character hex digest")?,
        ));
        let response = self.send(
            Method::Put,
            &upload.key,
            Vec::new(),
            headers,
            Body::File(upload.source.clone()),
            Some(upload.sha256.clone()),
        )?;
        let status = response.status;
        if matches!(status, 200 | 201 | 204) {
            return Ok(PutOutcome {
                status: match precondition {
                    Precondition::IfAbsent => PutStatus::Created,
                    Precondition::IfMatch(_) => PutStatus::Replaced,
                    Precondition::None => PutStatus::Replaced,
                },
                etag: response.header("etag").map(str::to_string),
                size: upload.size,
            });
        }
        if status == 412 {
            if matches!(precondition, Precondition::IfAbsent) {
                return self.existing_object(upload);
            }
            // A retried or lost response may have written exactly our bytes.
            if let Ok(bytes) = self.get(&upload.key, upload.size)
                && hex_sha256(&bytes) == upload.sha256
            {
                return Ok(PutOutcome {
                    status: PutStatus::Replaced,
                    etag: response.header("etag").map(str::to_string),
                    size: upload.size,
                });
            }
            return Err(TransportError::status(
                status,
                "S3 pointer precondition failed; another publisher won",
            )
            .into());
        }
        if status == 409 {
            bail!(
                "S3 write conflict for {}; retry after re-reading the index",
                upload.key
            );
        }
        let code = response
            .header("x-amz-request-id")
            .map(|id| format!(" (request {id})"))
            .unwrap_or_default();
        Err(TransportError::status(status, format!("S3 PUT {} failed{code}", upload.key)).into())
    }

    fn existing_object(&self, upload: &Upload) -> Result<PutOutcome> {
        let meta = self.head(&upload.key)?.with_context(|| {
            format!(
                "S3 reported a conditional conflict for {} but the object is missing",
                upload.key
            )
        })?;
        self.accept_existing(upload, meta)
    }

    /// Decide whether an object that already owns a key may be reused. A blob
    /// is only reused when the store reports a SHA-256 checksum equal to the
    /// staged bytes; size alone (or an ETag) is never treated as identity.
    fn accept_existing(&self, upload: &Upload, meta: ObjectMeta) -> Result<PutOutcome> {
        ensure!(
            meta.size == upload.size,
            "S3 object {} already exists with {} bytes (expected {}) — refusing to overwrite",
            upload.key,
            meta.size,
            upload.size
        );
        if upload.kind == UploadKind::Blob {
            let expected = checksum_sha256(&upload.sha256)
                .context("upload SHA-256 is not a 64-character hex digest")?;
            match meta.checksum_sha256.as_deref() {
                Some(found) if found.trim() == expected => {}
                Some(found) => bail!(
                    "S3 object {} already exists with SHA-256 {} (expected {}) — refusing to reuse it",
                    upload.key,
                    found.trim(),
                    expected
                ),
                None => bail!(
                    "S3 object {} already exists but the store returned no x-amz-checksum-sha256, \
                     so its bytes cannot be verified without overwriting; delete the object or \
                     publish to a store that reports SHA-256 checksums",
                    upload.key
                ),
            }
        } else {
            let bytes = self.get(&upload.key, upload.size)?;
            ensure!(
                hex_sha256(&bytes) == upload.sha256,
                "S3 object {} already exists with different bytes",
                upload.key
            );
        }
        Ok(PutOutcome {
            status: PutStatus::AlreadyExists,
            etag: meta.etag,
            size: meta.size,
        })
    }

    pub(super) fn put_multipart(
        &self,
        upload: &Upload,
        precondition: Precondition,
    ) -> Result<PutOutcome> {
        let plan = MultipartPlan::for_upload(upload)?;
        if matches!(&precondition, Precondition::IfAbsent)
            && let Some(meta) = self.head_lenient(&upload.key)?
        {
            return self.accept_existing(upload, meta);
        }
        // Multipart completion carries only per-part hashes, not a whole-object
        // checksum. Verify the staged source once here so the CAS key and the
        // uploaded bytes cannot drift apart before the first part is sent.
        crate::util::verify_file_hash(
            &upload.source,
            upload.size,
            &upload.sha256,
            "multipart source",
        )?;
        let upload_id = self.create_multipart(&upload.key, &upload.kind)?;
        let mut guard = AbortGuard {
            client: self.clone(),
            key: upload.key.clone(),
            upload_id: upload_id.clone(),
            armed: true,
        };
        let pool = self
            .part_pool
            .as_ref()
            .context("multipart upload requires a writer client")?;
        let results: Vec<Result<MultipartPart>> = pool.install(|| {
            plan.parts
                .par_iter()
                .map(|part| self.upload_part(&upload.key, &upload_id, upload, part))
                .collect()
        });
        let mut parts = Vec::with_capacity(results.len());
        for result in results {
            parts.push(result?);
        }
        let outcome =
            self.complete_multipart(&upload.key, &upload_id, &parts, precondition, upload)?;
        if outcome.status != PutStatus::AlreadyExists {
            guard.armed = false;
        } else if self.abort_multipart(&upload.key, &upload_id).is_ok() {
            // The object won the race; the parts we uploaded are redundant.
            // Keep the guard armed when the abort fails so drop retries once.
            guard.armed = false;
        }
        Ok(outcome)
    }

    fn create_multipart(&self, key: &str, kind: &UploadKind) -> Result<String> {
        let headers = vec![("content-type".to_string(), content_type(kind).to_string())];
        let response = self.send(
            Method::Post,
            key,
            vec![("uploads".to_string(), String::new())],
            headers,
            Body::Empty,
            None,
        )?;
        let response = response.ensure_success("S3 CreateMultipartUpload")?;
        let bytes = response.read_vec(16 * 1024)?;
        let text = String::from_utf8_lossy(&bytes);
        let raw = extract_xml(&text, "UploadId")
            .context("S3 CreateMultipartUpload response has no UploadId")?;
        let upload_id = decode_xml_entities(&raw, MAX_UPLOAD_ID_BYTES)
            .context("S3 returned an invalid UploadId")?;
        ensure!(
            !upload_id.is_empty()
                && upload_id.len() <= MAX_UPLOAD_ID_BYTES
                && !upload_id.chars().any(char::is_control),
            "S3 returned an invalid UploadId"
        );
        Ok(upload_id)
    }

    fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        upload: &Upload,
        part: &PartPlan,
    ) -> Result<MultipartPart> {
        let bytes = read_range(&upload.source, part.offset, part.len)?;
        let hash = hex_sha256(&bytes);
        let response = self.send(
            Method::Put,
            key,
            vec![
                ("partNumber".to_string(), part.number.to_string()),
                ("uploadId".to_string(), upload_id.to_string()),
            ],
            Vec::new(),
            Body::Bytes(bytes),
            Some(hash),
        )?;
        let response = response.ensure_success("S3 UploadPart")?;
        let etag = response
            .header("etag")
            .context("S3 UploadPart response has no ETag")?
            .to_string();
        Ok(MultipartPart {
            number: part.number,
            etag,
        })
    }

    fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[MultipartPart],
        precondition: Precondition,
        upload: &Upload,
    ) -> Result<PutOutcome> {
        let xml = complete_xml(parts);
        let mut headers = put_headers(&precondition);
        headers.push(("content-type".to_string(), "application/xml".to_string()));
        let response = self.send(
            Method::Post,
            key,
            vec![("uploadId".to_string(), upload_id.to_string())],
            headers,
            Body::Bytes(xml.into_bytes()),
            None,
        )?;
        let status = response.status;
        if matches!(status, 200 | 201 | 204) {
            let etag = response.header("etag").map(str::to_string);
            // S3 can answer 200 and then report the failure in the body.
            // Success is the result document, not the status code.
            ensure_completion_body(response.read_vec(64 * 1024)?)?;
            return Ok(PutOutcome {
                status: match precondition {
                    Precondition::IfAbsent => PutStatus::Created,
                    _ => PutStatus::Replaced,
                },
                etag,
                size: upload.size,
            });
        }
        if status == 412 {
            return self.existing_object(upload);
        }
        if status == 404 {
            // A retried Complete may have succeeded before the response was
            // lost. If the object is present with matching bytes, treat the
            // upload as complete.
            return self.existing_object(upload);
        }
        if matches!(status, 400 | 501) && matches!(precondition, Precondition::IfAbsent) {
            // Never retry without `If-None-Match`: the earlier HEAD is not a
            // guarantee, so degrading here could overwrite another publisher.
            return Err(TransportError::status(
                status,
                format!(
                    "S3 rejected the conditional CompleteMultipartUpload for {key}; the store \
                     does not support If-None-Match on multipart completion, so nothing was \
                     committed and no existing object was overwritten"
                ),
            )
            .into());
        }
        Err(TransportError::status(status, "S3 CompleteMultipartUpload failed").into())
    }

    fn abort_multipart(&self, key: &str, upload_id: &str) -> Result<()> {
        let response = self.send(
            Method::Delete,
            key,
            vec![("uploadId".to_string(), upload_id.to_string())],
            Vec::new(),
            Body::Empty,
            None,
        )?;
        if matches!(response.status, 200 | 204 | 404) {
            Ok(())
        } else {
            Err(TransportError::status(response.status, "S3 AbortMultipartUpload failed").into())
        }
    }
}

pub struct S3Source {
    client: Arc<S3Client>,
}

impl S3Source {
    pub fn new(config: &TransportConfig) -> Result<Self> {
        Ok(Self {
            client: Arc::new(S3Client::new_reader(config)?),
        })
    }

    pub fn from_client(client: Arc<S3Client>) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &S3Client {
        &self.client
    }
}

impl RemoteSource for S3Source {
    fn fetch_pointer(&self) -> Result<Vec<u8>> {
        self.client
            .get(INDEX_FILE, MAX_INDEX_POINTER_BYTES)
            .map_err(anyhow::Error::new)
    }

    fn fetch_pointer_optional(&self) -> Result<Option<FetchedPointer>> {
        match self
            .client
            .get_with_etag(INDEX_FILE, MAX_INDEX_POINTER_BYTES)
        {
            Ok(pointer) => Ok(Some(pointer)),
            Err(err) if err.is_miss() => Ok(None),
            Err(err) if err.kind == ErrorKind::Forbidden => Err(anyhow::Error::new(err).context(
                "S3 denied the remote index lookup; grant s3:ListBucket on the bucket so a \
                     missing index can be told apart from an access denial (needed to bootstrap a \
                     new store), then retry",
            )),
            Err(err) => Err(anyhow::Error::new(err)),
        }
    }

    fn fetch_body(&self, sha256: &str, max_bytes: u64) -> Result<Vec<u8>> {
        self.client
            .get(
                &format!("indexes/{sha256}.json"),
                max_bytes.min(MAX_INDEX_BODY_BYTES),
            )
            .map_err(anyhow::Error::new)
    }

    fn fetch_blob(&self, sha256: &str, max_bytes: u64, out: &mut dyn Write) -> Result<()> {
        let response = self.client.get_response(&format!("blobs/{sha256}"))?;
        response.copy_to(out, max_bytes)?;
        Ok(())
    }
}

pub struct S3Sink {
    client: Arc<S3Client>,
}

impl S3Sink {
    pub fn new(config: &TransportConfig) -> Result<Self> {
        Ok(Self {
            client: Arc::new(S3Client::new(config)?),
        })
    }

    pub fn from_client(client: Arc<S3Client>) -> Self {
        Self { client }
    }

    /// Bootstrap existence probe. A 403 here means the caller cannot list the
    /// bucket, so a missing `publisher.json` and an access denial are
    /// indistinguishable; fail with the permission to grant instead of
    /// pretending the object is absent.
    pub fn head_lenient(&self, key: &str) -> Result<Option<ObjectMeta>> {
        match self.client.head(key) {
            Ok(meta) => Ok(meta),
            Err(err) if err.kind == ErrorKind::Forbidden => {
                Err(anyhow::Error::new(err).context(format!(
                    "S3 denied the bootstrap lookup for {key}; grant s3:ListBucket on the bucket \
                     so a missing object can be told apart from an access denial, then retry"
                )))
            }
            Err(err) => Err(anyhow::Error::new(err)),
        }
    }
}

impl RemoteSink for S3Sink {
    fn head(&self, key: &str) -> Result<Option<ObjectMeta>> {
        self.client.head(key).map_err(anyhow::Error::new)
    }

    fn get(&self, key: &str, max_bytes: u64) -> Result<Vec<u8>> {
        self.client.get(key, max_bytes).map_err(anyhow::Error::new)
    }

    fn put(&self, upload: &Upload, precondition: Precondition) -> Result<PutOutcome> {
        if matches!(upload.kind, UploadKind::Blob) && upload.size >= MULTIPART_THRESHOLD {
            self.client.put_multipart(upload, precondition)
        } else {
            self.client.put_single(upload, precondition)
        }
    }
}

pub struct MultipartPart {
    pub number: u32,
    pub etag: String,
}

pub(super) struct PartPlan {
    pub(super) number: u32,
    pub(super) offset: u64,
    pub(super) len: u64,
}

pub(super) struct MultipartPlan {
    pub(super) parts: Vec<PartPlan>,
}

impl MultipartPlan {
    pub(super) fn for_upload(upload: &Upload) -> Result<Self> {
        ensure!(
            upload.size > 0,
            "refusing a multipart upload for an empty object"
        );
        let mut part_size = upload.size.div_ceil(1000).max(MULTIPART_MIN_PART);
        part_size = part_size.div_ceil(MIB) * MIB;
        part_size = part_size.min(MULTIPART_MAX_PART);
        if upload.size.div_ceil(part_size) > MAX_MULTIPART_PARTS {
            part_size = upload.size.div_ceil(MAX_MULTIPART_PARTS).div_ceil(MIB) * MIB;
        }
        ensure!(
            upload.size.div_ceil(part_size) <= MAX_MULTIPART_PARTS,
            "S3 multipart upload would exceed {MAX_MULTIPART_PARTS} parts"
        );
        let mut parts = Vec::new();
        let mut offset = 0u64;
        let mut number = 1u32;
        while offset < upload.size {
            let len = (upload.size - offset).min(part_size);
            parts.push(PartPlan {
                number,
                offset,
                len,
            });
            offset += len;
            number += 1;
        }
        Ok(Self { parts })
    }
}

struct AbortGuard {
    client: S3Client,
    key: String,
    upload_id: String,
    armed: bool,
}

impl Drop for AbortGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.client.abort_multipart(&self.key, &self.upload_id);
        }
    }
}

fn put_headers(precondition: &Precondition) -> Vec<(String, String)> {
    match precondition {
        Precondition::None => Vec::new(),
        Precondition::IfAbsent => vec![("if-none-match".to_string(), "*".to_string())],
        Precondition::IfMatch(etag) => vec![("if-match".to_string(), etag.clone())],
    }
}

fn content_type(kind: &UploadKind) -> &'static str {
    match kind {
        UploadKind::Blob => "application/octet-stream",
        UploadKind::Body | UploadKind::Pointer => "application/json",
        UploadKind::Publisher => "application/json",
    }
}

/// A 2xx CompleteMultipartUpload is only a success when the body says so.
/// An empty body is accepted for stores that answer 204; an error document
/// and an unrelated document are not.
fn ensure_completion_body(bytes: Vec<u8>) -> Result<()> {
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    if trimmed.contains("<Error") {
        let detail = extract_xml(trimmed, "Message")
            .or_else(|| extract_xml(trimmed, "Code"))
            .and_then(|raw| decode_xml_entities(&raw, 200).ok())
            .unwrap_or_else(|| trimmed.chars().take(200).collect());
        anyhow::bail!("S3 CompleteMultipartUpload returned an error document: {detail}");
    }
    ensure!(
        trimmed.contains("<CompleteMultipartUploadResult"),
        "S3 CompleteMultipartUpload returned an unexpected response body"
    );
    Ok(())
}

fn complete_xml(parts: &[MultipartPart]) -> String {
    let mut xml = String::from("<CompleteMultipartUpload>");
    for part in parts {
        xml.push_str(&format!(
            "<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>",
            part.number,
            xml_escape(&part.etag)
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");
    xml
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn extract_xml(text: &str, tag: &str) -> Option<String> {
    let start_tag = format!("<{tag}>");
    let end_tag = format!("</{tag}>");
    let start = text.find(&start_tag)? + start_tag.len();
    let end = text[start..].find(&end_tag)? + start;
    Some(text[start..end].to_string())
}

/// Decode the predefined XML entities plus decimal/hex character references.
/// Every reference must be well-formed and the decoded text must fit in
/// `max_bytes`, so a hostile or malformed document cannot grow the value or
/// leave an entity spelling in a query.
fn decode_xml_entities(text: &str, max_bytes: usize) -> Result<String> {
    let mut out = String::with_capacity(text.len().min(max_bytes));
    let mut rest = text;
    while let Some(position) = rest.find('&') {
        out.push_str(&rest[..position]);
        rest = &rest[position..];
        let end = rest
            .find(';')
            .context("unterminated XML entity reference")?;
        let entity = &rest[1..end];
        let decoded = match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let code = if let Some(hex) = entity
                    .strip_prefix("#x")
                    .or_else(|| entity.strip_prefix("#X"))
                {
                    u32::from_str_radix(hex, 16).ok()
                } else {
                    entity.strip_prefix('#').and_then(|dec| dec.parse().ok())
                };
                code.and_then(char::from_u32)
                    .context("invalid XML character reference")?
            }
        };
        ensure!(
            out.len() + decoded.len_utf8() <= max_bytes,
            "decoded XML value exceeds {max_bytes} bytes"
        );
        out.push(decoded);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    ensure!(
        out.len() <= max_bytes,
        "decoded XML value exceeds {max_bytes} bytes"
    );
    Ok(out)
}

/// Base64 of the raw SHA-256 digest, the form S3 uses for
/// `x-amz-checksum-sha256`.
pub(super) fn checksum_sha256(hex_digest: &str) -> Option<String> {
    let bytes = hex_bytes(hex_digest)?;
    (bytes.len() == 32).then(|| base64_encode(&bytes))
}

fn hex_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for pair in bytes.as_chunks::<2>().0 {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push((high * 16 + low) as u8);
    }
    Some(out)
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let triple = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let value = u32::from(triple[0]) << 16 | u32::from(triple[1]) << 8 | u32::from(triple[2]);
        out.push(TABLE[(value >> 18) as usize & 0x3f] as char);
        out.push(TABLE[(value >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(value >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[value as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

fn read_range(path: &Path, offset: u64, len: u64) -> Result<Vec<u8>> {
    let mut file = crate::util::open_regular(path, false)
        .with_context(|| format!("opening {}", path.display()))?;
    let size = file.metadata()?.len();
    ensure!(
        offset.checked_add(len).is_some_and(|end| end <= size),
        "multipart range {}..{}+{} exceeds {} bytes",
        path.display(),
        offset,
        len,
        size
    );
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0u8; usize::try_from(len).context("multipart part is too large")?];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}
