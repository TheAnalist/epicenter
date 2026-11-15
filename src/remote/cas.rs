//! Immutable content-addressed blobs and upload planning.
//!
//! A blob is named by the SHA-256 of its **stored** bytes, so a reader can
//! verify the object before decompressing it. The index also records the
//! decoded hash and size, so a valid gzip envelope around the wrong payload
//! is still rejected. Uploads are put-if-absent: a published blob is never
//! replaced.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use super::{
    MAX_BLOB_BYTES, MAX_INDEX_BODY_BYTES, MAX_INDEX_POINTER_BYTES, blob_path, body_path,
    ensure_sha256, publisher_report, sha256_hex, verify_body,
};
use crate::util::{COMPRESS_MIN_BYTES, metadata_nofollow, temp_nonce};

/// How a blob's stored bytes relate to the decoded file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Compression {
    Gzip,
    #[serde(rename = "none")]
    Raw,
}

impl Compression {
    pub fn as_str(self) -> &'static str {
        match self {
            Compression::Gzip => "gzip",
            Compression::Raw => "none",
        }
    }
}

/// One immutable CAS object plus the decoded facts the index records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRef {
    /// SHA-256 of the stored bytes; the object key is `blobs/<blob>`.
    pub blob: String,
    pub blob_size: u64,
    /// SHA-256 and size of the decoded bytes.
    pub sha256: String,
    pub size: u64,
    pub compression: Compression,
}

/// Store one file in the CAS, compressing when it wins. A missing blob is
/// created atomically; an existing blob is verified and never overwritten.
pub fn write_blob(src: &Path, root: &Path) -> Result<BlobRef> {
    let meta = match metadata_nofollow(src) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            bail!(
                "{} is a symlink/reparse point or not a regular file",
                src.display()
            );
        }
        Err(err) => return Err(err).with_context(|| format!("inspecting {}", src.display())),
    };
    if !meta.is_file() {
        bail!("{} is not a regular file", src.display());
    }
    if !crate::util::owned_by_us(src, &meta) {
        bail!(
            "{} is owned by another user — refusing to publish it",
            src.display()
        );
    }
    if meta.len() > MAX_BLOB_BYTES {
        bail!(
            "{} is {} bytes (cap {MAX_BLOB_BYTES})",
            src.display(),
            meta.len()
        );
    }

    let blobs = root.join(super::BLOBS_DIR);
    crate::util::create_private_dir_all(&blobs)?;

    let (stored_path, blob, blob_size, sha256, size, compression) =
        if meta.len() >= COMPRESS_MIN_BYTES {
            match compress_blob(src, &blobs)? {
                Some(compressed) => compressed,
                None => raw_blob(src, &blobs)?,
            }
        } else {
            raw_blob(src, &blobs)?
        };

    let final_path = blob_path(root, &blob)?;
    install_put_if_absent(&stored_path, &final_path, &blob, blob_size)?;
    Ok(BlobRef {
        blob,
        blob_size,
        sha256,
        size,
        compression,
    })
}

type StoredBlob = (PathBuf, String, u64, String, u64, Compression);

fn compress_blob(src: &Path, blobs: &Path) -> Result<Option<StoredBlob>> {
    use flate2::Compression as GzipLevel;
    use flate2::write::GzEncoder;

    let tmp = blobs.join(format!(".tmp-{}-{}.gz", std::process::id(), temp_nonce()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    let mut encoder = GzEncoder::new(file, GzipLevel::fast());
    let mut input = open_nofollow(src)?;
    let mut decoded = Sha256Writer::new();
    let mut buf = [0u8; 64 * 1024];
    let result = (|| -> Result<()> {
        loop {
            let n = input.read(&mut buf)?;
            if n == 0 {
                break;
            }
            decoded.update(&buf[..n]);
            if decoded.size > MAX_BLOB_BYTES {
                bail!("compressed source exceeds the maximum artifact size");
            }
            encoder.write_all(&buf[..n])?;
        }
        encoder.finish()?.sync_all()?;
        Ok(())
    })();
    if let Err(err) = result {
        let _ = fs::remove_file(&tmp);
        return Err(err).with_context(|| format!("compressing {}", src.display()));
    }
    let (size, sha256) = decoded.finish();
    let blob_size = fs::metadata(&tmp)?.len();
    if blob_size >= size {
        let _ = fs::remove_file(&tmp);
        return Ok(None);
    }
    let blob = crate::util::sha256_file(&tmp)?;
    Ok(Some((
        tmp,
        blob,
        blob_size,
        sha256,
        size,
        Compression::Gzip,
    )))
}

fn raw_blob(src: &Path, blobs: &Path) -> Result<StoredBlob> {
    let tmp = blobs.join(format!(".tmp-{}-{}", std::process::id(), temp_nonce()));
    let mut input = open_nofollow(src)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    let mut hasher = Sha256Writer::new();
    let mut buf = [0u8; 64 * 1024];
    let result = (|| -> Result<()> {
        loop {
            let n = input.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            if hasher.size > MAX_BLOB_BYTES {
                bail!("source exceeds the maximum artifact size");
            }
            output.write_all(&buf[..n])?;
        }
        output.sync_all()?;
        Ok(())
    })();
    if let Err(err) = result {
        let _ = fs::remove_file(&tmp);
        return Err(err).with_context(|| format!("copying {}", src.display()));
    }
    drop(output);
    let (size, sha256) = hasher.finish();
    let blob = crate::util::sha256_file(&tmp)?;
    Ok((tmp, blob, size, sha256, size, Compression::Raw))
}

fn install_put_if_absent(
    tmp: &Path,
    final_path: &Path,
    expected_blob: &str,
    expected_size: u64,
) -> Result<()> {
    match metadata_nofollow(final_path) {
        Ok(meta) if meta.is_file() => {
            if meta.len() != expected_size || crate::util::sha256_file(final_path)? != expected_blob
            {
                let _ = fs::remove_file(tmp);
                bail!(
                    "CAS object {} already exists with different bytes; refusing to overwrite",
                    final_path.display()
                );
            }
            let _ = fs::remove_file(tmp);
            Ok(())
        }
        Ok(_) => {
            let _ = fs::remove_file(tmp);
            bail!("CAS object {} is not a regular file", final_path.display());
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // Hard-link is atomic and put-if-absent: unlike rename on Unix it
            // cannot replace a blob created by a racing writer.
            match fs::hard_link(tmp, final_path) {
                Ok(()) => {
                    let _ = fs::remove_file(tmp);
                    Ok(())
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    let _ = fs::remove_file(tmp);
                    verify_blob_file(final_path, expected_blob, expected_size)
                }
                Err(err) => {
                    let _ = fs::remove_file(tmp);
                    Err(err).with_context(|| format!("installing {}", final_path.display()))
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            let _ = fs::remove_file(tmp);
            bail!(
                "CAS object {} is a symlink/reparse point",
                final_path.display()
            );
        }
        Err(err) => {
            let _ = fs::remove_file(tmp);
            Err(err).with_context(|| format!("inspecting {}", final_path.display()))
        }
    }
}

fn verify_blob_file(path: &Path, expected_blob: &str, expected_size: u64) -> Result<()> {
    let meta = metadata_nofollow(path)?;
    if !meta.is_file() || meta.len() != expected_size {
        bail!("CAS object {} has the wrong size", path.display());
    }
    if crate::util::sha256_file(path)? != expected_blob {
        bail!("CAS object {} failed its SHA-256 check", path.display());
    }
    Ok(())
}

/// Verify the stored object without decoding it.
pub fn verify_blob(root: &Path, blob: &BlobRef) -> Result<()> {
    ensure_sha256(&blob.blob, "blob SHA-256")?;
    ensure_sha256(&blob.sha256, "decoded SHA-256")?;
    if blob.blob_size > MAX_BLOB_BYTES || blob.size > MAX_BLOB_BYTES {
        bail!("blob exceeds the maximum artifact size");
    }
    verify_blob_file(&blob_path(root, &blob.blob)?, &blob.blob, blob.blob_size)
}

/// Verify and decode one blob. This buffers the decoded bytes; the reader's
/// streaming import path is added with the exec integration.
pub fn read_blob(root: &Path, blob: &BlobRef) -> Result<Vec<u8>> {
    verify_blob(root, blob)?;
    let path = blob_path(root, &blob.blob)?;
    let input = open_nofollow(&path)?;
    let mut bytes = Vec::with_capacity(blob.size.min(8 * 1024 * 1024) as usize);
    match blob.compression {
        Compression::Raw => {
            input
                .take(MAX_BLOB_BYTES + 1)
                .read_to_end(&mut bytes)
                .with_context(|| format!("reading {}", path.display()))?;
        }
        Compression::Gzip => {
            let mut decoder = flate2::read::GzDecoder::new(input);
            let mut limited = std::io::Read::take(&mut decoder, MAX_BLOB_BYTES + 1);
            limited
                .read_to_end(&mut bytes)
                .with_context(|| format!("decompressing {}", path.display()))?;
        }
    }
    if bytes.len() as u64 != blob.size {
        bail!(
            "decoded blob {} is {} bytes, expected {}",
            path.display(),
            bytes.len(),
            blob.size
        );
    }
    if sha256_hex(&bytes) != blob.sha256 {
        bail!("decoded blob {} failed its SHA-256 check", path.display());
    }
    Ok(bytes)
}

fn open_nofollow(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    Ok(file)
}

/// One object the publisher must upload.
pub struct Upload {
    /// Relative object key (`blobs/<sha>`, `indexes/<sha>.json`, ...).
    pub key: String,
    /// Local source path.
    pub source: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub mode: UploadMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadMode {
    /// Never replace an existing object; the remote must already match.
    PutIfAbsent,
    /// Replace atomically; only the pointer and the human-readable report.
    Replace,
}

/// Plan the upload for a verified index tree. Blobs and the body are
/// put-if-absent; `publisher.json` and the signed pointer are replaced last.
pub fn upload_plan(
    root: &Path,
    pointer: &super::IndexPointer,
    body_bytes: &[u8],
) -> Result<Vec<Upload>> {
    let body = verify_body(pointer, body_bytes, super::now_secs())?;
    if body_bytes.len() as u64 > MAX_INDEX_BODY_BYTES {
        bail!("index body exceeds the upload cap");
    }
    let mut uploads = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for unit in &body.units {
        for file in &unit.files {
            if !seen.insert(file.blob.clone()) {
                continue;
            }
            let path = blob_path(root, &file.blob)?;
            verify_blob_file(&path, &file.blob, file.blob_size)?;
            uploads.push(Upload {
                key: super::blob_key(&file.blob)?,
                source: path,
                sha256: file.blob.clone(),
                size: file.blob_size,
                mode: UploadMode::PutIfAbsent,
            });
        }
    }
    uploads.sort_by(|left, right| left.key.cmp(&right.key));

    let body_path = body_path(root, &pointer.body_sha256)?;
    let body_meta = metadata_nofollow(&body_path)
        .with_context(|| format!("inspecting {}", body_path.display()))?;
    if body_meta.len() != pointer.body_size || body_meta.len() != body_bytes.len() as u64 {
        bail!("index body file no longer matches the signed pointer");
    }
    if crate::util::sha256_file(&body_path)? != pointer.body_sha256 {
        bail!("index body file no longer matches the signed hash");
    }
    uploads.push(Upload {
        key: super::body_key(&pointer.body_sha256)?,
        source: body_path,
        sha256: pointer.body_sha256.clone(),
        size: body_meta.len(),
        mode: UploadMode::PutIfAbsent,
    });

    let report = publisher_report(pointer, &body)?;
    let report_path = root.join(super::PUBLISHER_FILE);
    let report_meta = metadata_nofollow(&report_path)
        .with_context(|| format!("inspecting {}", report_path.display()))?;
    if report_meta.len() != report.len() as u64
        || crate::util::sha256_file(&report_path)? != sha256_hex(&report)
    {
        bail!("publisher report file no longer matches its bytes");
    }
    uploads.push(Upload {
        key: super::PUBLISHER_FILE.to_string(),
        source: report_path,
        sha256: sha256_hex(&report),
        size: report_meta.len(),
        mode: UploadMode::Replace,
    });

    let pointer_bytes = serde_json::to_vec(pointer)?;
    if pointer_bytes.len() as u64 > MAX_INDEX_POINTER_BYTES {
        bail!("index pointer exceeds the upload cap");
    }
    let pointer_path = root.join(super::INDEX_FILE);
    let pointer_meta = metadata_nofollow(&pointer_path)
        .with_context(|| format!("inspecting {}", pointer_path.display()))?;
    if pointer_meta.len() != pointer_bytes.len() as u64
        || crate::util::sha256_file(&pointer_path)? != sha256_hex(&pointer_bytes)
    {
        bail!("index pointer file no longer matches its bytes");
    }
    uploads.push(Upload {
        key: super::INDEX_FILE.to_string(),
        source: pointer_path,
        sha256: sha256_hex(&pointer_bytes),
        size: pointer_meta.len(),
        mode: UploadMode::Replace,
    });
    Ok(uploads)
}

struct Sha256Writer {
    hasher: sha2::Sha256,
    size: u64,
}

impl Sha256Writer {
    fn new() -> Self {
        use sha2::Digest;
        Self {
            hasher: sha2::Sha256::new(),
            size: 0,
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        use sha2::Digest;
        self.hasher.update(bytes);
        self.size += bytes.len() as u64;
    }

    fn finish(self) -> (u64, String) {
        use sha2::Digest;
        (self.size, crate::vault::hex_encode(&self.hasher.finalize()))
    }
}
