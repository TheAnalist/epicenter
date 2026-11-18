//! Immutable content-addressed blobs and upload planning.
//!
//! A blob is named by the SHA-256 of its **stored** bytes, so a reader can
//! verify the object before decompressing it. The index also records the
//! decoded hash and size, so a valid gzip envelope around the wrong payload
//! is still rejected. Uploads are put-if-absent: a published blob is never
//! replaced.

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use super::{
    MAX_BLOB_BYTES, SignedIndex, blob_path, body_path, ensure_sha256, publisher_report, sha256_hex,
};
use crate::util::{COMPRESS_MIN_BYTES, metadata_nofollow};

const MAX_OBJECT_KEY_BYTES: usize = 4096;

/// How a blob's stored bytes relate to the decoded file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Compression {
    Gzip,
    #[serde(rename = "none")]
    Raw,
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
    let Some(meta) = crate::util::probe(src, "blob source")? else {
        bail!(
            "{} is a symlink/reparse point or not a regular file",
            src.display()
        );
    };
    ensure!(meta.is_file(), "{} is not a regular file", src.display());
    ensure!(
        crate::util::owned_by_us(src, &meta),
        "{} is owned by another user — refusing to publish it",
        src.display()
    );
    ensure!(
        meta.len() <= MAX_BLOB_BYTES,
        "{} is {} bytes (cap {MAX_BLOB_BYTES})",
        src.display(),
        meta.len()
    );

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

    let (tmp, file) = crate::util::create_temp(blobs, "tmp", ".gz", 0o600)?;
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
            ensure!(
                decoded.size <= MAX_BLOB_BYTES,
                "compressed source exceeds the maximum artifact size"
            );
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
    let mut input = open_nofollow(src)?;
    let (tmp, mut output) = crate::util::create_temp(blobs, "tmp", "", 0o600)?;
    let mut hasher = Sha256Writer::new();
    let mut buf = [0u8; 64 * 1024];
    let result = (|| -> Result<()> {
        loop {
            let n = input.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            ensure!(
                hasher.size <= MAX_BLOB_BYTES,
                "source exceeds the maximum artifact size"
            );
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

pub(crate) fn install_put_if_absent(
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
    ensure!(
        meta.is_file() && meta.len() == expected_size,
        "CAS object {} has the wrong size",
        path.display()
    );
    ensure!(
        crate::util::sha256_file(path)? == expected_blob,
        "CAS object {} failed its SHA-256 check",
        path.display()
    );
    Ok(())
}

/// Verify the stored object without decoding it.
pub fn verify_blob(root: &Path, blob: &BlobRef) -> Result<()> {
    ensure_sha256(&blob.blob, "blob SHA-256")?;
    ensure_sha256(&blob.sha256, "decoded SHA-256")?;
    ensure!(
        blob.blob_size <= MAX_BLOB_BYTES && blob.size <= MAX_BLOB_BYTES,
        "blob exceeds the maximum artifact size"
    );
    verify_blob_file(&blob_path(root, &blob.blob)?, &blob.blob, blob.blob_size)
}

/// Large blobs must be streamed; this is the in-memory convenience cap.
pub const MAX_IN_MEMORY_BLOB_BYTES: u64 = 64 * 1024 * 1024;

/// Verify and stream one blob into a writer. The decoded size is capped by the
/// signed `blob.size`, so a gzip bomb cannot expand past the expected artifact
/// size, and both the stored and decoded SHA-256 are checked.
pub fn decode_blob<W: Write>(root: &Path, blob: &BlobRef, writer: &mut W) -> Result<()> {
    verify_blob(root, blob)?;
    let path = blob_path(root, &blob.blob)?;
    let input = open_nofollow(&path)?;
    let mut reader: Box<dyn Read> = match blob.compression {
        Compression::Raw => Box::new(input),
        Compression::Gzip => Box::new(flate2::read::GzDecoder::new(input)),
    };

    crate::util::copy_verified(&mut reader, writer, blob.size, &blob.sha256, &path)
}

/// Buffer a small blob. Artifacts above [`MAX_IN_MEMORY_BLOB_BYTES`] must use
/// [`decode_blob`] so a large import cannot exhaust memory.
pub fn read_blob(root: &Path, blob: &BlobRef) -> Result<Vec<u8>> {
    ensure!(
        blob.size <= MAX_IN_MEMORY_BLOB_BYTES,
        "blob {} is {} bytes; use decode_blob() to stream it",
        blob.blob,
        blob.size
    );
    let mut bytes = Vec::with_capacity(blob.size as usize);
    decode_blob(root, blob, &mut bytes)?;
    Ok(bytes)
}

fn open_nofollow(path: &Path) -> Result<File> {
    crate::util::open_regular(path, false).with_context(|| format!("opening {}", path.display()))
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

/// Plan the upload for a signed index tree. Blobs and the body are
/// put-if-absent; `publisher.json` and the signed pointer are replaced last.
pub fn upload_plan(root: &Path, index: &SignedIndex) -> Result<Vec<Upload>> {
    let pointer = index.pointer();
    let mut uploads = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for file in index.body().units.iter().flat_map(|unit| &unit.files) {
        if !seen.insert(file.blob.as_str()) {
            continue;
        }
        uploads.push(upload_source(
            super::blob_key(&file.blob)?,
            blob_path(root, &file.blob)?,
            &file.blob,
            file.blob_size,
            UploadMode::PutIfAbsent,
        )?);
    }
    uploads.sort_by(|left, right| left.key.cmp(&right.key));

    uploads.push(upload_source(
        super::body_key(&pointer.body_sha256)?,
        body_path(root, &pointer.body_sha256)?,
        &pointer.body_sha256,
        pointer.body_size,
        UploadMode::PutIfAbsent,
    )?);

    let report = publisher_report(index)?;
    uploads.push(upload_source(
        super::PUBLISHER_FILE.to_string(),
        root.join(super::PUBLISHER_FILE),
        &sha256_hex(&report),
        report.len() as u64,
        UploadMode::Replace,
    )?);

    let pointer_bytes = index.pointer_bytes()?;
    uploads.push(upload_source(
        super::INDEX_FILE.to_string(),
        root.join(super::INDEX_FILE),
        &sha256_hex(&pointer_bytes),
        pointer_bytes.len() as u64,
        UploadMode::Replace,
    )?);
    Ok(uploads)
}

fn upload_source(
    key: String,
    source: PathBuf,
    expected_sha256: &str,
    expected_size: u64,
    mode: UploadMode,
) -> Result<Upload> {
    super::validate::relative_path(&key, "upload object key", MAX_OBJECT_KEY_BYTES)?;
    let meta =
        metadata_nofollow(&source).with_context(|| format!("inspecting {}", source.display()))?;
    ensure!(
        meta.is_file() && meta.len() == expected_size,
        "upload source {} changed size or is not a regular file",
        source.display()
    );
    ensure!(
        crate::util::sha256_file(&source)? == expected_sha256,
        "upload source {} no longer matches its SHA-256",
        source.display()
    );
    Ok(Upload {
        key,
        source,
        sha256: expected_sha256.to_string(),
        size: expected_size,
        mode,
    })
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
