//! Publisher upload orchestration: parallel immutable objects, then the
//! pointer last with a conditional write.

use anyhow::{Result, ensure};
use rayon::prelude::*;

use super::sink::{Precondition, PutStatus, RemoteSink};
use super::{INDEX_FILE, IndexPointer, MAX_INDEX_POINTER_BYTES, Upload, UploadKind, sha256_hex};

/// A remote index plus the ETag needed for a conditional pointer replace.
#[derive(Debug, Clone)]
pub struct RemotePointer {
    pub pointer: IndexPointer,
    pub etag: Option<String>,
}

pub struct UploadRequest<'a> {
    pub sink: &'a dyn RemoteSink,
    pub uploads: &'a [Upload],
    pub current: Option<&'a RemotePointer>,
}

#[derive(Debug, Default)]
pub struct UploadReport {
    pub uploaded: usize,
    pub skipped: usize,
    pub bytes: u64,
    pub pointer_etag: Option<String>,
}

pub fn upload(request: &UploadRequest<'_>) -> Result<UploadReport> {
    validate_order(request.uploads)?;
    let (blobs, ordered): (Vec<&Upload>, Vec<&Upload>) = request
        .uploads
        .iter()
        .partition(|upload| upload.kind == UploadKind::Blob);

    let workers = crate::settings::copy_workers();
    let blob_results: Vec<Result<UploadReport>> = if blobs.len() <= 1 || workers <= 1 {
        blobs
            .iter()
            .map(|upload| put_one(request.sink, upload, Precondition::IfAbsent))
            .collect()
    } else {
        crate::settings::copy_pool().install(|| {
            blobs
                .par_iter()
                .map(|upload| put_one(request.sink, upload, Precondition::IfAbsent))
                .collect()
        })
    };
    let mut report = UploadReport::default();
    for result in blob_results {
        merge(&mut report, result?);
    }

    for upload in ordered {
        let precondition = match upload.kind {
            UploadKind::Body => Precondition::IfAbsent,
            UploadKind::Publisher => Precondition::None,
            UploadKind::Pointer => request
                .current
                .and_then(|current| current.etag.clone())
                .map(Precondition::IfMatch)
                .unwrap_or(Precondition::IfAbsent),
            UploadKind::Blob => unreachable!("blobs are handled above"),
        };
        let mut result = put_one(request.sink, upload, precondition)?;
        if upload.kind == UploadKind::Pointer {
            verify_pointer(request.sink, upload)?;
            report.pointer_etag = result.pointer_etag.take();
        }
        merge(&mut report, result);
    }
    Ok(report)
}

fn put_one(
    sink: &dyn RemoteSink,
    upload: &Upload,
    precondition: Precondition,
) -> Result<UploadReport> {
    let outcome = sink.put(upload, precondition)?;
    Ok(match outcome.status {
        PutStatus::AlreadyExists => UploadReport {
            uploaded: 0,
            skipped: 1,
            bytes: 0,
            pointer_etag: (upload.kind == UploadKind::Pointer)
                .then_some(outcome.etag)
                .flatten(),
        },
        PutStatus::Created | PutStatus::Replaced => UploadReport {
            uploaded: 1,
            skipped: 0,
            bytes: upload.size,
            pointer_etag: (upload.kind == UploadKind::Pointer)
                .then_some(outcome.etag)
                .flatten(),
        },
    })
}

fn verify_pointer(sink: &dyn RemoteSink, upload: &Upload) -> Result<()> {
    // The staged pointer was already hashed into `upload.sha256` when the plan
    // was built. Comparing the remote hash avoids re-opening a local path at
    // the trust boundary.
    let bytes = sink.get(INDEX_FILE, MAX_INDEX_POINTER_BYTES)?;
    ensure!(
        sha256_hex(&bytes) == upload.sha256,
        "the uploaded index pointer does not match the staged bytes"
    );
    Ok(())
}

fn merge(report: &mut UploadReport, other: UploadReport) {
    report.uploaded += other.uploaded;
    report.skipped += other.skipped;
    report.bytes = report.bytes.saturating_add(other.bytes);
    if other.pointer_etag.is_some() {
        report.pointer_etag = other.pointer_etag;
    }
}

/// Ensure the upload plan has exactly one pointer and ends with it.
pub fn validate_order(uploads: &[Upload]) -> Result<()> {
    let pointers: Vec<&Upload> = uploads
        .iter()
        .filter(|upload| upload.kind == UploadKind::Pointer)
        .collect();
    ensure!(
        pointers.len() == 1,
        "upload plan must contain one index pointer"
    );
    ensure!(
        uploads
            .last()
            .is_some_and(|upload| upload.kind == UploadKind::Pointer),
        "the index pointer must be the last upload"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::sink::{ObjectMeta, PutOutcome, RemoteSink};
    use crate::remote::{UploadMode, sha256_hex};
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MemorySink {
        objects: Mutex<HashMap<String, Vec<u8>>>,
        order: Mutex<Vec<String>>,
        preconditions: Mutex<HashMap<String, Precondition>>,
    }

    impl MemorySink {
        fn new() -> Self {
            Self {
                objects: Mutex::new(HashMap::new()),
                order: Mutex::new(Vec::new()),
                preconditions: Mutex::new(HashMap::new()),
            }
        }
    }

    impl RemoteSink for MemorySink {
        fn head(&self, key: &str) -> anyhow::Result<Option<ObjectMeta>> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .get(key)
                .map(|bytes| ObjectMeta {
                    size: bytes.len() as u64,
                    etag: Some("etag".into()),
                    checksum_sha256: None,
                }))
        }

        fn get(&self, key: &str, _max_bytes: u64) -> anyhow::Result<Vec<u8>> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .unwrap_or_default())
        }

        fn put(&self, upload: &Upload, precondition: Precondition) -> anyhow::Result<PutOutcome> {
            self.order.lock().unwrap().push(upload.key.clone());
            self.preconditions
                .lock()
                .unwrap()
                .insert(upload.key.clone(), precondition);
            let bytes = std::fs::read(&upload.source)?;
            self.objects
                .lock()
                .unwrap()
                .insert(upload.key.clone(), bytes);
            Ok(PutOutcome {
                status: PutStatus::Created,
                etag: Some("etag".into()),
                size: upload.size,
            })
        }
    }

    fn upload_file(dir: &std::path::Path, name: &str, bytes: &[u8]) -> Upload {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, bytes).unwrap();
        Upload {
            key: name.to_string(),
            source: path,
            sha256: sha256_hex(bytes),
            size: bytes.len() as u64,
            mode: UploadMode::PutIfAbsent,
            kind: UploadKind::Body,
        }
    }

    #[test]
    fn uploads_the_pointer_last_and_verifies_it() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let sink = MemorySink::new();
        let body = upload_file(dir.path(), "indexes/body.json", b"body");
        let mut publisher = upload_file(dir.path(), "publisher.json", b"publisher");
        publisher.kind = UploadKind::Publisher;
        let mut pointer = upload_file(dir.path(), INDEX_FILE, b"pointer");
        pointer.kind = UploadKind::Pointer;
        let uploads = vec![body, publisher, pointer];
        let report = upload(&UploadRequest {
            sink: &sink,
            uploads: &uploads,
            current: None,
        })?;
        assert_eq!(report.uploaded, 3);
        assert_eq!(
            *sink.order.lock().unwrap(),
            vec![
                "indexes/body.json".to_string(),
                "publisher.json".to_string(),
                INDEX_FILE.to_string()
            ]
        );
        assert_eq!(
            sink.preconditions.lock().unwrap().get(INDEX_FILE),
            Some(&Precondition::IfAbsent)
        );
        Ok(())
    }
}
