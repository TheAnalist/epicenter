//! Anonymous HTTPS reader source.

use anyhow::{Result, bail};
use std::io::Write;

use super::http::{HttpClient, HttpRequest, Method};
use super::{Endpoint, HttpsEndpoint, TransportConfig};
use crate::remote::{FetchedPointer, MAX_INDEX_BODY_BYTES, MAX_INDEX_POINTER_BYTES, RemoteSource};

pub struct HttpsSource {
    client: HttpClient,
    endpoint: HttpsEndpoint,
}

impl HttpsSource {
    pub fn new(config: &TransportConfig) -> Result<Self> {
        let Endpoint::Https(endpoint) = &config.endpoint else {
            bail!("HTTPS source requires an https:// endpoint");
        };
        Ok(Self {
            client: HttpClient::new(config)?,
            endpoint: endpoint.clone(),
        })
    }

    fn get(&self, key: &str, max_bytes: u64) -> Result<Vec<u8>, super::TransportError> {
        let url = self.endpoint.url_for(key).map_err(|err| {
            super::TransportError::new(super::ErrorKind::Config, format!("{err:#}"))
        })?;
        let request = HttpRequest::new(Method::Get, url);
        let response = self.client.execute(&request)?;
        response.ensure_success("HTTPS GET")?.read_vec(max_bytes)
    }

    fn get_with_etag(
        &self,
        key: &str,
        max_bytes: u64,
    ) -> Result<FetchedPointer, super::TransportError> {
        let url = self.endpoint.url_for(key).map_err(|err| {
            super::TransportError::new(super::ErrorKind::Config, format!("{err:#}"))
        })?;
        let request = HttpRequest::new(Method::Get, url);
        let response = self.client.execute(&request)?;
        let response = response.ensure_success("HTTPS GET")?;
        let etag = response.header("etag").map(str::to_string);
        let bytes = response.read_vec(max_bytes)?;
        Ok(FetchedPointer { bytes, etag })
    }
}

impl RemoteSource for HttpsSource {
    fn fetch_pointer(&self) -> Result<Vec<u8>> {
        self.get(crate::remote::INDEX_FILE, MAX_INDEX_POINTER_BYTES)
            .map_err(anyhow::Error::new)
    }

    fn fetch_pointer_optional(&self) -> Result<Option<FetchedPointer>> {
        match self.get_with_etag(crate::remote::INDEX_FILE, MAX_INDEX_POINTER_BYTES) {
            Ok(pointer) => Ok(Some(pointer)),
            Err(err) if err.is_miss() => Ok(None),
            Err(err) => Err(anyhow::Error::new(err)),
        }
    }

    fn fetch_body(&self, sha256: &str, max_bytes: u64) -> Result<Vec<u8>> {
        self.get(
            &format!("indexes/{sha256}.json"),
            max_bytes.min(MAX_INDEX_BODY_BYTES),
        )
        .map_err(anyhow::Error::new)
    }

    fn fetch_blob(&self, sha256: &str, max_bytes: u64, out: &mut dyn Write) -> Result<()> {
        let url = self
            .endpoint
            .url_for(&format!("blobs/{sha256}"))
            .map_err(|err| {
                super::TransportError::new(super::ErrorKind::Config, format!("{err:#}"))
            })?;
        let request = HttpRequest::new(Method::Get, url);
        let response = self.client.execute(&request)?;
        response
            .ensure_success("HTTPS blob GET")?
            .copy_to(out, max_bytes)?;
        Ok(())
    }
}
