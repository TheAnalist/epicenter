//! AWS credential loading.
//!
//! 0.1.0 supports the environment and a standard shared-credentials profile.
//! IMDS/ECS metadata is deliberately absent: it adds SSRF and credential-theft
//! surface for no CI benefit.

use anyhow::{Context, Result, bail, ensure};
use std::fmt;
use std::path::{Path, PathBuf};

/// A string whose `Debug` representation never reveals its contents.
#[derive(Clone)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Debug, Clone)]
pub enum CredentialSource {
    Environment,
    Profile { path: PathBuf, profile: String },
}

#[derive(Debug, Clone)]
pub struct Credentials {
    access_key: SecretString,
    secret_key: SecretString,
    session_token: Option<SecretString>,
    source: CredentialSource,
}

impl Credentials {
    pub fn load() -> Result<Self> {
        let access = env_value("AWS_ACCESS_KEY_ID");
        let secret = env_value("AWS_SECRET_ACCESS_KEY");
        let token = env_value("AWS_SESSION_TOKEN").filter(|value| !value.is_empty());
        match (access, secret) {
            (Some(access), Some(secret)) => {
                validate_access_key(&access)?;
                return Ok(Self {
                    access_key: SecretString::new(access),
                    secret_key: SecretString::new(secret),
                    session_token: token.map(SecretString::new),
                    source: CredentialSource::Environment,
                });
            }
            (None, None) => {}
            _ => bail!("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set together"),
        }

        let profile = env_value("AWS_PROFILE")
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "default".to_string());
        validate_profile_name(&profile)?;
        let path = match env_value("AWS_SHARED_CREDENTIALS_FILE") {
            Some(path) => PathBuf::from(path),
            None => crate::paths::home()?.join(".aws/credentials"),
        };
        Self::from_profile(&path, &profile)
    }

    pub fn from_profile(path: &Path, profile: &str) -> Result<Self> {
        validate_profile_name(profile)?;
        let text = crate::util::read_private_text(path, 256 * 1024).with_context(|| {
            format!(
                "reading AWS credentials {} (must be a regular, owner-only file; \
                 chmod 600 or export the keys in the environment)",
                path.display()
            )
        })?;
        let mut current = String::new();
        let mut values = std::collections::HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some(name) = line
                .strip_prefix('[')
                .and_then(|line| line.strip_suffix(']'))
            {
                current = name.trim().to_string();
                continue;
            }
            if current != profile {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            values.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
        let access = values
            .remove("aws_access_key_id")
            .filter(|value| !value.is_empty())
            .with_context(|| format!("AWS profile {profile:?} has no aws_access_key_id"))?;
        let secret = values
            .remove("aws_secret_access_key")
            .filter(|value| !value.is_empty())
            .with_context(|| format!("AWS profile {profile:?} has no aws_secret_access_key"))?;
        validate_access_key(&access)?;
        Ok(Self {
            access_key: SecretString::new(access),
            secret_key: SecretString::new(secret),
            session_token: values
                .remove("aws_session_token")
                .filter(|value| !value.is_empty())
                .map(SecretString::new),
            source: CredentialSource::Profile {
                path: path.to_path_buf(),
                profile: profile.to_string(),
            },
        })
    }

    /// Test-only constructor; production code goes through the environment or
    /// a shared profile.
    #[cfg(test)]
    pub(crate) fn from_parts(access: &str, secret: &str, token: Option<&str>) -> Self {
        Self {
            access_key: SecretString::new(access),
            secret_key: SecretString::new(secret),
            session_token: token.map(SecretString::new),
            source: CredentialSource::Environment,
        }
    }

    pub fn access_key(&self) -> &SecretString {
        &self.access_key
    }

    pub fn secret_key(&self) -> &SecretString {
        &self.secret_key
    }

    pub fn session_token(&self) -> Option<&SecretString> {
        self.session_token.as_ref()
    }

    pub fn source(&self) -> &CredentialSource {
        &self.source
    }
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn validate_access_key(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 256
            && !value
                .chars()
                .any(|ch| ch.is_control() || ch.is_whitespace()),
        "AWS access key id is malformed"
    );
    Ok(())
}

fn validate_profile_name(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 128
            && !value
                .chars()
                .any(|ch| ch.is_control() || ch.is_whitespace()),
        "AWS profile name is malformed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_secrets() {
        let credentials = Credentials::from_parts("AKIDEXAMPLE", "TOPSECRET", Some("SESSIONTOKEN"));
        let text = format!("{credentials:?}");
        assert!(!text.contains("TOPSECRET"));
        assert!(!text.contains("SESSIONTOKEN"));
        assert!(!credentials.access_key().expose().to_string().is_empty());
    }
}
