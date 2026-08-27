use std::sync::{Arc, Mutex};

use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
pub struct OAuthTokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at_unix: Option<u64>,
}

impl OAuthTokenSet {
    pub fn is_expired(&self) -> bool {
        self.expires_at_unix
            .map(|expires| expires <= now_unix().saturating_add(30))
            .unwrap_or(false)
    }
}

impl std::fmt::Debug for OAuthTokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthTokenSet")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

impl Drop for OAuthTokenSet {
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(token) = &mut self.refresh_token {
            token.zeroize();
        }
    }
}

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("credential store unavailable")]
    Unavailable,
    #[error("credential not found")]
    NotFound,
    #[error("credential data is invalid")]
    Invalid,
}

#[derive(Serialize, Deserialize)]
struct StoredCredential {
    access_key: String,
    secret_key: String,
    session_token: Option<String>,
}

impl Drop for StoredCredential {
    fn drop(&mut self) {
        self.access_key.zeroize();
        self.secret_key.zeroize();
        if let Some(token) = &mut self.session_token {
            token.zeroize();
        }
    }
}

pub struct CredentialSet {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
}

impl std::fmt::Debug for CredentialSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialSet")
            .field("access_key", &"<redacted>")
            .field("secret_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl Drop for CredentialSet {
    fn drop(&mut self) {
        self.access_key.zeroize();
        self.secret_key.zeroize();
        if let Some(token) = &mut self.session_token {
            token.zeroize();
        }
    }
}

impl CredentialSet {
    fn to_stored(&self) -> StoredCredential {
        StoredCredential {
            access_key: self.access_key.clone(),
            secret_key: self.secret_key.clone(),
            session_token: self.session_token.clone(),
        }
    }

    fn from_stored(mut stored: StoredCredential) -> Self {
        Self {
            access_key: std::mem::take(&mut stored.access_key),
            secret_key: std::mem::take(&mut stored.secret_key),
            session_token: stored.session_token.take(),
        }
    }
}

pub trait CredentialStore: Send + Sync {
    fn put(&self, reference: &str, credentials: CredentialSet) -> Result<(), CredentialError>;
    fn get(&self, reference: &str) -> Result<CredentialSet, CredentialError>;
    fn delete(&self, reference: &str) -> Result<(), CredentialError>;
    fn put_oauth(&self, reference: &str, tokens: OAuthTokenSet) -> Result<(), CredentialError>;
    fn get_oauth(&self, reference: &str) -> Result<OAuthTokenSet, CredentialError>;
    fn delete_oauth(&self, reference: &str) -> Result<(), CredentialError>;
}

#[derive(Clone, Default)]
pub struct InMemoryCredentialStore {
    entries: Arc<Mutex<std::collections::HashMap<String, StoredCredential>>>,
    oauth_entries: Arc<Mutex<std::collections::HashMap<String, OAuthTokenSet>>>,
}

impl InMemoryCredentialStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CredentialStore for InMemoryCredentialStore {
    #[tracing::instrument(skip_all, fields(subsystem = "credentials", operation = "put"))]
    fn put(&self, reference: &str, credentials: CredentialSet) -> Result<(), CredentialError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| CredentialError::Unavailable)?;
        entries.insert(reference.to_owned(), credentials.to_stored());
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(subsystem = "credentials", operation = "get"))]
    fn get(&self, reference: &str) -> Result<CredentialSet, CredentialError> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| CredentialError::Unavailable)?;
        entries
            .get(reference)
            .map(|stored| CredentialSet {
                access_key: stored.access_key.clone(),
                secret_key: stored.secret_key.clone(),
                session_token: stored.session_token.clone(),
            })
            .ok_or(CredentialError::NotFound)
    }

    #[tracing::instrument(skip_all, fields(subsystem = "credentials", operation = "delete"))]
    fn delete(&self, reference: &str) -> Result<(), CredentialError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| CredentialError::Unavailable)?;
        entries
            .remove(reference)
            .ok_or(CredentialError::NotFound)
            .map(|_| ())
    }

    #[tracing::instrument(skip_all, fields(subsystem = "credentials", operation = "put_oauth"))]
    fn put_oauth(&self, reference: &str, tokens: OAuthTokenSet) -> Result<(), CredentialError> {
        self.oauth_entries
            .lock()
            .map_err(|_| CredentialError::Unavailable)?
            .insert(reference.to_owned(), tokens);
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(subsystem = "credentials", operation = "get_oauth"))]
    fn get_oauth(&self, reference: &str) -> Result<OAuthTokenSet, CredentialError> {
        let entries = self
            .oauth_entries
            .lock()
            .map_err(|_| CredentialError::Unavailable)?;
        entries
            .get(reference)
            .map(|tokens| OAuthTokenSet {
                access_token: tokens.access_token.clone(),
                refresh_token: tokens.refresh_token.clone(),
                expires_at_unix: tokens.expires_at_unix,
            })
            .ok_or(CredentialError::NotFound)
    }

    #[tracing::instrument(
        skip_all,
        fields(subsystem = "credentials", operation = "delete_oauth")
    )]
    fn delete_oauth(&self, reference: &str) -> Result<(), CredentialError> {
        self.oauth_entries
            .lock()
            .map_err(|_| CredentialError::Unavailable)?
            .remove(reference)
            .ok_or(CredentialError::NotFound)
            .map(|_| ())
    }
}

pub struct OsKeyringCredentialStore {
    service: String,
}

impl OsKeyringCredentialStore {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(service: &str, reference: &str) -> Result<keyring::Entry, CredentialError> {
        keyring::Entry::new(service, reference).map_err(|_| CredentialError::Unavailable)
    }
}

/// Runs `f` off any ambient Tokio context, since keyring's Linux backend nests its own runtime.
fn on_isolated_thread<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::spawn(f)
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

impl CredentialStore for OsKeyringCredentialStore {
    #[tracing::instrument(skip_all, fields(subsystem = "credentials", operation = "put"))]
    fn put(&self, reference: &str, credentials: CredentialSet) -> Result<(), CredentialError> {
        let mut encoded = serde_json::to_string(&credentials.to_stored())
            .map_err(|_| CredentialError::Invalid)?;
        let service = self.service.clone();
        let reference = reference.to_owned();
        let payload = encoded.clone();
        let result = on_isolated_thread(move || {
            Self::entry(&service, &reference)?
                .set_password(&payload)
                .map_err(|_| CredentialError::Unavailable)
        });
        encoded.zeroize();
        result
    }

    #[tracing::instrument(skip_all, fields(subsystem = "credentials", operation = "get"))]
    fn get(&self, reference: &str) -> Result<CredentialSet, CredentialError> {
        let service = self.service.clone();
        let reference = reference.to_owned();
        let mut encoded = on_isolated_thread(move || {
            Self::entry(&service, &reference)?
                .get_password()
                .map_err(|_| CredentialError::NotFound)
        })?;
        let stored = serde_json::from_str::<StoredCredential>(&encoded)
            .map_err(|_| CredentialError::Invalid);
        encoded.zeroize();
        stored.map(CredentialSet::from_stored)
    }

    #[tracing::instrument(skip_all, fields(subsystem = "credentials", operation = "delete"))]
    fn delete(&self, reference: &str) -> Result<(), CredentialError> {
        let service = self.service.clone();
        let reference = reference.to_owned();
        on_isolated_thread(move || {
            Self::entry(&service, &reference)?
                .delete_credential()
                .map_err(|_| CredentialError::Unavailable)
        })
    }

    #[tracing::instrument(skip_all, fields(subsystem = "credentials", operation = "put_oauth"))]
    fn put_oauth(&self, reference: &str, tokens: OAuthTokenSet) -> Result<(), CredentialError> {
        let mut encoded = serde_json::to_string(&tokens).map_err(|_| CredentialError::Invalid)?;
        let service = self.service.clone();
        let reference = reference.to_owned();
        let payload = encoded.clone();
        let result = on_isolated_thread(move || {
            Self::entry(&service, &reference)?
                .set_password(&payload)
                .map_err(|_| CredentialError::Unavailable)
        });
        encoded.zeroize();
        result
    }

    #[tracing::instrument(skip_all, fields(subsystem = "credentials", operation = "get_oauth"))]
    fn get_oauth(&self, reference: &str) -> Result<OAuthTokenSet, CredentialError> {
        let service = self.service.clone();
        let reference = reference.to_owned();
        let mut encoded = on_isolated_thread(move || {
            Self::entry(&service, &reference)?
                .get_password()
                .map_err(|_| CredentialError::NotFound)
        })?;
        let tokens =
            serde_json::from_str::<OAuthTokenSet>(&encoded).map_err(|_| CredentialError::Invalid);
        encoded.zeroize();
        tokens
    }

    #[tracing::instrument(
        skip_all,
        fields(subsystem = "credentials", operation = "delete_oauth")
    )]
    fn delete_oauth(&self, reference: &str) -> Result<(), CredentialError> {
        let service = self.service.clone();
        let reference = reference.to_owned();
        on_isolated_thread(move || {
            Self::entry(&service, &reference)?
                .delete_credential()
                .map_err(|_| CredentialError::Unavailable)
        })
    }
}

pub fn new_oauth_reference() -> String {
    new_reference_with_prefix("oauth")
}

fn new_reference_with_prefix(prefix: &str) -> String {
    let suffix: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    format!("{prefix}-{suffix}")
}

fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
