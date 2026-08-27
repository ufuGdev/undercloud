use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::TryStreamExt;
use rand::{distributions::Alphanumeric, Rng};
use reqwest::{Method, Response};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::io::StreamReader;
use undercloud_credentials::{CredentialError, CredentialStore, OAuthTokenSet};
use undercloud_storage::{
    backoff_delay, GetObjectRequest, ObjectLocator, ObjectMetadata, ObjectPage, ObjectReceipt,
    ObjectStream, PageCursor, ProviderCapabilities, ProviderError, ProviderHealth,
    PutObjectRequest, QuotaInfo, QuotaState, StorageProvider,
};
use url::Url;

use crate::oauth::{
    OAuthApplication, OAuthCancellation, OAuthClientConfig, OAuthError, OAuthFlow, OAuthToken,
    RedirectStrategy,
};

const GOOGLE_AUTH: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_REVOKE: &str = "https://oauth2.googleapis.com/revoke";
const GOOGLE_SCOPE: &str = "https://www.googleapis.com/auth/drive.appdata";
const GRAPH_AUTH: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
const GRAPH_TOKEN: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
const DROPBOX_AUTH: &str = "https://www.dropbox.com/oauth2/authorize";
const DROPBOX_TOKEN: &str = "https://api.dropboxapi.com/oauth2/token";
const DROPBOX_REVOKE: &str = "https://api.dropboxapi.com/2/auth/token/revoke";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudProviderKind {
    GoogleDrive,
    OneDrive,
    Dropbox,
}

impl CloudProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GoogleDrive => "google_drive",
            Self::OneDrive => "onedrive",
            Self::Dropbox => "dropbox",
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::GoogleDrive => "google",
            Self::OneDrive => "onedrive",
            Self::Dropbox => "dropbox",
        }
    }

    pub fn key_name(self) -> &'static str {
        self.key()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudProviderConfig {
    pub kind: CloudProviderKind,
    #[serde(default, deserialize_with = "deserialize_display_name")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_id: String,
    pub credential_reference: String,
    #[serde(default = "legacy_profile")]
    pub oauth_profile: String,
    #[serde(default = "default_redirect_strategy")]
    pub redirect_strategy: RedirectStrategy,
    pub account_id: Option<String>,
    pub account_email: Option<String>,
    #[serde(default)]
    pub api_base: Option<String>,
}

impl CloudProviderConfig {
    pub fn oauth_config(&self) -> OAuthClientConfig {
        let redirect_strategy = if self.oauth_profile == "legacy-byo"
            && matches!(self.redirect_strategy, RedirectStrategy::GoogleLoopback)
            && self.kind != CloudProviderKind::GoogleDrive
        {
            RedirectStrategy::default_for(self.kind)
        } else {
            self.redirect_strategy.clone()
        };
        match self.kind {
            CloudProviderKind::GoogleDrive => OAuthClientConfig {
                provider: self.kind.key().to_owned(),
                client_id: self.client_id.clone(),
                client_secret: crate::build_config::GOOGLE_CLIENT_SECRET
                    .map(str::to_owned)
                    .filter(|value| !value.is_empty()),
                authorization_endpoint: GOOGLE_AUTH.to_owned(),
                token_endpoint: GOOGLE_TOKEN.to_owned(),
                revoke_endpoint: Some(GOOGLE_REVOKE.to_owned()),
                scopes: vec![GOOGLE_SCOPE.to_owned()],
                profile_id: self.oauth_profile.clone(),
                redirect_strategy: redirect_strategy.clone(),
            },
            CloudProviderKind::OneDrive => OAuthClientConfig {
                provider: self.kind.key().to_owned(),
                client_id: self.client_id.clone(),
                client_secret: None,
                authorization_endpoint: GRAPH_AUTH.to_owned(),
                token_endpoint: GRAPH_TOKEN.to_owned(),
                revoke_endpoint: None,
                scopes: vec![
                    "Files.ReadWrite.AppFolder".to_owned(),
                    "offline_access".to_owned(),
                ],
                profile_id: self.oauth_profile.clone(),
                redirect_strategy: redirect_strategy.clone(),
            },
            CloudProviderKind::Dropbox => OAuthClientConfig {
                provider: self.kind.key().to_owned(),
                client_id: self.client_id.clone(),
                client_secret: None,
                authorization_endpoint: DROPBOX_AUTH.to_owned(),
                token_endpoint: DROPBOX_TOKEN.to_owned(),
                revoke_endpoint: Some(DROPBOX_REVOKE.to_owned()),
                scopes: vec![
                    "account_info.read".to_owned(),
                    "files.content.read".to_owned(),
                    "files.content.write".to_owned(),
                    "files.metadata.read".to_owned(),
                ],
                profile_id: self.oauth_profile.clone(),
                redirect_strategy,
            },
        }
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        if self.client_id.trim().is_empty() || self.credential_reference.trim().is_empty() {
            return Err(ProviderError::InvalidConfiguration);
        }
        Ok(())
    }

    pub fn from_application(
        kind: CloudProviderKind,
        application: &OAuthApplication,
        credential_reference: String,
    ) -> Self {
        Self {
            kind,
            display_name: None,
            client_id: application.client_id.clone(),
            credential_reference,
            oauth_profile: application.profile_id.clone(),
            redirect_strategy: application.redirect_strategy.clone(),
            account_id: None,
            account_email: None,
            api_base: None,
        }
    }
}

fn legacy_profile() -> String {
    "legacy-byo".to_owned()
}

fn deserialize_display_name<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum DisplayName {
        String(String),
        Optional(Option<String>),
    }
    Ok(match DisplayName::deserialize(deserializer)? {
        DisplayName::String(value) => Some(value),
        DisplayName::Optional(value) => value,
    })
}

fn default_redirect_strategy() -> RedirectStrategy {
    RedirectStrategy::GoogleLoopback
}

#[tracing::instrument(
    skip_all,
    fields(subsystem = "oauth", operation = "authorize", stage = "start")
)]
pub async fn authorize(
    kind: CloudProviderKind,
    application: &OAuthApplication,
    flow: &OAuthFlow,
    cancel: &OAuthCancellation,
) -> Result<OAuthToken, OAuthError> {
    if application.provider != kind.key() {
        return Err(OAuthError::InvalidConfiguration);
    }
    let config =
        CloudProviderConfig::from_application(kind, application, "authorization-only".to_owned());
    flow.authorize(&config.oauth_config(), cancel).await
}

struct CloudInner {
    config: CloudProviderConfig,
    credentials: Arc<dyn CredentialStore>,
    flow: OAuthFlow,
    client: reqwest::Client,
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

impl std::fmt::Debug for CloudInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudInner")
            .field("kind", &self.config.kind)
            .field("display_name", &"<redacted>")
            .field("account_id", &self.config.account_id)
            .finish()
    }
}

impl CloudInner {
    fn api_base(&self) -> &str {
        self.config
            .api_base
            .as_deref()
            .unwrap_or(match self.config.kind {
                CloudProviderKind::GoogleDrive => "https://www.googleapis.com",
                CloudProviderKind::OneDrive => "https://graph.microsoft.com",
                CloudProviderKind::Dropbox => "https://api.dropboxapi.com",
            })
    }

    fn content_base(&self) -> &str {
        self.config
            .api_base
            .as_deref()
            .unwrap_or(match self.config.kind {
                CloudProviderKind::Dropbox => "https://content.dropboxapi.com",
                _ => self.api_base(),
            })
    }

    async fn new(
        config: CloudProviderConfig,
        credentials: Arc<dyn CredentialStore>,
        flow: OAuthFlow,
        token: OAuthToken,
    ) -> Result<Self, ProviderError> {
        config.validate()?;
        credentials
            .put_oauth(
                &config.credential_reference,
                OAuthTokenSet {
                    access_token: token.access_token.clone(),
                    refresh_token: token.refresh_token.clone(),
                    expires_at_unix: token.expires_at_unix,
                },
            )
            .map_err(|_| ProviderError::AuthenticationRequired)?;
        Ok(Self {
            config,
            credentials,
            client: flow.client().clone(),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
            flow,
        })
    }

    async fn token(&self) -> Result<String, ProviderError> {
        let _refresh_guard = self.refresh_lock.lock().await;
        let token = self
            .credentials
            .get_oauth(&self.config.credential_reference)
            .map_err(map_credential_error)?;
        if !token.is_expired() {
            return Ok(token.access_token.clone());
        }
        let Some(refresh) = token.refresh_token.as_deref() else {
            return Err(ProviderError::AuthenticationRequired);
        };
        let refreshed = self
            .flow
            .refresh(&self.config.oauth_config(), refresh)
            .await
            .map_err(map_oauth_error)?;
        let result = refreshed.access_token.clone();
        self.credentials
            .put_oauth(
                &self.config.credential_reference,
                OAuthTokenSet {
                    access_token: refreshed.access_token.clone(),
                    refresh_token: refreshed
                        .refresh_token
                        .clone()
                        .or_else(|| Some(refresh.to_owned())),
                    expires_at_unix: refreshed.expires_at_unix,
                },
            )
            .map_err(|_| ProviderError::AuthenticationRequired)?;
        Ok(result)
    }

    #[tracing::instrument(
        skip_all,
        fields(subsystem = "provider", operation = "http_request", stage = "request")
    )]
    async fn request(&self, method: Method, url: &str) -> Result<Response, ProviderError> {
        let token = self.token().await?;
        self.send_with_retry(|| Ok(self.client.request(method.clone(), url).bearer_auth(&token)))
            .await
    }

    #[tracing::instrument(
        skip_all,
        fields(subsystem = "provider", operation = "http_request", stage = "body")
    )]
    async fn request_bytes(
        &self,
        method: Method,
        url: &str,
        bytes: Vec<u8>,
    ) -> Result<Response, ProviderError> {
        let token = self.token().await?;
        self.send_with_retry(|| {
            Ok(self
                .client
                .request(method.clone(), url)
                .bearer_auth(&token)
                .body(bytes.clone()))
        })
        .await
    }

    #[tracing::instrument(
        skip_all,
        fields(subsystem = "provider", operation = "http_request", stage = "retry")
    )]
    async fn send_with_retry<F>(&self, mut build: F) -> Result<Response, ProviderError>
    where
        F: FnMut() -> Result<reqwest::RequestBuilder, ProviderError>,
    {
        for attempt in 0..3 {
            let response = match build()?.send().await {
                Ok(response) => response,
                Err(_) if attempt < 2 => {
                    tokio::time::sleep(backoff_delay(attempt)).await;
                    continue;
                }
                Err(_) => return Err(ProviderError::EndpointUnreachable),
            };
            let http_status = response.status().as_u16();
            let retryable = http_status == 429 || (500..=599).contains(&http_status);
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .map(|seconds| std::time::Duration::from_secs(seconds.min(60)));
            tracing::info!(subsystem="provider", provider_type=%self.config.kind.key_name(), operation="http_request", http_status, retry_attempt=attempt, retryable, outcome="response");
            match map_status_with_body(response).await {
                Ok(response) => return Ok(response),
                Err(error) if error.is_retryable() && attempt < 2 => {
                    tokio::time::sleep(retry_after.unwrap_or_else(|| backoff_delay(attempt))).await;
                }
                Err(error) => return Err(error),
            }
        }
        Err(ProviderError::TemporarilyUnavailable)
    }
}

pub struct GoogleDriveProvider(CloudInner);
pub struct OneDriveProvider(CloudInner);
pub struct DropboxProvider(CloudInner);

macro_rules! impl_debug {
    ($name:ident) => {
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }
    };
}
impl_debug!(GoogleDriveProvider);
impl_debug!(OneDriveProvider);
impl_debug!(DropboxProvider);

impl GoogleDriveProvider {
    pub async fn connect(
        config: CloudProviderConfig,
        credentials: Arc<dyn CredentialStore>,
        flow: OAuthFlow,
        token: OAuthToken,
    ) -> Result<Self, ProviderError> {
        if config.kind != CloudProviderKind::GoogleDrive {
            return Err(ProviderError::InvalidConfiguration);
        }
        Ok(Self(
            CloudInner::new(config, credentials, flow, token).await?,
        ))
    }
}
impl OneDriveProvider {
    pub async fn connect(
        config: CloudProviderConfig,
        credentials: Arc<dyn CredentialStore>,
        flow: OAuthFlow,
        token: OAuthToken,
    ) -> Result<Self, ProviderError> {
        if config.kind != CloudProviderKind::OneDrive {
            return Err(ProviderError::InvalidConfiguration);
        }
        Ok(Self(
            CloudInner::new(config, credentials, flow, token).await?,
        ))
    }
}
impl DropboxProvider {
    fn object_path(locator: &str) -> String {
        locator
            .strip_prefix("d:")
            .map(|id| format!("id:{id}"))
            .unwrap_or_else(|| format!("/{locator}"))
    }
    pub async fn connect(
        config: CloudProviderConfig,
        credentials: Arc<dyn CredentialStore>,
        flow: OAuthFlow,
        token: OAuthToken,
    ) -> Result<Self, ProviderError> {
        if config.kind != CloudProviderKind::Dropbox {
            return Err(ProviderError::InvalidConfiguration);
        }
        Ok(Self(
            CloudInner::new(config, credentials, flow, token).await?,
        ))
    }
}

#[async_trait]
trait CloudBackend: Send + Sync {
    async fn capabilities(&self) -> Result<ProviderCapabilities, ProviderError>;
    async fn put(&self, locator: &str, bytes: Vec<u8>) -> Result<ObjectReceipt, ProviderError>;
    async fn get(&self, request: GetObjectRequest) -> Result<ObjectStream, ProviderError>;
    async fn head(&self, locator: &str) -> Result<ObjectMetadata, ProviderError>;
    async fn delete(&self, locator: &str) -> Result<(), ProviderError>;
    async fn list(&self, cursor: Option<PageCursor>) -> Result<ObjectPage, ProviderError>;
    async fn quota(&self) -> Result<QuotaInfo, ProviderError>;
    async fn health(&self) -> Result<ProviderHealth, ProviderError>;
}

fn map_credential_error(error: CredentialError) -> ProviderError {
    match error {
        CredentialError::NotFound | CredentialError::Invalid => {
            ProviderError::AuthenticationRequired
        }
        CredentialError::Unavailable => ProviderError::TemporarilyUnavailable,
    }
}

fn map_oauth_error(error: OAuthError) -> ProviderError {
    match error {
        OAuthError::Revoked | OAuthError::MissingScope => ProviderError::AuthenticationRequired,
        OAuthError::RefreshFailed => ProviderError::AuthenticationRequired,
        OAuthError::Denied | OAuthError::InvalidCallback => ProviderError::PermissionDenied,
        _ => ProviderError::TemporarilyUnavailable,
    }
}

async fn map_status_with_body(response: Response) -> Result<Response, ProviderError> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let error = match status {
        reqwest::StatusCode::UNAUTHORIZED => ProviderError::AuthenticationRequired,
        reqwest::StatusCode::FORBIDDEN => ProviderError::PermissionDenied,
        reqwest::StatusCode::NOT_FOUND => ProviderError::ObjectMissing,
        reqwest::StatusCode::TOO_MANY_REQUESTS => ProviderError::RateLimited,
        reqwest::StatusCode::PAYLOAD_TOO_LARGE => ProviderError::QuotaExceeded,
        s if s.is_server_error() => ProviderError::TemporarilyUnavailable,
        s => ProviderError::RequestRejected {
            status: s.as_u16(),
            message: None,
        },
    };
    Err(error)
}

fn locator_check(locator: &str) -> Result<(), ProviderError> {
    if locator.is_empty()
        || locator.len() > 512
        || locator.contains('/')
        || locator.contains('\\')
        || locator.contains('\'')
        || locator == "."
        || locator == ".."
        || locator.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(ProviderError::InvalidLocator);
    }
    Ok(())
}

async fn bytes_from(
    mut body: Pin<Box<dyn AsyncRead + Send + Sync>>,
) -> Result<Vec<u8>, ProviderError> {
    let mut bytes = Vec::new();
    body.read_to_end(&mut bytes).await?;
    Ok(bytes)
}

/// Wraps a live HTTP response body as an [`ObjectStream`] so bytes flow straight to the caller instead of being buffered in RAM (`response.bytes()` would hold the whole object at once).
fn response_stream(response: Response) -> ObjectStream {
    let body = response.bytes_stream().map_err(std::io::Error::other);
    Box::pin(StreamReader::new(body))
}

fn validate_range_response(
    response: Response,
    range: Option<(u64, u64)>,
) -> Result<Response, ProviderError> {
    let Some((requested_start, requested_end)) = range else {
        return Ok(response);
    };
    if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
        return Err(ProviderError::RequestRejected {
            status: response.status().as_u16(),
            message: None,
        });
    }
    let Some(value) = response
        .headers()
        .get(reqwest::header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
    else {
        return Err(ProviderError::IntegrityMismatch);
    };
    let Some((range, _total)) = value
        .strip_prefix("bytes ")
        .and_then(|value| value.split_once('/'))
    else {
        return Err(ProviderError::IntegrityMismatch);
    };
    let Some((start, end)) = range
        .split_once('-')
        .and_then(|(start, end)| Some((start.parse::<u64>().ok()?, end.parse::<u64>().ok()?)))
    else {
        return Err(ProviderError::IntegrityMismatch);
    };
    if start != requested_start || end < start || end > requested_end {
        return Err(ProviderError::IntegrityMismatch);
    }
    Ok(response)
}

fn receipt(locator: &str, size: u64) -> ObjectReceipt {
    ObjectReceipt {
        locator: ObjectLocator(locator.to_owned()),
        size,
        etag: None,
    }
}

macro_rules! impl_storage {
    ($name:ident, $backend:ty) => {
        #[async_trait]
        impl StorageProvider for $name {
            async fn capabilities(&self) -> Result<ProviderCapabilities, ProviderError> {
                CloudBackend::capabilities(self.backend()).await
            }
            async fn put_object(
                &self,
                request: PutObjectRequest,
            ) -> Result<ObjectReceipt, ProviderError> {
                locator_check(&request.locator.0)?;
                CloudBackend::put(
                    self.backend(),
                    &request.locator.0,
                    bytes_from(request.body).await?,
                )
                .await
            }
            async fn get_object(
                &self,
                request: GetObjectRequest,
            ) -> Result<ObjectStream, ProviderError> {
                locator_check(&request.locator.0)?;
                CloudBackend::get(self.backend(), request).await
            }
            async fn head_object(
                &self,
                locator: &ObjectLocator,
            ) -> Result<ObjectMetadata, ProviderError> {
                locator_check(&locator.0)?;
                CloudBackend::head(self.backend(), &locator.0).await
            }
            async fn delete_object(&self, locator: &ObjectLocator) -> Result<(), ProviderError> {
                locator_check(&locator.0)?;
                CloudBackend::delete(self.backend(), &locator.0).await
            }
            async fn list_objects(
                &self,
                cursor: Option<PageCursor>,
            ) -> Result<ObjectPage, ProviderError> {
                CloudBackend::list(self.backend(), cursor).await
            }
            async fn quota(&self) -> Result<QuotaInfo, ProviderError> {
                CloudBackend::quota(self.backend()).await
            }
            async fn health_check(&self) -> Result<ProviderHealth, ProviderError> {
                CloudBackend::health(self.backend()).await
            }
        }
    };
}

impl GoogleDriveProvider {
    fn backend(&self) -> &GoogleDriveProvider {
        self
    }
}
impl OneDriveProvider {
    fn backend(&self) -> &OneDriveProvider {
        self
    }
}
impl DropboxProvider {
    fn backend(&self) -> &DropboxProvider {
        self
    }
}

impl GoogleDriveProvider {
    fn object_id(locator: &str) -> Option<&str> {
        locator.strip_prefix("g:")
    }
    async fn find_id(&self, locator: &str) -> Result<String, ProviderError> {
        let mut url = Url::parse(&format!("{}/drive/v3/files", self.0.api_base())).unwrap();
        url.query_pairs_mut()
            .append_pair(
                "q",
                &format!(
                    "name = '{}' and 'appDataFolder' in parents and trashed = false",
                    locator
                ),
            )
            .append_pair("spaces", "appDataFolder")
            .append_pair("fields", "files(id,name,size)")
            .append_pair("pageSize", "1000");
        let response = self.0.request(Method::GET, url.as_str()).await?;
        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|_| ProviderError::TemporarilyUnavailable)?;
        value["files"][0]["id"]
            .as_str()
            .map(str::to_owned)
            .ok_or(ProviderError::ObjectMissing)
    }

    async fn about(&self) -> Result<serde_json::Value, ProviderError> {
        let response = self
            .0
            .request(
                Method::GET,
                &format!(
                    "{}/drive/v3/about?fields=user,storageQuota",
                    self.0.api_base()
                ),
            )
            .await?;
        response
            .json()
            .await
            .map_err(|_| ProviderError::TemporarilyUnavailable)
    }
}

#[async_trait]
impl CloudBackend for GoogleDriveProvider {
    async fn capabilities(&self) -> Result<ProviderCapabilities, ProviderError> {
        Ok(ProviderCapabilities {
            range_reads: true,
            quota_reporting: true,
            conditional_writes: true,
            native_checksums: true,
            case_sensitive: true,
            ..ProviderCapabilities::default()
        })
    }

    async fn put(&self, locator: &str, bytes: Vec<u8>) -> Result<ObjectReceipt, ProviderError> {
        let token = self.0.token().await?;
        let metadata = serde_json::json!({"name": locator, "parents": ["appDataFolder"]});
        // reqwest's `.multipart()` hardcodes `multipart/form-data`; Drive's multipart upload needs `multipart/related` (RFC 2387), hence the hand-built body.
        let boundary: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(48)
            .map(char::from)
            .collect();
        let mut body = Vec::with_capacity(bytes.len() + 256);
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n")
                .as_bytes(),
        );
        body.extend_from_slice(metadata.to_string().as_bytes());
        body.extend_from_slice(
            format!("\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n")
                .as_bytes(),
        );
        body.extend_from_slice(&bytes);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let url = format!(
            "{}/upload/drive/v3/files?uploadType=multipart",
            self.0.api_base()
        );
        let response = self
            .0
            .send_with_retry(|| {
                Ok(self
                    .0
                    .client
                    .post(&url)
                    .bearer_auth(&token)
                    .header(
                        reqwest::header::CONTENT_TYPE,
                        format!("multipart/related; boundary={boundary}"),
                    )
                    .body(body.clone()))
            })
            .await?;
        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|_| ProviderError::TemporarilyUnavailable)?;
        let id = value["id"]
            .as_str()
            .ok_or(ProviderError::TemporarilyUnavailable)?;
        Ok(receipt(&format!("g:{id}"), bytes.len() as u64))
    }

    async fn get(&self, request: GetObjectRequest) -> Result<ObjectStream, ProviderError> {
        let id = match Self::object_id(&request.locator.0) {
            Some(id) => id.to_owned(),
            None => self.find_id(&request.locator.0).await?,
        };
        let url = format!("{}/drive/v3/files/{id}?alt=media", self.0.api_base());
        let token = self.0.token().await?;
        let mut request_builder = self.0.client.get(url).bearer_auth(token);
        if let Some((start, end)) = request.range {
            request_builder = request_builder.header("Range", format!("bytes={start}-{end}"));
        }
        let response = self
            .0
            .send_with_retry(|| {
                request_builder
                    .try_clone()
                    .ok_or(ProviderError::TemporarilyUnavailable)
            })
            .await?;
        Ok(response_stream(validate_range_response(
            response,
            request.range,
        )?))
    }

    async fn head(&self, locator: &str) -> Result<ObjectMetadata, ProviderError> {
        let id = match Self::object_id(locator) {
            Some(id) => id.to_owned(),
            None => self.find_id(locator).await?,
        };
        let response = self
            .0
            .request(
                Method::GET,
                &format!("{}/drive/v3/files/{id}?fields=size", self.0.api_base()),
            )
            .await?;
        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|_| ProviderError::TemporarilyUnavailable)?;
        Ok(ObjectMetadata {
            size: value["size"]
                .as_str()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            etag: None,
        })
    }

    async fn delete(&self, locator: &str) -> Result<(), ProviderError> {
        let id = match Self::object_id(locator) {
            Some(id) => id.to_owned(),
            None => self.find_id(locator).await?,
        };
        self.0
            .request(
                Method::DELETE,
                &format!("{}/drive/v3/files/{id}", self.0.api_base()),
            )
            .await?;
        Ok(())
    }

    async fn list(&self, cursor: Option<PageCursor>) -> Result<ObjectPage, ProviderError> {
        let mut url = Url::parse(&format!("{}/drive/v3/files", self.0.api_base())).unwrap();
        url.query_pairs_mut()
            .append_pair("q", "'appDataFolder' in parents and trashed = false")
            .append_pair("spaces", "appDataFolder")
            .append_pair("fields", "files(name),nextPageToken")
            .append_pair("pageSize", "1000");
        if let Some(cursor) = cursor {
            url.query_pairs_mut().append_pair("pageToken", &cursor.0);
        }
        let response = self.0.request(Method::GET, url.as_str()).await?;
        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|_| ProviderError::TemporarilyUnavailable)?;
        let locators = value["files"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|file| {
                file["name"]
                    .as_str()
                    .map(|name| ObjectLocator(name.to_owned()))
            })
            .collect();
        Ok(ObjectPage {
            locators,
            next_cursor: value["nextPageToken"]
                .as_str()
                .map(|v| PageCursor(v.to_owned())),
        })
    }

    async fn quota(&self) -> Result<QuotaInfo, ProviderError> {
        let value = self.about().await?;
        let quota = &value["storageQuota"];
        let used = quota["usage"]
            .as_str()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let total = quota["limit"].as_str().and_then(|v| v.parse().ok());
        Ok(QuotaInfo {
            used_bytes: used,
            total_bytes: total,
            state: if total.is_some() {
                QuotaState::Known
            } else {
                QuotaState::Unknown
            },
        })
    }

    async fn health(&self) -> Result<ProviderHealth, ProviderError> {
        self.about().await.map(|_| ProviderHealth::Healthy)
    }
}

impl OneDriveProvider {
    fn object_id(locator: &str) -> Option<&str> {
        locator.strip_prefix("o:")
    }
    fn item_url(&self, locator: &str) -> String {
        format!(
            "{}/v1.0/me/drive/special/approot:/{locator}:",
            self.0.api_base()
        )
    }
    fn item_id_url(&self, id: &str) -> String {
        format!("{}/v1.0/me/drive/items/{id}", self.0.api_base())
    }
    async fn item(&self, locator: &str) -> Result<serde_json::Value, ProviderError> {
        let url = match Self::object_id(locator) {
            Some(id) => self.item_id_url(id),
            None => self.item_url(locator),
        };
        let response = self.0.request(Method::GET, &url).await?;
        response
            .json()
            .await
            .map_err(|_| ProviderError::TemporarilyUnavailable)
    }
}

#[async_trait]
impl CloudBackend for OneDriveProvider {
    async fn capabilities(&self) -> Result<ProviderCapabilities, ProviderError> {
        Ok(ProviderCapabilities {
            range_reads: true,
            quota_reporting: true,
            conditional_writes: true,
            case_sensitive: false,
            ..ProviderCapabilities::default()
        })
    }
    async fn put(&self, locator: &str, bytes: Vec<u8>) -> Result<ObjectReceipt, ProviderError> {
        let response = self
            .0
            .request_bytes(
                Method::PUT,
                &format!("{}/content", self.item_url(locator)),
                bytes.clone(),
            )
            .await?;
        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|_| ProviderError::TemporarilyUnavailable)?;
        let id = value["id"]
            .as_str()
            .ok_or(ProviderError::TemporarilyUnavailable)?;
        Ok(receipt(&format!("o:{id}"), bytes.len() as u64))
    }
    async fn get(&self, request: GetObjectRequest) -> Result<ObjectStream, ProviderError> {
        let token = self.0.token().await?;
        let mut builder = self
            .0
            .client
            .get(format!(
                "{}/content",
                match Self::object_id(&request.locator.0) {
                    Some(id) => self.item_id_url(id),
                    None => self.item_url(&request.locator.0),
                }
            ))
            .bearer_auth(token);
        if let Some((start, end)) = request.range {
            builder = builder.header("Range", format!("bytes={start}-{end}"));
        }
        let response = self
            .0
            .send_with_retry(|| {
                builder
                    .try_clone()
                    .ok_or(ProviderError::TemporarilyUnavailable)
            })
            .await?;
        Ok(response_stream(validate_range_response(
            response,
            request.range,
        )?))
    }
    async fn head(&self, locator: &str) -> Result<ObjectMetadata, ProviderError> {
        let value = self.item(locator).await?;
        Ok(ObjectMetadata {
            size: value["size"].as_u64().unwrap_or(0),
            etag: value["eTag"].as_str().map(str::to_owned),
        })
    }
    async fn delete(&self, locator: &str) -> Result<(), ProviderError> {
        let value = self.item(locator).await?;
        let id = value["id"].as_str().ok_or(ProviderError::ObjectMissing)?;
        self.0
            .request(Method::DELETE, &self.item_id_url(id))
            .await?;
        Ok(())
    }
    async fn list(&self, cursor: Option<PageCursor>) -> Result<ObjectPage, ProviderError> {
        let url = cursor.map(|cursor| cursor.0).unwrap_or_else(|| {
            format!(
                "{}/v1.0/me/drive/special/approot/children?$select=name",
                self.0.api_base()
            )
        });
        let response = self.0.request(Method::GET, &url).await?;
        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|_| ProviderError::TemporarilyUnavailable)?;
        let locators = value["value"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|item| {
                item["name"]
                    .as_str()
                    .map(|name| ObjectLocator(name.to_owned()))
            })
            .collect();
        Ok(ObjectPage {
            locators,
            next_cursor: value["@odata.nextLink"]
                .as_str()
                .map(|v| PageCursor(v.to_owned())),
        })
    }
    async fn quota(&self) -> Result<QuotaInfo, ProviderError> {
        let response = self
            .0
            .request(
                Method::GET,
                &format!("{}/v1.0/me/drive?$select=quota", self.0.api_base()),
            )
            .await?;
        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|_| ProviderError::TemporarilyUnavailable)?;
        let quota = &value["quota"];
        let used = quota["used"].as_u64().unwrap_or(0);
        let total = quota["total"].as_u64();
        Ok(QuotaInfo {
            used_bytes: used,
            total_bytes: total,
            state: if total.is_some() {
                QuotaState::Known
            } else {
                QuotaState::Unknown
            },
        })
    }
    async fn health(&self) -> Result<ProviderHealth, ProviderError> {
        self.item("undercloud-health")
            .await
            .or_else(|error| {
                if matches!(error, ProviderError::ObjectMissing) {
                    Ok(serde_json::json!({}))
                } else {
                    Err(error)
                }
            })
            .map(|_| ProviderHealth::Healthy)
    }
}

impl DropboxProvider {
    async fn api(
        &self,
        endpoint: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, ProviderError> {
        let token = self.0.token().await?;
        let body = body.to_string();
        let url = format!("{}/2/{endpoint}", self.0.api_base());
        let response = self
            .0
            .send_with_retry(|| {
                Ok(self
                    .0
                    .client
                    .post(&url)
                    .bearer_auth(&token)
                    .header("Content-Type", "application/json")
                    .body(body.clone()))
            })
            .await?;
        response
            .json()
            .await
            .map_err(|_| ProviderError::TemporarilyUnavailable)
    }
}

#[async_trait]
impl CloudBackend for DropboxProvider {
    async fn capabilities(&self) -> Result<ProviderCapabilities, ProviderError> {
        Ok(ProviderCapabilities {
            range_reads: true,
            quota_reporting: true,
            case_sensitive: true,
            ..ProviderCapabilities::default()
        })
    }
    async fn put(&self, locator: &str, bytes: Vec<u8>) -> Result<ObjectReceipt, ProviderError> {
        let token = self.0.token().await?;
        let arg = serde_json::json!({"path": format!("/{locator}"), "mode": "overwrite", "autorename": false, "mute": true});
        let url = format!("{}/2/files/upload", self.0.content_base());
        let arg = arg.to_string();
        let response = self
            .0
            .send_with_retry(|| {
                Ok(self
                    .0
                    .client
                    .post(&url)
                    .bearer_auth(&token)
                    .header("Dropbox-API-Arg", arg.clone())
                    .header("Content-Type", "application/octet-stream")
                    .body(bytes.clone()))
            })
            .await?;
        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|_| ProviderError::TemporarilyUnavailable)?;
        let id = value["id"]
            .as_str()
            .ok_or(ProviderError::TemporarilyUnavailable)?;
        Ok(receipt(&format!("d:{id}"), bytes.len() as u64))
    }
    async fn get(&self, request: GetObjectRequest) -> Result<ObjectStream, ProviderError> {
        let token = self.0.token().await?;
        let arg = serde_json::json!({"path": Self::object_path(&request.locator.0)});
        let mut builder = self
            .0
            .client
            .post(format!("{}/2/files/download", self.0.content_base()))
            .bearer_auth(token)
            .header("Dropbox-API-Arg", arg.to_string());
        if let Some((start, end)) = request.range {
            builder = builder.header("Range", format!("bytes={start}-{end}"));
        }
        let response = self
            .0
            .send_with_retry(|| {
                builder
                    .try_clone()
                    .ok_or(ProviderError::TemporarilyUnavailable)
            })
            .await?;
        Ok(response_stream(validate_range_response(
            response,
            request.range,
        )?))
    }
    async fn head(&self, locator: &str) -> Result<ObjectMetadata, ProviderError> {
        let value = self
            .api(
                "files/get_metadata",
                serde_json::json!({"path": Self::object_path(locator)}),
            )
            .await?;
        Ok(ObjectMetadata {
            size: value["size"].as_u64().unwrap_or(0),
            etag: value["content_hash"].as_str().map(str::to_owned),
        })
    }
    async fn delete(&self, locator: &str) -> Result<(), ProviderError> {
        self.api(
            "files/delete_v2",
            serde_json::json!({"path": Self::object_path(locator)}),
        )
        .await?;
        Ok(())
    }
    async fn list(&self, cursor: Option<PageCursor>) -> Result<ObjectPage, ProviderError> {
        let value = if let Some(cursor) = cursor {
            self.api(
                "files/list_folder/continue",
                serde_json::json!({"cursor": cursor.0}),
            )
            .await?
        } else {
            self.api(
                "files/list_folder",
                serde_json::json!({"path": "", "recursive": false, "include_deleted": false}),
            )
            .await?
        };
        let locators = value["entries"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|entry| {
                entry["name"]
                    .as_str()
                    .map(|name| ObjectLocator(name.to_owned()))
            })
            .collect();
        Ok(ObjectPage {
            locators,
            next_cursor: if value["has_more"].as_bool() == Some(true) {
                value["cursor"].as_str().map(|v| PageCursor(v.to_owned()))
            } else {
                None
            },
        })
    }
    async fn quota(&self) -> Result<QuotaInfo, ProviderError> {
        let value = self
            .api("users/get_space_usage", serde_json::json!({}))
            .await?;
        let used = value["used"].as_u64().unwrap_or(0);
        let total = value["allocation"]["allocated"].as_u64();
        Ok(QuotaInfo {
            used_bytes: used,
            total_bytes: total,
            state: if total.is_some() {
                QuotaState::Known
            } else {
                QuotaState::Unknown
            },
        })
    }
    async fn health(&self) -> Result<ProviderHealth, ProviderError> {
        self.api("users/get_current_account", serde_json::json!({}))
            .await
            .map(|_| ProviderHealth::Healthy)
    }
}

impl_storage!(GoogleDriveProvider, GoogleDriveProvider);
impl_storage!(OneDriveProvider, OneDriveProvider);
impl_storage!(DropboxProvider, DropboxProvider);
