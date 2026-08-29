use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{distributions::Alphanumeric, Rng};
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;
use zeroize::Zeroize;

use crate::providers::CloudProviderKind;

/// Timeout for establishing the TCP/TLS connection.
pub(crate) const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Aborts stalled connections that stop delivering bytes.
pub(crate) const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(60);
/// Caps total request time independently of the idle-read timeout.
pub(crate) const HTTP_TOTAL_TIMEOUT: Duration = Duration::from_secs(600);

/// Shared HTTP client with explicit request timeouts.
pub(crate) fn http_client() -> Client {
    Client::builder()
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .read_timeout(HTTP_READ_TIMEOUT)
        .timeout(HTTP_TOTAL_TIMEOUT)
        .build()
        .expect("client configuration is static and must be valid")
}

#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("oauth configuration is invalid")]
    InvalidConfiguration,
    #[error("authorization flow is already active")]
    AlreadyActive,
    #[error("system browser is unavailable")]
    BrowserUnavailable,
    #[error("authorization timed out")]
    Timeout,
    #[error("authorization was cancelled")]
    Cancelled,
    #[error("authorization callback was invalid")]
    InvalidCallback,
    #[error("authorization was denied")]
    Denied,
    #[error("token exchange failed")]
    TokenExchange,
    #[error("token endpoint was unreachable")]
    TokenExchangeNetwork,
    #[error("token exchange was rejected")]
    TokenExchangeRejected {
        status: u16,
        kind: TokenExchangeKind,
    },
    #[error("token exchange response was invalid")]
    TokenExchangeMalformed,
    #[error("token refresh failed")]
    RefreshFailed,
    #[error("provider authorization was revoked")]
    Revoked,
    #[error("required provider scope is missing")]
    MissingScope,
    #[error("provider request failed")]
    ProviderRequest,
    #[error("this provider is not configured in this build")]
    NotConfigured,
    #[error("no registered local callback port is available")]
    CallbackPortUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenExchangeKind {
    InvalidGrant,
    InvalidClient,
    UnauthorizedClient,
    InvalidRequest,
    RedirectUri,
    Pkce,
    AuthorizationCode,
    ClientId,
    Policy,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RedirectStrategy {
    GoogleLoopback,
    MicrosoftLocalhost,
    DropboxRegisteredPorts(Vec<u16>),
}

impl RedirectStrategy {
    pub fn default_for(provider: CloudProviderKind) -> Self {
        match provider {
            CloudProviderKind::GoogleDrive => Self::GoogleLoopback,
            CloudProviderKind::OneDrive => Self::MicrosoftLocalhost,
            CloudProviderKind::Dropbox => {
                Self::DropboxRegisteredPorts(vec![53682, 53683, 53684, 53685])
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthApplication {
    pub provider: String,
    pub profile_id: String,
    pub client_id: String,
    pub redirect_strategy: RedirectStrategy,
}

#[derive(Debug, Clone, Default)]
pub struct OAuthApplicationRegistry {
    applications: HashMap<String, OAuthApplication>,
}

impl OAuthApplicationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, application: OAuthApplication) {
        self.applications
            .insert(application.provider.clone(), application);
    }

    pub fn resolve(&self, provider: &str) -> Result<OAuthApplication, OAuthError> {
        self.applications
            .get(provider)
            .cloned()
            .ok_or(OAuthError::NotConfigured)
    }

    pub fn official() -> Self {
        let mut registry = Self::new();
        let entries = [
            (
                "google",
                crate::build_config::GOOGLE_CLIENT_ID,
                CloudProviderKind::GoogleDrive,
            ),
            (
                "onedrive",
                crate::build_config::ONEDRIVE_CLIENT_ID,
                CloudProviderKind::OneDrive,
            ),
            (
                "dropbox",
                crate::build_config::DROPBOX_APP_KEY,
                CloudProviderKind::Dropbox,
            ),
        ];
        for (provider, client_id, kind) in entries {
            if let Some(client_id) = client_id.filter(|value| valid_application_id(value)) {
                registry.insert(OAuthApplication {
                    provider: provider.to_owned(),
                    profile_id: "official-v1".to_owned(),
                    client_id: client_id.to_owned(),
                    redirect_strategy: redirect_strategy_from_build(kind),
                });
            }
        }
        registry
    }
}

fn valid_application_id(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && !value.contains("placeholder") && !value.contains("YOUR_")
}

fn redirect_strategy_from_build(kind: CloudProviderKind) -> RedirectStrategy {
    if kind == CloudProviderKind::Dropbox {
        if let Some(raw) = crate::build_config::DROPBOX_REDIRECT_PORTS {
            let ports = raw
                .split(',')
                .filter_map(|v| v.trim().parse().ok())
                .collect::<Vec<u16>>();
            if !ports.is_empty() {
                return RedirectStrategy::DropboxRegisteredPorts(ports);
            }
        }
    }
    RedirectStrategy::default_for(kind)
}

#[derive(Clone)]
pub struct OAuthClientConfig {
    pub provider: String,
    pub client_id: String,
    /// Required by Google's token endpoint for "Desktop app" clients even under PKCE.
    pub client_secret: Option<String>,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub revoke_endpoint: Option<String>,
    pub scopes: Vec<String>,
    pub profile_id: String,
    pub redirect_strategy: RedirectStrategy,
}

impl std::fmt::Debug for OAuthClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthClientConfig")
            .field("provider", &self.provider)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("revoke_endpoint", &self.revoke_endpoint)
            .field("scopes", &self.scopes)
            .field("profile_id", &self.profile_id)
            .field("redirect_strategy", &self.redirect_strategy)
            .finish()
    }
}

impl OAuthClientConfig {
    pub fn validate(&self) -> Result<(), OAuthError> {
        if self.provider.trim().is_empty()
            || self.client_id.trim().is_empty()
            || self.profile_id.trim().is_empty()
            || self.client_id.chars().any(char::is_control)
        {
            return Err(OAuthError::InvalidConfiguration);
        }
        for endpoint in [&self.authorization_endpoint, &self.token_endpoint] {
            let url = Url::parse(endpoint).map_err(|_| OAuthError::InvalidConfiguration)?;
            if url.scheme() != "https"
                && !(url.scheme() == "http"
                    && matches!(url.host_str(), Some("127.0.0.1" | "localhost")))
            {
                return Err(OAuthError::InvalidConfiguration);
            }
        }
        if self.scopes.is_empty() {
            return Err(OAuthError::InvalidConfiguration);
        }
        if let RedirectStrategy::DropboxRegisteredPorts(ports) = &self.redirect_strategy {
            if ports.is_empty() || ports.iter().any(|port| *port < 1024) {
                return Err(OAuthError::InvalidConfiguration);
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct OAuthToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at_unix: Option<u64>,
}

impl std::fmt::Debug for OAuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthToken")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

impl OAuthToken {
    pub fn is_expired(&self) -> bool {
        self.expires_at_unix
            .map(|expires| expires <= now_unix().saturating_add(30))
            .unwrap_or(false)
    }
}

impl Drop for OAuthToken {
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(token) = &mut self.refresh_token {
            token.zeroize();
        }
    }
}

#[derive(Clone, Default)]
pub struct AuthorizationCoordinator {
    active: Arc<Mutex<HashSet<String>>>,
}

impl AuthorizationCoordinator {
    pub fn begin(&self, provider: &str) -> Result<(), OAuthError> {
        let mut active = self.active.lock().map_err(|_| OAuthError::AlreadyActive)?;
        if !active.insert(provider.to_owned()) {
            return Err(OAuthError::AlreadyActive);
        }
        Ok(())
    }

    pub fn finish(&self, provider: &str) {
        if let Ok(mut active) = self.active.lock() {
            active.remove(provider);
        }
    }
}

#[derive(Clone)]
pub struct OAuthFlow {
    client: Client,
    coordinator: AuthorizationCoordinator,
}

impl Default for OAuthFlow {
    fn default() -> Self {
        Self::new()
    }
}

impl OAuthFlow {
    pub fn new() -> Self {
        Self {
            client: http_client(),
            coordinator: AuthorizationCoordinator::default(),
        }
    }

    pub fn coordinator(&self) -> AuthorizationCoordinator {
        self.coordinator.clone()
    }

    #[tracing::instrument(
        skip_all,
        fields(subsystem = "oauth", operation = "authorize", stage = "start")
    )]
    pub async fn authorize(
        &self,
        config: &OAuthClientConfig,
        cancel: &OAuthCancellation,
    ) -> Result<OAuthToken, OAuthError> {
        config.validate()?;
        self.coordinator
            .begin(&format!("{}:{}", config.provider, config.profile_id))?;
        let result = self.authorize_inner(config, cancel).await;
        self.coordinator
            .finish(&format!("{}:{}", config.provider, config.profile_id));
        result
    }

    async fn authorize_inner(
        &self,
        config: &OAuthClientConfig,
        cancel: &OAuthCancellation,
    ) -> Result<OAuthToken, OAuthError> {
        let (listener, redirect_uri) = bind_callback(&config.redirect_strategy).await?;
        let state: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(48)
            .map(char::from)
            .collect();
        let verifier: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();
        let challenge = pkce_challenge(&verifier);
        let mut authorize = Url::parse(&config.authorization_endpoint)
            .map_err(|_| OAuthError::InvalidConfiguration)?;
        {
            let mut query = authorize.query_pairs_mut();
            query
                .append_pair("client_id", &config.client_id)
                .append_pair("response_type", "code")
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("state", &state)
                .append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", "S256")
                .append_pair("scope", &config.scopes.join(" "));
            if config.provider == "google" {
                query
                    .append_pair("access_type", "offline")
                    .append_pair("prompt", "consent");
            } else if config.provider == "dropbox" {
                query.append_pair("token_access_type", "offline");
            }
        }
        webbrowser::open(authorize.as_str()).map_err(|_| OAuthError::BrowserUnavailable)?;
        let callback_path = callback_path_for(&config.redirect_strategy);
        let callback = receive_callback(&listener, &state, cancel, callback_path).await?;
        let mut form = vec![
            ("grant_type", "authorization_code".to_owned()),
            ("code", callback),
            ("redirect_uri", redirect_uri),
            ("client_id", config.client_id.clone()),
            ("code_verifier", verifier),
        ];
        if let Some(secret) = &config.client_secret {
            form.push(("client_secret", secret.clone()));
        }
        let response = self
            .client
            .post(&config.token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|_| OAuthError::TokenExchangeNetwork)?;
        parse_token_response(response, false, &config.scopes).await
    }

    #[tracing::instrument(
        skip_all,
        fields(subsystem = "oauth", operation = "refresh", stage = "start")
    )]
    pub async fn refresh(
        &self,
        config: &OAuthClientConfig,
        refresh_token: &str,
    ) -> Result<OAuthToken, OAuthError> {
        config.validate()?;
        let mut form = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", config.client_id.as_str()),
        ];
        if let Some(secret) = &config.client_secret {
            form.push(("client_secret", secret.as_str()));
        }
        let response = self
            .client
            .post(&config.token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|_| OAuthError::RefreshFailed)?;
        parse_token_response(response, true, &config.scopes).await
    }

    pub async fn revoke(
        &self,
        config: &OAuthClientConfig,
        access_token: &str,
    ) -> Result<(), OAuthError> {
        let Some(endpoint) = &config.revoke_endpoint else {
            return Ok(());
        };
        let response = self
            .client
            .post(endpoint)
            .form(&[("token", access_token)])
            .send()
            .await
            .map_err(|_| OAuthError::ProviderRequest)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(OAuthError::ProviderRequest)
        }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }
}

#[derive(Clone, Default)]
pub struct OAuthCancellation(Arc<std::sync::atomic::AtomicBool>);

impl OAuthCancellation {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        use std::sync::atomic::Ordering;
        self.0.store(true, Ordering::Release);
    }
    fn cancelled(&self) -> bool {
        use std::sync::atomic::Ordering;
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    error: Option<String>,
    error_description: Option<String>,
    scope: Option<String>,
}

async fn parse_token_response(
    response: reqwest::Response,
    refresh: bool,
    required_scopes: &[String],
) -> Result<OAuthToken, OAuthError> {
    let status = response.status();
    let body = response.json::<TokenResponse>().await.map_err(|_| {
        if refresh {
            OAuthError::RefreshFailed
        } else {
            OAuthError::TokenExchangeMalformed
        }
    })?;
    if !status.is_success() || body.error.is_some() {
        return Err(if refresh {
            OAuthError::RefreshFailed
        } else {
            OAuthError::TokenExchangeRejected {
                status: status.as_u16(),
                kind: token_exchange_kind(body.error.as_deref(), body.error_description.as_deref()),
            }
        });
    }
    let Some(access_token) = body.access_token.filter(|value| !value.is_empty()) else {
        return Err(if refresh {
            OAuthError::RefreshFailed
        } else {
            OAuthError::TokenExchangeMalformed
        });
    };
    if let Some(scope) = body.scope {
        let granted = scope.split_whitespace().collect::<HashSet<_>>();
        if required_scopes
            .iter()
            .any(|required| !granted.contains(required.as_str()))
        {
            return Err(OAuthError::MissingScope);
        }
    }
    Ok(OAuthToken {
        access_token,
        refresh_token: body.refresh_token,
        expires_at_unix: body
            .expires_in
            .map(|seconds| now_unix().saturating_add(seconds)),
    })
}

fn token_exchange_kind(error: Option<&str>, description: Option<&str>) -> TokenExchangeKind {
    // Prefer Google error codes; use descriptions only for ambiguous responses.
    match error {
        Some("invalid_grant") => return TokenExchangeKind::InvalidGrant,
        Some("invalid_client") => return TokenExchangeKind::InvalidClient,
        Some("unauthorized_client") => return TokenExchangeKind::UnauthorizedClient,
        _ => {}
    }
    let description = description.unwrap_or_default().to_ascii_lowercase();
    if description.contains("policy")
        || description.contains("comply")
        || description.contains("compliance")
        || description.contains("ineligible")
    {
        return TokenExchangeKind::Policy;
    }
    if description.contains("redirect_uri") || description.contains("redirect uri") {
        return TokenExchangeKind::RedirectUri;
    }
    if description.contains("code_verifier")
        || description.contains("code verifier")
        || description.contains("pkce")
    {
        return TokenExchangeKind::Pkce;
    }
    if description.contains("authorization code") {
        return TokenExchangeKind::AuthorizationCode;
    }
    if description.contains("client_id") || description.contains("client id") {
        return TokenExchangeKind::ClientId;
    }
    match error {
        Some("invalid_grant") => TokenExchangeKind::InvalidGrant,
        Some("invalid_client") => TokenExchangeKind::InvalidClient,
        Some("unauthorized_client") => TokenExchangeKind::UnauthorizedClient,
        Some("invalid_request") => TokenExchangeKind::InvalidRequest,
        _ => TokenExchangeKind::Other,
    }
}

#[tracing::instrument(
    skip_all,
    fields(subsystem = "oauth", operation = "callback", stage = "validation")
)]
async fn receive_callback(
    listener: &TcpListener,
    expected_state: &str,
    cancel: &OAuthCancellation,
    expected_path: &str,
) -> Result<String, OAuthError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    loop {
        if cancel.cancelled() {
            return Err(OAuthError::Cancelled);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(OAuthError::Timeout);
        }
        let accept = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        let Ok(Ok((mut stream, peer))) = accept else {
            continue;
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        let mut request = [0_u8; 8192];
        let read = stream
            .read(&mut request)
            .await
            .map_err(|_| OAuthError::InvalidCallback)?;
        let line = std::str::from_utf8(&request[..read])
            .ok()
            .and_then(|text| text.lines().next())
            .ok_or(OAuthError::InvalidCallback)?;
        let target = line
            .strip_prefix("GET ")
            .and_then(|value| value.split_whitespace().next())
            .ok_or(OAuthError::InvalidCallback)?;
        let callback = Url::parse(&format!("http://localhost{target}"))
            .map_err(|_| OAuthError::InvalidCallback)?;
        if callback.path() != expected_path {
            return Err(OAuthError::InvalidCallback);
        }
        let params = callback
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nUndercloud authorization received. You may close this window.";
        let _ = stream.write_all(response).await;
        if params.contains_key("error") {
            return Err(OAuthError::Denied);
        }
        let state_ok = params
            .get("state")
            .map(|value| value.as_bytes().ct_eq(expected_state.as_bytes()).into())
            .unwrap_or(false);
        if !state_ok {
            return Err(OAuthError::InvalidCallback);
        }
        return params
            .get("code")
            .map(|value| value.to_string())
            .ok_or(OAuthError::InvalidCallback);
    }
}

pub fn redirect_uri_for(strategy: &RedirectStrategy, port: u16) -> String {
    match strategy {
        RedirectStrategy::GoogleLoopback => format!("http://127.0.0.1:{port}"),
        RedirectStrategy::DropboxRegisteredPorts(_) => {
            format!("http://127.0.0.1:{port}/oauth/callback")
        }
        RedirectStrategy::MicrosoftLocalhost => {
            format!("http://localhost:{port}/oauth/callback")
        }
    }
}

pub fn registered_redirect_uri(
    strategy: &RedirectStrategy,
    port: u16,
) -> Result<String, OAuthError> {
    if let RedirectStrategy::DropboxRegisteredPorts(ports) = strategy {
        if !ports.contains(&port) {
            return Err(OAuthError::InvalidConfiguration);
        }
    }
    Ok(redirect_uri_for(strategy, port))
}

fn callback_path_for(strategy: &RedirectStrategy) -> &'static str {
    match strategy {
        RedirectStrategy::GoogleLoopback => "/",
        RedirectStrategy::MicrosoftLocalhost | RedirectStrategy::DropboxRegisteredPorts(_) => {
            "/oauth/callback"
        }
    }
}

async fn bind_callback(strategy: &RedirectStrategy) -> Result<(TcpListener, String), OAuthError> {
    match strategy {
        RedirectStrategy::GoogleLoopback | RedirectStrategy::MicrosoftLocalhost => {
            let host = if matches!(strategy, RedirectStrategy::GoogleLoopback) {
                "127.0.0.1"
            } else {
                "localhost"
            };
            let listener = TcpListener::bind((host, 0))
                .await
                .map_err(|_| OAuthError::CallbackPortUnavailable)?;
            let port = listener
                .local_addr()
                .map_err(|_| OAuthError::CallbackPortUnavailable)?
                .port();
            Ok((listener, registered_redirect_uri(strategy, port)?))
        }
        RedirectStrategy::DropboxRegisteredPorts(ports) => {
            for port in ports {
                if let Ok(listener) = TcpListener::bind(("127.0.0.1", *port)).await {
                    return Ok((listener, registered_redirect_uri(strategy, *port)?));
                }
            }
            Err(OAuthError::CallbackPortUnavailable)
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}
