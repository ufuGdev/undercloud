// SPDX-License-Identifier: Apache-2.0
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("authentication required")]
    AuthenticationRequired,
    #[error("permission denied")]
    PermissionDenied,
    #[error("quota exceeded")]
    QuotaExceeded,
    #[error("rate limited")]
    RateLimited,
    #[error("provider temporarily unavailable")]
    TemporarilyUnavailable,
    #[error("provider rejected the request (HTTP {status})")]
    RequestRejected {
        status: u16,
        message: Option<String>,
    },
    #[error("object missing")]
    ObjectMissing,
    #[error("integrity mismatch")]
    IntegrityMismatch,
    #[error("operation not supported by this provider")]
    Unsupported,
    #[error("provider configuration is invalid")]
    InvalidConfiguration,
    #[error("provider endpoint is unreachable")]
    EndpointUnreachable,
    #[error("multipart upload was aborted")]
    UploadAborted,
    #[error("invalid or unsafe object locator")]
    InvalidLocator,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl ProviderError {
    /// Whether a caller should retry this failure with backoff.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ProviderError::RateLimited
                | ProviderError::TemporarilyUnavailable
                | ProviderError::EndpointUnreachable
        )
    }
}
