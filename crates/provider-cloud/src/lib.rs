// SPDX-License-Identifier: Apache-2.0
//! OAuth-backed storage adapters for desktop providers.

mod oauth;
mod providers;

mod build_config {
    include!(concat!(env!("OUT_DIR"), "/oauth_build_config.rs"));
}

pub use oauth::{
    pkce_challenge, redirect_uri_for, registered_redirect_uri, AuthorizationCoordinator,
    OAuthApplication, OAuthApplicationRegistry, OAuthCancellation, OAuthClientConfig, OAuthError,
    OAuthFlow, OAuthToken, RedirectStrategy, TokenExchangeKind,
};
pub use providers::{
    authorize, CloudProviderConfig, CloudProviderKind, DropboxProvider, GoogleDriveProvider,
    OneDriveProvider,
};
