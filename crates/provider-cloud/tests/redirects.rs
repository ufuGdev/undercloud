use undercloud_provider_cloud::{
    redirect_uri_for, registered_redirect_uri, CloudProviderConfig, CloudProviderKind,
    OAuthApplication, OAuthApplicationRegistry, RedirectStrategy,
};

#[test]
fn provider_redirect_strategies_use_their_registered_shape() {
    assert_eq!(
        redirect_uri_for(&RedirectStrategy::GoogleLoopback, 41231),
        "http://127.0.0.1:41231"
    );
    assert_eq!(
        redirect_uri_for(&RedirectStrategy::MicrosoftLocalhost, 41232),
        "http://localhost:41232/oauth/callback"
    );
    let ports = RedirectStrategy::DropboxRegisteredPorts(vec![53682, 53683]);
    assert_eq!(
        redirect_uri_for(&ports, 53682),
        "http://127.0.0.1:53682/oauth/callback"
    );
    assert!(registered_redirect_uri(&ports, 41233).is_err());
}

#[test]
fn injected_registry_is_explicit_and_profile_scoped() {
    let mut registry = OAuthApplicationRegistry::new();
    registry.insert(OAuthApplication {
        provider: "google".to_owned(),
        profile_id: "official-v1".to_owned(),
        client_id: "test-public-id".to_owned(),
        redirect_strategy: RedirectStrategy::GoogleLoopback,
    });
    let app = registry.resolve("google").unwrap();
    assert_eq!(app.profile_id, "official-v1");
    assert!(registry.resolve("dropbox").is_err());
}

#[test]
fn official_profile_does_not_persist_the_application_identifier() {
    let config = CloudProviderConfig {
        kind: CloudProviderKind::GoogleDrive,
        display_name: Some("Google Drive".to_owned()),
        client_id: String::new(),
        credential_reference: "vault-target-profile".to_owned(),
        oauth_profile: "official-v1".to_owned(),
        redirect_strategy: RedirectStrategy::GoogleLoopback,
        account_id: None,
        account_email: None,
        api_base: None,
    };
    let encoded = serde_json::to_string(&config).unwrap();
    assert!(!encoded.contains("client_id"));
}

#[test]
fn legacy_connections_default_to_legacy_profile_without_reauthorization() {
    let config: CloudProviderConfig = serde_json::from_value(serde_json::json!({
        "kind": "one_drive",
        "display_name": "Old OneDrive",
        "client_id": "legacy-client",
        "credential_reference": "legacy-credential",
        "account_id": null,
        "account_email": null
    }))
    .unwrap();
    assert_eq!(config.oauth_profile, "legacy-byo");
    assert_eq!(config.oauth_config().profile_id, "legacy-byo");
    assert!(matches!(
        config.oauth_config().redirect_strategy,
        RedirectStrategy::MicrosoftLocalhost
    ));
}
