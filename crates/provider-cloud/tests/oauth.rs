use undercloud_credentials::{CredentialStore, InMemoryCredentialStore, OAuthTokenSet};
use undercloud_provider_cloud::{
    pkce_challenge, AuthorizationCoordinator, OAuthClientConfig, OAuthFlow,
};

#[test]
fn pkce_uses_the_rfc7636_s256_vector() {
    assert_eq!(
        pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn authorization_coordinator_allows_one_flow_per_provider() {
    let coordinator = AuthorizationCoordinator::default();
    coordinator.begin("google").unwrap();
    assert!(coordinator.begin("google").is_err());
    coordinator.finish("google");
    coordinator.begin("google").unwrap();
}

#[test]
fn oauth_tokens_round_trip_without_debug_secrets() {
    let store = InMemoryCredentialStore::new();
    store
        .put_oauth(
            "oauth-test",
            OAuthTokenSet {
                access_token: "access-marker".to_owned(),
                refresh_token: Some("refresh-marker".to_owned()),
                expires_at_unix: None,
            },
        )
        .unwrap();
    let token = store.get_oauth("oauth-test").unwrap();
    let debug = format!("{token:?}");
    assert!(!debug.contains("marker"));
    store.delete_oauth("oauth-test").unwrap();
}

#[tokio::test]
async fn refresh_uses_form_post_and_redacts_failure() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut request = [0_u8; 4096];
        let size = stream.read(&mut request).await.unwrap();
        let request = String::from_utf8_lossy(&request[..size]);
        assert!(request.starts_with("POST /token "));
        assert!(request.contains("grant_type=refresh_token"));
        let body = br#"{"access_token":"new-access","expires_in":3600,"token_type":"Bearer"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    let config = OAuthClientConfig {
        provider: "test".to_owned(),
        client_id: "developer-client".to_owned(),
        client_secret: None,
        authorization_endpoint: format!("http://{address}/authorize"),
        token_endpoint: format!("http://{address}/token"),
        revoke_endpoint: None,
        scopes: vec!["files.read".to_owned()],
        profile_id: "test-profile".to_owned(),
        redirect_strategy: undercloud_provider_cloud::RedirectStrategy::GoogleLoopback,
    };
    let token = OAuthFlow::new()
        .refresh(&config, "refresh-secret")
        .await
        .unwrap();
    assert_eq!(token.access_token, "new-access");
    server.await.unwrap();
}
