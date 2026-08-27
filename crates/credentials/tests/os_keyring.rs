use undercloud_credentials::{CredentialStore, OAuthTokenSet, OsKeyringCredentialStore};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_oauth_from_within_a_tokio_runtime_does_not_panic() {
    let store = OsKeyringCredentialStore::new("undercloud-diag-test");
    let reference = "os-keyring-regression-probe";
    let result = store.put_oauth(
        reference,
        OAuthTokenSet {
            access_token: "probe-token".to_owned(),
            refresh_token: None,
            expires_at_unix: None,
        },
    );
    let _ = store.delete_oauth(reference);
    result.expect("put_oauth must not panic when called from an async task");
}
