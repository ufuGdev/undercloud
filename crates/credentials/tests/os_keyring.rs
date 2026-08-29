use std::panic::{catch_unwind, AssertUnwindSafe};
use undercloud_credentials::{
    new_oauth_reference, CredentialError, CredentialStore, OAuthTokenSet, OsKeyringCredentialStore,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_oauth_from_within_a_tokio_runtime_does_not_panic() {
    let store = OsKeyringCredentialStore::new("undercloud-diag-test");
    let reference = new_oauth_reference();
    let result = catch_unwind(AssertUnwindSafe(|| {
        store.put_oauth(
            &reference,
            OAuthTokenSet {
                access_token: "probe-token".to_owned(),
                refresh_token: None,
                expires_at_unix: None,
            },
        )
    }));
    let result = match result {
        Ok(result) => result,
        Err(panic) => panic!("put_oauth panicked: {panic:?}"),
    };

    match result {
        Ok(()) => {
            let _ = store.delete_oauth(&reference);
        }
        Err(CredentialError::Unavailable) => {}
        Err(error) => panic!("put_oauth returned an unexpected error: {error:?}"),
    }
}
