use undercloud_credentials::{
    new_oauth_reference, CredentialError, CredentialSet, CredentialStore, InMemoryCredentialStore,
};

#[test]
fn memory_store_round_trips_and_redacts() {
    let store = InMemoryCredentialStore::new();
    let reference = new_oauth_reference();
    store
        .put(
            &reference,
            CredentialSet {
                access_key: "a".into(),
                secret_key: "secret-marker".into(),
                session_token: Some("token".into()),
            },
        )
        .unwrap();
    let loaded = store.get(&reference).unwrap();
    assert_eq!(loaded.access_key, "a");
    assert!(!format!("{loaded:?}").contains("secret-marker"));
    store.delete(&reference).unwrap();
    assert!(matches!(
        store.get(&reference),
        Err(CredentialError::NotFound)
    ));
}
