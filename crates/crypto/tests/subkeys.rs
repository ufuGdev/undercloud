// SPDX-License-Identifier: Apache-2.0
//! Behavioral tests for HKDF-SHA256 vault subkey derivation (ADR-006); KAT vectors pinning exact bytes live in tests/kat.rs, this file proves structural properties.
use undercloud_crypto::{derive_vault_subkeys, MasterKey};
use uuid::Uuid;

#[test]
fn derivation_is_stable_for_fixed_master_key_and_vault_id() {
    let master_key = MasterKey::from_bytes([0x01; 32]);
    let vault_id = Uuid::from_bytes([0x02; 16]);

    let first = derive_vault_subkeys(&master_key, vault_id);
    let second = derive_vault_subkeys(&master_key, vault_id);

    assert_eq!(
        first.file_key_wrap.expose_bytes(),
        second.file_key_wrap.expose_bytes()
    );
    assert_eq!(
        first.catalog_field.expose_bytes(),
        second.catalog_field.expose_bytes()
    );
    assert_eq!(
        first.content_hash.expose_bytes(),
        second.content_hash.expose_bytes()
    );
    assert_eq!(
        first.recovery.expose_bytes(),
        second.recovery.expose_bytes()
    );
}

#[test]
fn all_four_labels_produce_pairwise_distinct_keys() {
    let master_key = MasterKey::from_bytes([0x03; 32]);
    let vault_id = Uuid::from_bytes([0x04; 16]);
    let subkeys = derive_vault_subkeys(&master_key, vault_id);

    let keys: [&[u8; 32]; 4] = [
        subkeys.file_key_wrap.expose_bytes(),
        subkeys.catalog_field.expose_bytes(),
        subkeys.content_hash.expose_bytes(),
        subkeys.recovery.expose_bytes(),
    ];

    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(keys[i], keys[j], "subkeys at index {i} and {j} must differ");
        }
    }
}

#[test]
fn different_vault_ids_produce_different_subkeys_from_same_master_key() {
    let master_key = MasterKey::from_bytes([0x05; 32]);
    let vault_a = Uuid::from_bytes([0x06; 16]);
    let vault_b = Uuid::from_bytes([0x07; 16]);

    let subkeys_a = derive_vault_subkeys(&master_key, vault_a);
    let subkeys_b = derive_vault_subkeys(&master_key, vault_b);

    assert_ne!(
        subkeys_a.file_key_wrap.expose_bytes(),
        subkeys_b.file_key_wrap.expose_bytes()
    );
    assert_ne!(
        subkeys_a.catalog_field.expose_bytes(),
        subkeys_b.catalog_field.expose_bytes()
    );
    assert_ne!(
        subkeys_a.content_hash.expose_bytes(),
        subkeys_b.content_hash.expose_bytes()
    );
    assert_ne!(
        subkeys_a.recovery.expose_bytes(),
        subkeys_b.recovery.expose_bytes()
    );
}

#[test]
fn different_master_keys_produce_different_subkeys_for_same_label_and_vault_id() {
    let master_key_a = MasterKey::from_bytes([0x08; 32]);
    let master_key_b = MasterKey::from_bytes([0x09; 32]);
    let vault_id = Uuid::from_bytes([0x0a; 16]);

    let subkeys_a = derive_vault_subkeys(&master_key_a, vault_id);
    let subkeys_b = derive_vault_subkeys(&master_key_b, vault_id);

    assert_ne!(
        subkeys_a.file_key_wrap.expose_bytes(),
        subkeys_b.file_key_wrap.expose_bytes()
    );
    assert_ne!(
        subkeys_a.catalog_field.expose_bytes(),
        subkeys_b.catalog_field.expose_bytes()
    );
    assert_ne!(
        subkeys_a.content_hash.expose_bytes(),
        subkeys_b.content_hash.expose_bytes()
    );
    assert_ne!(
        subkeys_a.recovery.expose_bytes(),
        subkeys_b.recovery.expose_bytes()
    );
}
