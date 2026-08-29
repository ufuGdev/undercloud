// SPDX-License-Identifier: Apache-2.0
use undercloud_crypto::{
    generate_dek, generate_manifest_key, unwrap_dek, unwrap_manifest_key, wrap_dek,
    wrap_manifest_key, FileKeyWrapSubkey, WrappedFileKey,
};
use uuid::Uuid;

fn subkey() -> FileKeyWrapSubkey {
    FileKeyWrapSubkey::from_bytes([0x42; 32])
}

fn other_subkey() -> FileKeyWrapSubkey {
    FileKeyWrapSubkey::from_bytes([0x43; 32])
}

fn vault_id() -> Uuid {
    Uuid::from_u128(1)
}

fn file_version_id() -> Uuid {
    Uuid::from_u128(2)
}

#[test]
fn dek_round_trip_recovers_key() {
    let subkey = subkey();
    let dek = generate_dek();
    let wrapped = wrap_dek(&subkey, vault_id(), file_version_id(), &dek).unwrap();
    let recovered = unwrap_dek(&subkey, vault_id(), file_version_id(), &wrapped).unwrap();
    assert_eq!(recovered.expose_bytes(), dek.expose_bytes());
}

#[test]
fn manifest_key_round_trip_recovers_key() {
    let subkey = subkey();
    let key = generate_manifest_key();
    let wrapped = wrap_manifest_key(&subkey, vault_id(), file_version_id(), &key).unwrap();
    let recovered = unwrap_manifest_key(&subkey, vault_id(), file_version_id(), &wrapped).unwrap();
    assert_eq!(recovered.expose_bytes(), key.expose_bytes());
}

#[test]
fn tampering_with_ciphertext_body_fails_closed() {
    let subkey = subkey();
    let dek = generate_dek();
    let mut wrapped = wrap_dek(&subkey, vault_id(), file_version_id(), &dek).unwrap();
    wrapped.ciphertext[0] ^= 0xFF;
    assert!(unwrap_dek(&subkey, vault_id(), file_version_id(), &wrapped).is_err());
}

#[test]
fn tampering_with_authentication_tag_fails_closed() {
    let subkey = subkey();
    let dek = generate_dek();
    let mut wrapped = wrap_dek(&subkey, vault_id(), file_version_id(), &dek).unwrap();
    let last = wrapped.ciphertext.len() - 1;
    wrapped.ciphertext[last] ^= 0xFF; // inside the 16-byte Poly1305 tag
    assert!(unwrap_dek(&subkey, vault_id(), file_version_id(), &wrapped).is_err());
}

#[test]
fn wrong_vault_id_is_rejected() {
    let subkey = subkey();
    let dek = generate_dek();
    let wrapped = wrap_dek(&subkey, vault_id(), file_version_id(), &dek).unwrap();
    let wrong_vault_id = Uuid::from_u128(999);
    assert!(unwrap_dek(&subkey, wrong_vault_id, file_version_id(), &wrapped).is_err());
}

#[test]
fn wrong_file_version_id_is_rejected() {
    let subkey = subkey();
    let dek = generate_dek();
    let wrapped = wrap_dek(&subkey, vault_id(), file_version_id(), &dek).unwrap();
    let wrong_file_version_id = Uuid::from_u128(999);
    assert!(unwrap_dek(&subkey, vault_id(), wrong_file_version_id, &wrapped).is_err());
}

#[test]
fn cross_file_version_substitution_is_rejected() {
    let subkey = subkey();
    let dek = generate_dek();
    let file_version_a = Uuid::from_u128(100);
    let file_version_b = Uuid::from_u128(200);

    let wrapped_for_a = wrap_dek(&subkey, vault_id(), file_version_a, &dek).unwrap();
    assert!(unwrap_dek(&subkey, vault_id(), file_version_b, &wrapped_for_a).is_err());
}

/// Rejects a data-key wrapper passed to manifest-key unwrapping.
#[test]
fn wrapped_dek_is_rejected_by_unwrap_manifest_key() {
    let subkey = subkey();
    let dek = generate_dek();
    let wrapped = wrap_dek(&subkey, vault_id(), file_version_id(), &dek).unwrap();
    assert!(unwrap_manifest_key(&subkey, vault_id(), file_version_id(), &wrapped).is_err());
}

/// Rejects a manifest-key wrapper passed to data-key unwrapping.
#[test]
fn wrapped_manifest_key_is_rejected_by_unwrap_dek() {
    let subkey = subkey();
    let key = generate_manifest_key();
    let wrapped = wrap_manifest_key(&subkey, vault_id(), file_version_id(), &key).unwrap();
    assert!(unwrap_dek(&subkey, vault_id(), file_version_id(), &wrapped).is_err());
}

#[test]
fn wrong_subkey_is_rejected() {
    let dek = generate_dek();
    let wrapped = wrap_dek(&subkey(), vault_id(), file_version_id(), &dek).unwrap();
    assert!(unwrap_dek(&other_subkey(), vault_id(), file_version_id(), &wrapped).is_err());
}

#[test]
fn two_wraps_of_same_key_use_different_nonces_and_ciphertext() {
    let subkey = subkey();
    let dek = generate_dek();
    let a = wrap_dek(&subkey, vault_id(), file_version_id(), &dek).unwrap();
    let b = wrap_dek(&subkey, vault_id(), file_version_id(), &dek).unwrap();
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.ciphertext, b.ciphertext);
}

#[test]
fn key_type_byte_matches_documented_discriminant() {
    let wrapped = WrappedFileKey {
        key_type: undercloud_crypto::FileKeyType::Dek,
        nonce: [0u8; 24],
        ciphertext: vec![0u8; 48],
    };
    assert_eq!(wrapped.key_type, undercloud_crypto::FileKeyType::Dek);
}
