// SPDX-License-Identifier: Apache-2.0
use undercloud_crypto::{
    decrypt_manifest, encrypt_manifest, generate_manifest_key, ManifestIdentity,
};
use uuid::Uuid;

fn identity() -> ManifestIdentity {
    ManifestIdentity {
        format_version: 1,
        vault_id: Uuid::from_u128(1),
        file_version_id: Uuid::from_u128(2),
    }
}

#[test]
fn round_trip_recovers_plaintext() {
    let key = generate_manifest_key();
    let id = identity();
    let plaintext = b"manifest body bytes go here".to_vec();
    let encrypted = encrypt_manifest(&key, &id, &plaintext).unwrap();
    let decrypted = decrypt_manifest(&key, &id, &encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn tampering_with_ciphertext_body_fails_closed() {
    let key = generate_manifest_key();
    let id = identity();
    let mut encrypted = encrypt_manifest(&key, &id, b"payload").unwrap();
    encrypted.ciphertext[0] ^= 0xFF;
    assert!(decrypt_manifest(&key, &id, &encrypted).is_err());
}

#[test]
fn tampering_with_authentication_tag_fails_closed() {
    let key = generate_manifest_key();
    let id = identity();
    let mut encrypted = encrypt_manifest(&key, &id, b"payload").unwrap();
    let last = encrypted.ciphertext.len() - 1;
    encrypted.ciphertext[last] ^= 0xFF; // inside the 16-byte Poly1305 tag
    assert!(decrypt_manifest(&key, &id, &encrypted).is_err());
}

#[test]
fn wrong_vault_id_is_rejected() {
    let key = generate_manifest_key();
    let encrypted = encrypt_manifest(&key, &identity(), b"payload").unwrap();
    let mut wrong = identity();
    wrong.vault_id = Uuid::from_u128(999);
    assert!(decrypt_manifest(&key, &wrong, &encrypted).is_err());
}

#[test]
fn wrong_file_version_id_is_rejected() {
    let key = generate_manifest_key();
    let encrypted = encrypt_manifest(&key, &identity(), b"payload").unwrap();
    let mut wrong = identity();
    wrong.file_version_id = Uuid::from_u128(999);
    assert!(decrypt_manifest(&key, &wrong, &encrypted).is_err());
}

#[test]
fn cross_file_manifest_substitution_is_rejected() {
    let key = generate_manifest_key();
    let mut id_file_a = identity();
    id_file_a.file_version_id = Uuid::from_u128(100);
    let mut id_file_b = identity();
    id_file_b.file_version_id = Uuid::from_u128(200);

    let encrypted_for_a = encrypt_manifest(&key, &id_file_a, b"payload").unwrap();
    assert!(decrypt_manifest(&key, &id_file_b, &encrypted_for_a).is_err());
}

#[test]
fn wrong_key_is_rejected() {
    let key_a = generate_manifest_key();
    let key_b = generate_manifest_key();
    let id = identity();
    let encrypted = encrypt_manifest(&key_a, &id, b"payload").unwrap();
    assert!(decrypt_manifest(&key_b, &id, &encrypted).is_err());
}

#[test]
fn two_encryptions_of_same_plaintext_use_different_nonces_and_ciphertext() {
    let key = generate_manifest_key();
    let id = identity();
    let a = encrypt_manifest(&key, &id, b"same plaintext").unwrap();
    let b = encrypt_manifest(&key, &id, b"same plaintext").unwrap();
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.ciphertext, b.ciphertext);
}
