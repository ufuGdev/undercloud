// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the catalog field-encryption envelope.
use undercloud_catalog::{decrypt_field, encrypt_field, CatalogError, EntityType, FieldTag};
use undercloud_crypto::CatalogFieldSubkey;
use uuid::Uuid;

/// Decodes a lowercase hexadecimal string for test vectors.
fn hex_decode(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "hex string must have even length"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex byte pair"))
        .collect()
}

/// Independently generated field-envelope vector used as an encryption oracle.
#[test]
fn field_envelope_known_answer_vector() {
    let subkey = CatalogFieldSubkey::from_bytes([0x21; 32]);
    let vault_id = Uuid::from_bytes([0x22; 16]);
    let entity_id = Uuid::from_bytes([0x23; 16]);
    let expected_plaintext = b"undercloud catalog field kat vector 0001".to_vec();

    // Full serialized wire bytes: version(2 BE)=0001 || nonce(24, all 0x24) || ciphertext
    let envelope_bytes = hex_decode(
        "00012424242424242424242424242424242424242424242424246627d83a5c79756af7c6da0883e0b7250e78f3763388da60a12fc13a3df7db311807d8e0b633c074f676e531f923233a7c8f45ad4ae3b678",
    );

    let decrypted = decrypt_field(
        &subkey,
        vault_id,
        EntityType::LogicalFile,
        entity_id,
        FieldTag::Name,
        &envelope_bytes,
    )
    .unwrap();
    assert_eq!(decrypted, expected_plaintext);
}

/// Same envelope, wrong entity_id — must fail closed.
#[test]
fn field_envelope_known_answer_vector_rejects_wrong_entity_id() {
    let subkey = CatalogFieldSubkey::from_bytes([0x21; 32]);
    let vault_id = Uuid::from_bytes([0x22; 16]);
    let wrong_entity_id = Uuid::from_bytes([0xFF; 16]);

    let envelope_bytes = hex_decode(
        "00012424242424242424242424242424242424242424242424246627d83a5c79756af7c6da0883e0b7250e78f3763388da60a12fc13a3df7db311807d8e0b633c074f676e531f923233a7c8f45ad4ae3b678",
    );

    let result = decrypt_field(
        &subkey,
        vault_id,
        EntityType::LogicalFile,
        wrong_entity_id,
        FieldTag::Name,
        &envelope_bytes,
    );
    assert!(result.is_err(), "wrong entity_id must be rejected");
}

/// Same envelope, wrong vault_id — must fail closed.
#[test]
fn field_envelope_known_answer_vector_rejects_wrong_vault_id() {
    let subkey = CatalogFieldSubkey::from_bytes([0x21; 32]);
    let wrong_vault_id = Uuid::from_bytes([0xFF; 16]);
    let entity_id = Uuid::from_bytes([0x23; 16]);

    let envelope_bytes = hex_decode(
        "00012424242424242424242424242424242424242424242424246627d83a5c79756af7c6da0883e0b7250e78f3763388da60a12fc13a3df7db311807d8e0b633c074f676e531f923233a7c8f45ad4ae3b678",
    );

    let result = decrypt_field(
        &subkey,
        wrong_vault_id,
        EntityType::LogicalFile,
        entity_id,
        FieldTag::Name,
        &envelope_bytes,
    );
    assert!(result.is_err(), "wrong vault_id must be rejected");
}

/// Same envelope, wrong entity_type — must fail closed.
#[test]
fn field_envelope_known_answer_vector_rejects_wrong_entity_type() {
    let subkey = CatalogFieldSubkey::from_bytes([0x21; 32]);
    let vault_id = Uuid::from_bytes([0x22; 16]);
    let entity_id = Uuid::from_bytes([0x23; 16]);

    let envelope_bytes = hex_decode(
        "00012424242424242424242424242424242424242424242424246627d83a5c79756af7c6da0883e0b7250e78f3763388da60a12fc13a3df7db311807d8e0b633c074f676e531f923233a7c8f45ad4ae3b678",
    );

    let result = decrypt_field(
        &subkey,
        vault_id,
        EntityType::StorageTarget, // encrypted under LogicalFile
        entity_id,
        FieldTag::Name,
        &envelope_bytes,
    );
    assert!(result.is_err(), "wrong entity_type must be rejected");
}

/// Same envelope, wrong field_tag — must fail closed.
#[test]
fn field_envelope_known_answer_vector_rejects_wrong_field_tag() {
    let subkey = CatalogFieldSubkey::from_bytes([0x21; 32]);
    let vault_id = Uuid::from_bytes([0x22; 16]);
    let entity_id = Uuid::from_bytes([0x23; 16]);

    let envelope_bytes = hex_decode(
        "00012424242424242424242424242424242424242424242424246627d83a5c79756af7c6da0883e0b7250e78f3763388da60a12fc13a3df7db311807d8e0b633c074f676e531f923233a7c8f45ad4ae3b678",
    );

    let result = decrypt_field(
        &subkey,
        vault_id,
        EntityType::LogicalFile,
        entity_id,
        FieldTag::Mime, // encrypted under Name
        &envelope_bytes,
    );
    assert!(result.is_err(), "wrong field_tag must be rejected");
}

fn fresh_context() -> (CatalogFieldSubkey, Uuid, Uuid) {
    (
        CatalogFieldSubkey::from_bytes([0x11; 32]),
        Uuid::new_v4(),
        Uuid::new_v4(),
    )
}

#[test]
fn round_trip_text_like_plaintext() {
    let (subkey, vault_id, entity_id) = fresh_context();
    let plaintext = b"my-secret-diary.txt".to_vec();

    let envelope = encrypt_field(
        &subkey,
        vault_id,
        EntityType::LogicalFile,
        entity_id,
        FieldTag::Name,
        &plaintext,
    )
    .unwrap();

    let decrypted = decrypt_field(
        &subkey,
        vault_id,
        EntityType::LogicalFile,
        entity_id,
        FieldTag::Name,
        &envelope,
    )
    .unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn round_trip_arbitrary_binary_plaintext() {
    let (subkey, vault_id, entity_id) = fresh_context();
    let plaintext: Vec<u8> = (0..=255u8).collect();

    let envelope = encrypt_field(
        &subkey,
        vault_id,
        EntityType::Replica,
        entity_id,
        FieldTag::ProviderLocator,
        &plaintext,
    )
    .unwrap();

    let decrypted = decrypt_field(
        &subkey,
        vault_id,
        EntityType::Replica,
        entity_id,
        FieldTag::ProviderLocator,
        &envelope,
    )
    .unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn round_trip_empty_plaintext() {
    let (subkey, vault_id, entity_id) = fresh_context();
    let plaintext: Vec<u8> = Vec::new();

    let envelope = encrypt_field(
        &subkey,
        vault_id,
        EntityType::LogicalFolder,
        entity_id,
        FieldTag::Name,
        &plaintext,
    )
    .unwrap();

    // Empty plaintext still yields a 26-byte header + 16-byte tag.
    assert_eq!(envelope.len(), 26 + 16);

    let decrypted = decrypt_field(
        &subkey,
        vault_id,
        EntityType::LogicalFolder,
        entity_id,
        FieldTag::Name,
        &envelope,
    )
    .unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn round_trip_non_ascii_utf8_plaintext() {
    let (subkey, vault_id, entity_id) = fresh_context();
    let plaintext = "café résumé 日本語 🔒".as_bytes().to_vec();

    let envelope = encrypt_field(
        &subkey,
        vault_id,
        EntityType::LogicalFile,
        entity_id,
        FieldTag::Mime,
        &plaintext,
    )
    .unwrap();

    let decrypted = decrypt_field(
        &subkey,
        vault_id,
        EntityType::LogicalFile,
        entity_id,
        FieldTag::Mime,
        &envelope,
    )
    .unwrap();

    assert_eq!(decrypted, plaintext);
    assert_eq!(
        String::from_utf8(decrypted).unwrap(),
        "café résumé 日本語 🔒"
    );
}

#[test]
fn tampered_nonce_fails_closed() {
    let (subkey, vault_id, entity_id) = fresh_context();
    let plaintext = b"tamper nonce".to_vec();

    let mut envelope = encrypt_field(
        &subkey,
        vault_id,
        EntityType::StorageTarget,
        entity_id,
        FieldTag::ProviderConfig,
        &plaintext,
    )
    .unwrap();

    // Nonce occupies bytes [2..26).
    envelope[3] ^= 0xFF;

    let result = decrypt_field(
        &subkey,
        vault_id,
        EntityType::StorageTarget,
        entity_id,
        FieldTag::ProviderConfig,
        &envelope,
    );
    assert!(result.is_err(), "tampered nonce must be rejected");
}

#[test]
fn tampered_ciphertext_fails_closed() {
    let (subkey, vault_id, entity_id) = fresh_context();
    let plaintext = b"tamper ciphertext body".to_vec();

    let mut envelope = encrypt_field(
        &subkey,
        vault_id,
        EntityType::StorageTarget,
        entity_id,
        FieldTag::ProviderConfig,
        &plaintext,
    )
    .unwrap();

    // Ciphertext body starts at byte 26; flip a byte well before the trailing 16-byte Poly1305 tag.
    let target = 26;
    assert!(
        envelope.len() > target + 16,
        "plaintext must be long enough to have ciphertext bytes before the tag"
    );
    envelope[target] ^= 0xFF;

    let result = decrypt_field(
        &subkey,
        vault_id,
        EntityType::StorageTarget,
        entity_id,
        FieldTag::ProviderConfig,
        &envelope,
    );
    assert!(result.is_err(), "tampered ciphertext must be rejected");
}

#[test]
fn tampered_tag_fails_closed() {
    let (subkey, vault_id, entity_id) = fresh_context();
    let plaintext = b"tamper tag".to_vec();

    let mut envelope = encrypt_field(
        &subkey,
        vault_id,
        EntityType::StorageTarget,
        entity_id,
        FieldTag::ProviderConfig,
        &plaintext,
    )
    .unwrap();

    // The trailing 16 bytes are the Poly1305 tag.
    let last = envelope.len() - 1;
    envelope[last] ^= 0xFF;

    let result = decrypt_field(
        &subkey,
        vault_id,
        EntityType::StorageTarget,
        entity_id,
        FieldTag::ProviderConfig,
        &envelope,
    );
    assert!(result.is_err(), "tampered tag must be rejected");
}

#[test]
fn envelope_shorter_than_header_is_truncated_without_aead_attempt() {
    let subkey = CatalogFieldSubkey::from_bytes([0x11; 32]);
    let vault_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();

    // 25 bytes: one short of the fixed 26-byte header.
    let short_envelope = vec![0u8; 25];

    let result = decrypt_field(
        &subkey,
        vault_id,
        EntityType::LogicalFile,
        entity_id,
        FieldTag::Name,
        &short_envelope,
    );

    match result {
        Err(CatalogError::Truncated) => {}
        other => panic!("expected CatalogError::Truncated, got {other:?}"),
    }
}

#[test]
fn empty_envelope_is_truncated() {
    let subkey = CatalogFieldSubkey::from_bytes([0x11; 32]);
    let vault_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();

    let result = decrypt_field(
        &subkey,
        vault_id,
        EntityType::LogicalFile,
        entity_id,
        FieldTag::Name,
        &[],
    );

    match result {
        Err(CatalogError::Truncated) => {}
        other => panic!("expected CatalogError::Truncated, got {other:?}"),
    }
}

/// Rejects version 2 before attempting AEAD.
#[test]
fn unsupported_envelope_version_is_rejected_before_aead_attempt() {
    let subkey = CatalogFieldSubkey::from_bytes([0x11; 32]);
    let vault_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    let plaintext = b"version check ordering".to_vec();

    let mut envelope = encrypt_field(
        &subkey,
        vault_id,
        EntityType::LogicalFile,
        entity_id,
        FieldTag::Name,
        &plaintext,
    )
    .unwrap();

    // Keep valid ciphertext so the version check runs before AEAD.
    envelope[0..2].copy_from_slice(&2u16.to_be_bytes());

    let result = decrypt_field(
        &subkey,
        vault_id,
        EntityType::LogicalFile,
        entity_id,
        FieldTag::Name,
        &envelope,
    );

    match result {
        Err(CatalogError::UnsupportedFieldEnvelopeVersion { found }) => assert_eq!(found, 2),
        other => panic!("expected CatalogError::UnsupportedFieldEnvelopeVersion, got {other:?}"),
    }
}

#[test]
fn cross_row_substitution_fails_same_entity_type_different_entity_id() {
    let subkey = CatalogFieldSubkey::from_bytes([0x11; 32]);
    let vault_id = Uuid::new_v4();
    let entity_id_a = Uuid::new_v4();
    let entity_id_b = Uuid::new_v4();
    let plaintext = b"row a's name".to_vec();

    let envelope = encrypt_field(
        &subkey,
        vault_id,
        EntityType::LogicalFile,
        entity_id_a,
        FieldTag::Name,
        &plaintext,
    )
    .unwrap();

    let result = decrypt_field(
        &subkey,
        vault_id,
        EntityType::LogicalFile,
        entity_id_b, // different row, same table/column
        FieldTag::Name,
        &envelope,
    );
    assert!(result.is_err(), "cross-row substitution must be rejected");
}

#[test]
fn cross_column_substitution_fails_same_entity_id_different_field_tag() {
    let subkey = CatalogFieldSubkey::from_bytes([0x11; 32]);
    let vault_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    let plaintext = b"this file's name".to_vec();

    let envelope = encrypt_field(
        &subkey,
        vault_id,
        EntityType::LogicalFile,
        entity_id,
        FieldTag::Name,
        &plaintext,
    )
    .unwrap();

    let result = decrypt_field(
        &subkey,
        vault_id,
        EntityType::LogicalFile,
        entity_id,      // same row
        FieldTag::Mime, // different column
        &envelope,
    );
    assert!(
        result.is_err(),
        "cross-column substitution must be rejected"
    );
}

#[test]
fn cross_table_substitution_fails_same_entity_id_different_entity_type() {
    let subkey = CatalogFieldSubkey::from_bytes([0x11; 32]);
    let vault_id = Uuid::new_v4();
    let shared_id = Uuid::new_v4();
    let plaintext = b"storage target's provider config".to_vec();

    let envelope = encrypt_field(
        &subkey,
        vault_id,
        EntityType::StorageTarget,
        shared_id,
        FieldTag::ProviderConfig,
        &plaintext,
    )
    .unwrap();

    let result = decrypt_field(
        &subkey,
        vault_id,
        EntityType::LogicalFolder, // different table, numerically-equal entity_id
        shared_id,
        FieldTag::ProviderConfig,
        &envelope,
    );
    assert!(result.is_err(), "cross-table substitution must be rejected");
}
