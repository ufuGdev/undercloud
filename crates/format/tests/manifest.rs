// SPDX-License-Identifier: Apache-2.0
use undercloud_format::{
    parse_manifest_body, parse_manifest_envelope, serialize_manifest_body,
    serialize_manifest_envelope, FormatError, ManifestBody, ManifestEnvelope,
};
use uuid::Uuid;

fn sample_body() -> ManifestBody {
    ManifestBody {
        file_size: 12_345,
        chunk_count: 3,
        content_hash: [7u8; 32],
    }
}

#[test]
fn manifest_body_round_trips() {
    let body = sample_body();
    let bytes = serialize_manifest_body(&body);
    let parsed = parse_manifest_body(&bytes).unwrap();
    assert_eq!(parsed, body);
}

#[test]
fn unknown_optional_field_is_ignored() {
    let mut bytes = serialize_manifest_body(&sample_body());
    // Append an unknown, non-critical field: tag 0x0999 (bit15=0 => optional), len 2, value.
    bytes.extend_from_slice(&0x0999u16.to_be_bytes());
    bytes.extend_from_slice(&2u32.to_be_bytes());
    bytes.extend_from_slice(&[0xAA, 0xBB]);
    let parsed = parse_manifest_body(&bytes).unwrap();
    assert_eq!(parsed, sample_body());
}

#[test]
fn unknown_critical_field_fails_closed() {
    let mut bytes = serialize_manifest_body(&sample_body());
    // tag with bit15 set (critical), unknown to this parser version.
    let critical_unknown_tag: u16 = 0x8999;
    bytes.extend_from_slice(&critical_unknown_tag.to_be_bytes());
    bytes.extend_from_slice(&2u32.to_be_bytes());
    bytes.extend_from_slice(&[0xAA, 0xBB]);
    assert!(matches!(
        parse_manifest_body(&bytes),
        Err(FormatError::UnknownCriticalField(t)) if t == critical_unknown_tag
    ));
}

#[test]
fn duplicate_known_field_fails_closed() {
    // Reject duplicate known tags instead of silently taking the last value.
    let mut bytes = serialize_manifest_body(&sample_body());
    let duplicate_file_size_tag: u16 = 0x0001;
    bytes.extend_from_slice(&duplicate_file_size_tag.to_be_bytes());
    bytes.extend_from_slice(&8u32.to_be_bytes());
    bytes.extend_from_slice(&99_999u64.to_be_bytes());
    assert!(parse_manifest_body(&bytes).is_err());
}

#[test]
fn manifest_envelope_round_trips_and_fails_closed_on_bad_magic() {
    let env = ManifestEnvelope {
        format_version: 1,
        vault_id: Uuid::from_u128(1),
        file_version_id: Uuid::from_u128(2),
        nonce: [3u8; 24],
        ciphertext: vec![1, 2, 3],
    };
    let bytes = serialize_manifest_envelope(&env);
    let parsed = parse_manifest_envelope(&bytes).unwrap();
    assert_eq!(parsed, env);

    let mut bad = bytes.clone();
    bad[0] = b'Z';
    assert!(parse_manifest_envelope(&bad).is_err());
}

#[test]
fn manifest_envelope_version_one_above_current_is_rejected() {
    // Reject versions newer than the parser understands.
    let env = ManifestEnvelope {
        format_version: 1,
        vault_id: Uuid::from_u128(1),
        file_version_id: Uuid::from_u128(2),
        nonce: [3u8; 24],
        ciphertext: vec![1, 2, 3],
    };
    let mut bytes = serialize_manifest_envelope(&env);
    bytes[5] = 2; // version is bytes[4..6], big-endian low byte
    assert!(matches!(
        parse_manifest_envelope(&bytes),
        Err(FormatError::UnsupportedVersion(v)) if v == 2
    ));
}
