// SPDX-License-Identifier: Apache-2.0
use undercloud_format::{
    parse_chunk_envelope, serialize_chunk_envelope, ChunkEnvelope, FormatError,
};
use uuid::Uuid;

fn sample() -> ChunkEnvelope {
    ChunkEnvelope {
        format_version: 1,
        vault_id: Uuid::from_u128(1),
        file_version_id: Uuid::from_u128(2),
        chunk_index: 7,
        nonce: [9u8; 24],
        ciphertext: vec![1, 2, 3, 4, 5],
    }
}

#[test]
fn round_trip_serialize_parse() {
    let env = sample();
    let bytes = serialize_chunk_envelope(&env);
    let parsed = parse_chunk_envelope(&bytes).unwrap();
    assert_eq!(parsed.format_version, env.format_version);
    assert_eq!(parsed.vault_id, env.vault_id);
    assert_eq!(parsed.file_version_id, env.file_version_id);
    assert_eq!(parsed.chunk_index, env.chunk_index);
    assert_eq!(parsed.nonce, env.nonce);
    assert_eq!(parsed.ciphertext, env.ciphertext);
}

#[test]
fn wrong_magic_fails_closed() {
    let mut bytes = serialize_chunk_envelope(&sample());
    bytes[0] = b'X';
    assert!(matches!(
        parse_chunk_envelope(&bytes),
        Err(FormatError::InvalidMagic)
    ));
}

#[test]
fn unsupported_version_fails_closed() {
    let mut bytes = serialize_chunk_envelope(&sample());
    // version is bytes[4..6], big-endian
    bytes[4] = 0xFF;
    bytes[5] = 0xFF;
    assert!(matches!(
        parse_chunk_envelope(&bytes),
        Err(FormatError::UnsupportedVersion(v)) if v == 0xFFFF
    ));
}

#[test]
fn version_one_above_current_is_rejected() {
    // Reject versions newer than the parser understands.
    let mut bytes = serialize_chunk_envelope(&sample());
    bytes[5] = 2; // version 2, big-endian low byte
    assert!(matches!(
        parse_chunk_envelope(&bytes),
        Err(FormatError::UnsupportedVersion(v)) if v == 2
    ));
}

#[test]
fn truncated_input_fails_closed() {
    let bytes = serialize_chunk_envelope(&sample());
    let truncated = &bytes[..bytes.len() - 10];
    assert!(matches!(
        parse_chunk_envelope(truncated),
        Err(FormatError::Truncated)
    ));
}

#[test]
fn empty_input_fails_closed() {
    assert!(parse_chunk_envelope(&[]).is_err());
}
