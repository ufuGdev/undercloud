// SPDX-License-Identifier: Apache-2.0
//! Known-answer tests for the on-disk wire format.
use undercloud_format::{
    parse_chunk_envelope, parse_manifest_body, parse_manifest_envelope, serialize_chunk_envelope,
    serialize_manifest_body, serialize_manifest_envelope, ChunkEnvelope, ManifestBody,
    ManifestEnvelope,
};
use uuid::Uuid;

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Header-layout vector using fixed filler bytes; ciphertext is not tested here.
#[test]
fn chunk_envelope_known_answer_vector() {
    let env = ChunkEnvelope {
        format_version: 1,
        vault_id: Uuid::from_bytes([0x33; 16]),
        file_version_id: Uuid::from_bytes([0x44; 16]),
        chunk_index: 0,
        nonce: [0x22; 24],
        ciphertext: vec![0xcc; 80],
    };
    let expected_hex = "55434c44000133333333333333333333333333333333444444444444444444444444444444440000000000000000222222222222222222222222222222222222222222222222cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    let bytes = serialize_chunk_envelope(&env);
    assert_eq!(hex_decode(expected_hex), bytes);

    let parsed = parse_chunk_envelope(&bytes).unwrap();
    assert_eq!(parsed, env);
}

/// file_size = 200, chunk_count = 4, content_hash = 32 bytes of 0xab.
#[test]
fn manifest_body_known_answer_vector() {
    let body = ManifestBody {
        file_size: 200,
        chunk_count: 4,
        content_hash: [0xab; 32],
    };
    let expected_hex = "00010000000800000000000000c800020000000400000004000300000020abababababababababababababababababababababababababababababababab";

    let bytes = serialize_manifest_body(&body);
    assert_eq!(hex_decode(expected_hex), bytes);

    let parsed = parse_manifest_body(&bytes).unwrap();
    assert_eq!(parsed, body);
}

/// Uses the manifest body vector as opaque ciphertext until manifest AEAD is implemented.
#[test]
fn manifest_envelope_known_answer_vector() {
    let body_bytes = hex_decode("00010000000800000000000000c800020000000400000004000300000020abababababababababababababababababababababababababababababababab");
    let env = ManifestEnvelope {
        format_version: 1,
        vault_id: Uuid::from_bytes([0x33; 16]),
        file_version_id: Uuid::from_bytes([0x44; 16]),
        nonce: [0x77; 24],
        ciphertext: body_bytes,
    };
    let expected_hex = "55434c4d0001333333333333333333333333333333334444444444444444444444444444444477777777777777777777777777777777777777777777777700010000000800000000000000c800020000000400000004000300000020abababababababababababababababababababababababababababababababab";

    let bytes = serialize_manifest_envelope(&env);
    assert_eq!(hex_decode(expected_hex), bytes);

    let parsed = parse_manifest_envelope(&bytes).unwrap();
    assert_eq!(parsed, env);
}
