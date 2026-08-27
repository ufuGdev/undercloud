// SPDX-License-Identifier: Apache-2.0
use undercloud_format::{serialize_chunk_envelope, ChunkEnvelope};
use uuid::Uuid;

#[test]
fn chunk_envelope_debug_does_not_pretty_print_ciphertext_as_utf8_plaintext_marker() {
    // Regression guard: an accidentally-added Display impl must not interpret ciphertext bytes as a string, which could panic or leak plaintext-looking output.
    let env = ChunkEnvelope {
        format_version: 1,
        vault_id: Uuid::from_u128(1),
        file_version_id: Uuid::from_u128(2),
        chunk_index: 0,
        nonce: [0u8; 24],
        ciphertext: b"plaintext-marker-should-not-appear-in-any-log".to_vec(),
    };
    let debug_str = format!("{env:?}");
    // Debug on a Vec<u8> prints numeric bytes, not the UTF-8 string — assert this so nobody "improves" it into a lossy string print later.
    assert!(!debug_str.contains("plaintext-marker-should-not-appear-in-any-log"));
    let _ = serialize_chunk_envelope(&env); // exercise serialization path too
}
