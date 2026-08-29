// SPDX-License-Identifier: Apache-2.0
use undercloud_format::{serialize_chunk_envelope, ChunkEnvelope};
use uuid::Uuid;

#[test]
fn chunk_envelope_debug_does_not_pretty_print_ciphertext_as_utf8_plaintext_marker() {
    // Keep ciphertext debug output as numeric bytes.
    let env = ChunkEnvelope {
        format_version: 1,
        vault_id: Uuid::from_u128(1),
        file_version_id: Uuid::from_u128(2),
        chunk_index: 0,
        nonce: [0u8; 24],
        ciphertext: b"plaintext-marker-should-not-appear-in-any-log".to_vec(),
    };
    let debug_str = format!("{env:?}");
    // Keep ciphertext debug output as numeric bytes.
    assert!(!debug_str.contains("plaintext-marker-should-not-appear-in-any-log"));
    let _ = serialize_chunk_envelope(&env); // exercise serialization path too
}
