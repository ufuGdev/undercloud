// SPDX-License-Identifier: Apache-2.0
//! Structural tests for the keyed content hash (ADR-006); the KAT vector lives in tests/kat.rs — this file covers streaming equivalence, empty-input determinism, and key sensitivity.
use undercloud_crypto::{ContentHashSubkey, ContentHasher};

/// Hashing a fixed plaintext in one `update()` call must produce the same digest as several small, unaligned `update()` calls.
#[test]
fn streaming_equivalence() {
    let plaintext: Vec<u8> = (0..300).map(|i| (i % 256) as u8).collect();
    let key = ContentHashSubkey::from_bytes([0xAB; 32]);

    let mut whole = ContentHasher::new(&key);
    whole.update(&plaintext);
    let whole_digest = whole.finalize();

    // Split at byte 7, 100, 250 -- deliberately not aligned to any natural chunk boundary.
    let mut streamed = ContentHasher::new(&key);
    streamed.update(&plaintext[0..7]);
    streamed.update(&plaintext[7..100]);
    streamed.update(&plaintext[100..250]);
    streamed.update(&plaintext[250..300]);
    let streamed_digest = streamed.finalize();

    assert_eq!(whole_digest, streamed_digest);
}

/// `ContentHasher::new(key).finalize()` with zero `update()` calls is BLAKE3's well-defined keyed hash of the empty input, deterministic across instances.
#[test]
fn empty_input_is_deterministic() {
    let key = ContentHashSubkey::from_bytes([0x5A; 32]);

    let first = ContentHasher::new(&key).finalize();
    let second = ContentHasher::new(&key).finalize();

    assert_eq!(first, second);
}

/// Different keys must produce different hashes for the same plaintext.
#[test]
fn different_keys_produce_different_hashes() {
    let plaintext = b"the same plaintext, hashed under two different keys";

    let key_a = ContentHashSubkey::from_bytes([0x01; 32]);
    let key_b = ContentHashSubkey::from_bytes([0x02; 32]);

    let mut hasher_a = ContentHasher::new(&key_a);
    hasher_a.update(plaintext);

    let mut hasher_b = ContentHasher::new(&key_b);
    hasher_b.update(plaintext);

    assert_ne!(hasher_a.finalize(), hasher_b.finalize());
}
