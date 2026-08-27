// SPDX-License-Identifier: Apache-2.0
use undercloud_crypto::{decrypt_chunk, encrypt_chunk, generate_dek, ChunkIdentity};
use uuid::Uuid;

fn identity(chunk_index: u64) -> ChunkIdentity {
    ChunkIdentity {
        format_version: 1,
        vault_id: Uuid::from_u128(1),
        file_version_id: Uuid::from_u128(2),
        chunk_index,
    }
}

#[test]
fn round_trip_recovers_plaintext() {
    let dek = generate_dek();
    let id = identity(0);
    let plaintext = b"hello undercloud".to_vec();
    let encrypted = encrypt_chunk(&dek, &id, &plaintext).unwrap();
    let decrypted = decrypt_chunk(&dek, &id, &encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn tampering_with_ciphertext_fails_closed() {
    let dek = generate_dek();
    let id = identity(0);
    let mut encrypted = encrypt_chunk(&dek, &id, b"payload").unwrap();
    encrypted.ciphertext[0] ^= 0xFF;
    assert!(decrypt_chunk(&dek, &id, &encrypted).is_err());
}

#[test]
fn chunk_reorder_is_rejected() {
    // Encrypted as index 0, decrypted as index 1 — simulates a tampered manifest pointing at the wrong slot.
    let dek = generate_dek();
    let encrypted = encrypt_chunk(&dek, &identity(0), b"payload").unwrap();
    let result = decrypt_chunk(&dek, &identity(1), &encrypted);
    assert!(result.is_err());
}

#[test]
fn cross_file_chunk_substitution_is_rejected() {
    let dek = generate_dek();
    let mut id_file_a = identity(0);
    id_file_a.file_version_id = uuid::Uuid::from_u128(100);
    let mut id_file_b = identity(0);
    id_file_b.file_version_id = uuid::Uuid::from_u128(200);

    let encrypted_for_a = encrypt_chunk(&dek, &id_file_a, b"payload").unwrap();
    let result = decrypt_chunk(&dek, &id_file_b, &encrypted_for_a);
    assert!(result.is_err());
}

#[test]
fn two_encryptions_of_same_plaintext_use_different_nonces_and_ciphertext() {
    let dek = generate_dek();
    let id = identity(0);
    let a = encrypt_chunk(&dek, &id, b"same plaintext").unwrap();
    let b = encrypt_chunk(&dek, &id, b"same plaintext").unwrap();
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.ciphertext, b.ciphertext);
}
