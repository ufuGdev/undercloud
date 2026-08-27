// SPDX-License-Identifier: Apache-2.0
use proptest::prelude::*;
use undercloud_crypto::{decrypt_chunk, encrypt_chunk, generate_dek, ChunkIdentity};
use uuid::Uuid;

proptest! {
    #[test]
    fn round_trip_holds_for_random_sizes(plaintext in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let dek = generate_dek();
        let id = ChunkIdentity {
            format_version: 1,
            vault_id: Uuid::from_u128(1),
            file_version_id: Uuid::from_u128(2),
            chunk_index: 0,
        };
        let encrypted = encrypt_chunk(&dek, &id, &plaintext).unwrap();
        let decrypted = decrypt_chunk(&dek, &id, &encrypted).unwrap();
        prop_assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn single_bit_flip_in_ciphertext_always_fails_auth(
        plaintext in proptest::collection::vec(any::<u8>(), 1..512),
        flip_byte_seed in any::<usize>(),
    ) {
        let dek = generate_dek();
        let id = ChunkIdentity {
            format_version: 1,
            vault_id: Uuid::from_u128(1),
            file_version_id: Uuid::from_u128(2),
            chunk_index: 0,
        };
        let mut encrypted = encrypt_chunk(&dek, &id, &plaintext).unwrap();
        let idx = flip_byte_seed % encrypted.ciphertext.len();
        encrypted.ciphertext[idx] ^= 0x01;
        prop_assert!(decrypt_chunk(&dek, &id, &encrypted).is_err());
    }
}
