// SPDX-License-Identifier: Apache-2.0
use proptest::prelude::*;
use undercloud_format::{parse_manifest_body, ManifestBody};

proptest! {
    #[test]
    fn parser_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = parse_manifest_body(&bytes);
    }

    #[test]
    fn valid_body_always_round_trips(
        file_size in any::<u64>(),
        chunk_count in any::<u32>(),
        hash_seed in any::<u8>(),
    ) {
        let body = ManifestBody {
            file_size,
            chunk_count,
            content_hash: [hash_seed; 32],
        };
        let bytes = undercloud_format::serialize_manifest_body(&body);
        let parsed = parse_manifest_body(&bytes).unwrap();
        prop_assert_eq!(parsed, body);
    }
}
