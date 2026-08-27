// SPDX-License-Identifier: Apache-2.0
use undercloud_crypto::generate_master_key;

#[test]
fn master_key_display_and_debug_never_contain_raw_bytes() {
    let key = generate_master_key();
    let raw_hex = hex::encode(key.expose_bytes());
    let debug_str = format!("{key:?}");
    assert!(!debug_str.contains(&raw_hex));
    assert!(debug_str.contains("REDACTED"));
}
