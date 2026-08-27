// SPDX-License-Identifier: Apache-2.0
use undercloud_crypto::{generate_master_key, MasterKey};

#[test]
fn master_key_is_32_random_bytes_and_not_all_zero() {
    let key: MasterKey = generate_master_key();
    assert_eq!(key.expose_bytes().len(), 32);
    assert!(key.expose_bytes().iter().any(|&b| b != 0));
}

#[test]
fn two_generated_master_keys_differ() {
    let a = generate_master_key();
    let b = generate_master_key();
    assert_ne!(a.expose_bytes(), b.expose_bytes());
}

#[test]
fn master_key_debug_does_not_leak_bytes() {
    let key = generate_master_key();
    let debug_str = format!("{key:?}");
    assert!(!debug_str.contains(&hex::encode(key.expose_bytes())));
}
