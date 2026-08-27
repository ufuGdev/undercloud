// SPDX-License-Identifier: Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;
use undercloud_format::{parse_manifest_body, parse_manifest_envelope};

fuzz_target!(|data: &[u8]| {
    let _ = parse_manifest_envelope(data);
    let _ = parse_manifest_body(data);
});
