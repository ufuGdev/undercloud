// SPDX-License-Identifier: Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;
use undercloud_format::parse_chunk_envelope;

fuzz_target!(|data: &[u8]| {
    // Must never panic, regardless of input.
    let _ = parse_chunk_envelope(data);
});
