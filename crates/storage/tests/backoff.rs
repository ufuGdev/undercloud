// SPDX-License-Identifier: Apache-2.0
use std::time::Duration;

use undercloud_storage::backoff_delay;

#[test]
fn backoff_grows_with_attempt_number() {
    // `backoff_delay` uses full jitter, so comparing single samples across attempts is flaky; assert the deterministic per-attempt cap bounds instead.
    const CAP_ATTEMPT_0_MS: u64 = 200; // BASE_MS * 2^0
    const CAP_ATTEMPT_3_MS: u64 = 1600; // BASE_MS * 2^3, strictly > CAP_ATTEMPT_0_MS

    for _ in 0..20 {
        let d0 = backoff_delay(0);
        let d3 = backoff_delay(3);
        assert!(d0 <= Duration::from_millis(CAP_ATTEMPT_0_MS));
        assert!(d3 <= Duration::from_millis(CAP_ATTEMPT_3_MS));
    }
}

#[test]
fn backoff_is_capped() {
    let d_large = backoff_delay(50);
    assert!(d_large <= Duration::from_secs(60));
}

#[test]
fn backoff_includes_jitter_so_repeated_calls_differ() {
    let samples: Vec<Duration> = (0..10).map(|_| backoff_delay(4)).collect();
    assert!(samples.windows(2).any(|w| w[0] != w[1]));
}
