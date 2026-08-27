// SPDX-License-Identifier: Apache-2.0
use std::time::Duration;

use rand::Rng;

const BASE_MS: u64 = 200;
const CAP: Duration = Duration::from_secs(60);

/// Exponential backoff with full jitter, capped at 60s.
pub fn backoff_delay(attempt: u32) -> Duration {
    let exp_ms = BASE_MS.saturating_mul(1u64 << attempt.min(20));
    let capped_ms = exp_ms.min(CAP.as_millis() as u64);
    let jittered_ms = rand::thread_rng().gen_range(0..=capped_ms.max(1));
    Duration::from_millis(jittered_ms)
}
