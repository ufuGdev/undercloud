// SPDX-License-Identifier: Apache-2.0
//! Keyed content-identity hash (ADR-006) of the whole plaintext before chunking, not the chunk sequence; a post-restore integrity check, never a substitute for per-chunk AEAD (ADR-002).
use crate::subkeys::ContentHashSubkey;

/// Wraps a keyed `blake3::Hasher`; keyed by the vault's `ContentHashSubkey` so the digest can't be recomputed or forged without it.
pub struct ContentHasher(blake3::Hasher);

impl ContentHasher {
    pub fn new(key: &ContentHashSubkey) -> Self {
        Self(blake3::Hasher::new_keyed(key.expose_bytes()))
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finalize(&self) -> [u8; 32] {
        *self.0.finalize().as_bytes()
    }
}
