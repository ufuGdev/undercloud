// SPDX-License-Identifier: Apache-2.0
//! Hashes whole plaintext before chunking; per-chunk AEAD remains authoritative.
use crate::subkeys::ContentHashSubkey;

/// Wraps a keyed BLAKE3 hasher under the vault content-hash subkey.
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
