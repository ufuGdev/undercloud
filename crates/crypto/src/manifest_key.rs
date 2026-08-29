// SPDX-License-Identifier: Apache-2.0
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::secret::SecretBytes;

/// Key that authenticates a manifest body and is wrapped for persistence.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ManifestKey(SecretBytes<32>);

impl ManifestKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretBytes::from_array(bytes))
    }

    pub fn expose_bytes(&self) -> &[u8; 32] {
        self.0.expose_bytes()
    }
}

pub fn generate_manifest_key() -> ManifestKey {
    ManifestKey(SecretBytes::random())
}
