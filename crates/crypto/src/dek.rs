// SPDX-License-Identifier: Apache-2.0
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::secret::SecretBytes;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DataEncryptionKey(SecretBytes<32>);

impl DataEncryptionKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretBytes::from_array(bytes))
    }

    pub fn expose_bytes(&self) -> &[u8; 32] {
        self.0.expose_bytes()
    }
}

pub fn generate_dek() -> DataEncryptionKey {
    DataEncryptionKey(SecretBytes::random())
}
