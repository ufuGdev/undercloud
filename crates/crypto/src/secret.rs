// SPDX-License-Identifier: Apache-2.0
use std::fmt;

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Fixed-size secret buffer that zeroizes on drop and never prints its contents via `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    pub fn from_array(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    pub fn random() -> Self {
        let mut bytes = [0u8; N];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn expose_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes<{N}>(REDACTED)")
    }
}

/// The vault.s random master key is never derived from a password.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(SecretBytes<32>);

impl MasterKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretBytes::from_array(bytes))
    }

    pub fn expose_bytes(&self) -> &[u8; 32] {
        self.0.expose_bytes()
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MasterKey(REDACTED)")
    }
}

/// Generates a fresh master key from the OS CSPRNG.
pub fn generate_master_key() -> MasterKey {
    MasterKey(SecretBytes::random())
}
