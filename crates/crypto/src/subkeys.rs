// SPDX-License-Identifier: Apache-2.0
//! Derives purpose-specific vault subkeys with HKDF-SHA-256 from master-key material.
use hkdf::Hkdf;
use sha2::Sha256;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::secret::{MasterKey, SecretBytes};

const FILE_KEY_WRAP_LABEL: &[u8] = b"undercloud/file-key-wrap/v1";
const CATALOG_FIELD_LABEL: &[u8] = b"undercloud/catalog-field/v1";
const CONTENT_HASH_LABEL: &[u8] = b"undercloud/content-hash/v1";
const RECOVERY_LABEL: &[u8] = b"undercloud/recovery/v1";

/// Wraps per-file keys for persistence while keeping their types distinct.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct FileKeyWrapSubkey(SecretBytes<32>);

impl FileKeyWrapSubkey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretBytes::from_array(bytes))
    }

    pub fn expose_bytes(&self) -> &[u8; 32] {
        self.0.expose_bytes()
    }
}

/// Encrypts sensitive catalog field values; nominally distinct from the other three subkey types.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CatalogFieldSubkey(SecretBytes<32>);

impl CatalogFieldSubkey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretBytes::from_array(bytes))
    }

    pub fn expose_bytes(&self) -> &[u8; 32] {
        self.0.expose_bytes()
    }
}

/// Key for content-identity hashing.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ContentHashSubkey(SecretBytes<32>);

impl ContentHashSubkey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretBytes::from_array(bytes))
    }

    pub fn expose_bytes(&self) -> &[u8; 32] {
        self.0.expose_bytes()
    }
}

/// Key for protecting the recovery-kit catalog snapshot.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoverySubkey(SecretBytes<32>);

impl RecoverySubkey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretBytes::from_array(bytes))
    }

    pub fn expose_bytes(&self) -> &[u8; 32] {
        self.0.expose_bytes()
    }
}

/// All purpose-specific subkeys derived for one vault.
#[derive(Clone)]
pub struct VaultSubkeys {
    pub file_key_wrap: FileKeyWrapSubkey,
    pub catalog_field: CatalogFieldSubkey,
    pub content_hash: ContentHashSubkey,
    pub recovery: RecoverySubkey,
}

fn expand_subkey(hkdf: &Hkdf<Sha256>, label: &[u8], vault_id: Uuid) -> [u8; 32] {
    let mut info = Vec::with_capacity(label.len() + 16);
    info.extend_from_slice(label);
    info.extend_from_slice(vault_id.as_bytes());

    let mut okm = [0u8; 32];
    hkdf.expand(&info, &mut okm)
        .expect("32-byte okm is a valid HKDF-SHA256 output length");
    okm
}

/// Derives all four vault subkeys from the master key and vault ID.
pub fn derive_vault_subkeys(master_key: &MasterKey, vault_id: Uuid) -> VaultSubkeys {
    let hkdf = Hkdf::<Sha256>::new(None, master_key.expose_bytes());

    VaultSubkeys {
        file_key_wrap: FileKeyWrapSubkey::from_bytes(expand_subkey(
            &hkdf,
            FILE_KEY_WRAP_LABEL,
            vault_id,
        )),
        catalog_field: CatalogFieldSubkey::from_bytes(expand_subkey(
            &hkdf,
            CATALOG_FIELD_LABEL,
            vault_id,
        )),
        content_hash: ContentHashSubkey::from_bytes(expand_subkey(
            &hkdf,
            CONTENT_HASH_LABEL,
            vault_id,
        )),
        recovery: RecoverySubkey::from_bytes(expand_subkey(&hkdf, RECOVERY_LABEL, vault_id)),
    }
}
