// SPDX-License-Identifier: Apache-2.0
//! Purpose-specific vault subkeys derived via HKDF-SHA-256 (ADR-006); no salt passed to `Hkdf::new` since the master key is already high-entropy CSPRNG IKM.
use hkdf::Hkdf;
use sha2::Sha256;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::secret::{MasterKey, SecretBytes};

const FILE_KEY_WRAP_LABEL: &[u8] = b"undercloud/file-key-wrap/v1";
const CATALOG_FIELD_LABEL: &[u8] = b"undercloud/catalog-field/v1";
const CONTENT_HASH_LABEL: &[u8] = b"undercloud/content-hash/v1";
const RECOVERY_LABEL: &[u8] = b"undercloud/recovery/v1";

/// Wraps per-file `DataEncryptionKey`/`ManifestKey` for persistence; nominally distinct from the other three subkey types despite all wrapping 32 secret bytes.
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

/// Keys the content-identity hash (`ContentHasher`); nominally distinct from the other three subkey types.
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

/// Protects the recovery-kit's embedded catalog snapshot; nominally distinct from the other three subkey types.
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

/// The complete set of purpose-specific subkeys derived from a vault's master key for one `vault_id`.
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

/// Derives all four purpose-specific vault subkeys from `master_key` and `vault_id` via HKDF-SHA-256 (ADR-006); `info = label || vault_id.as_bytes()`, no salt passed to `Hkdf::new`.
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
