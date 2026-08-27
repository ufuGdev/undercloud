// SPDX-License-Identifier: Apache-2.0
//! Cryptographic primitives for Undercloud's vault key hierarchy, AEAD encryption, and content hashing; no I/O, no provider knowledge, no catalog knowledge — see ADR-002 and ADR-006 for the design.
mod chunk;
mod content_hash;
mod dek;
mod error;
mod file_key_wrap;
mod manifest;
mod manifest_key;
mod secret;
mod subkeys;
mod wrap;

pub use chunk::{decrypt_chunk, encrypt_chunk, ChunkIdentity, EncryptedChunk};
pub use content_hash::ContentHasher;
pub use dek::{generate_dek, DataEncryptionKey};
pub use error::CryptoError;
pub use file_key_wrap::{
    unwrap_dek, unwrap_manifest_key, wrap_dek, wrap_manifest_key, FileKeyType, WrappedFileKey,
};
pub use manifest::{decrypt_manifest, encrypt_manifest, EncryptedManifest, ManifestIdentity};
pub use manifest_key::{generate_manifest_key, ManifestKey};
pub use secret::{generate_master_key, MasterKey, SecretBytes};
pub use subkeys::{
    derive_vault_subkeys, CatalogFieldSubkey, ContentHashSubkey, FileKeyWrapSubkey, RecoverySubkey,
    VaultSubkeys,
};
pub use wrap::{unwrap_master_key, wrap_master_key, PasswordEnvelope, PASSWORD_ENVELOPE_VERSION};
