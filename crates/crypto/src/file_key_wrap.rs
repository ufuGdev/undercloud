// SPDX-License-Identifier: Apache-2.0
//! Wraps randomly generated per-file keys under the vault file-key subkey.
use chacha20poly1305::aead::{Aead, KeyInit, OsRng as AeadOsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use uuid::Uuid;

use crate::dek::DataEncryptionKey;
use crate::error::CryptoError;
use crate::manifest_key::ManifestKey;
use crate::subkeys::FileKeyWrapSubkey;

/// Current wire version of the per-file key wrap AAD.
const FILE_KEY_WRAP_VERSION: u16 = 1;

/// Separates file-key-wrap ciphertext from other envelope types.
const FILE_KEY_WRAP_DOMAIN: u8 = 0x03;

/// Distinguishes wrapped data and manifest keys in the authenticated AAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKeyType {
    Dek = 0x01,
    ManifestKey = 0x02,
}

/// A per-file key bound to its vault, file version, and key type.
#[derive(Debug, Clone)]
pub struct WrappedFileKey {
    pub key_type: FileKeyType,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

fn file_key_wrap_aad(vault_id: Uuid, file_version_id: Uuid, key_type: FileKeyType) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 2 + 16 + 16 + 1);
    aad.push(FILE_KEY_WRAP_DOMAIN);
    aad.extend_from_slice(&FILE_KEY_WRAP_VERSION.to_be_bytes());
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(file_version_id.as_bytes());
    aad.push(key_type as u8);
    aad
}

fn wrap_key_bytes(
    subkey: &FileKeyWrapSubkey,
    vault_id: Uuid,
    file_version_id: Uuid,
    key_type: FileKeyType,
    plaintext: &[u8],
) -> Result<WrappedFileKey, CryptoError> {
    let cipher = XChaCha20Poly1305::new(subkey.expose_bytes().into());
    let mut nonce_bytes = [0u8; 24];
    AeadOsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let aad = file_key_wrap_aad(vault_id, file_version_id, key_type);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    Ok(WrappedFileKey {
        key_type,
        nonce: nonce_bytes,
        ciphertext,
    })
}

fn unwrap_key_bytes(
    subkey: &FileKeyWrapSubkey,
    vault_id: Uuid,
    file_version_id: Uuid,
    expected_type: FileKeyType,
    wrapped: &WrappedFileKey,
) -> Result<[u8; 32], CryptoError> {
    // Check the key type before decryption for a clear failure.
    if wrapped.key_type != expected_type {
        return Err(CryptoError::AuthenticationFailed);
    }

    let cipher = XChaCha20Poly1305::new(subkey.expose_bytes().into());
    let nonce = XNonce::from_slice(&wrapped.nonce);
    let aad = file_key_wrap_aad(vault_id, file_version_id, expected_type);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: wrapped.ciphertext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    plaintext
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)
}

/// Wraps a data-encryption key with identity-bound AAD.
pub fn wrap_dek(
    subkey: &FileKeyWrapSubkey,
    vault_id: Uuid,
    file_version_id: Uuid,
    dek: &DataEncryptionKey,
) -> Result<WrappedFileKey, CryptoError> {
    wrap_key_bytes(
        subkey,
        vault_id,
        file_version_id,
        FileKeyType::Dek,
        dek.expose_bytes().as_slice(),
    )
}

/// Unwraps a data-encryption key and rejects identity or authentication failures.
pub fn unwrap_dek(
    subkey: &FileKeyWrapSubkey,
    vault_id: Uuid,
    file_version_id: Uuid,
    wrapped: &WrappedFileKey,
) -> Result<DataEncryptionKey, CryptoError> {
    let bytes = unwrap_key_bytes(subkey, vault_id, file_version_id, FileKeyType::Dek, wrapped)?;
    Ok(DataEncryptionKey::from_bytes(bytes))
}

/// Wraps a manifest key with identity-bound AAD.
pub fn wrap_manifest_key(
    subkey: &FileKeyWrapSubkey,
    vault_id: Uuid,
    file_version_id: Uuid,
    key: &ManifestKey,
) -> Result<WrappedFileKey, CryptoError> {
    wrap_key_bytes(
        subkey,
        vault_id,
        file_version_id,
        FileKeyType::ManifestKey,
        key.expose_bytes().as_slice(),
    )
}

/// Unwraps a manifest key and rejects identity or authentication failures.
pub fn unwrap_manifest_key(
    subkey: &FileKeyWrapSubkey,
    vault_id: Uuid,
    file_version_id: Uuid,
    wrapped: &WrappedFileKey,
) -> Result<ManifestKey, CryptoError> {
    let bytes = unwrap_key_bytes(
        subkey,
        vault_id,
        file_version_id,
        FileKeyType::ManifestKey,
        wrapped,
    )?;
    Ok(ManifestKey::from_bytes(bytes))
}
