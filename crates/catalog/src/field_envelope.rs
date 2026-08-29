// SPDX-License-Identifier: Apache-2.0
//! Field envelopes encrypt sensitive catalog fields with identity-bound AAD.
use chacha20poly1305::aead::{Aead, KeyInit, OsRng as AeadOsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use uuid::Uuid;

use undercloud_crypto::{CatalogFieldSubkey, CryptoError};

use crate::error::CatalogError;

/// Identifies the table bound into field-envelope authentication.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityType {
    Vault = 0x01,
    StorageTarget = 0x02,
    LogicalFolder = 0x03,
    LogicalFile = 0x04,
    Replica = 0x05,
    ActivityEvent = 0x06,
}

/// Which column (logical field) within an entity's row a field-encrypted value belongs to.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldTag {
    Name = 0x01,
    ProviderConfig = 0x02,
    ProviderLocator = 0x03,
    Mime = 0x04,
    /// Reserved, unused in Milestone 1 — no description field exists in this milestone's UI.
    Description = 0x05,
    DisplayName = 0x06,
}

/// The one and only field-envelope wire format version this crate currently supports.
pub const FIELD_ENVELOPE_VERSION: u16 = 1;

/// Domain-separation byte for catalog field-envelope AAD.
const FIELD_ENVELOPE_DOMAIN: u8 = 0x04;

/// Fixed header length; shorter values cannot contain a valid envelope.
const FIELD_ENVELOPE_HEADER_LEN: usize = 2 + 24;

fn field_envelope_aad(
    vault_id: Uuid,
    envelope_version: u16,
    entity_type: EntityType,
    entity_id: Uuid,
    field_tag: FieldTag,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 2 + 16 + 1 + 16 + 1);
    aad.push(FIELD_ENVELOPE_DOMAIN);
    aad.extend_from_slice(&envelope_version.to_be_bytes());
    aad.extend_from_slice(vault_id.as_bytes());
    aad.push(entity_type as u8);
    aad.extend_from_slice(entity_id.as_bytes());
    aad.push(field_tag as u8);
    aad
}

/// Encrypts plaintext with AAD binding its catalog identity and field tag.
pub fn encrypt_field(
    subkey: &CatalogFieldSubkey,
    vault_id: Uuid,
    entity_type: EntityType,
    entity_id: Uuid,
    field_tag: FieldTag,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(subkey.expose_bytes().into());
    let mut nonce_bytes = [0u8; 24];
    AeadOsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let aad = field_envelope_aad(
        vault_id,
        FIELD_ENVELOPE_VERSION,
        entity_type,
        entity_id,
        field_tag,
    );

    let ciphertext = cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    let mut envelope = Vec::with_capacity(FIELD_ENVELOPE_HEADER_LEN + ciphertext.len());
    envelope.extend_from_slice(&FIELD_ENVELOPE_VERSION.to_be_bytes());
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

/// Decrypts after recomputing AAD from trusted catalog identity fields.
pub fn decrypt_field(
    subkey: &CatalogFieldSubkey,
    vault_id: Uuid,
    entity_type: EntityType,
    entity_id: Uuid,
    field_tag: FieldTag,
    envelope_bytes: &[u8],
) -> Result<Vec<u8>, CatalogError> {
    if envelope_bytes.len() < FIELD_ENVELOPE_HEADER_LEN {
        return Err(CatalogError::Truncated);
    }

    let envelope_version = u16::from_be_bytes([envelope_bytes[0], envelope_bytes[1]]);
    if envelope_version != FIELD_ENVELOPE_VERSION {
        return Err(CatalogError::UnsupportedFieldEnvelopeVersion {
            found: envelope_version,
        });
    }

    let nonce_bytes = &envelope_bytes[2..FIELD_ENVELOPE_HEADER_LEN];
    let ciphertext = &envelope_bytes[FIELD_ENVELOPE_HEADER_LEN..];

    let cipher = XChaCha20Poly1305::new(subkey.expose_bytes().into());
    let nonce = XNonce::from_slice(nonce_bytes);
    let aad = field_envelope_aad(
        vault_id,
        envelope_version,
        entity_type,
        entity_id,
        field_tag,
    );

    let plaintext = cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    Ok(plaintext)
}
