// SPDX-License-Identifier: Apache-2.0
use chacha20poly1305::aead::{Aead, KeyInit, OsRng as AeadOsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use uuid::Uuid;

use crate::error::CryptoError;
use crate::manifest_key::ManifestKey;

/// Domain-separation byte for manifest AEAD AAD; chunk envelopes lack an equivalent since `ChunkIdentity::to_aad` predates this convention and its KAT vectors are pinned — new envelope types should follow this pattern, not the chunk one.
const MANIFEST_ENVELOPE_TYPE: u8 = 0x02;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestIdentity {
    pub format_version: u16,
    pub vault_id: Uuid,
    pub file_version_id: Uuid,
}

impl ManifestIdentity {
    fn to_aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(1 + 2 + 16 + 16);
        aad.push(MANIFEST_ENVELOPE_TYPE);
        aad.extend_from_slice(&self.format_version.to_be_bytes());
        aad.extend_from_slice(self.vault_id.as_bytes());
        aad.extend_from_slice(self.file_version_id.as_bytes());
        aad
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedManifest {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

pub fn encrypt_manifest(
    key: &ManifestKey,
    identity: &ManifestIdentity,
    plaintext: &[u8],
) -> Result<EncryptedManifest, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.expose_bytes().into());
    let mut nonce_bytes = [0u8; 24];
    AeadOsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let aad = identity.to_aad();
    let ciphertext = cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    Ok(EncryptedManifest {
        nonce: nonce_bytes,
        ciphertext,
    })
}

pub fn decrypt_manifest(
    key: &ManifestKey,
    identity: &ManifestIdentity,
    manifest: &EncryptedManifest,
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.expose_bytes().into());
    let nonce = XNonce::from_slice(&manifest.nonce);
    let aad = identity.to_aad();

    cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: &manifest.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}
