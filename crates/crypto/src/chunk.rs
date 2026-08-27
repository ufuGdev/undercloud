// SPDX-License-Identifier: Apache-2.0
use chacha20poly1305::aead::{Aead, KeyInit, OsRng as AeadOsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use uuid::Uuid;

use crate::dek::DataEncryptionKey;
use crate::error::CryptoError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkIdentity {
    pub format_version: u16,
    pub vault_id: Uuid,
    pub file_version_id: Uuid,
    pub chunk_index: u64,
}

impl ChunkIdentity {
    fn to_aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(2 + 16 + 16 + 8);
        aad.extend_from_slice(&self.format_version.to_be_bytes());
        aad.extend_from_slice(self.vault_id.as_bytes());
        aad.extend_from_slice(self.file_version_id.as_bytes());
        aad.extend_from_slice(&self.chunk_index.to_be_bytes());
        aad
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedChunk {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

pub fn encrypt_chunk(
    dek: &DataEncryptionKey,
    identity: &ChunkIdentity,
    plaintext: &[u8],
) -> Result<EncryptedChunk, CryptoError> {
    let cipher = XChaCha20Poly1305::new(dek.expose_bytes().into());
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

    Ok(EncryptedChunk {
        nonce: nonce_bytes,
        ciphertext,
    })
}

pub fn decrypt_chunk(
    dek: &DataEncryptionKey,
    identity: &ChunkIdentity,
    chunk: &EncryptedChunk,
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(dek.expose_bytes().into());
    let nonce = XNonce::from_slice(&chunk.nonce);
    let aad = identity.to_aad();

    cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: &chunk.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}
