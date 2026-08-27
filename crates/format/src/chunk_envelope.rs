// SPDX-License-Identifier: Apache-2.0
use uuid::Uuid;

use crate::error::FormatError;

pub const MAGIC: [u8; 4] = *b"UCLD";
pub const CHUNK_FORMAT_VERSION: u16 = 1;

const HEADER_LEN: usize = 4 + 2 + 16 + 16 + 8 + 24; // 70 bytes

/// A parsed, on-disk chunk envelope — security: its fields come from untrusted bytes, never build `ChunkIdentity` from them directly, always look it up from the manifest's chunk list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkEnvelope {
    pub format_version: u16,
    pub vault_id: Uuid,
    pub file_version_id: Uuid,
    pub chunk_index: u64,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

pub fn serialize_chunk_envelope(env: &ChunkEnvelope) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + env.ciphertext.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&env.format_version.to_be_bytes());
    out.extend_from_slice(env.vault_id.as_bytes());
    out.extend_from_slice(env.file_version_id.as_bytes());
    out.extend_from_slice(&env.chunk_index.to_be_bytes());
    out.extend_from_slice(&env.nonce);
    out.extend_from_slice(&env.ciphertext);
    out
}

/// Parses the on-disk chunk envelope header + ciphertext; see the security note on [`ChunkEnvelope`] about not building `ChunkIdentity` from the returned fields.
pub fn parse_chunk_envelope(bytes: &[u8]) -> Result<ChunkEnvelope, FormatError> {
    if bytes.len() < HEADER_LEN {
        return Err(FormatError::Truncated);
    }
    if bytes[0..4] != MAGIC {
        return Err(FormatError::InvalidMagic);
    }
    let format_version = u16::from_be_bytes([bytes[4], bytes[5]]);
    // Versioning policy: readers accept any version <= CHUNK_FORMAT_VERSION and reject newer ones, writers always emit the current version; add a parse branch here (keeping old ones) when a new version is introduced.
    if format_version == 0 || format_version > CHUNK_FORMAT_VERSION {
        return Err(FormatError::UnsupportedVersion(format_version));
    }

    let vault_id = Uuid::from_slice(&bytes[6..22]).map_err(|_| FormatError::Truncated)?;
    let file_version_id = Uuid::from_slice(&bytes[22..38]).map_err(|_| FormatError::Truncated)?;
    let chunk_index = u64::from_be_bytes(bytes[38..46].try_into().unwrap());
    let nonce: [u8; 24] = bytes[46..70].try_into().unwrap();
    let ciphertext = bytes[70..].to_vec();

    Ok(ChunkEnvelope {
        format_version,
        vault_id,
        file_version_id,
        chunk_index,
        nonce,
        ciphertext,
    })
}
