// SPDX-License-Identifier: Apache-2.0
use uuid::Uuid;

use crate::error::FormatError;

pub const MANIFEST_MAGIC: [u8; 4] = *b"UCLM";
pub const MANIFEST_FORMAT_VERSION: u16 = 1;

const ENVELOPE_HEADER_LEN: usize = 4 + 2 + 16 + 16 + 24; // 62 bytes

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEnvelope {
    pub format_version: u16,
    pub vault_id: Uuid,
    pub file_version_id: Uuid,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

pub fn serialize_manifest_envelope(env: &ManifestEnvelope) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENVELOPE_HEADER_LEN + env.ciphertext.len());
    out.extend_from_slice(&MANIFEST_MAGIC);
    out.extend_from_slice(&env.format_version.to_be_bytes());
    out.extend_from_slice(env.vault_id.as_bytes());
    out.extend_from_slice(env.file_version_id.as_bytes());
    out.extend_from_slice(&env.nonce);
    out.extend_from_slice(&env.ciphertext);
    out
}

pub fn parse_manifest_envelope(bytes: &[u8]) -> Result<ManifestEnvelope, FormatError> {
    if bytes.len() < ENVELOPE_HEADER_LEN {
        return Err(FormatError::Truncated);
    }
    if bytes[0..4] != MANIFEST_MAGIC {
        return Err(FormatError::InvalidMagic);
    }
    let format_version = u16::from_be_bytes([bytes[4], bytes[5]]);
    // Versioning policy: readers accept any version <= MANIFEST_FORMAT_VERSION and reject newer ones, writers always emit the current version; add a parse branch here (keeping old ones) when a new version is introduced.
    if format_version == 0 || format_version > MANIFEST_FORMAT_VERSION {
        return Err(FormatError::UnsupportedVersion(format_version));
    }
    let vault_id = Uuid::from_slice(&bytes[6..22]).map_err(|_| FormatError::Truncated)?;
    let file_version_id = Uuid::from_slice(&bytes[22..38]).map_err(|_| FormatError::Truncated)?;
    let nonce: [u8; 24] = bytes[38..62].try_into().unwrap();
    let ciphertext = bytes[62..].to_vec();

    Ok(ManifestEnvelope {
        format_version,
        vault_id,
        file_version_id,
        nonce,
        ciphertext,
    })
}

// --- TLV inner body (the plaintext structure, before/after encryption) ---

const TAG_FILE_SIZE: u16 = 0x0001;
const TAG_CHUNK_COUNT: u16 = 0x0002;
const TAG_CONTENT_HASH: u16 = 0x0003;
const CRITICAL_BIT: u16 = 0x8000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestBody {
    pub file_size: u64,
    pub chunk_count: u32,
    pub content_hash: [u8; 32],
}

fn write_tlv(out: &mut Vec<u8>, tag: u16, value: &[u8]) {
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

pub fn serialize_manifest_body(body: &ManifestBody) -> Vec<u8> {
    let mut out = Vec::new();
    write_tlv(&mut out, TAG_FILE_SIZE, &body.file_size.to_be_bytes());
    write_tlv(&mut out, TAG_CHUNK_COUNT, &body.chunk_count.to_be_bytes());
    write_tlv(&mut out, TAG_CONTENT_HASH, &body.content_hash);
    out
}

pub fn parse_manifest_body(bytes: &[u8]) -> Result<ManifestBody, FormatError> {
    let mut file_size: Option<u64> = None;
    let mut chunk_count: Option<u32> = None;
    let mut content_hash: Option<[u8; 32]> = None;

    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if bytes.len() - cursor < 6 {
            return Err(FormatError::Truncated);
        }
        let tag = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
        let len = u32::from_be_bytes(bytes[cursor + 2..cursor + 6].try_into().unwrap()) as usize;
        cursor += 6;
        if bytes.len() - cursor < len {
            return Err(FormatError::Truncated);
        }
        let value = &bytes[cursor..cursor + len];
        cursor += len;

        match tag {
            TAG_FILE_SIZE => {
                if file_size.is_some() {
                    return Err(FormatError::UnknownCriticalField(tag));
                }
                file_size = Some(u64::from_be_bytes(
                    value.try_into().map_err(|_| FormatError::Truncated)?,
                ));
            }
            TAG_CHUNK_COUNT => {
                if chunk_count.is_some() {
                    return Err(FormatError::UnknownCriticalField(tag));
                }
                chunk_count = Some(u32::from_be_bytes(
                    value.try_into().map_err(|_| FormatError::Truncated)?,
                ));
            }
            TAG_CONTENT_HASH => {
                if content_hash.is_some() {
                    return Err(FormatError::UnknownCriticalField(tag));
                }
                content_hash = Some(value.try_into().map_err(|_| FormatError::Truncated)?);
            }
            unknown if unknown & CRITICAL_BIT != 0 => {
                return Err(FormatError::UnknownCriticalField(unknown));
            }
            _ => {
                // Unknown, non-critical: skip, already advanced cursor past it.
            }
        }
    }

    Ok(ManifestBody {
        file_size: file_size.ok_or(FormatError::Truncated)?,
        chunk_count: chunk_count.ok_or(FormatError::Truncated)?,
        content_hash: content_hash.ok_or(FormatError::Truncated)?,
    })
}
