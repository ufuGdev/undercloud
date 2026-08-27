// SPDX-License-Identifier: Apache-2.0
//! Versioned wire format for encrypted chunk and manifest envelopes; moves opaque encrypted bytes, has no encryption keys.

mod chunk_envelope;
mod error;
mod manifest;
pub use chunk_envelope::{
    parse_chunk_envelope, serialize_chunk_envelope, ChunkEnvelope, CHUNK_FORMAT_VERSION, MAGIC,
};
pub use error::FormatError;
pub use manifest::{
    parse_manifest_body, parse_manifest_envelope, serialize_manifest_body,
    serialize_manifest_envelope, ManifestBody, ManifestEnvelope, MANIFEST_FORMAT_VERSION,
    MANIFEST_MAGIC,
};
