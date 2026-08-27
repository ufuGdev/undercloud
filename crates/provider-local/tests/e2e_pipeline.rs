// SPDX-License-Identifier: Apache-2.0
//! End-to-end test: plaintext -> chunk -> encrypt -> wire-format -> LocalProvider -> retrieve -> parse/authenticate -> decrypt -> exact plaintext recovery, plus negative cases proving every tamper path fails closed; manifest bodies are AEAD-encrypted with a per-file `ManifestKey` whose AAD binds envelope type, format_version, vault_id, and file_version_id (deriving the key from the vault master key via subkey derivation instead of random minting remains Milestone 1 scope).
use std::io::Cursor;

use tempfile::tempdir;
use tokio::io::AsyncReadExt;
use undercloud_chunker::chunk_stream;
use undercloud_crypto::{
    decrypt_chunk, decrypt_manifest, encrypt_chunk, encrypt_manifest, generate_dek,
    generate_manifest_key, ChunkIdentity, DataEncryptionKey, EncryptedChunk, EncryptedManifest,
    ManifestIdentity, ManifestKey,
};
use undercloud_format::{
    parse_chunk_envelope, parse_manifest_body, parse_manifest_envelope, serialize_chunk_envelope,
    serialize_manifest_body, serialize_manifest_envelope, ChunkEnvelope, FormatError, ManifestBody,
    ManifestEnvelope,
};
use undercloud_provider_local::LocalProvider;
use undercloud_storage::{
    GetObjectRequest, ObjectLocator, ProviderError, PutObjectRequest, StorageProvider,
};
use uuid::Uuid;

const CHUNK_SIZE: usize = 64;

fn synthetic_plaintext() -> Vec<u8> {
    // 4 full chunks + 1 partial chunk, so multi-chunk and non-aligned-final-chunk are both covered in one file.
    (0..(CHUNK_SIZE * 4 + 17))
        .map(|i| (i % 251) as u8)
        .collect()
}

fn chunk_locator(file_version_id: Uuid, index: u64) -> ObjectLocator {
    ObjectLocator(format!("chunk-{}-{}", file_version_id.simple(), index))
}

fn manifest_locator(file_version_id: Uuid) -> ObjectLocator {
    ObjectLocator(format!("manifest-{}", file_version_id.simple()))
}

/// Splits, encrypts, formats, and stores `plaintext` under a fresh vault_id/file_version_id/DEK, returning everything the restore path needs so tests can corrupt one piece before restoring.
struct StoredFile {
    provider: LocalProvider,
    dek: DataEncryptionKey,
    manifest_key: ManifestKey,
    vault_id: Uuid,
    file_version_id: Uuid,
    chunk_count: u64,
    // Kept for symmetry with the fields callers need to reconstruct a StoredFile; restore_file() recomputes the hash from the fetched manifest instead of reading this field, so it's intentionally unread here.
    #[allow(dead_code)]
    content_hash: [u8; 32],
}

async fn store_file(root: &std::path::Path, plaintext: &[u8]) -> StoredFile {
    let provider = LocalProvider::new(root);
    let dek = generate_dek();
    let vault_id = Uuid::new_v4();
    let file_version_id = Uuid::new_v4();
    let content_hash: [u8; 32] = blake3::hash(plaintext).into();

    let mut rx = chunk_stream(Cursor::new(plaintext.to_vec()), CHUNK_SIZE)
        .await
        .expect("valid chunk size must be accepted");
    let mut chunk_count = 0u64;
    while let Some(chunk_result) = rx.recv().await {
        let chunk_bytes = chunk_result.unwrap();
        let identity = ChunkIdentity {
            format_version: 1,
            vault_id,
            file_version_id,
            chunk_index: chunk_count,
        };
        let encrypted = encrypt_chunk(&dek, &identity, &chunk_bytes).unwrap();
        let envelope = ChunkEnvelope {
            format_version: 1,
            vault_id,
            file_version_id,
            chunk_index: chunk_count,
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
        };
        let envelope_bytes = serialize_chunk_envelope(&envelope);
        provider
            .put_object(PutObjectRequest {
                locator: chunk_locator(file_version_id, chunk_count),
                body: Box::pin(Cursor::new(envelope_bytes.clone())),
                expected_size: envelope_bytes.len() as u64,
            })
            .await
            .unwrap();
        chunk_count += 1;
    }

    let manifest_body = ManifestBody {
        file_size: plaintext.len() as u64,
        chunk_count: chunk_count as u32,
        content_hash,
    };
    let manifest_body_bytes = serialize_manifest_body(&manifest_body);
    let manifest_key = generate_manifest_key();
    let manifest_identity = ManifestIdentity {
        format_version: 1,
        vault_id,
        file_version_id,
    };
    let encrypted_manifest =
        encrypt_manifest(&manifest_key, &manifest_identity, &manifest_body_bytes).unwrap();
    let manifest_envelope = ManifestEnvelope {
        format_version: 1,
        vault_id,
        file_version_id,
        nonce: encrypted_manifest.nonce,
        ciphertext: encrypted_manifest.ciphertext,
    };
    let manifest_bytes = serialize_manifest_envelope(&manifest_envelope);
    provider
        .put_object(PutObjectRequest {
            locator: manifest_locator(file_version_id),
            body: Box::pin(Cursor::new(manifest_bytes.clone())),
            expected_size: manifest_bytes.len() as u64,
        })
        .await
        .unwrap();

    StoredFile {
        provider,
        dek,
        manifest_key,
        vault_id,
        file_version_id,
        chunk_count,
        content_hash,
    }
}

async fn get_bytes(
    provider: &LocalProvider,
    locator: ObjectLocator,
) -> Result<Vec<u8>, ProviderError> {
    let mut stream = provider
        .get_object(GetObjectRequest {
            locator,
            range: None,
        })
        .await?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(ProviderError::Io)?;
    Ok(buf)
}

/// Restores the full file: fetches the manifest, then every chunk in order, decrypting and concatenating; errors at the first failure rather than assembling a partial result.
async fn restore_file(stored: &StoredFile) -> Result<Vec<u8>, String> {
    let manifest_bytes = get_bytes(&stored.provider, manifest_locator(stored.file_version_id))
        .await
        .map_err(|e| format!("manifest fetch failed: {e}"))?;
    let manifest_envelope = parse_manifest_envelope(&manifest_bytes)
        .map_err(|e| format!("manifest envelope parse failed: {e}"))?;

    let manifest_identity = ManifestIdentity {
        format_version: 1,
        vault_id: stored.vault_id,
        file_version_id: stored.file_version_id,
    };
    let encrypted_manifest = EncryptedManifest {
        nonce: manifest_envelope.nonce,
        ciphertext: manifest_envelope.ciphertext,
    };
    let manifest_body_bytes = decrypt_manifest(
        &stored.manifest_key,
        &manifest_identity,
        &encrypted_manifest,
    )
    .map_err(|e| format!("manifest authentication failed: {e}"))?;
    let manifest_body = parse_manifest_body(&manifest_body_bytes)
        .map_err(|e| format!("manifest body parse failed: {e}"))?;

    let mut plaintext = Vec::new();
    for index in 0..(manifest_body.chunk_count as u64) {
        let envelope_bytes = get_bytes(
            &stored.provider,
            chunk_locator(stored.file_version_id, index),
        )
        .await
        .map_err(|e| format!("chunk {index} fetch failed: {e}"))?;
        let envelope = parse_chunk_envelope(&envelope_bytes)
            .map_err(|e| format!("chunk {index} envelope parse failed: {e}"))?;
        let identity = ChunkIdentity {
            format_version: 1,
            vault_id: stored.vault_id,
            file_version_id: stored.file_version_id,
            chunk_index: index,
        };
        let encrypted = EncryptedChunk {
            nonce: envelope.nonce,
            ciphertext: envelope.ciphertext,
        };
        let decrypted = decrypt_chunk(&stored.dek, &identity, &encrypted)
            .map_err(|e| format!("chunk {index} decryption failed: {e}"))?;
        plaintext.extend_from_slice(&decrypted);
    }

    let recomputed_hash: [u8; 32] = blake3::hash(&plaintext).into();
    if recomputed_hash != manifest_body.content_hash {
        return Err("content_hash mismatch after restore".to_string());
    }

    Ok(plaintext)
}

// --- Positive case ---

#[tokio::test]
async fn full_pipeline_round_trips_multi_chunk_file_exactly() {
    let dir = tempdir().unwrap();
    let plaintext = synthetic_plaintext();
    let stored = store_file(dir.path(), &plaintext).await;
    assert!(stored.chunk_count >= 4, "test file must be multi-chunk");

    let restored = restore_file(&stored).await.unwrap();
    assert_eq!(restored, plaintext);
}

// --- Negative cases ---

#[tokio::test]
async fn corrupted_ciphertext_byte_is_rejected() {
    let dir = tempdir().unwrap();
    let plaintext = synthetic_plaintext();
    let stored = store_file(dir.path(), &plaintext).await;

    let loc = chunk_locator(stored.file_version_id, 0);
    let mut bytes = get_bytes(&stored.provider, loc.clone()).await.unwrap();
    let last = bytes.len() - 1;
    bytes[last - 20] ^= 0xff; // flip a byte in the ciphertext body
    stored
        .provider
        .put_object(PutObjectRequest {
            locator: loc,
            body: Box::pin(Cursor::new(bytes.clone())),
            expected_size: bytes.len() as u64,
        })
        .await
        .unwrap();

    let result = restore_file(&stored).await;
    assert!(
        result.is_err(),
        "corrupted ciphertext must not restore successfully"
    );
}

#[tokio::test]
async fn modified_authentication_tag_is_rejected() {
    let dir = tempdir().unwrap();
    let plaintext = synthetic_plaintext();
    let stored = store_file(dir.path(), &plaintext).await;

    let loc = chunk_locator(stored.file_version_id, 0);
    let mut bytes = get_bytes(&stored.provider, loc.clone()).await.unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff; // flip the final byte, inside the 16-byte Poly1305 tag
    stored
        .provider
        .put_object(PutObjectRequest {
            locator: loc,
            body: Box::pin(Cursor::new(bytes.clone())),
            expected_size: bytes.len() as u64,
        })
        .await
        .unwrap();

    let result = restore_file(&stored).await;
    assert!(
        result.is_err(),
        "modified auth tag must not restore successfully"
    );
}

#[tokio::test]
async fn reordered_chunks_are_rejected() {
    let dir = tempdir().unwrap();
    let plaintext = synthetic_plaintext();
    let stored = store_file(dir.path(), &plaintext).await;
    assert!(stored.chunk_count >= 2);

    // Swap the stored bytes at chunk-0's and chunk-1's locators.
    let loc0 = chunk_locator(stored.file_version_id, 0);
    let loc1 = chunk_locator(stored.file_version_id, 1);
    let bytes0 = get_bytes(&stored.provider, loc0.clone()).await.unwrap();
    let bytes1 = get_bytes(&stored.provider, loc1.clone()).await.unwrap();

    stored
        .provider
        .put_object(PutObjectRequest {
            locator: loc0,
            body: Box::pin(Cursor::new(bytes1.clone())),
            expected_size: bytes1.len() as u64,
        })
        .await
        .unwrap();
    stored
        .provider
        .put_object(PutObjectRequest {
            locator: loc1,
            body: Box::pin(Cursor::new(bytes0.clone())),
            expected_size: bytes0.len() as u64,
        })
        .await
        .unwrap();

    let result = restore_file(&stored).await;
    assert!(
        result.is_err(),
        "reordered chunks must not restore successfully"
    );
}

#[tokio::test]
async fn chunk_substituted_from_another_file_version_is_rejected() {
    let dir = tempdir().unwrap();
    let plaintext_a = synthetic_plaintext();
    let stored_a = store_file(dir.path(), &plaintext_a).await;

    // A second, unrelated file stored in the same provider root.
    let plaintext_b = b"a completely different file's content, also multi-chunk in size aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec();
    let stored_b = store_file(dir.path(), &plaintext_b).await;

    // Substitute file B's chunk 0 into file A's chunk-0 slot.
    let loc_a0 = chunk_locator(stored_a.file_version_id, 0);
    let loc_b0 = chunk_locator(stored_b.file_version_id, 0);
    let bytes_b0 = get_bytes(&stored_b.provider, loc_b0).await.unwrap();
    stored_a
        .provider
        .put_object(PutObjectRequest {
            locator: loc_a0,
            body: Box::pin(Cursor::new(bytes_b0.clone())),
            expected_size: bytes_b0.len() as u64,
        })
        .await
        .unwrap();

    let result = restore_file(&stored_a).await;
    assert!(
        result.is_err(),
        "chunk substituted from another file version must not restore successfully"
    );
}

#[tokio::test]
async fn modified_manifest_envelope_header_is_rejected() {
    let dir = tempdir().unwrap();
    let plaintext = synthetic_plaintext();
    let stored = store_file(dir.path(), &plaintext).await;

    let loc = manifest_locator(stored.file_version_id);
    let mut bytes = get_bytes(&stored.provider, loc.clone()).await.unwrap();
    bytes[0] = b'X'; // corrupt the manifest envelope's magic bytes
    stored
        .provider
        .put_object(PutObjectRequest {
            locator: loc,
            body: Box::pin(Cursor::new(bytes.clone())),
            expected_size: bytes.len() as u64,
        })
        .await
        .unwrap();

    let result = restore_file(&stored).await;
    assert!(
        result.is_err(),
        "modified manifest envelope header must not restore successfully"
    );
}

#[tokio::test]
async fn manifest_with_unsupported_critical_field_is_rejected_by_parser() {
    // Targets FormatError::UnknownCriticalField: encryption/decryption succeed over the malformed TLV body since AEAD doesn't know TLV semantics; only parse_manifest_body rejects it, proving the two layers compose rather than one masking the other.
    let body = ManifestBody {
        file_size: 10,
        chunk_count: 1,
        content_hash: [0u8; 32],
    };
    let mut body_bytes = serialize_manifest_body(&body);
    let critical_unknown_tag: u16 = 0x8abc;
    body_bytes.extend_from_slice(&critical_unknown_tag.to_be_bytes());
    body_bytes.extend_from_slice(&2u32.to_be_bytes());
    body_bytes.extend_from_slice(&[0xaa, 0xbb]);

    let vault_id = Uuid::new_v4();
    let file_version_id = Uuid::new_v4();
    let manifest_key = generate_manifest_key();
    let manifest_identity = ManifestIdentity {
        format_version: 1,
        vault_id,
        file_version_id,
    };
    let encrypted_manifest =
        encrypt_manifest(&manifest_key, &manifest_identity, &body_bytes).unwrap();
    let envelope = ManifestEnvelope {
        format_version: 1,
        vault_id,
        file_version_id,
        nonce: encrypted_manifest.nonce,
        ciphertext: encrypted_manifest.ciphertext,
    };
    let envelope_bytes = serialize_manifest_envelope(&envelope);

    let dir = tempdir().unwrap();
    let provider = LocalProvider::new(dir.path());
    let loc = ObjectLocator("manifest-with-critical-field".to_string());
    provider
        .put_object(PutObjectRequest {
            locator: loc.clone(),
            body: Box::pin(Cursor::new(envelope_bytes.clone())),
            expected_size: envelope_bytes.len() as u64,
        })
        .await
        .unwrap();

    let retrieved = get_bytes(&provider, loc).await.unwrap();
    let retrieved_envelope = parse_manifest_envelope(&retrieved).unwrap();
    let retrieved_encrypted = EncryptedManifest {
        nonce: retrieved_envelope.nonce,
        ciphertext: retrieved_envelope.ciphertext,
    };
    let decrypted_body_bytes =
        decrypt_manifest(&manifest_key, &manifest_identity, &retrieved_encrypted)
            .expect("authentic, unmodified ciphertext must decrypt successfully");
    let result = parse_manifest_body(&decrypted_body_bytes);
    assert!(
        matches!(result, Err(FormatError::UnknownCriticalField(tag)) if tag == critical_unknown_tag)
    );
}

#[tokio::test]
async fn manifest_with_duplicate_tlv_tag_is_rejected_by_parser() {
    let body = ManifestBody {
        file_size: 10,
        chunk_count: 1,
        content_hash: [0u8; 32],
    };
    let mut body_bytes = serialize_manifest_body(&body);
    // Append a second file_size (tag 0x0001) field - duplicate.
    body_bytes.extend_from_slice(&0x0001u16.to_be_bytes());
    body_bytes.extend_from_slice(&8u32.to_be_bytes());
    body_bytes.extend_from_slice(&999u64.to_be_bytes());

    let vault_id = Uuid::new_v4();
    let file_version_id = Uuid::new_v4();
    let manifest_key = generate_manifest_key();
    let manifest_identity = ManifestIdentity {
        format_version: 1,
        vault_id,
        file_version_id,
    };
    let encrypted_manifest =
        encrypt_manifest(&manifest_key, &manifest_identity, &body_bytes).unwrap();
    let envelope = ManifestEnvelope {
        format_version: 1,
        vault_id,
        file_version_id,
        nonce: encrypted_manifest.nonce,
        ciphertext: encrypted_manifest.ciphertext,
    };
    let envelope_bytes = serialize_manifest_envelope(&envelope);

    let dir = tempdir().unwrap();
    let provider = LocalProvider::new(dir.path());
    let loc = ObjectLocator("manifest-with-duplicate-tag".to_string());
    provider
        .put_object(PutObjectRequest {
            locator: loc.clone(),
            body: Box::pin(Cursor::new(envelope_bytes.clone())),
            expected_size: envelope_bytes.len() as u64,
        })
        .await
        .unwrap();

    let retrieved = get_bytes(&provider, loc).await.unwrap();
    let retrieved_envelope = parse_manifest_envelope(&retrieved).unwrap();
    let retrieved_encrypted = EncryptedManifest {
        nonce: retrieved_envelope.nonce,
        ciphertext: retrieved_envelope.ciphertext,
    };
    let decrypted_body_bytes =
        decrypt_manifest(&manifest_key, &manifest_identity, &retrieved_encrypted)
            .expect("authentic, unmodified ciphertext must decrypt successfully");
    let result = parse_manifest_body(&decrypted_body_bytes);
    assert!(result.is_err(), "duplicate TLV tag must be rejected");
}

#[tokio::test]
async fn missing_chunk_is_rejected() {
    let dir = tempdir().unwrap();
    let plaintext = synthetic_plaintext();
    let stored = store_file(dir.path(), &plaintext).await;

    let loc = chunk_locator(stored.file_version_id, 1);
    stored.provider.delete_object(&loc).await.unwrap();

    let result = restore_file(&stored).await;
    assert!(
        result.is_err(),
        "missing chunk must not restore successfully"
    );
}

/// Closes the semantic-tamper gap of a coordinated chunk_count + recomputed content_hash edit (previously a truncated file restored successfully): without the manifest key, the attacker cannot re-encrypt the edited body into a ciphertext that passes AEAD authentication.
#[tokio::test]
async fn manifest_body_semantic_tamper_is_rejected_by_aead_authentication() {
    let dir = tempdir().unwrap();
    let plaintext = synthetic_plaintext();
    let stored = store_file(dir.path(), &plaintext).await;
    assert_eq!(
        stored.chunk_count, 5,
        "test assumes synthetic_plaintext() chunks into exactly 5 pieces \
         at CHUNK_SIZE=64 (4 full chunks of 64 + 1 partial chunk of 17)"
    );

    // Drop the last 2 of 5 chunks and recompute content_hash to match the truncated plaintext; without the manifest key the attacker can only write forged bytes, not a ciphertext that authenticates under the real key.
    let reduced_chunk_count: u32 = stored.chunk_count as u32 - 2; // 5 -> 3
    let truncated_len = reduced_chunk_count as usize * CHUNK_SIZE; // 192
    assert!(truncated_len < plaintext.len(), "must be a real truncation");
    let truncated_hash: [u8; 32] = blake3::hash(&plaintext[..truncated_len]).into();
    let forged_body = ManifestBody {
        file_size: truncated_len as u64,
        chunk_count: reduced_chunk_count,
        content_hash: truncated_hash,
    };
    let forged_body_bytes = serialize_manifest_body(&forged_body);
    let forged_envelope = ManifestEnvelope {
        format_version: 1,
        vault_id: stored.vault_id,
        file_version_id: stored.file_version_id,
        nonce: [0xAB; 24], // attacker-chosen; cannot know the real key regardless
        ciphertext: forged_body_bytes, // plaintext bytes, NOT real AEAD ciphertext
    };
    let forged_bytes = serialize_manifest_envelope(&forged_envelope);
    stored
        .provider
        .put_object(PutObjectRequest {
            locator: manifest_locator(stored.file_version_id),
            body: Box::pin(Cursor::new(forged_bytes.clone())),
            expected_size: forged_bytes.len() as u64,
        })
        .await
        .unwrap();

    let result = restore_file(&stored).await;
    assert!(
        result.is_err(),
        "manifest body forged without the manifest key must fail AEAD authentication, not restore a truncated file"
    );
}

#[tokio::test]
async fn corrupted_manifest_ciphertext_byte_is_rejected() {
    let dir = tempdir().unwrap();
    let plaintext = synthetic_plaintext();
    let stored = store_file(dir.path(), &plaintext).await;

    let loc = manifest_locator(stored.file_version_id);
    let mut bytes = get_bytes(&stored.provider, loc.clone()).await.unwrap();
    let last = bytes.len() - 1;
    bytes[last - 20] ^= 0xff; // flip a byte in the manifest ciphertext body
    stored
        .provider
        .put_object(PutObjectRequest {
            locator: loc,
            body: Box::pin(Cursor::new(bytes.clone())),
            expected_size: bytes.len() as u64,
        })
        .await
        .unwrap();

    let result = restore_file(&stored).await;
    assert!(
        result.is_err(),
        "corrupted manifest ciphertext must not restore successfully"
    );
}

#[tokio::test]
async fn modified_manifest_authentication_tag_is_rejected() {
    let dir = tempdir().unwrap();
    let plaintext = synthetic_plaintext();
    let stored = store_file(dir.path(), &plaintext).await;

    let loc = manifest_locator(stored.file_version_id);
    let mut bytes = get_bytes(&stored.provider, loc.clone()).await.unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff; // flip the final byte, inside the 16-byte Poly1305 tag
    stored
        .provider
        .put_object(PutObjectRequest {
            locator: loc,
            body: Box::pin(Cursor::new(bytes.clone())),
            expected_size: bytes.len() as u64,
        })
        .await
        .unwrap();

    let result = restore_file(&stored).await;
    assert!(
        result.is_err(),
        "modified manifest auth tag must not restore successfully"
    );
}

/// This schema has no separate "file_id" vs "file_version_id" concept, so substituting a manifest from a different file and substituting an earlier version of the same file are the same mechanism, both caught by the AAD's file_version_id binding.
#[tokio::test]
async fn manifest_copied_from_another_file_version_is_rejected() {
    let dir = tempdir().unwrap();
    let plaintext_a = synthetic_plaintext();
    let stored_a = store_file(dir.path(), &plaintext_a).await;

    // A second, unrelated file stored in the same provider root.
    let plaintext_b = b"a completely different file's content, also multi-chunk in size aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec();
    let stored_b = store_file(dir.path(), &plaintext_b).await;

    // Take file A's fully-authentic manifest envelope bytes verbatim (not re-encrypted) and store them under file B's manifest locator.
    let loc_a = manifest_locator(stored_a.file_version_id);
    let loc_b = manifest_locator(stored_b.file_version_id);
    let bytes_a = get_bytes(&stored_a.provider, loc_a).await.unwrap();
    stored_b
        .provider
        .put_object(PutObjectRequest {
            locator: loc_b,
            body: Box::pin(Cursor::new(bytes_a.clone())),
            expected_size: bytes_a.len() as u64,
        })
        .await
        .unwrap();

    let result = restore_file(&stored_b).await;
    assert!(
        result.is_err(),
        "a perfectly valid manifest for a different file must not authenticate under this file's identity"
    );
}

// --- Multi-target replication / repair demonstration: crates/core's orchestration (SyncJob, RepairJob) is Milestone 1 scope; this proves the underlying mechanism sound using existing crates: replicate to 2 roots, lose one, restore from the survivor, repair without ever decrypting. ---
#[tokio::test]
async fn two_target_replication_survives_one_target_loss_and_repairs() {
    let base = tempdir().unwrap();
    let root_a = base.path().join("target-a");
    let root_b = base.path().join("target-b");
    std::fs::create_dir_all(&root_a).unwrap();
    std::fs::create_dir_all(&root_b).unwrap();

    let plaintext = synthetic_plaintext();
    let dek = generate_dek();
    let vault_id = Uuid::new_v4();
    let file_version_id = Uuid::new_v4();
    let content_hash: [u8; 32] = blake3::hash(&plaintext).into();

    let provider_a = LocalProvider::new(&root_a);
    let provider_b = LocalProvider::new(&root_b);

    // Mirror 2x: put every chunk (and the manifest) to BOTH targets.
    let mut rx = chunk_stream(Cursor::new(plaintext.clone()), CHUNK_SIZE)
        .await
        .expect("valid chunk size must be accepted");
    let mut chunk_count = 0u64;
    while let Some(chunk_result) = rx.recv().await {
        let chunk_bytes = chunk_result.unwrap();
        let identity = ChunkIdentity {
            format_version: 1,
            vault_id,
            file_version_id,
            chunk_index: chunk_count,
        };
        let encrypted = encrypt_chunk(&dek, &identity, &chunk_bytes).unwrap();
        let envelope = ChunkEnvelope {
            format_version: 1,
            vault_id,
            file_version_id,
            chunk_index: chunk_count,
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
        };
        let envelope_bytes = serialize_chunk_envelope(&envelope);
        for provider in [&provider_a, &provider_b] {
            provider
                .put_object(PutObjectRequest {
                    locator: chunk_locator(file_version_id, chunk_count),
                    body: Box::pin(Cursor::new(envelope_bytes.clone())),
                    expected_size: envelope_bytes.len() as u64,
                })
                .await
                .unwrap();
        }
        chunk_count += 1;
    }
    let manifest_body = ManifestBody {
        file_size: plaintext.len() as u64,
        chunk_count: chunk_count as u32,
        content_hash,
    };
    let manifest_body_bytes = serialize_manifest_body(&manifest_body);
    let manifest_key = generate_manifest_key();
    let manifest_identity = ManifestIdentity {
        format_version: 1,
        vault_id,
        file_version_id,
    };
    let encrypted_manifest =
        encrypt_manifest(&manifest_key, &manifest_identity, &manifest_body_bytes).unwrap();
    let manifest_bytes = serialize_manifest_envelope(&ManifestEnvelope {
        format_version: 1,
        vault_id,
        file_version_id,
        nonce: encrypted_manifest.nonce,
        ciphertext: encrypted_manifest.ciphertext,
    });
    for provider in [&provider_a, &provider_b] {
        provider
            .put_object(PutObjectRequest {
                locator: manifest_locator(file_version_id),
                body: Box::pin(Cursor::new(manifest_bytes.clone())),
                expected_size: manifest_bytes.len() as u64,
            })
            .await
            .unwrap();
    }

    // Simulate total loss of target A.
    std::fs::remove_dir_all(&root_a).unwrap();

    // Restore must still succeed from target B alone.
    let stored_via_b = StoredFile {
        provider: LocalProvider::new(&root_b),
        dek: DataEncryptionKey::from_bytes(*dek.expose_bytes()),
        manifest_key: manifest_key.clone(),
        vault_id,
        file_version_id,
        chunk_count,
        content_hash,
    };
    let restored = restore_file(&stored_via_b).await.unwrap();
    assert_eq!(
        restored, plaintext,
        "must restore exactly from the surviving target"
    );

    // Repair: replace target A with a fresh empty root and copy every already-encrypted object from surviving target B to it, without ever decrypting during the copy.
    let root_a_replacement = base.path().join("target-a-replacement");
    std::fs::create_dir_all(&root_a_replacement).unwrap();
    let provider_a_replacement = LocalProvider::new(&root_a_replacement);

    for index in 0..chunk_count {
        let loc = chunk_locator(file_version_id, index);
        let bytes = get_bytes(&provider_b, loc.clone()).await.unwrap();
        provider_a_replacement
            .put_object(PutObjectRequest {
                locator: loc,
                body: Box::pin(Cursor::new(bytes.clone())),
                expected_size: bytes.len() as u64,
            })
            .await
            .unwrap();
    }
    let manifest_loc = manifest_locator(file_version_id);
    let manifest_bytes_from_b = get_bytes(&provider_b, manifest_loc.clone()).await.unwrap();
    provider_a_replacement
        .put_object(PutObjectRequest {
            locator: manifest_loc,
            body: Box::pin(Cursor::new(manifest_bytes_from_b.clone())),
            expected_size: manifest_bytes_from_b.len() as u64,
        })
        .await
        .unwrap();

    // 2/2 replica coverage restored: both targets now independently authenticate and restore the exact original plaintext.
    for root in [&root_a_replacement, &root_b] {
        let stored = StoredFile {
            provider: LocalProvider::new(root),
            dek: DataEncryptionKey::from_bytes(*dek.expose_bytes()),
            manifest_key: manifest_key.clone(),
            vault_id,
            file_version_id,
            chunk_count,
            content_hash,
        };
        let restored = restore_file(&stored).await.unwrap();
        assert_eq!(restored, plaintext);
    }
}
