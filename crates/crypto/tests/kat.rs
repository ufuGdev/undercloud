// SPDX-License-Identifier: Apache-2.0
//! Known-answer tests pinning the on-disk wire format; a failure here means the format silently changed — never "fix" it by updating expected hex without confirming intent and backward-compat impact.
use undercloud_crypto::{
    decrypt_chunk, decrypt_manifest, derive_vault_subkeys, unwrap_dek, unwrap_manifest_key,
    unwrap_master_key, ChunkIdentity, ContentHashSubkey, ContentHasher, DataEncryptionKey,
    EncryptedChunk, EncryptedManifest, FileKeyType, FileKeyWrapSubkey, ManifestIdentity,
    ManifestKey, MasterKey, PasswordEnvelope, WrappedFileKey,
};
use uuid::Uuid;

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_array_24(s: &str) -> [u8; 24] {
    hex_decode(s).try_into().unwrap()
}

fn hex_array_16(s: &str) -> [u8; 16] {
    hex_decode(s).try_into().unwrap()
}

fn hex_array_32(s: &str) -> [u8; 32] {
    hex_decode(s).try_into().unwrap()
}

/// Vector 1: chunk AEAD KAT — dek=0x11×32, nonce=0x22×24, vault_id=0x33×16, file_version_id=0x44×16, format_version=1, chunk_index=0.
#[test]
fn chunk_aead_known_answer_vector() {
    let dek = DataEncryptionKey::from_bytes([0x11; 32]);
    let identity = ChunkIdentity {
        format_version: 1,
        vault_id: Uuid::from_bytes([0x33; 16]),
        file_version_id: Uuid::from_bytes([0x44; 16]),
        chunk_index: 0,
    };
    let nonce = hex_array_24("222222222222222222222222222222222222222222222222");
    let ciphertext_hex = "f60983692eda88fb902934a0dc0d819457f4b7bb67becad4507a56ca5186305d3bb39637e08cae62971302433940465006984e431887e5604a7ab7db86a47d8e34015f799e68b55250bcee704ea2b70a";
    let expected_plaintext =
        b"undercloud kat vector 0001 - fixed test plaintext for chunk AEAD".to_vec();

    let encrypted = EncryptedChunk {
        nonce,
        ciphertext: hex_decode(ciphertext_hex),
    };
    let decrypted = decrypt_chunk(&dek, &identity, &encrypted).unwrap();
    assert_eq!(decrypted, expected_plaintext);
}

/// Same vector with wrong chunk_index — must fail closed against this fixed ciphertext, so a future AAD-encoding change can't accidentally pass.
#[test]
fn chunk_aead_known_answer_vector_rejects_wrong_chunk_index() {
    let dek = DataEncryptionKey::from_bytes([0x11; 32]);
    let wrong_identity = ChunkIdentity {
        format_version: 1,
        vault_id: Uuid::from_bytes([0x33; 16]),
        file_version_id: Uuid::from_bytes([0x44; 16]),
        chunk_index: 1, // was encrypted under chunk_index = 0
    };
    let nonce = hex_array_24("222222222222222222222222222222222222222222222222");
    let ciphertext_hex = "f60983692eda88fb902934a0dc0d819457f4b7bb67becad4507a56ca5186305d3bb39637e08cae62971302433940465006984e431887e5604a7ab7db86a47d8e34015f799e68b55250bcee704ea2b70a";
    let encrypted = EncryptedChunk {
        nonce,
        ciphertext: hex_decode(ciphertext_hex),
    };
    assert!(decrypt_chunk(&dek, &wrong_identity, &encrypted).is_err());
}

/// Vector 5: password envelope KAT (ADR-006); independently verified via argon2-cffi and PyNaCl (see ADR-006's "Independent verification" section) — vault_id=0xD1×16, salt=0xD2×16, m/t/p=19456/2/1, master_key=0xD3×32, nonce=0xD4×24.
#[test]
fn password_envelope_known_answer_vector() {
    let envelope = PasswordEnvelope {
        vault_id: Uuid::from_bytes([0xD1; 16]),
        envelope_version: 1,
        salt: hex_array_16("d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"),
        m_cost: 19_456,
        t_cost: 2,
        p_cost: 1,
        nonce: hex_array_24("d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4"),
        ciphertext: hex_decode(
            "bf9f16ef5f829e942a053806e02652f15dea2b13c250230cfeb3bb677147d954af32f26d8ce1af319f6ab8d14046e6b4",
        ),
    };
    let expected_master_key = [0xD3u8; 32];
    let recovered = unwrap_master_key(
        Uuid::from_bytes([0xD1; 16]),
        "undercloud-m1-kat-vector-0001",
        &envelope,
    )
    .unwrap();
    assert_eq!(recovered.expose_bytes(), &expected_master_key);
}

/// Same envelope, wrong vault_id — must fail closed (AAD mismatch).
#[test]
fn password_envelope_known_answer_vector_rejects_wrong_vault_id() {
    let envelope = PasswordEnvelope {
        vault_id: Uuid::from_bytes([0xD1; 16]),
        envelope_version: 1,
        salt: hex_array_16("d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"),
        m_cost: 19_456,
        t_cost: 2,
        p_cost: 1,
        nonce: hex_array_24("d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4"),
        ciphertext: hex_decode(
            "bf9f16ef5f829e942a053806e02652f15dea2b13c250230cfeb3bb677147d954af32f26d8ce1af319f6ab8d14046e6b4",
        ),
    };
    assert!(unwrap_master_key(
        Uuid::from_bytes([0xFF; 16]),
        "undercloud-m1-kat-vector-0001",
        &envelope
    )
    .is_err());
}

/// Same envelope, wrong password — must fail closed.
#[test]
fn password_envelope_known_answer_vector_rejects_wrong_password() {
    let envelope = PasswordEnvelope {
        vault_id: Uuid::from_bytes([0xD1; 16]),
        envelope_version: 1,
        salt: hex_array_16("d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"),
        m_cost: 19_456,
        t_cost: 2,
        p_cost: 1,
        nonce: hex_array_24("d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4"),
        ciphertext: hex_decode(
            "bf9f16ef5f829e942a053806e02652f15dea2b13c250230cfeb3bb677147d954af32f26d8ce1af319f6ab8d14046e6b4",
        ),
    };
    assert!(unwrap_master_key(Uuid::from_bytes([0xD1; 16]), "wrong-password", &envelope).is_err());
}

/// Sanity check that MasterKey::from_bytes/expose_bytes round-trip the fixed bytes used across these vectors, independent of any AEAD/KDF.
#[test]
fn master_key_from_bytes_matches_known_bytes() {
    let key = MasterKey::from_bytes([0x66; 32]);
    assert_eq!(key.expose_bytes(), &[0x66u8; 32]);
}

/// Vector 3: manifest AEAD KAT — manifest_key=0x88×32, nonce=0x99×24, vault_id=0xAA×16, file_version_id=0xBB×16, format_version=1.
#[test]
fn manifest_aead_known_answer_vector() {
    let key = ManifestKey::from_bytes([0x88; 32]);
    let identity = ManifestIdentity {
        format_version: 1,
        vault_id: Uuid::from_bytes([0xAA; 16]),
        file_version_id: Uuid::from_bytes([0xBB; 16]),
    };
    let nonce = hex_array_24("999999999999999999999999999999999999999999999999");
    let ciphertext_hex = "573ee3474ca9107db68ebe38e2ba649f8e952a0f14488c06bbb46351493b293c53f88a8cf26e16e701696f6b607f8f8947eb4c055a1b5f22063f8a907908153a63fe4f317e3a69e8ff2075897504981e88e2b8913faf89ad22894467";
    let expected_plaintext =
        b"undercloud manifest kat vector 0001 - fixed test plaintext for manifest AEAD".to_vec();

    let encrypted = EncryptedManifest {
        nonce,
        ciphertext: hex_decode(ciphertext_hex),
    };
    let decrypted = decrypt_manifest(&key, &identity, &encrypted).unwrap();
    assert_eq!(decrypted, expected_plaintext);
}

/// Same vector, wrong vault_id — must fail closed.
#[test]
fn manifest_aead_known_answer_vector_rejects_wrong_vault_id() {
    let key = ManifestKey::from_bytes([0x88; 32]);
    let wrong_identity = ManifestIdentity {
        format_version: 1,
        vault_id: Uuid::from_bytes([0xFF; 16]), // was encrypted under 0xAA
        file_version_id: Uuid::from_bytes([0xBB; 16]),
    };
    let nonce = hex_array_24("999999999999999999999999999999999999999999999999");
    let ciphertext_hex = "573ee3474ca9107db68ebe38e2ba649f8e952a0f14488c06bbb46351493b293c53f88a8cf26e16e701696f6b607f8f8947eb4c055a1b5f22063f8a907908153a63fe4f317e3a69e8ff2075897504981e88e2b8913faf89ad22894467";
    let encrypted = EncryptedManifest {
        nonce,
        ciphertext: hex_decode(ciphertext_hex),
    };
    assert!(decrypt_manifest(&key, &wrong_identity, &encrypted).is_err());
}

/// Vector 4: HKDF-SHA256 subkey KAT — master_key=0xC1×32, vault_id=0xC2×16; independently verified against a hand-rolled RFC 5869 HKDF (Python hmac/hashlib, no HKDF lib) — see ADR-006's "Independent verification" section.
#[test]
fn subkey_derivation_known_answer_vector() {
    let master_key = MasterKey::from_bytes([0xC1; 32]);
    let vault_id = Uuid::from_bytes([0xC2; 16]);
    let subkeys = derive_vault_subkeys(&master_key, vault_id);

    assert_eq!(
        hex_encode(subkeys.file_key_wrap.expose_bytes()),
        "0b63a46ec9cc0f21cdf5dc494558fd4e3a94241f39ffd8f05c41882e2f6a9182"
    );
    assert_eq!(
        hex_encode(subkeys.catalog_field.expose_bytes()),
        "5c99035fe676661555da71274b30ccadaabd94e8a44d1dbf32f8f62a71d1999b"
    );
    assert_eq!(
        hex_encode(subkeys.content_hash.expose_bytes()),
        "8da4016bc9081e0f51bed26e6db0f6a14a32943e94775534d6353cb776574f9f"
    );
    assert_eq!(
        hex_encode(subkeys.recovery.expose_bytes()),
        "51058c4acdc62cefbce8541c49c0f715a2ce88313728fed4abd8243500780750"
    );
}

/// Same master_key, different vault_id — file-key-wrap subkey must differ from the vector above.
#[test]
fn subkey_derivation_known_answer_vector_different_vault_id() {
    let master_key = MasterKey::from_bytes([0xC1; 32]);
    let vault_id = Uuid::from_bytes([0xC3; 16]);
    let subkeys = derive_vault_subkeys(&master_key, vault_id);
    assert_eq!(
        hex_encode(subkeys.file_key_wrap.expose_bytes()),
        "56a4667b61d6387252871b21cbb90b379204abf24d65dedd0ede5fe57a1c9e02"
    );
}

/// Different master_key, same vault_id as the primary vector — must also differ.
#[test]
fn subkey_derivation_known_answer_vector_different_master_key() {
    let master_key = MasterKey::from_bytes([0xC4; 32]);
    let vault_id = Uuid::from_bytes([0xC2; 16]);
    let subkeys = derive_vault_subkeys(&master_key, vault_id);
    assert_eq!(
        hex_encode(subkeys.file_key_wrap.expose_bytes()),
        "e3612a21b2450eedbc3aa00097dd08bd61fe273624d85920cc5e3202dc3367ed"
    );
}

/// Vector 6: per-file key wrap KAT (DEK) — independently verified against PyNaCl, incl. cross-type rejection (see ADR-006); subkey=0xE1×32, vault_id=0xE2×16, file_version_id=0xE3×16, key_type=Dek, nonce=0xE5×24.
#[test]
fn file_key_wrap_known_answer_vector_dek() {
    let subkey = FileKeyWrapSubkey::from_bytes([0xE1; 32]);
    let wrapped = WrappedFileKey {
        key_type: FileKeyType::Dek,
        nonce: hex_array_24("e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5"),
        ciphertext: hex_decode(
            "e596a11cdb42cf6c112381416e819c0725b447f7324d8b3894cb66d76cb68ab13a0c9be6d514733327c886d6dabd7e7a",
        ),
    };
    let expected_dek = [0xE4u8; 32];
    let recovered = unwrap_dek(
        &subkey,
        Uuid::from_bytes([0xE2; 16]),
        Uuid::from_bytes([0xE3; 16]),
        &wrapped,
    )
    .unwrap();
    assert_eq!(recovered.expose_bytes(), &expected_dek);
}

/// Same ciphertext, but requested as a ManifestKey — must fail closed.
#[test]
fn file_key_wrap_known_answer_vector_rejects_wrong_key_type() {
    let subkey = FileKeyWrapSubkey::from_bytes([0xE1; 32]);
    let wrapped = WrappedFileKey {
        key_type: FileKeyType::ManifestKey, // mislabeled on purpose
        nonce: hex_array_24("e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5"),
        ciphertext: hex_decode(
            "e596a11cdb42cf6c112381416e819c0725b447f7324d8b3894cb66d76cb68ab13a0c9be6d514733327c886d6dabd7e7a",
        ),
    };
    assert!(unwrap_manifest_key(
        &subkey,
        Uuid::from_bytes([0xE2; 16]),
        Uuid::from_bytes([0xE3; 16]),
        &wrapped
    )
    .is_err());
}

/// KAT vector: key=0xF1×32, plaintext="undercloud content hash m1 vector"; Python blake3 binding cross-checked against BLAKE3's own published test vectors — weaker independence than the AEAD/HKDF vectors (shared Rust blake3 lineage), see ADR-006's caveat.
#[test]
fn content_hash_known_answer_vector() {
    let key = ContentHashSubkey::from_bytes([0xF1; 32]);
    let mut hasher = ContentHasher::new(&key);
    hasher.update(b"undercloud content hash m1 vector");
    let expected = hex_array_32("93a0a85c9e22108a917364e55d708356a4b5e0879f851a558bbee5459faf2dd4");
    assert_eq!(hasher.finalize(), expected);
}
