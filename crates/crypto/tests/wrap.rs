// SPDX-License-Identifier: Apache-2.0
use undercloud_crypto::{
    generate_master_key, unwrap_master_key, wrap_master_key, PasswordEnvelope,
};
use uuid::Uuid;

fn vault_id_a() -> Uuid {
    Uuid::from_bytes([0xA1; 16])
}

fn vault_id_b() -> Uuid {
    Uuid::from_bytes([0xB2; 16])
}

#[test]
fn wrap_then_unwrap_recovers_the_same_master_key() {
    let key = generate_master_key();
    let wrapped = wrap_master_key(vault_id_a(), "correct horse battery staple", &key).unwrap();
    let recovered =
        unwrap_master_key(vault_id_a(), "correct horse battery staple", &wrapped).unwrap();
    assert_eq!(key.expose_bytes(), recovered.expose_bytes());
}

#[test]
fn unwrap_with_wrong_password_fails_closed() {
    let key = generate_master_key();
    let wrapped = wrap_master_key(vault_id_a(), "correct horse battery staple", &key).unwrap();
    let result = unwrap_master_key(vault_id_a(), "wrong password", &wrapped);
    assert!(result.is_err());
}

#[test]
fn two_wraps_of_the_same_key_use_different_salts_and_nonces() {
    let key = generate_master_key();
    let a = wrap_master_key(vault_id_a(), "pw", &key).unwrap();
    let b = wrap_master_key(vault_id_a(), "pw", &key).unwrap();
    assert_ne!(a.salt, b.salt);
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.ciphertext, b.ciphertext);
}

#[test]
fn unwrap_rejects_absurd_persisted_argon2_params_without_hashing() {
    // An absurd m_cost (~4 GiB) must be rejected before Params::new/Argon2, which could OOM or abort the process (panic="abort" release profile) during unlock; assert both the error and that it returned fast.
    let key = generate_master_key();
    let mut wrapped = wrap_master_key(vault_id_a(), "correct horse battery staple", &key).unwrap();
    wrapped.m_cost = 4_000_000; // ~4 GiB, far outside sane bounds

    let start = std::time::Instant::now();
    let result = unwrap_master_key(vault_id_a(), "correct horse battery staple", &wrapped);
    let elapsed = start.elapsed();

    assert!(result.is_err());
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "unwrap_master_key should reject out-of-bounds params before hashing, took {elapsed:?}"
    );
}

#[test]
fn password_change_reruns_wrap_without_changing_underlying_key() {
    let key = generate_master_key();
    let wrapped_old = wrap_master_key(vault_id_a(), "old-password", &key).unwrap();
    let wrapped_new = wrap_master_key(vault_id_a(), "new-password", &key).unwrap();
    let recovered_old = unwrap_master_key(vault_id_a(), "old-password", &wrapped_old).unwrap();
    let recovered_new = unwrap_master_key(vault_id_a(), "new-password", &wrapped_new).unwrap();
    assert_eq!(recovered_old.expose_bytes(), recovered_new.expose_bytes());
}

/// ADR-006's cross-vault rejection: an envelope wrapped for `vault_id_a` must fail to unwrap under `vault_id_b`, since the AAD binds `vault_id`.
#[test]
fn unwrap_rejects_correct_envelope_under_a_different_vault_id() {
    let key = generate_master_key();
    let wrapped = wrap_master_key(vault_id_a(), "correct horse battery staple", &key).unwrap();
    let result = unwrap_master_key(vault_id_b(), "correct horse battery staple", &wrapped);
    assert!(result.is_err());
}

/// Ciphertext/tag tampering must fail closed; closes a gap Milestone 0's wrap.rs lacked, mirroring the chunk/manifest AEAD tampering tests.
#[test]
fn tampering_with_ciphertext_fails_closed() {
    let key = generate_master_key();
    let mut wrapped = wrap_master_key(vault_id_a(), "correct horse battery staple", &key).unwrap();
    let last = wrapped.ciphertext.len() - 1;
    wrapped.ciphertext[last] ^= 0xFF;
    assert!(unwrap_master_key(vault_id_a(), "correct horse battery staple", &wrapped).is_err());
}

/// Tampering with the authentication tag (final 16 bytes of `ciphertext` under XChaCha20-Poly1305's combined encoding) must also fail closed.
#[test]
fn tampering_with_authentication_tag_fails_closed() {
    let key = generate_master_key();
    let mut wrapped = wrap_master_key(vault_id_a(), "correct horse battery staple", &key).unwrap();
    let tag_start = wrapped.ciphertext.len() - 16;
    wrapped.ciphertext[tag_start] ^= 0xFF;
    assert!(unwrap_master_key(vault_id_a(), "correct horse battery staple", &wrapped).is_err());
}

/// An `envelope_version` other than the current `PASSWORD_ENVELOPE_VERSION` must be rejected before AEAD is touched (ADR-006), for a clear error instead of a confusing auth failure.
#[test]
fn unwrap_rejects_unsupported_envelope_version() {
    let key = generate_master_key();
    let mut wrapped = wrap_master_key(vault_id_a(), "correct horse battery staple", &key).unwrap();
    wrapped.envelope_version = 2; // one past PASSWORD_ENVELOPE_VERSION
    assert!(unwrap_master_key(vault_id_a(), "correct horse battery staple", &wrapped).is_err());
}

/// ADR-006's AAD includes a key-envelope-type byte (`KEY_ENVELOPE_TYPE_MASTER_KEY = 0x01`); no second envelope type exists yet, so this test hand-builds a wrong-type AAD with the same primitives to verify the byte is checked at all.
#[test]
fn unwrap_rejects_ciphertext_produced_with_a_different_key_envelope_type_byte() {
    use argon2::{Algorithm, Argon2, Params, Version};
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    let vault_id = vault_id_a();
    let password = "correct horse battery staple";
    let salt = [0x12u8; 16];
    let m_cost: u32 = 19_456;
    let t_cost: u32 = 2;
    let p_cost: u32 = 1;
    let nonce_bytes = [0x34u8; 24];
    let envelope_version: u16 = 1;

    let params = Params::new(m_cost, t_cost, p_cost, Some(32)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut pdk = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut pdk)
        .unwrap();

    // AAD identical to production's password_envelope_aad, except the final key-envelope-type byte is 0x02 instead of the real 0x01.
    let mut wrong_type_aad = Vec::with_capacity(1 + 2 + 16 + 4 + 4 + 4 + 1);
    wrong_type_aad.push(0x01); // PASSWORD_ENVELOPE_DOMAIN, unchanged
    wrong_type_aad.extend_from_slice(&envelope_version.to_be_bytes());
    wrong_type_aad.extend_from_slice(vault_id.as_bytes());
    wrong_type_aad.extend_from_slice(&m_cost.to_be_bytes());
    wrong_type_aad.extend_from_slice(&t_cost.to_be_bytes());
    wrong_type_aad.extend_from_slice(&p_cost.to_be_bytes());
    wrong_type_aad.push(0x02); // WRONG: real production value is 0x01

    let cipher = XChaCha20Poly1305::new((&pdk).into());
    let nonce = XNonce::from_slice(&nonce_bytes);
    let master_key_plaintext = [0x9Au8; 32];
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &master_key_plaintext,
                aad: &wrong_type_aad,
            },
        )
        .unwrap();

    let envelope = PasswordEnvelope {
        vault_id,
        envelope_version,
        salt,
        m_cost,
        t_cost,
        p_cost,
        nonce: nonce_bytes,
        ciphertext,
    };

    // Production computes the AAD with type byte 0x01, which won't match the 0x02 this ciphertext was authenticated under, so this must fail closed.
    assert!(unwrap_master_key(vault_id, password, &envelope).is_err());
}
