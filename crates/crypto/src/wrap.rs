// SPDX-License-Identifier: Apache-2.0
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng as AeadOsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::secret::MasterKey;

const M_COST_KIB: u32 = 19_456;
const T_COST: u32 = 2;
const P_COST: u32 = 1;

// Reject absurd persisted Argon2 parameters before hashing.
const MIN_M_COST_KIB: u32 = 8 * 1024; // 8 MiB
const MAX_M_COST_KIB: u32 = 1024 * 1024; // 1 GiB
const MIN_T_COST: u32 = 1;
const MAX_T_COST: u32 = 10;
const MIN_P_COST: u32 = 1;
const MAX_P_COST: u32 = 4;

/// Current password-envelope wire version; mismatches are rejected before AEAD.
pub const PASSWORD_ENVELOPE_VERSION: u16 = 1;

/// Separates password-envelope ciphertext from other envelope types.
const PASSWORD_ENVELOPE_DOMAIN: u8 = 0x01;

/// Identifies the master-key envelope type in authenticated data.
const KEY_ENVELOPE_TYPE_MASTER_KEY: u8 = 0x01;

fn validate_argon2_params(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<(), CryptoError> {
    if !(MIN_M_COST_KIB..=MAX_M_COST_KIB).contains(&m_cost)
        || !(MIN_T_COST..=MAX_T_COST).contains(&t_cost)
        || !(MIN_P_COST..=MAX_P_COST).contains(&p_cost)
    {
        return Err(CryptoError::InvalidKeyLength);
    }
    Ok(())
}

/// Password-wrapped master key bound to vault, version, and Argon2 parameters.
#[derive(Debug, Clone)]
pub struct PasswordEnvelope {
    pub vault_id: Uuid,
    pub envelope_version: u16,
    pub salt: [u8; 16],
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

fn password_envelope_aad(
    vault_id: Uuid,
    envelope_version: u16,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 2 + 16 + 4 + 4 + 4 + 1);
    aad.push(PASSWORD_ENVELOPE_DOMAIN);
    aad.extend_from_slice(&envelope_version.to_be_bytes());
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(&m_cost.to_be_bytes());
    aad.extend_from_slice(&t_cost.to_be_bytes());
    aad.extend_from_slice(&p_cost.to_be_bytes());
    aad.push(KEY_ENVELOPE_TYPE_MASTER_KEY);
    aad
}

fn derive_password_key(
    password: &str,
    salt: &[u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    validate_argon2_params(m_cost, t_cost, p_cost)?;
    let params =
        Params::new(m_cost, t_cost, p_cost, Some(32)).map_err(|_| CryptoError::InvalidKeyLength)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|_| CryptoError::UnwrapFailed)?;
    Ok(Zeroizing::new(out))
}

pub fn wrap_master_key(
    vault_id: Uuid,
    password: &str,
    key: &MasterKey,
) -> Result<PasswordEnvelope, CryptoError> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let pdk_bytes = derive_password_key(password, &salt, M_COST_KIB, T_COST, P_COST)?;

    let cipher = XChaCha20Poly1305::new((&*pdk_bytes).into());
    let mut nonce_bytes = [0u8; 24];
    AeadOsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let aad = password_envelope_aad(
        vault_id,
        PASSWORD_ENVELOPE_VERSION,
        M_COST_KIB,
        T_COST,
        P_COST,
    );
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: key.expose_bytes().as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::UnwrapFailed)?;

    Ok(PasswordEnvelope {
        vault_id,
        envelope_version: PASSWORD_ENVELOPE_VERSION,
        salt,
        m_cost: M_COST_KIB,
        t_cost: T_COST,
        p_cost: P_COST,
        nonce: nonce_bytes,
        ciphertext,
    })
}

pub fn unwrap_master_key(
    vault_id: Uuid,
    password: &str,
    envelope: &PasswordEnvelope,
) -> Result<MasterKey, CryptoError> {
    if envelope.envelope_version != PASSWORD_ENVELOPE_VERSION {
        return Err(CryptoError::UnwrapFailed);
    }

    validate_argon2_params(envelope.m_cost, envelope.t_cost, envelope.p_cost)?;

    let pdk_bytes = derive_password_key(
        password,
        &envelope.salt,
        envelope.m_cost,
        envelope.t_cost,
        envelope.p_cost,
    )?;
    let cipher = XChaCha20Poly1305::new((&*pdk_bytes).into());
    let nonce = XNonce::from_slice(&envelope.nonce);
    let aad = password_envelope_aad(
        vault_id,
        envelope.envelope_version,
        envelope.m_cost,
        envelope.t_cost,
        envelope.p_cost,
    );

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: envelope.ciphertext.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::UnwrapFailed)?,
    );

    let bytes: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    Ok(MasterKey::from_bytes(bytes))
}

/// Verifies Argon2 parameter bounds before hashing.
#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> PasswordEnvelope {
        let vault_id = Uuid::from_bytes([0x01; 16]);
        let key = MasterKey::from_bytes([0x02; 32]);
        wrap_master_key(vault_id, "correct horse battery staple", &key).unwrap()
    }

    /// Confirms invalid parameters fail before Argon2 runs.
    fn assert_rejected_before_argon2_runs(envelope: &PasswordEnvelope) {
        let vault_id = Uuid::from_bytes([0x01; 16]);
        let start = std::time::Instant::now();
        let result = unwrap_master_key(vault_id, "correct horse battery staple", envelope);
        let elapsed = start.elapsed();
        assert!(matches!(result, Err(CryptoError::InvalidKeyLength)));
        assert!(
            elapsed < std::time::Duration::from_millis(100),
            "expected rejection before Argon2 ran, took {elapsed:?}"
        );
    }

    #[test]
    fn rejects_m_cost_below_minimum() {
        let mut envelope = sample_envelope();
        envelope.m_cost = MIN_M_COST_KIB - 1;
        assert_rejected_before_argon2_runs(&envelope);
    }

    #[test]
    fn rejects_m_cost_above_maximum() {
        let mut envelope = sample_envelope();
        envelope.m_cost = MAX_M_COST_KIB + 1;
        assert_rejected_before_argon2_runs(&envelope);
    }

    #[test]
    fn rejects_t_cost_below_minimum() {
        let mut envelope = sample_envelope();
        envelope.t_cost = MIN_T_COST - 1;
        assert_rejected_before_argon2_runs(&envelope);
    }

    #[test]
    fn rejects_t_cost_above_maximum() {
        let mut envelope = sample_envelope();
        envelope.t_cost = MAX_T_COST + 1;
        assert_rejected_before_argon2_runs(&envelope);
    }

    #[test]
    fn rejects_p_cost_below_minimum() {
        let mut envelope = sample_envelope();
        envelope.p_cost = MIN_P_COST - 1;
        assert_rejected_before_argon2_runs(&envelope);
    }

    #[test]
    fn rejects_p_cost_above_maximum() {
        let mut envelope = sample_envelope();
        envelope.p_cost = MAX_P_COST + 1;
        assert_rejected_before_argon2_runs(&envelope);
    }
}
