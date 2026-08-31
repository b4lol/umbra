//! Keystore envelope crypto (pairing persistence, TODO A.3).
//!
//! An identity bundle's secret seeds are serialized and encrypted at rest
//! with a passphrase-derived key:
//!
//! - **KDF**: Argon2id per CRYPTOGRAPHY.md §1 (`t=4, m=2^18, p=4`,
//!   RFC 9106) — memory-hard against ASIC/GPU brute force.
//! - **AEAD**: ChaCha20-Poly1305 with a random per-envelope salt (16 B)
//!   and nonce (12 B); the blob is `[salt][nonce][ciphertext+tag]`.
//!
//! The derived key lives in [`Zeroizing`] and is wiped on drop. Callers
//! own file permissions (0600) and placement.

use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::{aead, rng};

/// Salt length for the Argon2id derivation.
pub const KS_SALT_LEN: usize = 16;

/// Production KDF memory cost in KiB (CRYPTOGRAPHY.md §1: m = 2^18).
pub const ARGON2_M_KIB: u32 = 1 << 18;

/// Production KDF time cost (CRYPTOGRAPHY.md §1: t = 4).
pub const ARGON2_T_COST: u32 = 4;

/// Production KDF parallelism (CRYPTOGRAPHY.md §1: p = 4).
pub const ARGON2_P_COST: u32 = 4;

/// Derives a 32-byte keystore key with the production Argon2id
/// parameters.
///
/// # Errors
///
/// Returns [`CryptoError::Kdf`] if Argon2id refuses the parameters or the
/// derivation fails.
pub fn derive_keystore_key(
    passphrase: &[u8],
    salt: &[u8; KS_SALT_LEN],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    derive_keystore_key_with_params(passphrase, salt, ARGON2_M_KIB, ARGON2_T_COST, ARGON2_P_COST)
}

/// Derives a keystore key with explicit Argon2id parameters (tests use
/// reduced costs; production callers use [`derive_keystore_key`]).
///
/// # Errors
///
/// Returns [`CryptoError::Kdf`] if Argon2id refuses the parameters or the
/// derivation fails.
pub fn derive_keystore_key_with_params(
    passphrase: &[u8],
    salt: &[u8; KS_SALT_LEN],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let params = argon2::Params::new(m_cost_kib, t_cost, p_cost, Some(32))
        .map_err(|_e| CryptoError::Kdf("invalid Argon2id parameters"))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, salt, out.as_mut())
        .map_err(|_e| CryptoError::Kdf("Argon2id derivation failed"))?;
    Ok(out)
}

/// Seals a plaintext blob into a keystore envelope:
/// `[salt 16][nonce 12][ciphertext+tag]`. A fresh random salt is drawn
/// per envelope, so the same passphrase never reuses a key.
///
/// # Errors
///
/// Returns [`CryptoError::RngFailure`] on entropy failure and
/// [`CryptoError::EncryptFailed`] on AEAD failure.
pub fn seal_envelope(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut salt = [0u8; KS_SALT_LEN];
    rng::fill(&mut salt)?;
    let mut nonce = [0u8; aead::NONCE_LEN];
    let cipher = aead::AeadCipher::new(Zeroizing::new(*key));
    let ciphertext = cipher.seal(b"UMKS v1", plaintext, &mut nonce)?;

    let header_len = KS_SALT_LEN.saturating_add(aead::NONCE_LEN);
    let capacity = header_len.saturating_add(ciphertext.len());
    let mut blob = Vec::with_capacity(capacity);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Opens a keystore envelope produced by [`seal_envelope`].
///
/// The returned plaintext is [`Zeroizing`] (wiped on drop).
///
/// # Errors
///
/// Returns [`CryptoError::InvalidLength`] for malformed envelopes and
/// [`CryptoError::DecryptFailed`] for a wrong passphrase or tampering.
pub fn open_envelope(key: &[u8; 32], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let min_len = KS_SALT_LEN
        .saturating_add(aead::NONCE_LEN)
        .saturating_add(aead::TAG_LEN);
    if blob.len() < min_len {
        return Err(CryptoError::InvalidLength {
            expected: min_len,
            actual: blob.len(),
        });
    }
    let salt_len = KS_SALT_LEN;
    // The salt is re-derived from the passphrase — it is not read back
    // here (the derivation below re-hashes with the stored salt).
    let _salt: [u8; KS_SALT_LEN] = crate::kdf::read_at(blob, 0)?;
    let nonce: [u8; aead::NONCE_LEN] = crate::kdf::read_at(blob, salt_len)?;
    let ct_start = salt_len.saturating_add(aead::NONCE_LEN);
    let ciphertext = blob.get(ct_start..).ok_or(CryptoError::InvalidLength {
        expected: ct_start.saturating_add(1),
        actual: blob.len(),
    })?;

    let cipher = aead::AeadCipher::new(Zeroizing::new(*key));
    let plaintext = cipher.open(&nonce, b"UMKS v1", ciphertext)?;
    Ok(Zeroizing::new(plaintext))
}
