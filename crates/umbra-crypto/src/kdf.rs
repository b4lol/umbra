//! Key derivation functions (CRYPTOGRAPHY.md §1: HKDF-SHA512 + BLAKE3).
//!
//! - [`derive_root_key`]: PQXDH hybrid root key,
//!   `SK = HKDF-SHA512(DH1 || DH2 || DH3 || SS_KEM, salt, info)`.
//! - [`kdf_ratchet_step`]: Double Ratchet root-key ratchet.
//! - [`advance_chain`]: Double Ratchet chain-key ratchet (chain + message key).
//! - [`keyed_digest`]: keyed BLAKE3 for nonces and SAS derivation.

use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::error::CryptoError;

/// HKDF salt for the PQXDH root derivation (CRYPTOGRAPHY.md §2 ContextInfo).
pub const ROOT_SALT: &[u8] = b"Umbra PQXDH v1 root salt";

/// HKDF info string for the PQXDH root derivation (CRYPTOGRAPHY.md §2).
pub const ROOT_INFO: &[u8] = b"Umbra session root key";

/// Info string for the Double Ratchet root-key ratchet step.
pub const RATCHET_ROOT_INFO: &[u8] = b"Umbra ratchet root";

/// Info string for the Double Ratchet chain-key ratchet step.
pub const RATCHET_CHAIN_INFO: &[u8] = b"Umbra ratchet chain";

/// Info string for the per-message key derived from a chain key.
pub const MESSAGE_KEY_INFO: &[u8] = b"Umbra message key";

/// Info string for the next chain key derived from a chain key.
pub const NEXT_CHAIN_INFO: &[u8] = b"Umbra next chain key";

/// Session root key material. Zeroized on drop.
#[derive(Clone)]
pub struct RootKey(Zeroizing<[u8; 32]>);

impl RootKey {
    /// Wraps raw 32-byte root key material.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrowed view of the key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derives the PQXDH hybrid root key from the concatenated shared secrets.
///
/// Input layout (CRYPTOGRAPHY.md §2): `DH1 || DH2 || DH3 || SS_ML-KEM`
/// (4 x 32 bytes = 128 bytes).
///
/// # Errors
///
/// Returns [`CryptoError::InvalidLength`] if `ikm` is not exactly 128 bytes.
pub fn derive_root_key(ikm: &[u8]) -> Result<RootKey, CryptoError> {
    if ikm.len() != 128 {
        return Err(CryptoError::InvalidLength {
            expected: 128,
            actual: ikm.len(),
        });
    }
    let hk = Hkdf::<Sha512>::new(Some(ROOT_SALT), ikm);
    let mut okm = [0u8; 32];
    hk.expand(ROOT_INFO, &mut okm)
        .map_err(|_e| CryptoError::InvalidLength {
            expected: 32,
            actual: okm.len(),
        })?;
    Ok(RootKey::from_bytes(okm))
}

/// Double Ratchet root ratchet: `(RK', CK) = KDF_RK(RK, DH(DHs, DHr))`.
///
/// Returns the new root key and the new sending/receiving chain key.
#[must_use]
pub fn kdf_ratchet_step(root_key: &RootKey, dh_out: &[u8; 32]) -> (RootKey, [u8; 32]) {
    let hk = Hkdf::<Sha512>::new(Some(root_key.as_bytes()), dh_out);
    let mut new_root = [0u8; 32];
    let mut chain = [0u8; 32];
    // 32-byte expansions cannot fail (below the 255*HashLen limit); map the
    // infallible case defensively without panicking.
    let _ = hk.expand(RATCHET_ROOT_INFO, &mut new_root);
    let _ = hk.expand(RATCHET_CHAIN_INFO, &mut chain);
    (RootKey::from_bytes(new_root), chain)
}

/// Double Ratchet chain ratchet: `(CK', MK) = KDF_CK(CK)`.
///
/// Returns the next chain key and the single-use message key.
#[must_use]
pub fn advance_chain(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha512>::new(None, chain_key);
    let mut next_chain = [0u8; 32];
    let mut message_key = [0u8; 32];
    let _ = hk.expand(NEXT_CHAIN_INFO, &mut next_chain);
    let _ = hk.expand(MESSAGE_KEY_INFO, &mut message_key);
    (next_chain, message_key)
}

/// Keyed BLAKE3 digest (CRYPTOGRAPHY.md §1).
#[must_use]
pub fn keyed_digest(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(key, data).as_bytes()
}

/// Context-string BLAKE3 key derivation (`blake3::derive_key`).
#[must_use]
pub fn derive_key(context: &str, material: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, material)
}

/// Canonical identity fingerprint: BLAKE3 domain-separated digest over
/// the ML-DSA-65 verification key (length-prefixed) followed by the
/// X25519 identity key. This is the value compared out of band during
/// pairing and bound into `umbra_protocol::smp::bound_secret`; 256 bits,
/// truncation-free. The SPK is deliberately NOT covered: its
/// authenticity is transitive via the ML-DSA signature, so key rotation
/// does not change the fingerprint; the ML-KEM ephemeral key is
/// authenticated only by the full-payload pairing comparison.
#[must_use]
pub fn identity_fingerprint(ik: &[u8; 32], dsa_vk: &[u8]) -> [u8; 32] {
    // Length-prefix the variable-length VK so the encoding is
    // unambiguous; the fixed 32-byte IK needs no prefix.
    let mut material = Vec::with_capacity(dsa_vk.len().saturating_add(40));
    material.extend_from_slice(
        &u64::try_from(dsa_vk.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    material.extend_from_slice(dsa_vk);
    material.extend_from_slice(ik);
    blake3::derive_key("Umbra identity fingerprint v1", &material)
}

/// Copies `src` into `dst` starting at `offset` with bounds checking.
///
/// Used everywhere instead of slice arithmetic so that the
/// `clippy::indexing_slicing` ban is honored with explicit errors.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidLength`] if the write would go out of bounds.
pub fn write_at(dst: &mut [u8], offset: usize, src: &[u8]) -> Result<(), CryptoError> {
    let end = offset
        .checked_add(src.len())
        .ok_or(CryptoError::InvalidLength {
            expected: dst.len(),
            actual: usize::MAX,
        })?;
    let out_of_bounds = CryptoError::InvalidLength {
        expected: dst.len(),
        actual: end,
    };
    let target = dst.get_mut(offset..end).ok_or(out_of_bounds)?;
    target.copy_from_slice(src);
    Ok(())
}

/// Reads `LEN` bytes at `offset` from `src` with bounds checking.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidLength`] if the read would go out of bounds.
pub fn read_at<const LEN: usize>(src: &[u8], offset: usize) -> Result<[u8; LEN], CryptoError> {
    let end = offset.checked_add(LEN).ok_or(CryptoError::InvalidLength {
        expected: src.len(),
        actual: usize::MAX,
    })?;
    let out_of_bounds = CryptoError::InvalidLength {
        expected: src.len(),
        actual: end,
    };
    let chunk = src.get(offset..end).ok_or(out_of_bounds)?;
    let mut out = [0u8; LEN];
    out.copy_from_slice(chunk);
    Ok(out)
}
