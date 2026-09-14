//! Decoy Vault, Phase 1 (TODO B.3): a hidden-volume container format.
//! Adapts VeraCrypt's well-analyzed hidden-volume pattern — reuses this
//! crate's existing Argon2id KDF and ChaCha20-Poly1305 AEAD, invents no
//! new cryptographic primitive (ADR-011/028/030/032/034's "adapt, don't
//! invent" doctrine).
//!
//! # Layout
//!
//! A fixed-size ([`CONTAINER_LEN`]) buffer, entirely CSPRNG-filled by
//! [`create_container`] before anything is written. The OUTER region
//! occupies `[0, OUTER_REGION_LEN)` — a fixed offset and fixed max
//! size. The HIDDEN region's starting offset is derived (Argon2id,
//! same production cost as passphrase verification itself) from the
//! hidden passphrase, constrained to
//! `[OUTER_REGION_LEN, CONTAINER_LEN - HIDDEN_REGION_LEN]` — a range
//! that starts strictly after the outer region ends, so overlap is
//! impossible BY CONSTRUCTION for any derived offset, not merely
//! improbable.
//!
//! # No cleartext length field (see the design spec's §3)
//!
//! Each region's ciphertext is always the SAME fixed size. The real
//! content's length is a 4-byte prefix INSIDE the encrypted plaintext
//! (protected by AEAD), followed by the real bytes, followed by
//! zero-padding out to the region's fixed plaintext capacity. A
//! cleartext length field was considered and rejected: a uniformly
//! random 32-bit value lands in a "plausible small length" range by
//! sheer chance often enough to let a statistical scan narrow down
//! candidate hidden-region offsets without either passphrase.
//!
//! # Deniability property
//!
//! [`open_hidden`] with a WRONG passphrase and [`open_hidden`] against
//! a container where [`write_hidden`] was NEVER called both fail
//! identically with [`CryptoError::DecryptFailed`] — there is no way
//! to distinguish "wrong passphrase" from "no hidden volume exists
//! here at all", which is the entire point.

use zeroize::Zeroizing;

use crate::aead::{self, AeadCipher};
use crate::error::CryptoError;
use crate::keystore::{self, KS_SALT_LEN};
use crate::rng;

/// Total container size (fixed).
pub const CONTAINER_LEN: usize = 1024 * 1024;

/// Bytes `[0, OUTER_REGION_LEN)` are reserved for the outer (decoy)
/// region.
pub const OUTER_REGION_LEN: usize = 256 * 1024;

/// Max size of the hidden region's own envelope.
pub const HIDDEN_REGION_LEN: usize = 256 * 1024;

/// AAD binding both regions' AEAD envelopes to this format/version.
const ENVELOPE_AAD: &[u8] = b"umbra-decoy-vault-v1";

/// Fixed, non-secret domain-separation salt for hidden-offset
/// derivation — distinct from any per-region AEAD salt. Not secret:
/// the derivation's cost (full production Argon2id) is what gates
/// brute-forcing candidate offsets, not this salt's own secrecy.
const HIDDEN_OFFSET_SALT: [u8; KS_SALT_LEN] = *b"UmbraHiddenOfst1";

/// Hidden-region offset candidates are aligned to this granularity.
const SLOT_ALIGNMENT: usize = 4096;

/// Per-region envelope overhead: AEAD salt + nonce + tag.
const ENVELOPE_OVERHEAD: usize = KS_SALT_LEN
    .saturating_add(aead::NONCE_LEN)
    .saturating_add(aead::TAG_LEN);

/// Length-prefix size inside a region's decrypted plaintext.
const LENGTH_PREFIX_LEN: usize = 4;

/// Plaintext capacity for a region of `region_len` bytes.
const fn padded_plaintext_capacity(region_len: usize) -> usize {
    region_len.saturating_sub(ENVELOPE_OVERHEAD)
}

/// Encodes `content` as `[len: u32 BE][content][zero padding]`, sized
/// to exactly `capacity` bytes.
///
/// # Errors
/// [`CryptoError::InvalidLength`] if `content` does not fit.
fn encode_padded_plaintext(content: &[u8], capacity: usize) -> Result<Vec<u8>, CryptoError> {
    let needed = LENGTH_PREFIX_LEN.saturating_add(content.len());
    if needed > capacity {
        return Err(CryptoError::InvalidLength {
            expected: capacity,
            actual: needed,
        });
    }
    let content_len_u32 = u32::try_from(content.len()).map_err(|_| CryptoError::InvalidLength {
        expected: capacity,
        actual: content.len(),
    })?;
    let mut padded = Vec::with_capacity(capacity);
    padded.extend_from_slice(&content_len_u32.to_be_bytes());
    padded.extend_from_slice(content);
    padded.resize(capacity, 0u8);
    Ok(padded)
}

/// Decodes a padded plaintext produced by [`encode_padded_plaintext`].
///
/// # Errors
/// [`CryptoError::DecryptFailed`] if `padded` is too short or its
/// length prefix claims more content than remains (a corrupted, if
/// somehow still AEAD-authentic, blob — defensively rejected).
fn decode_padded_plaintext(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let len_bytes = padded
        .get(..LENGTH_PREFIX_LEN)
        .ok_or(CryptoError::DecryptFailed)?;
    let mut len_array = [0u8; LENGTH_PREFIX_LEN];
    len_array.copy_from_slice(len_bytes);
    let content_len = u32::from_be_bytes(len_array);
    let content_len = usize::try_from(content_len).map_err(|_| CryptoError::DecryptFailed)?;
    let content = padded
        .get(LENGTH_PREFIX_LEN..)
        .and_then(|rest| rest.get(..content_len))
        .ok_or(CryptoError::DecryptFailed)?;
    Ok(Zeroizing::new(content.to_vec()))
}

/// Writes one region's envelope (`[salt][nonce][ciphertext+tag]`) into
/// `container[offset..offset + region_len]`.
///
/// Module-private helper (not part of this module's public API), so a
/// narrow `#[allow]` here is preferable to reshaping the public
/// `_with_params` functions' plain `(m_cost_kib, t_cost, p_cost)`
/// signatures — see the design spec's §5 API surface.
#[allow(clippy::too_many_arguments)]
fn write_region(
    container: &mut [u8],
    offset: usize,
    region_len: usize,
    passphrase: &[u8],
    plaintext: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<(), CryptoError> {
    let capacity = padded_plaintext_capacity(region_len);
    let padded = encode_padded_plaintext(plaintext, capacity)?;

    let mut salt = [0u8; KS_SALT_LEN];
    rng::fill(&mut salt)?;
    let key =
        keystore::derive_keystore_key_with_params(passphrase, &salt, m_cost_kib, t_cost, p_cost)?;
    let cipher = AeadCipher::new(key);
    let mut nonce = [0u8; aead::NONCE_LEN];
    let ciphertext = cipher.seal(ENVELOPE_AAD, &padded, &mut nonce)?;

    let region_end = offset.saturating_add(region_len);
    let container_len = container.len();
    let region = container
        .get_mut(offset..region_end)
        .ok_or(CryptoError::InvalidLength {
            expected: region_len,
            actual: container_len.saturating_sub(offset),
        })?;

    let (salt_slot, rest) = region.split_at_mut(KS_SALT_LEN);
    salt_slot.copy_from_slice(&salt);
    let (nonce_slot, cipher_slot) = rest.split_at_mut(aead::NONCE_LEN);
    nonce_slot.copy_from_slice(&nonce);
    let cipher_slot_len = cipher_slot.len();
    let cipher_dest =
        cipher_slot
            .get_mut(..ciphertext.len())
            .ok_or(CryptoError::InvalidLength {
                expected: ciphertext.len(),
                actual: cipher_slot_len,
            })?;
    cipher_dest.copy_from_slice(&ciphertext);
    Ok(())
}

/// Opens one region's envelope.
fn open_region(
    container: &[u8],
    offset: usize,
    region_len: usize,
    passphrase: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let region_end = offset.saturating_add(region_len);
    let region = container
        .get(offset..region_end)
        .ok_or(CryptoError::DecryptFailed)?;

    let salt_bytes = region
        .get(..KS_SALT_LEN)
        .ok_or(CryptoError::DecryptFailed)?;
    let mut salt = [0u8; KS_SALT_LEN];
    salt.copy_from_slice(salt_bytes);

    let nonce_start = KS_SALT_LEN;
    let nonce_end = nonce_start.saturating_add(aead::NONCE_LEN);
    let nonce_bytes = region
        .get(nonce_start..nonce_end)
        .ok_or(CryptoError::DecryptFailed)?;
    let mut nonce = [0u8; aead::NONCE_LEN];
    nonce.copy_from_slice(nonce_bytes);

    let ciphertext = region.get(nonce_end..).ok_or(CryptoError::DecryptFailed)?;

    let key =
        keystore::derive_keystore_key_with_params(passphrase, &salt, m_cost_kib, t_cost, p_cost)?;
    let cipher = AeadCipher::new(key);
    let padded = cipher.open(&nonce, ENVELOPE_AAD, ciphertext)?;
    decode_padded_plaintext(&padded)
}

/// Derives the hidden region's starting offset from `passphrase`.
fn hidden_offset_with_params(
    passphrase: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<usize, CryptoError> {
    let derived = keystore::derive_keystore_key_with_params(
        passphrase,
        &HIDDEN_OFFSET_SALT,
        m_cost_kib,
        t_cost,
        p_cost,
    )?;
    let first8 = derived.get(..8).ok_or(CryptoError::DecryptFailed)?;
    let mut first8_array = [0u8; 8];
    first8_array.copy_from_slice(first8);
    let derived_u64 = u64::from_be_bytes(first8_array);

    let candidate_span = CONTAINER_LEN
        .saturating_sub(OUTER_REGION_LEN)
        .saturating_sub(HIDDEN_REGION_LEN);
    let num_slots = candidate_span
        .saturating_div(SLOT_ALIGNMENT)
        .saturating_add(1);
    let num_slots_u64 = u64::try_from(num_slots).unwrap_or(u64::MAX);
    let slot_u64 = derived_u64.checked_rem(num_slots_u64).unwrap_or(0);
    let slot = usize::try_from(slot_u64).unwrap_or(0);

    Ok(OUTER_REGION_LEN.saturating_add(slot.saturating_mul(SLOT_ALIGNMENT)))
}

/// Creates a fresh, fully CSPRNG-filled container with the outer
/// region's envelope written at offset 0.
///
/// # Errors
/// [`CryptoError::InvalidLength`] if `outer_plaintext` does not fit
/// the outer region's fixed plaintext capacity; [`CryptoError::RngFailure`]/
/// [`CryptoError::Kdf`]/[`CryptoError::EncryptFailed`] as usual.
pub fn create_container(
    outer_passphrase: &[u8],
    outer_plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    create_container_with_params(
        outer_passphrase,
        outer_plaintext,
        keystore::ARGON2_M_KIB,
        keystore::ARGON2_T_COST,
        keystore::ARGON2_P_COST,
    )
}

/// [`create_container`] with explicit Argon2id parameters (tests use
/// reduced costs).
///
/// # Errors
/// See [`create_container`].
pub fn create_container_with_params(
    outer_passphrase: &[u8],
    outer_plaintext: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Vec<u8>, CryptoError> {
    let mut container = vec![0u8; CONTAINER_LEN];
    rng::fill(&mut container)?;
    write_region(
        &mut container,
        0,
        OUTER_REGION_LEN,
        outer_passphrase,
        outer_plaintext,
        m_cost_kib,
        t_cost,
        p_cost,
    )?;
    Ok(container)
}

/// Writes (or overwrites) the hidden region within an EXISTING
/// container, at the offset derived from `hidden_passphrase`.
///
/// # Errors
/// [`CryptoError::InvalidLength`] if `container.len() != `[`CONTAINER_LEN`]
/// or `hidden_plaintext` does not fit the hidden region's fixed
/// plaintext capacity.
pub fn write_hidden(
    container: &mut [u8],
    hidden_passphrase: &[u8],
    hidden_plaintext: &[u8],
) -> Result<(), CryptoError> {
    write_hidden_with_params(
        container,
        hidden_passphrase,
        hidden_plaintext,
        keystore::ARGON2_M_KIB,
        keystore::ARGON2_T_COST,
        keystore::ARGON2_P_COST,
    )
}

/// [`write_hidden`] with explicit Argon2id parameters.
///
/// # Errors
/// See [`write_hidden`].
pub fn write_hidden_with_params(
    container: &mut [u8],
    hidden_passphrase: &[u8],
    hidden_plaintext: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<(), CryptoError> {
    if container.len() != CONTAINER_LEN {
        return Err(CryptoError::InvalidLength {
            expected: CONTAINER_LEN,
            actual: container.len(),
        });
    }
    let offset = hidden_offset_with_params(hidden_passphrase, m_cost_kib, t_cost, p_cost)?;
    write_region(
        container,
        offset,
        HIDDEN_REGION_LEN,
        hidden_passphrase,
        hidden_plaintext,
        m_cost_kib,
        t_cost,
        p_cost,
    )
}

/// Opens the outer region.
///
/// # Errors
/// [`CryptoError::DecryptFailed`] for a wrong passphrase or a
/// malformed/truncated container.
pub fn open_outer(container: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    open_outer_with_params(
        container,
        passphrase,
        keystore::ARGON2_M_KIB,
        keystore::ARGON2_T_COST,
        keystore::ARGON2_P_COST,
    )
}

/// [`open_outer`] with explicit Argon2id parameters.
///
/// # Errors
/// See [`open_outer`].
pub fn open_outer_with_params(
    container: &[u8],
    passphrase: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    open_region(
        container,
        0,
        OUTER_REGION_LEN,
        passphrase,
        m_cost_kib,
        t_cost,
        p_cost,
    )
}

/// Opens the hidden region at the offset derived from `passphrase`.
/// Indistinguishable failure modes by design: a wrong passphrase and
/// "no hidden volume was ever written here" both fail identically
/// with [`CryptoError::DecryptFailed`].
///
/// # Errors
/// [`CryptoError::DecryptFailed`] as described above.
pub fn open_hidden(container: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    open_hidden_with_params(
        container,
        passphrase,
        keystore::ARGON2_M_KIB,
        keystore::ARGON2_T_COST,
        keystore::ARGON2_P_COST,
    )
}

/// [`open_hidden`] with explicit Argon2id parameters.
///
/// # Errors
/// See [`open_hidden`].
pub fn open_hidden_with_params(
    container: &[u8],
    passphrase: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if container.len() != CONTAINER_LEN {
        return Err(CryptoError::DecryptFailed);
    }
    let offset = hidden_offset_with_params(passphrase, m_cost_kib, t_cost, p_cost)?;
    open_region(
        container,
        offset,
        HIDDEN_REGION_LEN,
        passphrase,
        m_cost_kib,
        t_cost,
        p_cost,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_M_COST_KIB: u32 = 8192;
    const TEST_T_COST: u32 = 2;
    const TEST_P_COST: u32 = 1;

    #[test]
    fn outer_round_trips_and_wrong_passphrase_fails()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let container = create_container_with_params(
            b"outer-pw",
            b"outer secret content",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;
        let opened = open_outer_with_params(
            &container,
            b"outer-pw",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;
        assert_eq!(&opened[..], b"outer secret content");

        let wrong = open_outer_with_params(
            &container,
            b"wrong-pw",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        );
        assert!(matches!(wrong, Err(CryptoError::DecryptFailed)));
        Ok(())
    }

    #[test]
    fn hidden_round_trips_and_wrong_passphrase_fails_the_same_as_no_hidden_volume()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut container = create_container_with_params(
            b"outer-pw",
            b"outer content",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;

        // Before write_hidden: opening with the intended hidden
        // passphrase must fail (no hidden volume exists yet).
        let before = open_hidden_with_params(
            &container,
            b"hidden-pw",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        );
        assert!(matches!(before, Err(CryptoError::DecryptFailed)));

        write_hidden_with_params(
            &mut container,
            b"hidden-pw",
            b"the real secret",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;

        let opened = open_hidden_with_params(
            &container,
            b"hidden-pw",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;
        assert_eq!(&opened[..], b"the real secret");

        // Wrong hidden passphrase: same error as "no hidden volume",
        // indistinguishable by design.
        let wrong = open_hidden_with_params(
            &container,
            b"wrong-hidden-pw",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        );
        assert!(matches!(wrong, Err(CryptoError::DecryptFailed)));

        // The outer region is completely unaffected by writing the
        // hidden region.
        let outer_still_works = open_outer_with_params(
            &container,
            b"outer-pw",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;
        assert_eq!(&outer_still_works[..], b"outer content");
        Ok(())
    }

    #[test]
    fn different_hidden_passphrases_land_at_different_offsets_never_overlapping_outer()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // A structural (not merely statistical) proof: for a large
        // sample of passphrases, the derived offset must always fall
        // within [OUTER_REGION_LEN, CONTAINER_LEN - HIDDEN_REGION_LEN].
        let mut distinct_offsets = std::collections::HashSet::new();
        for index in 0..200 {
            let passphrase = format!("hidden-pw-{index}");
            let offset = hidden_offset_with_params(
                passphrase.as_bytes(),
                TEST_M_COST_KIB,
                TEST_T_COST,
                TEST_P_COST,
            )?;
            assert!(
                offset >= OUTER_REGION_LEN,
                "offset {offset} must be >= OUTER_REGION_LEN"
            );
            assert!(
                offset.saturating_add(HIDDEN_REGION_LEN) <= CONTAINER_LEN,
                "offset {offset} + HIDDEN_REGION_LEN must fit within CONTAINER_LEN"
            );
            distinct_offsets.insert(offset);
        }
        // Not asserting a specific distinct count (slot collisions
        // across 200 samples into 129 slots are expected by the
        // pigeonhole principle) — the structural bounds above are the
        // real property under test; this just confirms derivation
        // isn't degenerately constant.
        assert!(distinct_offsets.len() > 1);
        Ok(())
    }

    #[test]
    fn content_too_large_for_a_region_is_rejected() {
        let too_large = vec![0u8; OUTER_REGION_LEN];
        let result = create_container_with_params(
            b"outer-pw",
            &too_large,
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        );
        assert!(matches!(result, Err(CryptoError::InvalidLength { .. })));
    }

    #[test]
    fn wrong_size_container_is_rejected_cleanly() {
        let mut too_small = vec![0u8; 100];
        let write_result = write_hidden_with_params(
            &mut too_small,
            b"pw",
            b"x",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        );
        assert!(matches!(
            write_result,
            Err(CryptoError::InvalidLength { .. })
        ));

        let open_result =
            open_hidden_with_params(&too_small, b"pw", TEST_M_COST_KIB, TEST_T_COST, TEST_P_COST);
        assert!(matches!(open_result, Err(CryptoError::DecryptFailed)));
    }

    #[test]
    fn fresh_container_padding_has_no_detectable_zero_runs()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Basic sanity check, not a full randomness-test-suite: a
        // freshly created container's bytes OUTSIDE the outer
        // envelope's own salt/nonce/ciphertext must not contain any
        // long run of zero bytes (which CSPRNG output essentially
        // never produces, but a bug that skipped the initial fill or
        // zeroed padding would).
        let container = create_container_with_params(
            b"outer-pw",
            b"short",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;
        let tail = container
            .get(OUTER_REGION_LEN..)
            .ok_or("container shorter than OUTER_REGION_LEN")?;
        let longest_zero_run = tail
            .split(|byte| *byte != 0)
            .map(<[u8]>::len)
            .max()
            .unwrap_or(0);
        assert!(
            longest_zero_run < 64,
            "found a suspiciously long zero-byte run ({longest_zero_run} bytes) in what should \
             be CSPRNG-filled padding"
        );
        Ok(())
    }
}
