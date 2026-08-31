//! Socialist Millionaire Protocol engine (TODO A.3, CRYPTOGRAPHY.md §5).
//!
//! Faithful implementation of the OTR version 3 SMP
//! (Protocol-v3-4.1.1, "Socialist Millionaires' Protocol"), which is
//! itself based on Boudot, Schoenmakers and Traoré (2001). This is NOT
//! invented cryptography: every formula below is transcribed from the
//! published spec, with two deliberate, documented encoding choices:
//!
//! 1. The hash input is `[version BYTE][MPI...]` where each MPI is the
//!    usual 4-byte big-endian length + big-endian bytes (the spec's own
//!    MPI wire format).
//! 2. Wire serialization for Umbra is the same length-prefixed form with
//!    an MPI-count header; Umbra is not OTR-TLV wire compatible.
//!
//! Group: the RFC 3526 1536-bit MODP modulus `p` (the exact hex below is
//! the spec's), generator `g1 = 2`, order `q = (p-1)/2`. Group elements
//! are validated to `[2, p-2]` on receipt. `D` values are computed mod q.
//!
//! Residuals (documented):
//! - `num-bigint` modpow is not constant-time. The secret here is the
//!   pairing-secret digest (256 bits, not a long-term key), and OTR's own
//!   implementations share this property; the constant-time mandate
//!   applies to key/MAC comparisons (`subtle`).
//! - Small-subgroup confinement matches OTR v3 (range check only; no
//!   `y^q == 1` check). Because `p` is a safe prime, the range check
//!   already excludes every small-order element ({1, p-1}); worst case an
//!   order-2q element leaks only the parity of the secret digest.
//! - Identity + channel binding: the engine itself proves
//!   shared-password knowledge. [`bound_secret`] folds the parties'
//!   pairing-authenticated fingerprints into the password material, and
//!   the session driver mixes in the per-handshake transcript SSID
//!   ([`umbra_protocol::session::Session::transcript_ssid`]) before the
//!   secret reaches the engine — a MITM relaying SMP messages between
//!   two distinct sessions derives mismatched secrets and fails the
//!   proofs. Residual: the password (or the out-of-band fingerprint
//!   comparison) remains the root of trust; anyone holding it passes
//!   SMP by design.
//! - DoS: SMP costs ~10-20 1536-bit modexps per side. The session
//!   driver runs it only over established sessions; per-peer rate
//!   limiting is NOT yet implemented and stays a documented gap.
//!
//! Transport boundary: serialized SMP messages exceed one packet payload
//! (SMP2 ≈ 1.5 KB > 990 B); chunked carriage over `DATA_MESSAGE` is
//! implemented by the session layer (TAG_SMP multiplexer) and driven by
//! `umbra_net::messenger`.

// Justified blanket exception to `clippy::arithmetic_side_effects`:
// `BigUint` `+`/`*` are total (arbitrary precision), division panics only
// on zero divisors (here exclusively the fixed non-zero constants p and
// q), and SUBTRACTION underflow panics — which is why every subtraction
// in this module goes through `sub_mod_q` (order-normalized) or operates
// on compile-time constants larger than the subtrahend. Checked variants
// would add noise without safety value.
#![allow(clippy::arithmetic_side_effects)]

use num_bigint::BigUint;
use num_traits::Num;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use umbra_crypto::rng;

use crate::error::ProtocolError;

/// The RFC 3526 1536-bit MODP modulus (spec-quoted, big-endian hex).
pub const P_HEX: &str = concat!(
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 ",
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD ",
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 ",
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED ",
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D ",
    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F ",
    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D ",
    "670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF"
);

/// The group generator `g1 = 2` (spec).
pub const G1: u32 = 2;

/// Largest accepted serialized MPI size in bytes (group elements are
/// 192 bytes; the cap admits canonical encodings with margin).
const MAX_MPI_BYTES: usize = 200;

/// Per-run cached group constants.
struct Group {
    /// The 1536-bit modulus.
    p: BigUint,
    /// Group order `q = (p-1)/2`.
    q: BigUint,
    /// Generator `g1 = 2`.
    g1: BigUint,
    /// `p - 2` (modular inversion via Fermat's little theorem).
    p_minus_2: BigUint,
}

/// Lazily-built, process-wide group constants.
fn group() -> &'static Group {
    use std::sync::OnceLock;
    static GROUP: OnceLock<Group> = OnceLock::new();
    GROUP.get_or_init(|| {
        let hex: String = P_HEX.chars().filter(|c| !c.is_whitespace()).collect();
        let p = BigUint::from_str_radix(&hex, 16).unwrap_or_else(|_e| BigUint::from(0u32));
        // Constant-context arithmetic: p is the spec's fixed 1536-bit prime
        // (never zero), so the subtraction/division cannot fault.
        #[allow(clippy::arithmetic_side_effects)]
        let build = |p: &BigUint| -> (BigUint, BigUint, BigUint) {
            let q = (p - 1u32) / 2u32;
            let g1 = BigUint::from(G1);
            let p_minus_2 = p - 2u32;
            (q, g1, p_minus_2)
        };
        let (q, g1, p_minus_2) = build(&p);
        Group {
            p,
            q,
            g1,
            p_minus_2,
        }
    })
}

/// Derives the SMP secret integer from the pairing material, per the
/// spec's binding principle (version byte, both identities, session id,
/// user secret): the SHA256 digest becomes `x`/`y`.
#[must_use]
pub fn smp_secret(
    initiator_identity: &[u8; 32],
    responder_identity: &[u8; 32],
    ssid: &[u8],
    user_secret: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update([0x01u8]); // SMP version byte (spec)
    hasher.update(initiator_identity);
    hasher.update(responder_identity);
    // Variable-length fields are length-prefixed (8-byte big-endian) to
    // make the concatenation unambiguous.
    let ssid_len = (ssid.len() as u64).to_be_bytes();
    hasher.update(ssid_len);
    hasher.update(ssid);
    let secret_len = (user_secret.len() as u64).to_be_bytes();
    hasher.update(secret_len);
    hasher.update(user_secret);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Zeroizing::new(out)
}

/// SHA256 of `[version BYTE][MPI...]` (the spec's SMP hash function).
fn hash_mpi(version: u8, mpis: &[&BigUint]) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update([version]);
    for mpi in mpis {
        let bytes = mpi.to_bytes_be();
        let len = u32::try_from(bytes.len()).unwrap_or(0).to_be_bytes();
        hasher.update(len);
        hasher.update(&bytes);
    }
    BigUint::from_bytes_be(&hasher.finalize())
}

/// A Chaum-Pedersen-style single-exponent proof `(c, D)` for `g1^e`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Zkp1 {
    /// Hash commitment.
    c: BigUint,
    /// Response value.
    d: BigUint,
}

/// The spec's coordinates proof `(cP, D5, D6)`: proves `P = g3^e` and
/// `Q = g1^e · g2^secret` for the same secret `e`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ZkpCoords {
    /// Hash commitment.
    c: BigUint,
    /// Response for the blinding part.
    d1: BigUint,
    /// Response for the secret part.
    d2: BigUint,
}

/// Draws a fresh random exponent in `[2, q-2]` (spec: 1536-bit).
fn rand_exponent() -> Result<BigUint, ProtocolError> {
    for _attempt in 0..8 {
        let mut bytes = [0u8; 192];
        rng::fill(&mut bytes).map_err(ProtocolError::from)?;
        let exp = BigUint::from_bytes_be(&bytes) % group().q.clone();
        if exp >= BigUint::from(2u32) {
            return Ok(exp);
        }
    }
    Err(ProtocolError::Smp("entropy produced degenerate exponents"))
}

/// Modular inverse of `value` mod `p` (Fermat: `value^(p-2)`).
fn inverse(value: &BigUint) -> BigUint {
    let g = group();
    value.modpow(&g.p_minus_2, &g.p)
}

/// Multiplication mod `p`.
fn mul_mod(a: &BigUint, b: &BigUint) -> BigUint {
    (a * b) % group().p.clone()
}

/// `(a - b) mod q` on unsigned values.
fn sub_mod_q(a: BigUint, b: BigUint) -> BigUint {
    let q = group().q.clone();
    if a >= b {
        (a - b) % q
    } else {
        let sum = a + q.clone();
        (sum - b) % q
    }
}

/// Whether a received value is a legal group element (`2 <= v <= p-2`).
///
/// Comparison-only by design: `p - value` would PANIC (BigUint
/// underflow) for attacker-supplied values larger than `p`.
fn valid_element(value: &BigUint) -> bool {
    let g = group();
    value >= &BigUint::from(2u32) && value <= &g.p_minus_2
}

/// Proves knowledge of `e` for the public value `g1^e` (spec log ZKP).
fn prove_log(version: u8, e: &BigUint) -> Result<Zkp1, ProtocolError> {
    let g = group();
    let r = rand_exponent()?;
    let g1_r = g.g1.modpow(&r, &g.p);
    let c = hash_mpi(version, &[&g1_r]);
    let d = sub_mod_q(r, (e * &c) % g.q.clone());
    Ok(Zkp1 { c, d })
}

/// Verifies a log proof: `c == H(version, g1^D · value^c)`.
fn verify_log(version: u8, value: &BigUint, proof: &Zkp1) -> Result<(), ProtocolError> {
    let g = group();
    if !valid_element(value) {
        return Err(ProtocolError::Smp("group element out of range"));
    }
    let g1_d = g.g1.modpow(&proof.d, &g.p);
    let value_c = value.modpow(&proof.c, &g.p);
    let recomputed = hash_mpi(version, &[&mul_mod(&g1_d, &value_c)]);
    if recomputed != proof.c {
        return Err(ProtocolError::Smp("log proof verification failed"));
    }
    Ok(())
}

/// Proves `P = g3^e` and `Q = g1^e · g2^secret` (spec coordinates ZKP).
///
/// Returns `(P, Q, proof)`.
fn prove_coords(
    version: u8,
    g2: &BigUint,
    g3: &BigUint,
    secret: &BigUint,
    e: &BigUint,
) -> Result<(BigUint, BigUint, ZkpCoords), ProtocolError> {
    let g = group();
    let r_blind = rand_exponent()?;
    let r_secret = rand_exponent()?;
    let p_value = g3.modpow(e, &g.p);
    let q_value = mul_mod(&g.g1.modpow(e, &g.p), &g2.modpow(secret, &g.p));

    let p_blind = g3.modpow(&r_blind, &g.p);
    let q_blind = mul_mod(&g.g1.modpow(&r_blind, &g.p), &g2.modpow(&r_secret, &g.p));
    let c = hash_mpi(version, &[&p_blind, &q_blind]);
    let d1 = sub_mod_q(r_blind, (e * &c) % g.q.clone());
    let d2 = sub_mod_q(r_secret, (secret * &c) % g.q.clone());
    Ok((p_value, q_value, ZkpCoords { c, d1, d2 }))
}

/// Verifies the coordinates proof: `c == H(version, g3^D1 · P^c,
/// g1^D1 · g2^D2 · Q^c)`.
fn verify_coords(
    version: u8,
    g2: &BigUint,
    g3: &BigUint,
    p_value: &BigUint,
    q_value: &BigUint,
    proof: &ZkpCoords,
) -> Result<(), ProtocolError> {
    let g = group();
    if !valid_element(p_value) || !valid_element(q_value) {
        return Err(ProtocolError::Smp("group element out of range"));
    }
    let lhs = mul_mod(&g3.modpow(&proof.d1, &g.p), &p_value.modpow(&proof.c, &g.p));
    let rhs = mul_mod(
        &mul_mod(&g.g1.modpow(&proof.d1, &g.p), &g2.modpow(&proof.d2, &g.p)),
        &q_value.modpow(&proof.c, &g.p),
    );
    let recomputed = hash_mpi(version, &[&lhs, &rhs]);
    if recomputed != proof.c {
        return Err(ProtocolError::Smp("coordinates proof verification failed"));
    }
    Ok(())
}

/// Proves `R = QaQb^e` for exponent `e` (spec equal-logs ZKP:
/// `cR = H(version, g1^D · G3^c, QaQb^D · R^c)` with blinding `r`).
fn prove_equal_logs(
    version: u8,
    qaqb: &BigUint,
    e: &BigUint,
) -> Result<(BigUint, Zkp1), ProtocolError> {
    let g = group();
    let r = rand_exponent()?;
    let value = qaqb.modpow(e, &g.p);
    let g1_r = g.g1.modpow(&r, &g.p);
    let qaqb_r = qaqb.modpow(&r, &g.p);
    let c = hash_mpi(version, &[&g1_r, &qaqb_r]);
    let d = sub_mod_q(r, (e * &c) % g.q.clone());
    Ok((value, Zkp1 { c, d }))
}

/// Verifies the equal-logs proof: `c == H(version, g1^D · g3^c,
/// QaQb^D · R^c)`.
fn verify_equal_logs(
    version: u8,
    qaqb: &BigUint,
    g3: &BigUint,
    value: &BigUint,
    proof: &Zkp1,
) -> Result<(), ProtocolError> {
    let g = group();
    if !valid_element(value) {
        return Err(ProtocolError::Smp("group element out of range"));
    }
    let lhs = mul_mod(&g.g1.modpow(&proof.d, &g.p), &g3.modpow(&proof.c, &g.p));
    let rhs = mul_mod(&qaqb.modpow(&proof.d, &g.p), &value.modpow(&proof.c, &g.p));
    let recomputed = hash_mpi(version, &[&lhs, &rhs]);
    if recomputed != proof.c {
        return Err(ProtocolError::Smp("equal-logs proof verification failed"));
    }
    Ok(())
}

/// Serializes a message's MPIs: `[4-byte count][4-byte len + bytes]*`.
fn mpis_to_wire(mpis: &[&BigUint]) -> Vec<u8> {
    let mut out = Vec::new();
    let count = u32::try_from(mpis.len()).unwrap_or(0).to_be_bytes();
    out.extend_from_slice(&count);
    for mpi in mpis {
        let bytes = mpi.to_bytes_be();
        let len = u32::try_from(bytes.len()).unwrap_or(0).to_be_bytes();
        out.extend_from_slice(&len);
        out.extend_from_slice(&bytes);
    }
    out
}

/// Parses a serialized message into exactly `expected` MPIs, enforcing
/// the count, size caps, and no trailing bytes.
fn mpis_from_wire(bytes: &[u8], expected: usize) -> Result<Vec<BigUint>, ProtocolError> {
    let count = u32::from_be_bytes(umbra_crypto::kdf::read_at(bytes, 0)?) as usize;
    if count != expected {
        return Err(ProtocolError::Smp("wrong MPI count in message"));
    }
    let mut cursor = 4usize;
    let mut mpis = Vec::with_capacity(expected);
    for _ in 0..count {
        let len = u32::from_be_bytes(umbra_crypto::kdf::read_at(bytes, cursor)?) as usize;
        if len > MAX_MPI_BYTES {
            return Err(ProtocolError::Smp("oversized MPI in message"));
        }
        let mid = cursor.checked_add(4).ok_or(ProtocolError::StateViolation)?;
        let end = mid.checked_add(len).ok_or(ProtocolError::StateViolation)?;
        let slice = bytes.get(mid..end).ok_or(ProtocolError::InvalidLength {
            expected: len,
            actual: bytes.len(),
        })?;
        mpis.push(BigUint::from_bytes_be(slice));
        cursor = end;
    }
    if cursor != bytes.len() {
        return Err(ProtocolError::Smp("trailing bytes in message"));
    }
    Ok(mpis)
}

/// Takes a fixed slice of the parsed MPI vector.
fn take(mpis: &[BigUint], index: usize) -> Result<BigUint, ProtocolError> {
    mpis.get(index)
        .cloned()
        .ok_or(ProtocolError::StateViolation)
}

/// SMP Message 1 (initiator): `[g2a, c2, D2, g3a, c3, D3]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmpMsg1 {
    /// Initiator's half of the g2 generator exchange.
    pub g2a: BigUint,
    /// ZKP for g2a.
    pub c2: BigUint,
    /// ZKP for g2a.
    pub d2: BigUint,
    /// Initiator's half of the g3 generator exchange.
    pub g3a: BigUint,
    /// ZKP for g3a.
    pub c3: BigUint,
    /// ZKP for g3a.
    pub d3: BigUint,
}

impl SmpMsg1 {
    /// Wire serialization.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        mpis_to_wire(&[&self.g2a, &self.c2, &self.d2, &self.g3a, &self.c3, &self.d3])
    }

    /// Parses and validates group elements (spec: `[2, p-2]`).
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Smp`] on malformed messages.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let m = mpis_from_wire(bytes, 6)?;
        let msg = Self {
            g2a: take(&m, 0)?,
            c2: take(&m, 1)?,
            d2: take(&m, 2)?,
            g3a: take(&m, 3)?,
            c3: take(&m, 4)?,
            d3: take(&m, 5)?,
        };
        if !valid_element(&msg.g2a) || !valid_element(&msg.g3a) {
            return Err(ProtocolError::Smp("group element out of range"));
        }
        Ok(msg)
    }
}

/// SMP Message 2 (responder): `[g2b, c2, D2, g3b, c3, D3, Pb, Qb, cP, D5, D6]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmpMsg2 {
    /// Responder's half of the g2 exchange.
    pub g2b: BigUint,
    /// ZKP for g2b.
    pub c2: BigUint,
    /// ZKP for g2b.
    pub d2: BigUint,
    /// Responder's half of the g3 exchange.
    pub g3b: BigUint,
    /// ZKP for g3b.
    pub c3: BigUint,
    /// ZKP for g3b.
    pub d3: BigUint,
    /// Final comparison value.
    pub pb: BigUint,
    /// Final comparison value.
    pub qb: BigUint,
    /// Coordinates proof commitment.
    pub cp: BigUint,
    /// Coordinates proof response (blinding).
    pub d5: BigUint,
    /// Coordinates proof response (secret).
    pub d6: BigUint,
}

impl SmpMsg2 {
    /// Wire serialization.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        mpis_to_wire(&[
            &self.g2b, &self.c2, &self.d2, &self.g3b, &self.c3, &self.d3, &self.pb, &self.qb,
            &self.cp, &self.d5, &self.d6,
        ])
    }

    /// Parses and validates group elements.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Smp`] on malformed messages.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let m = mpis_from_wire(bytes, 11)?;
        let msg = Self {
            g2b: take(&m, 0)?,
            c2: take(&m, 1)?,
            d2: take(&m, 2)?,
            g3b: take(&m, 3)?,
            c3: take(&m, 4)?,
            d3: take(&m, 5)?,
            pb: take(&m, 6)?,
            qb: take(&m, 7)?,
            cp: take(&m, 8)?,
            d5: take(&m, 9)?,
            d6: take(&m, 10)?,
        };
        if !valid_element(&msg.g2b)
            || !valid_element(&msg.g3b)
            || !valid_element(&msg.pb)
            || !valid_element(&msg.qb)
        {
            return Err(ProtocolError::Smp("group element out of range"));
        }
        Ok(msg)
    }
}

/// SMP Message 3 (initiator): `[Pa, Qa, cP, D5, D6, Ra, cR, D7]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmpMsg3 {
    /// Final comparison value.
    pub pa: BigUint,
    /// Final comparison value.
    pub qa: BigUint,
    /// Coordinates proof commitment.
    pub cp: BigUint,
    /// Coordinates proof response (blinding).
    pub d5: BigUint,
    /// Coordinates proof response (secret).
    pub d6: BigUint,
    /// Equal-logs comparison value.
    pub ra: BigUint,
    /// Equal-logs proof commitment.
    pub cr: BigUint,
    /// Equal-logs proof response.
    pub d7: BigUint,
}

impl SmpMsg3 {
    /// Wire serialization.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        mpis_to_wire(&[
            &self.pa, &self.qa, &self.cp, &self.d5, &self.d6, &self.ra, &self.cr, &self.d7,
        ])
    }

    /// Parses and validates group elements.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Smp`] on malformed messages.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let m = mpis_from_wire(bytes, 8)?;
        let msg = Self {
            pa: take(&m, 0)?,
            qa: take(&m, 1)?,
            cp: take(&m, 2)?,
            d5: take(&m, 3)?,
            d6: take(&m, 4)?,
            ra: take(&m, 5)?,
            cr: take(&m, 6)?,
            d7: take(&m, 7)?,
        };
        if !valid_element(&msg.pa) || !valid_element(&msg.qa) || !valid_element(&msg.ra) {
            return Err(ProtocolError::Smp("group element out of range"));
        }
        Ok(msg)
    }
}

/// SMP Message 4 (responder, final): `[Rb, cR, D7]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmpMsg4 {
    /// Equal-logs comparison value.
    pub rb: BigUint,
    /// Equal-logs proof commitment.
    pub cr: BigUint,
    /// Equal-logs proof response.
    pub d7: BigUint,
}

impl SmpMsg4 {
    /// Wire serialization.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        mpis_to_wire(&[&self.rb, &self.cr, &self.d7])
    }

    /// Parses and validates group elements.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Smp`] on malformed messages.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let m = mpis_from_wire(bytes, 3)?;
        let msg = Self {
            rb: take(&m, 0)?,
            cr: take(&m, 1)?,
            d7: take(&m, 2)?,
        };
        if !valid_element(&msg.rb) {
            return Err(ProtocolError::Smp("group element out of range"));
        }
        Ok(msg)
    }
}

/// The initiator's (Alice's) SMP state machine.
///
/// Flow: [`Self::start`] produces [`SmpMsg1`]; [`Self::receive_msg2`]
/// consumes the responder's message and produces [`SmpMsg3`];
/// [`Self::finish`] consumes [`SmpMsg4`] and yields the verdict.
pub struct SmpFirstParty {
    /// Secret exponent x.
    secret: BigUint,
    /// Initiator exponent a2 (re-derived generator in msg2).
    a2: BigUint,
    /// Initiator exponent a3 (final comparison exponent).
    a3: BigUint,
    /// Stored comparison value `(Qa / Qb)` (after msg2).
    qaqb: Option<BigUint>,
    /// Stored comparison value `(Pa / Pb)` (after msg2).
    papb: Option<BigUint>,
    /// Stored g3b for the msg4 equal-logs verification.
    g3b: Option<BigUint>,
}

impl SmpFirstParty {
    /// Starts the exchange with the derived secret (spec "user requests
    /// to begin SMP").
    ///
    /// # Errors
    ///
    /// Returns errors only if entropy fails.
    pub fn start(secret: &BigUint) -> Result<(Self, SmpMsg1), ProtocolError> {
        let g = group();
        let a2 = rand_exponent()?;
        let a3 = rand_exponent()?;
        let g2a = g.g1.modpow(&a2, &g.p);
        let g3a = g.g1.modpow(&a3, &g.p);
        let proof2 = prove_log(1, &a2)?;
        let proof3 = prove_log(2, &a3)?;
        Ok((
            Self {
                secret: secret.clone(),
                a2,
                a3,
                qaqb: None,
                papb: None,
                g3b: None,
            },
            SmpMsg1 {
                g2a,
                c2: proof2.c,
                d2: proof2.d,
                g3a,
                c3: proof3.c,
                d3: proof3.d,
            },
        ))
    }

    /// Verifies the responder's message (spec msg2 checks) and produces
    /// the initiator's final comparison message.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Smp`] on any proof failure.
    pub fn receive_msg2(mut self, msg: SmpMsg2) -> Result<(Self, SmpMsg3), ProtocolError> {
        let g = group();
        verify_log(
            3,
            &msg.g2b,
            &Zkp1 {
                c: msg.c2.clone(),
                d: msg.d2.clone(),
            },
        )?;
        verify_log(
            4,
            &msg.g3b,
            &Zkp1 {
                c: msg.c3.clone(),
                d: msg.d3.clone(),
            },
        )?;
        let g2 = msg.g2b.modpow(&self.a2, &g.p);
        let g3 = msg.g3b.modpow(&self.a3, &g.p);
        let (pa, qa, coords) = prove_coords(6, &g2, &g3, &self.secret, &rand_exponent()?)?;
        verify_coords(
            5,
            &g2,
            &g3,
            &msg.pb,
            &msg.qb,
            &ZkpCoords {
                c: msg.cp.clone(),
                d1: msg.d5.clone(),
                d2: msg.d6.clone(),
            },
        )?;

        // Ra = (Qa / Qb)^a3, with its equal-logs proof.
        let qaqb = mul_mod(&qa, &inverse(&msg.qb));
        let (ra, ra_proof) = prove_equal_logs(7, &qaqb, &self.a3)?;

        let papb = mul_mod(&pa, &inverse(&msg.pb));
        self.qaqb = Some(qaqb);
        self.papb = Some(papb);
        self.g3b = Some(msg.g3b);
        Ok((
            self,
            SmpMsg3 {
                pa,
                qa,
                cp: coords.c,
                d5: coords.d1,
                d6: coords.d2,
                ra,
                cr: ra_proof.c,
                d7: ra_proof.d,
            },
        ))
    }

    /// Verifies the responder's final proof and returns whether the
    /// secrets are equal (spec msg4 checks + comparison).
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Smp`] on proof failure.
    pub fn finish(self, msg: SmpMsg4) -> Result<bool, ProtocolError> {
        let g3b = self.g3b.ok_or(ProtocolError::StateViolation)?;
        let qaqb = self.qaqb.ok_or(ProtocolError::StateViolation)?;
        verify_equal_logs(
            8,
            &qaqb,
            &g3b,
            &msg.rb,
            &Zkp1 {
                c: msg.cr.clone(),
                d: msg.d7.clone(),
            },
        )?;
        // Rab = Rb^a3; success iff Rab == Pa/Pb.
        let rab = msg.rb.modpow(&self.a3, &group().p);
        let papb = self.papb.ok_or(ProtocolError::StateViolation)?;
        Ok(rab == papb)
    }
}

/// The responder's (Bob's) SMP state machine.
///
/// Flow: [`Self::receive_msg1`] consumes [`SmpMsg1`] and produces
/// [`SmpMsg2`]; [`Self::receive_msg3`] consumes [`SmpMsg3`], yields the
/// verdict and [`SmpMsg4`].
pub struct SmpSecondParty {
    /// Responder exponent b3 (used in the final comparison).
    b3: BigUint,
    /// Shared generator `g2 = g2a^b2` (after msg1).
    g2: Option<BigUint>,
    /// Shared generator `g3 = g3a^b3` (after msg1).
    g3: Option<BigUint>,
    /// Stored initiator value `g3a` (for the msg3 equal-logs check).
    g3a: Option<BigUint>,
    /// Stored responder comparison value `Qb` (after msg1).
    qb: Option<BigUint>,
    /// Stored responder comparison value `Pb` (after msg1).
    pb: Option<BigUint>,
    /// Stored comparison value `(Qa / Qb)` (after msg3).
    qaqb: Option<BigUint>,
    /// Stored comparison value `(Pa / Pb)` (after msg3).
    papb: Option<BigUint>,
    /// Verdict (available after msg3).
    result: Option<bool>,
}

impl SmpSecondParty {
    /// Verifies the initiator's message (spec msg1 checks) and produces
    /// the responder's message.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Smp`] on any proof failure.
    pub fn receive_msg1(secret: &BigUint, msg: SmpMsg1) -> Result<(Self, SmpMsg2), ProtocolError> {
        let g = group();
        verify_log(
            1,
            &msg.g2a,
            &Zkp1 {
                c: msg.c2.clone(),
                d: msg.d2.clone(),
            },
        )?;
        verify_log(
            2,
            &msg.g3a,
            &Zkp1 {
                c: msg.c3.clone(),
                d: msg.d3.clone(),
            },
        )?;
        let b2 = rand_exponent()?;
        let b3 = rand_exponent()?;
        let g2b = g.g1.modpow(&b2, &g.p);
        let g3b = g.g1.modpow(&b3, &g.p);
        let proof2 = prove_log(3, &b2)?;
        let proof3 = prove_log(4, &b3)?;
        let g2 = msg.g2a.modpow(&b2, &g.p);
        let g3 = msg.g3a.modpow(&b3, &g.p);
        let (pb, qb, coords) = prove_coords(5, &g2, &g3, secret, &rand_exponent()?)?;
        let msg2 = SmpMsg2 {
            g2b,
            c2: proof2.c,
            d2: proof2.d,
            g3b,
            c3: proof3.c,
            d3: proof3.d,
            pb: pb.clone(),
            qb: qb.clone(),
            cp: coords.c,
            d5: coords.d1,
            d6: coords.d2,
        };
        Ok((
            Self {
                b3,
                g2: Some(g2),
                g3: Some(g3),
                g3a: Some(msg.g3a),
                qb: Some(qb),
                pb: Some(pb),
                qaqb: None,
                papb: None,
                result: None,
            },
            msg2,
        ))
    }

    /// Verifies the initiator's final message, computes the verdict, and
    /// produces the responder's final message (spec msg3 checks).
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Smp`] on proof failure.
    pub fn receive_msg3(mut self, msg: SmpMsg3) -> Result<(Self, bool, SmpMsg4), ProtocolError> {
        let g = group();
        let g2 = self.g2.clone().ok_or(ProtocolError::StateViolation)?;
        let g3 = self.g3.clone().ok_or(ProtocolError::StateViolation)?;
        let g3a = self.g3a.clone().ok_or(ProtocolError::StateViolation)?;
        let pb = self.pb.clone().ok_or(ProtocolError::StateViolation)?;
        let qb = self.qb.clone().ok_or(ProtocolError::StateViolation)?;
        verify_coords(
            6,
            &g2,
            &g3,
            &msg.pa,
            &msg.qa,
            &ZkpCoords {
                c: msg.cp.clone(),
                d1: msg.d5.clone(),
                d2: msg.d6.clone(),
            },
        )?;
        let qaqb = mul_mod(&msg.qa, &inverse(&qb));
        verify_equal_logs(
            7,
            &qaqb,
            &g3a,
            &msg.ra,
            &Zkp1 {
                c: msg.cr.clone(),
                d: msg.d7.clone(),
            },
        )?;

        let (rb, rb_proof) = prove_equal_logs(8, &qaqb, &self.b3)?;
        // Rab = Ra^b3; success iff Rab == Pa/Pb.
        let rab = msg.ra.modpow(&self.b3, &g.p);
        let papb = mul_mod(&msg.pa, &inverse(&pb));
        let result = rab == papb;

        self.qaqb = Some(qaqb);
        self.papb = Some(papb);
        self.result = Some(result);
        Ok((
            self,
            result,
            SmpMsg4 {
                rb,
                cr: rb_proof.c,
                d7: rb_proof.d,
            },
        ))
    }

    /// The verdict, if computed.
    #[must_use]
    pub fn result(&self) -> Option<bool> {
        self.result
    }
}

// NOTE (documented residual): num-bigint provides no zeroization API, so
// the in-memory secret exponents in these state machines are not wiped on
// drop. The secret is the 256-bit pairing digest (short-lived, not a
// long-term key); the source bytes from `smp_secret` ARE `Zeroizing`.

/// Derives the password material with both parties' identity fingerprints
/// bound in, from a shared out-of-band password and the two
/// [`umbra_crypto::kdf::identity_fingerprint`] values. The fingerprint
/// pair is sorted canonically so initiator and responder compute the
/// same value regardless of role; `shared` is length-prefixed.
///
/// This is the PAIRING-level material only: the session driver MUST
/// still mix the per-handshake transcript SSID before the value reaches
/// the engine (see `umbra_net::messenger`), otherwise identical material
/// on both sides lets a relay forward SMP messages verbatim between two
/// distinct sessions. Residual: fingerprints derive from public keys, so
/// this binding's strength reduces to password secrecy plus the
/// out-of-band fingerprint comparison.
#[must_use]
pub fn bound_secret(shared: &[u8], fp_a: &[u8; 32], fp_b: &[u8; 32]) -> [u8; 32] {
    let (first, second) = if fp_a <= fp_b {
        (fp_a, fp_b)
    } else {
        (fp_b, fp_a)
    };
    let mut material = Vec::with_capacity(shared.len().saturating_add(64 + 8 + 1));
    material.push(0x03); // material tag within this derivation only; BLAKE3
    // context strings carry the cross-protocol separation
    material.extend_from_slice(first);
    material.extend_from_slice(second);
    material.extend_from_slice(
        &u64::try_from(shared.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    material.extend_from_slice(shared);
    umbra_crypto::kdf::derive_key("Umbra SMP bound secret v1", &material)
}
