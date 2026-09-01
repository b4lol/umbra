//! PQXDH hybrid handshake (CRYPTOGRAPHY.md §2).
//!
//! `SK = HKDF-SHA512(DH1 || DH2 || DH3 || SS_ML-KEM, ROOT_SALT, ROOT_INFO)`
//! where
//!
//! - `DH1 = DH(IK_A, SPK_B)`
//! - `DH2 = DH(EK_A, IK_B)`
//! - `DH3 = DH(EK_A, SPK_B)`
//! - `SS_ML-KEM` = ML-KEM-768 encapsulation secret toward `PK_KEM_B`
//!
//! Even if X25519 falls to a future quantum computer, the session secret
//! remains protected by the ML-KEM lattice problem ("Harvest Now, Decrypt
//! Later" defense).

use crate::error::CryptoError;
use crate::kdf::{self, RootKey};
use crate::keys::{
    KEM_CT_LEN, MlKemKeyPair, MlKemPeerKey, X25519_PK_LEN, X25519KeyPair, X25519PublicKey,
};

/// Wire length of the encoded initial handshake blob:
/// `IK_A (32) || EK_A (32) || CT_ML-KEM (1088)`.
pub const HANDSHAKE_BLOB_LEN: usize = X25519_PK_LEN + X25519_PK_LEN + KEM_CT_LEN;

/// The initiator's first-flight handshake material.
///
/// SPECIFICATION.md packs `HANDSHAKE_INIT` into a single 1024-byte packet,
/// which cannot hold 1152 bytes of handshake blob alongside headers; the
/// blob is therefore chunked by the transport layer (see `umbra-net`).
pub struct InitialHandshake {
    /// Initiator identity public key.
    ik_a: [u8; 32],
    /// Initiator ephemeral public key.
    ek_a: [u8; 32],
    /// ML-KEM-768 ciphertext encapsulated toward the responder.
    kem_ct: [u8; KEM_CT_LEN],
}

impl InitialHandshake {
    /// Encodes the handshake blob for the wire (1152 bytes).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HANDSHAKE_BLOB_LEN);
        out.extend_from_slice(&self.ik_a);
        out.extend_from_slice(&self.ek_a);
        out.extend_from_slice(&self.kem_ct);
        out
    }

    /// Decodes a handshake blob produced by [`Self::encode`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] unless `blob` is exactly
    /// [`HANDSHAKE_BLOB_LEN`] bytes.
    pub fn decode(blob: &[u8]) -> Result<Self, CryptoError> {
        if blob.len() != HANDSHAKE_BLOB_LEN {
            return Err(CryptoError::InvalidLength {
                expected: HANDSHAKE_BLOB_LEN,
                actual: blob.len(),
            });
        }
        Ok(Self {
            ik_a: kdf::read_at(blob, 0)?,
            ek_a: kdf::read_at(blob, 32)?,
            kem_ct: kdf::read_at(blob, 64)?,
        })
    }
}

/// Performs the initiator (Alice) side of PQXDH.
///
/// Returns the wire blob for the responder and the derived session root key.
///
/// # Errors
///
/// Returns [`CryptoError::HandshakeFailed`] if any X25519 output is
/// non-contributory.
pub fn initiator_start(
    ik_a: &X25519KeyPair,
    ik_b: &X25519PublicKey,
    spk_b: &X25519PublicKey,
    peer_kem: &MlKemPeerKey,
) -> Result<(InitialHandshake, RootKey), CryptoError> {
    let ek_a = X25519KeyPair::generate();
    let dh1 = ik_a.dh(spk_b)?;
    let dh2 = ek_a.dh(ik_b)?;
    let dh3 = ek_a.dh(spk_b)?;
    let (kem_ct, kem_ss) = peer_kem.encapsulate();

    let mut ikm = [0u8; 128];
    kdf::write_at(&mut ikm, 0, &dh1)?;
    kdf::write_at(&mut ikm, 32, &dh2)?;
    kdf::write_at(&mut ikm, 64, &dh3)?;
    kdf::write_at(&mut ikm, 96, &kem_ss)?;

    let root = kdf::derive_root_key(&ikm)?;
    // Best-effort register scrub (ADR-025 revision note): DH scalars and
    // the KEM shared secret transit caller-saved registers above.
    umbra_hardware::hardening::scrub_volatile_registers();
    Ok((
        InitialHandshake {
            ik_a: ik_a.public_bytes(),
            ek_a: ek_a.public_bytes(),
            kem_ct,
        },
        root,
    ))
}

/// Performs the responder (Bob) side of PQXDH.
///
/// Consumes the initiator's blob and derives the same session root key.
///
/// # Errors
///
/// Returns [`CryptoError::HandshakeFailed`] if any X25519 output is
/// non-contributory, or [`CryptoError::InvalidLength`] for a malformed blob.
pub fn responder_respond(
    ik_b: &X25519KeyPair,
    spk_b: &X25519KeyPair,
    kem: &MlKemKeyPair,
    msg: &InitialHandshake,
) -> Result<RootKey, CryptoError> {
    let encoded = msg.encode();
    let ik_a = X25519PublicKey::from_bytes(&kdf::read_at(&encoded, 0)?);
    let ek_a = X25519PublicKey::from_bytes(&kdf::read_at(&encoded, 32)?);
    let kem_ct: [u8; KEM_CT_LEN] = kdf::read_at(&encoded, 64)?;

    let dh1 = spk_b.dh(&ik_a)?;
    let dh2 = ik_b.dh(&ek_a)?;
    let dh3 = spk_b.dh(&ek_a)?;
    let kem_ss = kem.decapsulate(&kem_ct)?;

    let mut ikm = [0u8; 128];
    kdf::write_at(&mut ikm, 0, &dh1)?;
    kdf::write_at(&mut ikm, 32, &dh2)?;
    kdf::write_at(&mut ikm, 64, &dh3)?;
    kdf::write_at(&mut ikm, 96, &kem_ss)?;

    let root = kdf::derive_root_key(&ikm)?;
    // Best-effort register scrub (ADR-025 revision note): the KEM shared
    // secret (decapsulate above) and DH scalars transit caller-saved
    // registers.
    umbra_hardware::hardening::scrub_volatile_registers();
    Ok(root)
}
