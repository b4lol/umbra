//! Out-of-band pairing payload and SAS derivation (TODO A.3,
//! CRYPTOGRAPHY.md §5).
//!
//! The pairing payload carries the full public identity of one side
//! (X25519 IK + SPK + SPK signature + ML-KEM EK + ML-DSA VK) and is
//! exchanged out of band (QR / copy-paste). Both sides then derive the
//! same 6-digit SAS code from the two payloads — the code is compared
//! visually or over a trusted channel to exclude MITMs.

use base64::Engine as _;

use umbra_crypto::keys::{IdentityBundle, KEM_PK_LEN};
use umbra_protocol::sas::SasCode;

use crate::cli::CliError;

/// Wire length of a pairing payload:
/// `ik(32) + spk(32) + spk_sig + kem(1184) + dsa_vk`.
pub const PAYLOAD_LEN: usize =
    32 + 32 + umbra_crypto::signing::SIG_LEN + KEM_PK_LEN + umbra_crypto::signing::VK_LEN;

/// Builds the base64url pairing payload for a local identity.
///
/// # Errors
///
/// Returns [`CliError::Keystore`] on internal length mismatches (cannot
/// happen with fixed-size fields).
pub fn payload_for(bundle: &IdentityBundle) -> Result<String, CliError> {
    let mut bytes = Vec::with_capacity(PAYLOAD_LEN);
    bytes.extend_from_slice(&bundle.x25519.public_bytes());
    bytes.extend_from_slice(&bundle.spk.public_bytes());
    bytes.extend_from_slice(&bundle.spk_signature);
    bytes.extend_from_slice(&bundle.kem.public_bytes());
    bytes.extend_from_slice(&bundle.dsa.public_bytes());
    if bytes.len() != PAYLOAD_LEN {
        return Err(CliError::Keystore(format!(
            "pairing payload length mismatch: {} != {PAYLOAD_LEN}",
            bytes.len()
        )));
    }
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes))
}

/// Parses a base64url pairing payload and verifies its internal SPK
/// signature (the payload is self-authenticating: whoever holds the
/// ML-DSA secret made it).
///
/// # Errors
///
/// Returns [`CliError`] on base64, length, or signature failure.
pub fn parse_payload(encoded: &str) -> Result<PeerIdentity, CliError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .map_err(|e| CliError::Keystore(format!("invalid payload base64: {e}")))?;
    if bytes.len() != PAYLOAD_LEN {
        return Err(CliError::Keystore(format!(
            "payload length mismatch: {} != {PAYLOAD_LEN}",
            bytes.len()
        )));
    }
    let mut cursor = 0usize;
    let mut read = |count: usize| -> Result<Vec<u8>, CliError> {
        let end = cursor
            .checked_add(count)
            .ok_or(CliError::Keystore("payload overflow".into()))?;
        let slice = bytes
            .get(cursor..end)
            .ok_or_else(|| CliError::Keystore("payload truncated".into()))?;
        cursor = end;
        Ok(slice.to_vec())
    };

    let ik = read(32)?;
    let spk = read(32)?;
    let spk_signature = read(umbra_crypto::signing::SIG_LEN)?;
    let kem = read(KEM_PK_LEN)?;
    let dsa = read(umbra_crypto::signing::VK_LEN)?;

    // Self-authentication: the SPK signature must verify under the
    // payload's own ML-DSA key.
    umbra_crypto::signing::MlDsaKeyPair::verify(&dsa, &spk, &spk_signature)
        .map_err(CliError::Crypto)?;

    let mut ik_arr = [0u8; 32];
    ik_arr.copy_from_slice(&ik);
    let mut spk_arr = [0u8; 32];
    spk_arr.copy_from_slice(&spk);
    let mut kem_arr = [0u8; KEM_PK_LEN];
    kem_arr.copy_from_slice(&kem);

    Ok(PeerIdentity {
        ik,
        ik_arr,
        spk_arr,
        spk_signature,
        kem_arr,
        dsa,
        onion: None,
    })
}

/// The parsed public identity of a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// X25519 identity public key.
    pub ik_arr: [u8; 32],
    /// Raw ik bytes (owned).
    pub ik: Vec<u8>,
    /// SPK public bytes.
    pub spk_arr: [u8; 32],
    /// SPK signature.
    pub spk_signature: Vec<u8>,
    /// ML-KEM encapsulation key.
    pub kem_arr: [u8; 1184],
    /// ML-DSA verification key.
    pub dsa: Vec<u8>,
    /// The peer's `.onion` service address, when the operator recorded
    /// one (`umbra pair --onion`); absent for payload-only records.
    pub onion: Option<String>,
}

/// Derives the shared 6-digit SAS code from BOTH pairing payloads
/// (order-independent: payloads are hashed in sorted order).
///
/// Both parties must observe the same code over a trusted channel.
#[must_use]
pub fn pairing_sas(own_payload: &str, peer_payload: &str) -> SasCode {
    let own = own_payload.trim().as_bytes();
    let peer = peer_payload.trim().as_bytes();
    // Order-independent binding: hash the sorted pair.
    let (first, second) = if own <= peer {
        (own, peer)
    } else {
        (peer, own)
    };
    let capacity = first.len().saturating_add(second.len()).saturating_add(1);
    let mut material = Vec::with_capacity(capacity);
    material.push(0x01); // domain separator: pairing SAS
    material.extend_from_slice(&(first.len() as u64).to_be_bytes());
    material.extend_from_slice(first);
    material.extend_from_slice(&(second.len() as u64).to_be_bytes());
    material.extend_from_slice(second);
    let digest = umbra_crypto::kdf::derive_key("Umbra pairing SAS v1", &material);
    SasCode::derive(&digest)
}
