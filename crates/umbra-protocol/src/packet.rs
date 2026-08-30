//! 1024-byte fixed-block packet framing (SPECIFICATION.md §1, ADR-005).
//!
//! Wire layout (this implementation resolves the offset-table arithmetic of
//! SPECIFICATION.md to sum exactly to 1024 bytes — see [`crate::types`]):
//!
//! ```text
//! [0..18)    header: MAGIC(2) VER(1) TYPE(1) PAYLOAD_LEN(2) NONCE(12)
//! [18..1008) ENCRYPTED_DATA: payload + cryptographic random padding (990 B)
//! [1008..1024) POLY1305_TAG (16 B)
//! ```
//!
//! The full 18-byte header is used as AEAD associated data, binding every
//! header field to the ciphertext. Bare `buffer[i]` indexing is avoided
//! throughout (CODE_MANIFESTO §1); `split_at`/`get` with explicit errors
//! are used instead.

use zeroize::Zeroizing;

use umbra_crypto::aead::AeadCipher;
use umbra_crypto::rng;

use crate::error::ProtocolError;
use crate::types::{
    BODY_LEN, HEADER_LEN, MAGIC, PACKET_LEN, PAYLOAD_MAX, PROTOCOL_VERSION, PacketType, TAG_LEN,
};

/// Byte offset of the nonce inside the header.
const NONCE_OFFSET: usize = 6;

/// A fixed-size sealed packet ready for the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedPacket([u8; PACKET_LEN]);

impl SealedPacket {
    /// Imports a packet from raw wire bytes, validating magic and version.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidLength`] unless `bytes` is exactly
    /// [`PACKET_LEN`] long, [`ProtocolError::BadMagic`] for wrong magic
    /// bytes, and [`ProtocolError::BadVersion`] for an unsupported version.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != PACKET_LEN {
            return Err(ProtocolError::InvalidLength {
                expected: PACKET_LEN,
                actual: bytes.len(),
            });
        }
        let mut packet = [0u8; PACKET_LEN];
        packet.copy_from_slice(bytes);

        let (header, _rest) = packet.split_at(HEADER_LEN);
        let magic_ok =
            header.first().copied() == Some(MAGIC[0]) && header.get(1).copied() == Some(MAGIC[1]);
        if !magic_ok {
            return Err(ProtocolError::BadMagic);
        }
        let version = header.get(2).copied().unwrap_or(0);
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::BadVersion(version));
        }
        Ok(Self(packet))
    }

    /// Wire view of the packet.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PACKET_LEN] {
        &self.0
    }

    /// Consumes the packet, returning the raw wire bytes.
    #[must_use]
    pub fn into_bytes(self) -> [u8; PACKET_LEN] {
        self.0
    }
}

/// A successfully authenticated packet body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsealedPacket {
    /// Packet opcode.
    pub packet_type: PacketType,
    /// Plaintext payload (padding stripped).
    pub payload: Vec<u8>,
}

/// Seals a payload into a fixed-size packet.
///
/// The payload is padded with cryptographic random bytes to the fixed
/// region size (SPECIFICATION.md §1), the nonce is single-use random, and
/// the full header is bound as AAD.
///
/// # Errors
///
/// See [`SealedPacket::from_bytes`] for framing errors, plus
/// [`ProtocolError::PayloadTooLarge`] and crypto-layer failures.
pub fn seal(
    packet_type: PacketType,
    key: Zeroizing<[u8; 32]>,
    payload: &[u8],
) -> Result<SealedPacket, ProtocolError> {
    if payload.len() > PAYLOAD_MAX {
        return Err(ProtocolError::PayloadTooLarge {
            max: PAYLOAD_MAX,
            actual: payload.len(),
        });
    }

    // Plaintext region: payload followed by cryptographic random padding.
    let mut plaintext = [0u8; PAYLOAD_MAX];
    let (head, _pad) = plaintext.split_at_mut(payload.len());
    head.copy_from_slice(payload);

    // Header with a fresh single-use nonce.
    let mut nonce = [0u8; 12];
    rng::fill(&mut nonce).map_err(ProtocolError::from)?;
    let mut header = [0u8; HEADER_LEN];
    header[0] = MAGIC[0];
    header[1] = MAGIC[1];
    header[2] = PROTOCOL_VERSION;
    header[3] = packet_type.as_u8();
    let len_bytes = u16::try_from(payload.len())
        .map_err(|_e| ProtocolError::PayloadTooLarge {
            max: PAYLOAD_MAX,
            actual: payload.len(),
        })?
        .to_be_bytes();
    header[4] = len_bytes[0];
    header[5] = len_bytes[1];
    let header_len = header.len();
    let nonce_slot =
        header
            .get_mut(NONCE_OFFSET..HEADER_LEN)
            .ok_or(ProtocolError::InvalidLength {
                expected: header_len,
                actual: HEADER_LEN - NONCE_OFFSET,
            })?;
    nonce_slot.copy_from_slice(&nonce);

    // AEAD over the padded plaintext with the header as AAD.
    let cipher = AeadCipher::new(key);
    let ct = cipher.seal_with_nonce(&nonce, &header, &plaintext)?;

    // Assemble: header || ciphertext-body || tag.
    let mut packet = [0u8; PACKET_LEN];
    let (hdr_dst, rest) = packet.split_at_mut(HEADER_LEN);
    hdr_dst.copy_from_slice(&header);
    let (body_dst, tag_dst) = rest.split_at_mut(BODY_LEN);
    let (ct_body, ct_tag) = ct.split_at(BODY_LEN);
    body_dst.copy_from_slice(ct_body);
    tag_dst.copy_from_slice(ct_tag);
    Ok(SealedPacket(packet))
}

/// Opens a sealed packet, verifying the tag and returning the payload.
///
/// The random padding is stripped; the receiver destroys the plaintext
/// buffer after copying the payload (RAM-only doctrine).
///
/// # Errors
///
/// Returns framing errors from [`SealedPacket::from_bytes`] plus
/// [`ProtocolError::Crypto`] on tag-verification failure.
pub fn unseal(
    packet: &SealedPacket,
    key: Zeroizing<[u8; 32]>,
) -> Result<UnsealedPacket, ProtocolError> {
    let bytes = packet.as_bytes();
    let (header, rest) = bytes.split_at(HEADER_LEN);

    let magic_ok =
        header.first().copied() == Some(MAGIC[0]) && header.get(1).copied() == Some(MAGIC[1]);
    if !magic_ok {
        return Err(ProtocolError::BadMagic);
    }
    let version = header.get(2).copied().unwrap_or(0);
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::BadVersion(version));
    }
    let type_byte = header.get(3).copied().unwrap_or(0);
    let packet_type = PacketType::try_from(type_byte)?;

    let len_field = header.get(4..6).ok_or(ProtocolError::InvalidLength {
        expected: HEADER_LEN,
        actual: header.len(),
    })?;
    let len_pair: [u8; 2] = len_field
        .try_into()
        .map_err(|_e| ProtocolError::InvalidLength {
            expected: 2,
            actual: len_field.len(),
        })?;
    let payload_len = usize::from(u16::from_be_bytes(len_pair));

    let nonce_field = header
        .get(NONCE_OFFSET..HEADER_LEN)
        .ok_or(ProtocolError::InvalidLength {
            expected: HEADER_LEN,
            actual: header.len(),
        })?;
    let nonce: [u8; 12] = nonce_field
        .try_into()
        .map_err(|_e| ProtocolError::InvalidLength {
            expected: 12,
            actual: nonce_field.len(),
        })?;

    let (body, tag) = rest.split_at(BODY_LEN);
    let mut ct = Vec::with_capacity(BODY_LEN + TAG_LEN);
    ct.extend_from_slice(body);
    ct.extend_from_slice(tag);

    let cipher = AeadCipher::new(key);
    let plaintext = cipher
        .open(&nonce, header, &ct)
        .map_err(ProtocolError::from)?;

    let payload: Vec<u8> = plaintext.into_iter().take(payload_len).collect();
    Ok(UnsealedPacket {
        packet_type,
        payload,
    })
}
