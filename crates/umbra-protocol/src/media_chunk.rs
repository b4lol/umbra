//! MEDIA_CHUNK framing for sterilized media (TODO A.3, SPECIFICATION.md
//! opcode `0x06`).
//!
//! A sterilized PNG generally exceeds one packet's 990-byte payload, so it
//! is split into fixed chunks. Every chunk payload carries:
//!
//! ```text
//! [0..16)   transfer id   (random, per transfer)
//! [16..20)  chunk index   (u32 BE, 0-based)
//! [20..24)  chunk total   (u32 BE)
//! [24..56)  BLAKE3 digest of the FULL padded media (integrity at finish)
//! [56..60)  true media length (u32 BE; padding stripped at finish)
//! [60..)    data
//! ```
//!
//! Size masking: media is padded with random bytes to the next power of
//! two before splitting, so a passive observer learns at most the
//! power-of-two bucket — not the exact length (ADR-005 message-size
//! masking; the 2x bucket resolution residual is recorded in ADR-005).
//! The digest covers the padded buffer; `finish` verifies it and then
//! truncates to the true length.
//!
//! Integrity is verified on reassembly (`finish`), not per packet — the
//! per-packet AEAD already authenticates each chunk; the digest binds the
//! whole transfer together and catches loss/truncation/corruption.
//!
//! Hostile-input bounds: the chunk total is capped at [`MAX_CHUNKS`]
//! (derived from [`MAX_MEDIA_BYTES`]) before any allocation, and the
//! reassembled media is `Zeroizing` — wiped on drop (ADR-003/ADR-015).

use zeroize::{Zeroize, Zeroizing};

use umbra_crypto::kdf;
use umbra_crypto::rng;

use crate::error::ProtocolError;
use crate::packet::{self, SealedPacket};
use crate::types::PacketType;

/// Transfer id length in bytes.
pub const TRANSFER_ID_LEN: usize = 16;

/// Length of the per-chunk header (id + index + total + digest + true len).
pub const CHUNK_HEADER_LEN: usize = TRANSFER_ID_LEN + 4 + 4 + 32 + 4;

/// Offset of the true media length field within the chunk payload.
const TRUE_LEN_OFFSET: usize = TRANSFER_ID_LEN + 4 + 4 + 32;

/// Maximum media bytes carried by one chunk's payload.
pub const MAX_CHUNK_DATA: usize = crate::types::PAYLOAD_MAX - CHUNK_HEADER_LEN;

/// Hard cap on a single media transfer, in bytes (128 MiB).
///
/// Generous beyond the sterilizer's own output bounds; exists so that a
/// hostile peer can never drive unbounded allocation through chunk
/// accounting.
pub const MAX_MEDIA_BYTES: usize = 128 * 1024 * 1024;

/// Maximum chunk count for one transfer (derived from [`MAX_MEDIA_BYTES`]).
pub const MAX_CHUNKS: u32 = (MAX_MEDIA_BYTES / MAX_CHUNK_DATA) as u32;

/// Splits media into sealed [`PacketType::MediaChunk`] packets.
///
/// The media is padded with random bytes to the next power-of-two bucket
/// (see the module docs), then sealed chunk by chunk; every chunk carries
/// the BLAKE3 digest of the padded media and the true media length.
///
/// # Errors
///
/// Returns [`ProtocolError::MediaTooLarge`] if `media` exceeds
/// [`MAX_MEDIA_BYTES`], and packet-layer errors from sealing.
pub fn split_media(
    media: &[u8],
    key: Zeroizing<[u8; 32]>,
) -> Result<Vec<SealedPacket>, ProtocolError> {
    if media.len() > MAX_MEDIA_BYTES {
        return Err(ProtocolError::MediaTooLarge);
    }

    let mut transfer_id = [0u8; TRANSFER_ID_LEN];
    rng::fill(&mut transfer_id).map_err(ProtocolError::from)?;

    // Size masking: pad to the next power-of-two bucket (minimum one chunk
    // worth of data so even tiny media occupies a stable bucket).
    let true_len = media.len();
    let padded_len = true_len.next_power_of_two().max(MAX_CHUNK_DATA);
    let mut padded = Vec::with_capacity(padded_len);
    padded.extend_from_slice(media);
    let pad_len = padded_len.saturating_sub(true_len);
    let mut pad = vec![0u8; pad_len];
    rng::fill(&mut pad).map_err(ProtocolError::from)?;
    padded.extend_from_slice(&pad);

    let digest = *blake3::hash(&padded).as_bytes();
    let total = padded.len().div_ceil(MAX_CHUNK_DATA);
    let total32 = u32::try_from(total).map_err(|_e| ProtocolError::InvalidLength {
        expected: u32::MAX as usize,
        actual: padded.len(),
    })?;

    let mut packets = Vec::with_capacity(total);
    for index in 0..total {
        let start = index
            .checked_mul(MAX_CHUNK_DATA)
            .ok_or(ProtocolError::InvalidLength {
                expected: padded.len(),
                actual: usize::MAX,
            })?;
        let end = start
            .checked_add(MAX_CHUNK_DATA)
            .unwrap_or(padded.len())
            .min(padded.len());
        let data = padded.get(start..end).unwrap_or(&[]);

        let capacity = CHUNK_HEADER_LEN.saturating_add(data.len());
        let mut payload = Vec::with_capacity(capacity);
        payload.extend_from_slice(&transfer_id);
        let index32 = u32::try_from(index).map_err(|_e| ProtocolError::InvalidLength {
            expected: u32::MAX as usize,
            actual: index,
        })?;
        payload.extend_from_slice(&index32.to_be_bytes());
        payload.extend_from_slice(&total32.to_be_bytes());
        payload.extend_from_slice(&digest);
        payload.extend_from_slice(&(true_len as u32).to_be_bytes());
        payload.extend_from_slice(data);

        let sealed = packet::seal(PacketType::MediaChunk, key.clone(), &payload)?;
        packets.push(sealed);
    }
    Ok(packets)
}

/// Reassembles a media transfer from its chunks.
///
/// Chunks may arrive in any order; duplicates are ignored. [`Self::finish`]
/// succeeds only when every chunk is present and the BLAKE3 digest matches;
/// the returned media is truncated to the true length and wrapped in
/// [`Zeroizing`] (wiped on drop — ADR-003). Dropping an incomplete
/// assembler also wipes whatever arrived.
pub struct MediaAssembler {
    /// Random transfer id all chunks must share.
    transfer_id: [u8; TRANSFER_ID_LEN],
    /// BLAKE3 digest of the full padded media.
    digest: [u8; 32],
    /// Expected total chunk count (0 until the first chunk arrives).
    total: u32,
    /// True media length (0 until the first chunk arrives).
    true_len: usize,
    /// Received chunk data slots (index-ordered).
    slots: Vec<Option<Vec<u8>>>,
    /// Number of filled slots.
    received: u32,
}

impl MediaAssembler {
    /// Creates an empty assembler; the first pushed chunk defines the
    /// transfer id, total, digest, and true length.
    #[must_use]
    pub fn new() -> Self {
        Self {
            transfer_id: [0u8; TRANSFER_ID_LEN],
            digest: [0u8; 32],
            total: 0,
            true_len: 0,
            slots: Vec::new(),
            received: 0,
        }
    }

    /// Parses and registers one unsealed MEDIA_CHUNK payload.
    ///
    /// The caller unseals the wire packet first (packet-layer AEAD), then
    /// hands the plaintext payload here.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidLength`] for malformed payloads and
    /// [`ProtocolError::StateViolation`] for out-of-range indices,
    /// over-cap totals, or transfer-id/total/length mismatches.
    pub fn push(&mut self, payload: &[u8]) -> Result<(), ProtocolError> {
        if payload.len() < CHUNK_HEADER_LEN {
            return Err(ProtocolError::InvalidLength {
                expected: CHUNK_HEADER_LEN,
                actual: payload.len(),
            });
        }
        let transfer_id: [u8; TRANSFER_ID_LEN] = kdf::read_at(payload, 0)?;
        let index = u32::from_be_bytes(kdf::read_at(payload, TRANSFER_ID_LEN)?);
        let total = u32::from_be_bytes(kdf::read_at(payload, TRANSFER_ID_LEN + 4)?);
        let digest: [u8; 32] = kdf::read_at(payload, TRANSFER_ID_LEN + 8)?;
        let true_len = u32::from_be_bytes(kdf::read_at(payload, TRUE_LEN_OFFSET)?) as usize;
        if total > MAX_CHUNKS || true_len > MAX_MEDIA_BYTES {
            return Err(ProtocolError::StateViolation);
        }

        if self.slots.is_empty() {
            // First chunk defines the transfer.
            self.transfer_id = transfer_id;
            self.digest = digest;
            self.total = total;
            self.true_len = true_len;
            self.slots = vec![None; total as usize];
        } else if self.transfer_id != transfer_id
            || self.total != total
            || self.true_len != true_len
        {
            return Err(ProtocolError::StateViolation);
        }

        let index_usize = index as usize;
        if index_usize >= self.slots.len() {
            return Err(ProtocolError::StateViolation);
        }
        let data = payload.get(CHUNK_HEADER_LEN..).unwrap_or(&[]);
        match self.slots.get_mut(index_usize) {
            Some(Some(_existing)) => {} // duplicate chunk: ignore
            Some(slot) => {
                *slot = Some(data.to_vec());
                self.received = self.received.saturating_add(1);
            }
            None => return Err(ProtocolError::StateViolation),
        }
        Ok(())
    }

    /// Whether every chunk has arrived (false until at least one chunk
    /// defines the transfer).
    #[must_use]
    pub fn complete(&self) -> bool {
        self.total > 0 && self.received as usize == self.slots.len()
    }

    /// Concatenates the chunks, verifies the digest over the padded media,
    /// and truncates to the true length.
    ///
    /// The result is [`Zeroizing`]: wiped when dropped (ADR-003/ADR-015
    /// RAM-only lifecycle; 24-hour crypto-shredding is applied at the
    /// client layer where media ages out).
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::StateViolation`] unless all chunks are
    /// present, and [`ProtocolError::InvalidMedia`] on digest mismatch.
    pub fn finish(self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        if !self.complete() {
            return Err(ProtocolError::StateViolation);
        }
        let mut padded = Vec::new();
        for slot in self.slots.iter().flatten() {
            padded.extend_from_slice(slot);
        }
        if *blake3::hash(&padded).as_bytes() != self.digest {
            padded.zeroize();
            return Err(ProtocolError::InvalidMedia);
        }
        // Strip the size-masking padding (digest was over the padded media).
        padded.truncate(self.true_len);
        Ok(Zeroizing::new(padded))
    }
}

impl Default for MediaAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for MediaAssembler {
    fn drop(&mut self) {
        // RAM-only hygiene: wipe every received chunk.
        for slot in self.slots.iter_mut().flatten() {
            slot.zeroize();
        }
    }
}
