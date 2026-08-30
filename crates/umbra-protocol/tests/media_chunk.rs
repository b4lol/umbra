//! MEDIA_CHUNK transfer tests (TODO A.3, SPECIFICATION.md opcode `0x06`).
//!
//! Hermetic: no network, no filesystem.

use proptest::prelude::*;
use zeroize::Zeroizing;

use umbra_protocol::media_chunk::{MediaAssembler, split_media};
use umbra_protocol::packet::unseal;
use umbra_protocol::types::PacketType;

/// A full media transfer survives split -> unseal -> reassemble.
#[test]
fn media_transfer_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let media: Vec<u8> = (0..5000usize).map(|i| (i % 253) as u8).collect();
    let key = Zeroizing::new([9u8; 32]);
    let packets = split_media(&media, key.clone())?;
    assert!(packets.len() >= 6, "5000 bytes must span multiple chunks");

    let mut assembler = MediaAssembler::new();
    for sealed in &packets {
        let unsealed = unseal(sealed, key.clone())?;
        assert_eq!(unsealed.packet_type, PacketType::MediaChunk);
        assembler.push(&unsealed.payload)?;
    }
    assert!(assembler.complete());
    let reassembled = assembler.finish()?;
    assert_eq!(*reassembled, media);
    Ok(())
}

/// Out-of-order delivery still reassembles correctly.
#[test]
fn media_transfer_out_of_order() -> Result<(), Box<dyn std::error::Error>> {
    let media: Vec<u8> = (0..3000usize).map(|i| (i % 249) as u8).collect();
    let key = Zeroizing::new([3u8; 32]);
    let mut packets = split_media(&media, key.clone())?;
    // Reverse delivery order (keep at least one chunk to reverse).
    packets.reverse();

    let mut assembler = MediaAssembler::new();
    for sealed in &packets {
        let unsealed = unseal(sealed, key.clone())?;
        assembler.push(&unsealed.payload)?;
    }
    assert_eq!(*assembler.finish()?, media);
    Ok(())
}

/// Digest verification catches a corrupted reassembly.
#[test]
fn digest_mismatch_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let media = vec![1u8; 2000];
    let key = Zeroizing::new([4u8; 32]);
    let packets = split_media(&media, key.clone())?;
    let mut assembler = MediaAssembler::new();
    // Push all chunks except the last normally.
    let (head, tail) = packets.split_at(packets.len() - 1);
    for sealed in head {
        let unsealed = unseal(sealed, key.clone())?;
        assembler.push(&unsealed.payload)?;
    }
    // Then the last chunk with one data byte corrupted (simulating content
    // corruption between unseal and reassembly).
    let last = tail.first().ok_or("at least one chunk")?;
    let mut unsealed = unseal(last, key.clone())?;
    if let Some(last_byte) = unsealed.payload.last_mut() {
        *last_byte = last_byte.wrapping_add(1);
    }
    assembler.push(&unsealed.payload)?;
    assert!(assembler.finish().is_err());
    Ok(())
}

/// An incomplete transfer cannot be finished.
#[test]
fn incomplete_transfer_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let media = vec![2u8; 2000];
    let key = Zeroizing::new([7u8; 32]);
    let packets = split_media(&media, key.clone())?;
    assert!(packets.len() > 1);

    let mut assembler = MediaAssembler::new();
    let first = packets.first().ok_or("at least one chunk")?;
    let unsealed = unseal(first, key.clone())?;
    assembler.push(&unsealed.payload)?;
    assert!(!assembler.complete());
    assert!(assembler.finish().is_err());
    Ok(())
}

proptest! {
    /// Any media size round-trips through chunking and reassembly.
    #[test]
    fn media_transfer_property(
        size in 0usize..=6000,
        seed in any::<u64>(),
    ) {
        let media: Vec<u8> = (0..size).map(|i| ((i as u64) ^ seed) as u8).collect();
        let key = Zeroizing::new([11u8; 32]);
        let packets = split_media(&media, key.clone())?;
        let mut assembler = MediaAssembler::new();
        for sealed in &packets {
            let unsealed = unseal(sealed, key.clone())?;
            assembler.push(&unsealed.payload)?;
        }
        let reassembled = assembler.finish()?;
        let plain: &[u8] = reassembled.as_ref();
        prop_assert_eq!(plain, &media);
    }
}

/// A hostile chunk claiming an over-cap total is rejected before any
/// large allocation (memory-exhaustion defense).
#[test]
fn hostile_total_rejected() -> Result<(), Box<dyn std::error::Error>> {
    use umbra_protocol::media_chunk::{CHUNK_HEADER_LEN, MAX_CHUNKS};
    let mut payload = vec![0u8; CHUNK_HEADER_LEN + 8];
    // transfer_id zeros are fine; index 0; total = u32::MAX (> MAX_CHUNKS);
    // digest zeros; true_len zeros; 8 bytes of data.
    let slot = payload.get_mut(20..24).ok_or("header slot missing")?;
    slot.copy_from_slice(&u32::MAX.to_be_bytes());
    let mut assembler = MediaAssembler::new();
    assert!(matches!(
        assembler.push(&payload),
        Err(umbra_protocol::ProtocolError::StateViolation)
    ));
    let _ = MAX_CHUNKS;
    Ok(())
}

/// A chunk whose true_len exceeds the media cap is rejected.
#[test]
fn hostile_true_len_rejected() -> Result<(), Box<dyn std::error::Error>> {
    use umbra_protocol::media_chunk::{CHUNK_HEADER_LEN, MAX_MEDIA_BYTES};
    let mut payload = vec![0u8; CHUNK_HEADER_LEN + 8];
    // total = 1 (valid), true_len = MAX_MEDIA_BYTES + 1 (over cap).
    let digest_slot = payload.get_mut(24..28).ok_or("digest slot missing")?;
    digest_slot.copy_from_slice(&[9u8; 4]); // digest placeholder
    let len_slot = payload.get_mut(56..60).ok_or("true-length slot missing")?;
    len_slot.copy_from_slice(&(MAX_MEDIA_BYTES as u32).wrapping_add(1).to_be_bytes());
    let mut assembler = MediaAssembler::new();
    assert!(matches!(
        assembler.push(&payload),
        Err(umbra_protocol::ProtocolError::StateViolation)
    ));
    Ok(())
}
