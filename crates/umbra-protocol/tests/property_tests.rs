//! Property-based tests for the wire protocol (TODO A.5).
//!
//! Hermetic: no network, no filesystem.

use proptest::prelude::*;
use zeroize::Zeroizing;

use umbra_protocol::newtypes::{EpochId, SequenceNumber};
use umbra_protocol::packet::{seal, unseal};
use umbra_protocol::sas::SasCode;
use umbra_protocol::types::{PACKET_LEN, PacketType};

proptest! {
    /// Packet seal/unseal roundtrip preserves type and payload.
    #[test]
    fn packet_roundtrip(
        payload in proptest::collection::vec(any::<u8>(), 0..=900),
        tag in 0x01u8..=0x09,
    ) {
        let ptype = PacketType::try_from(tag)?;
        let key = Zeroizing::new([42u8; 32]);
        let sealed = seal(ptype, key.clone(), &payload)?;
        prop_assert_eq!(sealed.as_bytes().len(), PACKET_LEN);
        let opened = unseal(&sealed, key)?;
        prop_assert_eq!(opened.packet_type, ptype);
        prop_assert_eq!(opened.payload, payload);
    }

    /// Unseal fails when the packet is tampered with.
    #[test]
    fn packet_rejects_tamper(payload in proptest::collection::vec(any::<u8>(), 1..=900)) {
        let key = Zeroizing::new([7u8; 32]);
        let mut sealed = seal(PacketType::DataMessage, key.clone(), &payload)?.into_bytes();
        if let Some(last) = sealed.last_mut() {
            *last = last.wrapping_add(1);
        }
        let wire = umbra_protocol::packet::SealedPacket::from_bytes(&sealed)?;
        prop_assert!(unseal(&wire, key).is_err());
    }

    /// SAS codes are stable for the same secret and 6-digit bounded.
    #[test]
    fn sas_stable(a in any::<[u8; 32]>()) {
        let s1 = SasCode::derive(&a);
        let s1_again = SasCode::derive(&a);
        prop_assert!(s1.matches(&s1_again));
        prop_assert!(s1.value() < 1_000_000);
        prop_assert_eq!(s1.to_string().len(), 6);
    }

    /// Sequence numbers never wrap silently.
    #[test]
    fn sequence_checked(max in proptest::num::u64::ANY) {
        let seq = SequenceNumber::new(max);
        let ok = match (max.checked_add(1), seq.next()) {
            (Some(expected), Some(next)) => next.as_u64() == expected,
            (None, None) => max == u64::MAX,
            _ => false,
        };
        prop_assert!(ok);
    }

    /// Epoch identifiers never wrap silently.
    #[test]
    fn epoch_checked(max in proptest::num::u32::ANY) {
        let epoch = EpochId::new(max);
        let ok = match (max.checked_add(1), epoch.next()) {
            (Some(expected), Some(next)) => next.as_u32() == expected,
            (None, None) => max == u32::MAX,
            _ => false,
        };
        prop_assert!(ok);
    }
}
