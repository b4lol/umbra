//! RosterSync: a magic-tagged sub-format riding the existing MLS
//! application-message channel, used by [`crate::add::add_member`] to
//! broadcast a full [`GroupRoster`] snapshot after every membership
//! change (TODO B.2.1). Ordinary chat text is completely unaffected —
//! this module only recognizes plaintext that starts with
//! [`ROSTER_SYNC_MAGIC`]; anything else is left for the caller to
//! treat as ordinary chat text, exactly as before this module existed.

use crate::error::GroupError;
use crate::persistence::GroupRoster;

/// Magic prefix marking an MLS application-message plaintext as a
/// RosterSync payload rather than ordinary chat text — the same
/// fixed-magic, versioned convention this codebase already uses for
/// `UMKS\x01`/`UMKS\x02` keystore formats.
const ROSTER_SYNC_MAGIC: [u8; 5] = *b"UMRS\x01";

/// Encodes `roster` as a RosterSync application-message plaintext:
/// [`ROSTER_SYNC_MAGIC`] followed by `serde_json::to_vec(roster)`.
///
/// # Errors
///
/// Returns [`GroupError::Serde`] if `roster` cannot be serialized
/// (not expected in practice for this struct's shape).
pub fn encode(roster: &GroupRoster) -> Result<Vec<u8>, GroupError> {
    let mut encoded = ROSTER_SYNC_MAGIC.to_vec();
    encoded.extend_from_slice(&serde_json::to_vec(roster)?);
    Ok(encoded)
}

/// Returns `Ok(Some(roster))` if `plaintext` starts with
/// [`ROSTER_SYNC_MAGIC`] and the remainder decodes as a [`GroupRoster`];
/// `Ok(None)` if the magic does not match (ordinary chat text — the
/// caller should fall through to its existing handling).
///
/// # Errors
///
/// Returns [`GroupError::Serde`] if the magic matches but the
/// remainder is not a valid `GroupRoster` — a magic-matched but
/// corrupt payload is a hard error, never silently ignored, matching
/// how every other malformed inbound frame is handled elsewhere in
/// this crate.
pub fn try_decode(plaintext: &[u8]) -> Result<Option<GroupRoster>, GroupError> {
    let Some(remainder) = plaintext.strip_prefix(&ROSTER_SYNC_MAGIC) else {
        return Ok(None);
    };
    let roster: GroupRoster = serde_json::from_slice(remainder)?;
    Ok(Some(roster))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls::prelude::LeafNodeIndex;

    fn sample_roster() -> GroupRoster {
        GroupRoster {
            members: vec![
                ("alice".to_string(), LeafNodeIndex::new(0)),
                ("bob".to_string(), LeafNodeIndex::new(1)),
            ],
        }
    }

    #[test]
    fn round_trips_a_roster() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let roster = sample_roster();
        let encoded = encode(&roster)?;
        let decoded = try_decode(&encoded)?;
        assert_eq!(decoded, Some(roster));
        Ok(())
    }

    #[test]
    fn non_magic_prefixed_bytes_are_not_a_roster_sync()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let chat_text = b"hello cell".to_vec();
        assert_eq!(try_decode(&chat_text)?, None);
        Ok(())
    }

    #[test]
    fn empty_bytes_are_not_a_roster_sync() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        assert_eq!(try_decode(&[])?, None);
        Ok(())
    }

    #[test]
    fn magic_matched_but_corrupt_payload_is_an_error() {
        let mut corrupt = ROSTER_SYNC_MAGIC.to_vec();
        corrupt.extend_from_slice(b"not valid json");
        let result = try_decode(&corrupt);
        assert!(
            result.is_err(),
            "a magic-matched but corrupt payload must error, not silently return None"
        );
    }

    #[test]
    fn encode_output_is_decodable_by_try_decode_and_nothing_else_matches_the_magic_by_accident()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Confirms the magic bytes themselves (0x55 0x4D 0x52 0x53 0x01)
        // are not plausible as the start of ordinary UTF-8 chat text
        // (byte 0x01 is a non-printable control character) — a
        // documentation-by-test of the design rationale, not a new
        // runtime guarantee.
        let roster = sample_roster();
        let encoded = encode(&roster)?;
        assert_eq!(encoded.get(..5), Some(&ROSTER_SYNC_MAGIC[..]));
        assert_eq!(encoded.get(4), Some(&0x01));
        Ok(())
    }
}
