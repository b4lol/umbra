//! Tor v3 onion service address validation (docs/NETWORK_PROTOCOL.md §2).

use core::fmt;

use crate::error::TransportError;

/// Character set of a base32-encoded v3 onion address.
const BASE32_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Length of the base32-encoded 256-bit v3 onion service ID.
const ONION_ID_LEN: usize = 56;

/// A validated Tor v3 onion service address (56-char base32 ID, without the
/// `.onion` suffix internally).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OnionAddr {
    /// Base32 service ID.
    id: [u8; ONION_ID_LEN],
}

impl OnionAddr {
    /// Parses and validates a `.onion` address (suffix optional).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::InvalidPeer`] for wrong length or
    /// non-base32 characters.
    pub fn parse(addr: &str) -> Result<Self, TransportError> {
        let trimmed = addr.strip_suffix(".onion").unwrap_or(addr);
        if trimmed.len() != ONION_ID_LEN {
            return Err(TransportError::InvalidPeer);
        }
        let bytes = trimmed.as_bytes();
        if !bytes.iter().all(|b| BASE32_CHARS.contains(b)) {
            return Err(TransportError::InvalidPeer);
        }
        let mut id = [0u8; ONION_ID_LEN];
        id.copy_from_slice(bytes);
        Ok(Self { id })
    }

    /// Base32 service-ID view.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // The ID is validated to be ASCII base32 at construction time, so
        // this cast is lossless and safe.
        core::str::from_utf8(&self.id).unwrap_or("")
    }
}

impl fmt::Display for OnionAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.onion", self.as_str())
    }
}

/// A validated Wi-Fi Direct P2P Device Address (IEEE 802 MAC form,
/// `aa:bb:cc:dd:ee:ff`) — the mesh transport's peer identifier,
/// analogous to [`OnionAddr`] for the Tor transport (TODO B.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MeshPeerAddr {
    /// 6-byte MAC address octets.
    octets: [u8; 6],
}

impl MeshPeerAddr {
    /// Parses a colon-separated hex MAC address, case-insensitive.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::InvalidPeer`] for the wrong number of
    /// groups, wrong group length, or non-hex characters.
    pub fn parse(addr: &str) -> Result<Self, TransportError> {
        let mut octets = [0u8; 6];
        let mut groups = addr.split(':');
        for octet in &mut octets {
            let group = groups.next().ok_or(TransportError::InvalidPeer)?;
            if group.len() != 2 {
                return Err(TransportError::InvalidPeer);
            }
            *octet = u8::from_str_radix(group, 16).map_err(|_e| TransportError::InvalidPeer)?;
        }
        if groups.next().is_some() {
            return Err(TransportError::InvalidPeer);
        }
        Ok(Self { octets })
    }

    /// Raw 6-byte form, for building `P2P_CONNECT <addr> pbc`.
    #[must_use]
    pub fn octets(&self) -> [u8; 6] {
        self.octets
    }
}

impl fmt::Display for MeshPeerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.octets;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

#[cfg(test)]
mod mesh_addr_tests {
    use super::MeshPeerAddr;

    #[test]
    fn parses_valid_address() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = MeshPeerAddr::parse("aa:bb:cc:dd:ee:ff")?;
        assert_eq!(addr.octets(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(addr.to_string(), "aa:bb:cc:dd:ee:ff");
        Ok(())
    }

    #[test]
    fn uppercase_hex_is_normalized_on_display()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = MeshPeerAddr::parse("AA:BB:CC:DD:EE:FF")?;
        assert_eq!(addr.octets(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(addr.to_string(), "aa:bb:cc:dd:ee:ff");
        Ok(())
    }

    #[test]
    fn rejects_wrong_group_count() {
        assert!(MeshPeerAddr::parse("aa:bb:cc:dd:ee").is_err());
        assert!(MeshPeerAddr::parse("aa:bb:cc:dd:ee:ff:00").is_err());
    }

    #[test]
    fn rejects_non_hex_group() {
        assert!(MeshPeerAddr::parse("zz:bb:cc:dd:ee:ff").is_err());
    }

    #[test]
    fn rejects_short_group() {
        assert!(MeshPeerAddr::parse("a:bb:cc:dd:ee:ff").is_err());
    }

    #[test]
    fn rejects_empty_string() {
        assert!(MeshPeerAddr::parse("").is_err());
    }
}
