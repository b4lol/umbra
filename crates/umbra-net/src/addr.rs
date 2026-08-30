//! Tor v3 onion service address validation (NETWORK_PROTOCOL.md §2).

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
