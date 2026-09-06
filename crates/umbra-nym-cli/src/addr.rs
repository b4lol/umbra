//! A validated Nym mixnet address (TODO B.1) — thin wrapper around
//! [`nym_sdk::mixnet::Recipient`] for call-site consistency with
//! `umbra-net`'s `OnionAddr`/`MeshPeerAddr`. Validation is delegated
//! entirely to the SDK's own `FromStr` impl.

use core::fmt;

use umbra_net::TransportError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NymPeerAddr {
    /// The validated, SDK-parsed address.
    recipient: nym_sdk::mixnet::Recipient,
}

impl NymPeerAddr {
    /// Parses a Nym address (`identity.encryption@gateway` form).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::InvalidPeer`] if the SDK's own parser
    /// rejects the string.
    pub fn parse(addr: &str) -> Result<Self, TransportError> {
        addr.parse::<nym_sdk::mixnet::Recipient>()
            .map(|recipient| Self { recipient })
            .map_err(|_e| TransportError::InvalidPeer)
    }

    /// The underlying SDK address, for handing to `NymClient::send`.
    ///
    /// `Recipient` is `Copy`, so this is a cheap bitwise copy, not a clone.
    #[must_use]
    pub fn recipient(&self) -> nym_sdk::mixnet::Recipient {
        self.recipient
    }
}

impl fmt::Display for NymPeerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.recipient)
    }
}

#[cfg(test)]
mod tests {
    use super::NymPeerAddr;

    // A real, SDK-generated address string: three locally generated
    // ed25519/x25519 keypairs (no network needed) fed into
    // `Recipient::new`, then printed via its `Display` impl. Not a real
    // routable identity — no corresponding gateway exists — used only
    // as a shape/checksum fixture for `Recipient::from_str`
    // round-tripping.
    const VALID: &str = "\
GYNv1juVSbsNWKAkwar45rui1HkiPckX5S36PfF2zixf.\
3TFDuq9F4vjS52DLj3ANjpgFhFsRzM9ozcNCDQpkYRY9\
@4Nn9dSb2uKzb8qtaE5ioHrb7zCy7JqgExZaiHDCVRAz8";

    #[test]
    fn parses_valid_address() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = NymPeerAddr::parse(VALID)?;
        assert_eq!(addr.to_string(), VALID);
        Ok(())
    }

    #[test]
    fn rejects_garbage() {
        assert!(NymPeerAddr::parse("not-a-nym-address").is_err());
        assert!(NymPeerAddr::parse("").is_err());
    }
}
