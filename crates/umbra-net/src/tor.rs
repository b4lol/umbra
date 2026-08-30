//! Embedded Arti Tor v3 transport (TODO A.2, ADR-001/ADR-008).
//!
//! The `arti-client` dependency is declared behind the `tor` feature; the
//! bootstrap, circuit-lifetime, and Strict Vanguards-Lite policy wiring are
//! the first task of TODO Section A.2. This module pins the API surface so
//! the transport can be dropped in without touching call sites.

use crate::addr::OnionAddr;
use crate::error::TransportError;
use crate::transport::Transport;
use umbra_protocol::packet::SealedPacket;

/// Embedded Arti Tor v3 onion transport.
pub struct TorTransport;

impl TorTransport {
    /// Feature gate marker; real construction lands with TODO A.2.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for TorTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for TorTransport {
    async fn send(&self, _peer: &OnionAddr, _packet: &SealedPacket) -> Result<(), TransportError> {
        Err(TransportError::Unsupported(
            "Arti bootstrap lands with TODO A.2 (arti-client 0.45)",
        ))
    }

    async fn recv(&self) -> Result<(OnionAddr, SealedPacket), TransportError> {
        Err(TransportError::Unsupported(
            "Arti bootstrap lands with TODO A.2 (arti-client 0.45)",
        ))
    }
}
