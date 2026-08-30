//! Async transport abstraction (ARCHITECTURE.md "Network Router").
//!
//! [`LoopbackPair`] provides a fully hermetic in-memory transport pair for
//! deterministic tests; the real wire transport is the feature-gated
//! [`crate::tor`] module (TODO A.2).

use tokio::sync::Mutex;
use tokio::sync::mpsc::{self, Receiver, Sender};

use crate::addr::OnionAddr;
use crate::error::TransportError;
use umbra_protocol::packet::SealedPacket;

/// Async packet transport toward Tor v3 onion peers.
pub trait Transport: Send + Sync {
    /// Sends one sealed packet to `peer`.
    ///
    /// # Errors
    ///
    /// Transport-specific failures ([`TransportError`]).
    fn send(
        &self,
        peer: &OnionAddr,
        packet: &SealedPacket,
    ) -> impl core::future::Future<Output = Result<(), TransportError>> + Send;

    /// Receives the next inbound packet with its source.
    ///
    /// # Errors
    ///
    /// Transport-specific failures ([`TransportError`]).
    fn recv(
        &self,
    ) -> impl core::future::Future<Output = Result<(OnionAddr, SealedPacket), TransportError>> + Send;
}

/// Capacity of the loopback channel, in packets.
const LOOPBACK_CAPACITY: usize = 256;

/// In-memory loopback transport for hermetic tests.
pub struct LoopbackTransport {
    /// Outbound queue.
    tx: Sender<(OnionAddr, SealedPacket)>,
    /// Inbound queue (locked per receive; `Receiver` is not `Clone`).
    rx: Mutex<Receiver<(OnionAddr, SealedPacket)>>,
}

/// A matched pair of loopback transports (two peers talking in-memory).
pub struct LoopbackPair {
    /// Endpoint A.
    pub a: LoopbackTransport,
    /// Endpoint B.
    pub b: LoopbackTransport,
}

impl LoopbackPair {
    /// Creates a matched pair of loopback transports.
    #[must_use]
    pub fn new() -> Self {
        let (tx_a, rx_b) = mpsc::channel(LOOPBACK_CAPACITY);
        let (tx_b, rx_a) = mpsc::channel(LOOPBACK_CAPACITY);
        Self {
            a: LoopbackTransport {
                tx: tx_a,
                rx: Mutex::new(rx_a),
            },
            b: LoopbackTransport {
                tx: tx_b,
                rx: Mutex::new(rx_b),
            },
        }
    }
}

impl Default for LoopbackPair {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for LoopbackTransport {
    async fn send(&self, peer: &OnionAddr, packet: &SealedPacket) -> Result<(), TransportError> {
        self.tx
            .send((peer.clone(), packet.clone()))
            .await
            .map_err(|_e| TransportError::ChannelClosed)
    }

    async fn recv(&self) -> Result<(OnionAddr, SealedPacket), TransportError> {
        let mut rx = self.rx.lock().await;
        rx.recv().await.ok_or(TransportError::ChannelClosed)
    }
}
