//! The real [`NymTransport`] implementation (TODO B.1), wrapping
//! [`nym_sdk::mixnet::MixnetClient`] in either of its two identity
//! modes:
//!
//! - [`NymClient::connect`] — PERSISTENT, on-disk identity rooted at a
//!   caller-supplied config directory, the Nym-address equivalent of
//!   the Tor transport's stable `.onion` keystore. Used by `serve-nym`,
//!   which must present the same address across restarts.
//! - [`NymClient::connect_ephemeral`] — EPHEMERAL, in-memory identity,
//!   discarded when the process exits and never written to disk. Used
//!   by `send-nym`: PQXDH lets a sender complete and transmit using
//!   only the recipient's asynchronously-known prekey bundle, so there
//!   is no reply at the Nym transport layer and therefore no reason for
//!   a sender to have a stable — or persisted — Nym address at all.

use std::path::Path;

use futures::StreamExt as _;
use nym_sdk::mixnet::{MixnetClient, MixnetClientBuilder, NymNetworkDetails, StoragePaths};
use umbra_net::TransportError;

use crate::addr::NymPeerAddr;
use crate::nym_network::sandbox_network_details;
use crate::transport::NymTransport;

/// Which Nym network a [`NymClient`] connects to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NymNetwork {
    /// Nym's Sandbox testnet (vendored, pinned fixture; see
    /// [`crate::nym_network`]).
    Sandbox,
    /// Nym's production mainnet.
    Mainnet,
}

impl NymNetwork {
    /// Resolves this selection to the concrete [`NymNetworkDetails`]
    /// the SDK's builder expects.
    ///
    /// Callers MUST invoke this before starting a Tokio runtime and
    /// hand the result to [`NymClient::connect`] /
    /// [`NymClient::connect_ephemeral`], rather than letting the
    /// connect call resolve it: the [`NymNetwork::Sandbox`] arm goes
    /// through [`sandbox_network_details`], which populates the process
    /// environment on first use. Its `Once` guard serialises concurrent
    /// WRITES, but cannot stop a concurrent read on another runtime
    /// worker thread from racing that write. Resolving once on the main
    /// thread, before any worker thread exists, removes the race
    /// entirely.
    #[must_use]
    pub fn details(self) -> NymNetworkDetails {
        match self {
            Self::Sandbox => sandbox_network_details(),
            Self::Mainnet => NymNetworkDetails::new_mainnet(),
        }
    }
}

/// Exact message [`NymClient`]'s [`NymTransport::recv`] impl puts in a
/// [`TransportError::Nym`] when the underlying mixnet client's own
/// stream ends — a FATAL condition, since the SDK's `MixnetClient` will
/// never yield another message afterwards. `serve-nym`'s accept loop
/// matches on this constant (not a hand-copied literal) to tell it
/// apart from a recoverable per-message handshake/decode failure.
pub const STREAM_ENDED: &str = "mixnet client stream ended";

/// A connected Nym mixnet client, with either a persistent,
/// disk-backed identity ([`NymClient::connect`]) or an ephemeral,
/// in-memory one ([`NymClient::connect_ephemeral`]).
pub struct NymClient {
    /// The underlying, already-connected SDK client.
    inner: MixnetClient,
    /// This client's own address, cached from `inner.nym_address()` at
    /// connect time so `address()` need not re-parse on every call.
    address: NymPeerAddr,
}

impl NymClient {
    /// Connects to the network described by `network` using PERSISTENT
    /// storage rooted at `config_dir` (identity keys, gateway
    /// registration, SURB state — all surviving process restarts).
    /// `config_dir` must already exist with restrictive permissions
    /// (`0700`) — callers create it before the sandbox is installed.
    ///
    /// `network` is a resolved [`NymNetworkDetails`], not a
    /// [`NymNetwork`], deliberately: see [`NymNetwork::details`] for
    /// why it must be resolved before a Tokio runtime exists.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Nym`] if storage setup or mixnet
    /// connection fails.
    pub async fn connect(
        config_dir: &Path,
        network: NymNetworkDetails,
    ) -> Result<Self, TransportError> {
        let storage_paths = StoragePaths::new_from_dir(config_dir)
            .map_err(|e| TransportError::Nym(format!("storage paths: {e}")))?;
        let built = MixnetClientBuilder::new_with_default_storage(storage_paths)
            .await
            .map_err(|e| TransportError::Nym(format!("storage init: {e}")))?
            .network_details(network)
            .build()
            .map_err(|e| TransportError::Nym(format!("client build: {e}")))?;
        Self::from_connected(
            built
                .connect_to_mixnet()
                .await
                .map_err(|e| TransportError::Nym(format!("mixnet connect: {e}")))?,
        )
    }

    /// Connects to the network described by `network` with an
    /// EPHEMERAL, in-memory identity: no `StoragePaths`, no config
    /// directory, and nothing — least of all a freshly generated
    /// ed25519/x25519 private key — written to disk.
    ///
    /// This is what `send-nym` wants. Umbra's PQXDH design lets a
    /// sender complete and transmit using only the recipient's
    /// asynchronously-known prekey bundle (Task 8's duplex-bridge
    /// finding), so there is no reply at the Nym transport layer, and
    /// therefore no reason for a sender to hold a stable Nym address —
    /// or to persist transport identity material at all.
    ///
    /// `network` is a resolved [`NymNetworkDetails`]: see
    /// [`NymNetwork::details`] for why it must be resolved before a
    /// Tokio runtime exists.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Nym`] if the client cannot be built or
    /// the mixnet connection fails.
    pub async fn connect_ephemeral(network: NymNetworkDetails) -> Result<Self, TransportError> {
        let built = MixnetClientBuilder::new_ephemeral()
            .network_details(network)
            .build()
            .map_err(|e| TransportError::Nym(format!("client build: {e}")))?;
        Self::from_connected(
            built
                .connect_to_mixnet()
                .await
                .map_err(|e| TransportError::Nym(format!("mixnet connect: {e}")))?,
        )
    }

    /// Shared tail of both constructors: caches the connected client's
    /// own address so [`NymClient::address`] need not re-parse on every
    /// call. Kept in one place so the persistent and ephemeral paths
    /// cannot drift in how they derive it. (The `connect_to_mixnet`
    /// call itself stays in each constructor: the SDK's
    /// `DisconnectedMixnetClient` is generic over its storage backend,
    /// and the two builders instantiate it differently.)
    fn from_connected(inner: MixnetClient) -> Result<Self, TransportError> {
        let address = NymPeerAddr::parse(&inner.nym_address().to_string())
            .map_err(|_e| TransportError::Nym("own address failed to round-trip parse".into()))?;
        Ok(Self { inner, address })
    }

    /// Gracefully disconnects from the mixnet, consuming `self`.
    pub async fn disconnect(self) {
        self.inner.disconnect().await;
    }
}

impl NymTransport for NymClient {
    fn address(&self) -> NymPeerAddr {
        self.address.clone()
    }

    async fn send(&self, to: NymPeerAddr, payload: Vec<u8>) -> Result<(), TransportError> {
        use nym_sdk::mixnet::MixnetMessageSender as _;
        self.inner
            .send_plain_message(to.recipient(), payload)
            .await
            .map_err(|e| TransportError::Nym(format!("send: {e}")))
    }

    async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        self.inner
            .next()
            .await
            .map(|reconstructed| reconstructed.message)
            .ok_or_else(|| TransportError::Nym(STREAM_ENDED.into()))
    }
}

#[cfg(test)]
mod network_selection_tests {
    use super::NymNetwork;

    #[test]
    fn sandbox_and_mainnet_produce_distinct_network_names() {
        let sandbox = NymNetwork::Sandbox.details();
        let mainnet = NymNetwork::Mainnet.details();
        assert_ne!(format!("{sandbox:?}"), format!("{mainnet:?}"));
    }
}
