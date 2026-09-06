//! The real [`NymTransport`] implementation (TODO B.1), wrapping
//! [`nym_sdk::mixnet::MixnetClient`] with persistent on-disk identity
//! — the Nym-address equivalent of the Tor transport's stable
//! `.onion` keystore.

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
    fn details(self) -> NymNetworkDetails {
        match self {
            Self::Sandbox => sandbox_network_details(),
            Self::Mainnet => NymNetworkDetails::new_mainnet(),
        }
    }
}

/// A connected Nym mixnet client with a persistent, disk-backed
/// identity (survives process restarts, unlike an ephemeral client).
pub struct NymClient {
    /// The underlying, already-connected SDK client.
    inner: MixnetClient,
    /// This client's own address, cached from `inner.nym_address()` at
    /// connect time so `address()` need not re-parse on every call.
    address: NymPeerAddr,
}

impl NymClient {
    /// Connects to `network` using persistent storage rooted at
    /// `config_dir`. `config_dir` must already exist with restrictive
    /// permissions (`0700`) — callers create it before the sandbox is
    /// installed.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Nym`] if storage setup or mixnet
    /// connection fails.
    pub async fn connect(config_dir: &Path, network: NymNetwork) -> Result<Self, TransportError> {
        let storage_paths = StoragePaths::new_from_dir(config_dir)
            .map_err(|e| TransportError::Nym(format!("storage paths: {e}")))?;
        let built = MixnetClientBuilder::new_with_default_storage(storage_paths)
            .await
            .map_err(|e| TransportError::Nym(format!("storage init: {e}")))?
            .network_details(network.details())
            .build()
            .map_err(|e| TransportError::Nym(format!("client build: {e}")))?;
        let inner = built
            .connect_to_mixnet()
            .await
            .map_err(|e| TransportError::Nym(format!("mixnet connect: {e}")))?;
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
            .ok_or_else(|| TransportError::Nym("mixnet client stream ended".into()))
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
