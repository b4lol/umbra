//! Embedded Arti Tor v3 transport (TODO A.2, ADR-001/ADR-008).
//!
//! Outbound path — **implemented**: bootstraps an embedded pure-Rust Arti
//! client (no external `tor` daemon) and opens anonymized streams to peer
//! `.onion` services, writing fixed 1024-byte packets.
//!
//! Inbound path — **not wired**: hosting our own Tor v3 onion service
//! (receiving `recv()`) needs `tor-hsservice` key management and a service
//! lifecycle loop; it lands with the second half of TODO A.2. Until then
//! [`Transport::recv`] returns [`TransportError::Unsupported`].
//!
//! Anonymity posture (honest scope): this layer provides Tor v3 anonymity
//! for on-demand sends. It does **not** yet provide Global Passive
//! Adversary resistance (THREAT_MODEL "Global Passive Adversary" row):
//! that requires Poisson cover traffic ([`crate::SUPERSEDED_BY`]: the
//! protocol-layer `DUMMY_COVER` pump, TODO A.3) and eventually mixnets.
//! One fresh circuit per send also adds circuit-establishment timing;
//! persistent streams are revisited with the inbound work.
//!
//! State handling: Tor directory cache and persistent state are pointed at
//! an ephemeral per-run temp directory — no Umbra-owned residue under the
//! user's profile (ADR-006 anti-residue), wiped when the OS reclaims /tmp.
//! Persistent guard state is a v2 decision (forensic-correlation tradeoff).
//!
//! Rustls provider: the explicit `ring` CryptoProvider is enabled because
//! rustls 0.23 panics at client construction when zero or two providers are
//! active. `ring` contains C/assembly — this is a recorded deviation from
//! ADR-011 (see ADR-028).
//!
//! # Errors
//!
//! All fallible operations return typed [`TransportError`]s; see the
//! variant docs.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arti_client::{DataStream, TorClient, TorClientConfig};
use tokio::io::AsyncWriteExt;

use crate::addr::OnionAddr;
use crate::error::TransportError;
use crate::transport::Transport;
use umbra_protocol::packet::SealedPacket;

/// Provisional Umbra P2P port for peer onion services.
///
/// SPECIFICATION.md does not yet fix a port; this constant is the single
/// source of truth until the spec revision lands.
pub const PROVISIONAL_PEER_PORT: u16 = 39_441;

/// Upper bound for the Tor bootstrap phase.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(180);

/// Builds an ephemeral, per-run `TorClientConfig`.
///
/// Both the state directory (guards, keystores) and the cache directory
/// (directory descriptors) point under a unique `/tmp`-style path, so
/// nothing is written beneath the user profile and the OS reclaims the
/// bytes afterwards.
///
/// # Errors
///
/// Returns [`TransportError::EphemeralDir`] if a unique directory name
/// cannot be derived.
fn ephemeral_config() -> Result<TorClientConfig, TransportError> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir_name = format!("umbra-tor-{}-{nanos}", std::process::id());
    let base = std::env::temp_dir().join(dir_name);
    if base.as_os_str().is_empty() {
        return Err(TransportError::EphemeralDir);
    }
    let state = base.join("state");
    let cache = base.join("cache");
    let config = arti_client::config::TorClientConfigBuilder::from_directories(state, cache)
        .build()
        .map_err(|err| TransportError::Config {
            details: err.to_string(),
        })?;
    Ok(config)
}

/// Embedded Arti Tor v3 transport.
pub struct TorTransport {
    /// Bootstrapped (or, in tests, unbootstrapped) Arti client.
    client: Arc<TorClient<tor_rtcompat::PreferredRuntime>>,
}

impl TorTransport {
    /// Bootstraps the embedded Arti client against the live Tor network.
    ///
    /// Bounded by [`BOOTSTRAP_TIMEOUT`]; a censored or unreachable network
    /// yields [`TransportError::Timeout`] instead of a hang (ADR-006).
    ///
    /// Must be called within a Tokio context.
    ///
    /// # Errors
    ///
    /// See [`TransportError`].
    pub async fn bootstrap() -> Result<Self, TransportError> {
        // Derives the runtime from the current Tokio context (call within
        // `#[tokio::main]` / a `#[tokio::test]`).
        let client = tokio::time::timeout(
            BOOTSTRAP_TIMEOUT,
            TorClient::<tor_rtcompat::PreferredRuntime>::create_bootstrapped(ephemeral_config()?),
        )
        .await
        .map_err(|_elapsed| TransportError::Timeout {
            operation: "Tor bootstrap",
        })??;
        Ok(Self { client })
    }

    /// Creates an unbootstrapped client — no network contact.
    ///
    /// Used by hermetic tests (CONTRIBUTING §"Hermetic and Deterministic
    /// Tests") to exercise the type surface without Tor connectivity.
    /// Storage still points at the ephemeral temp directory, so no residue
    /// lands under the user profile.
    ///
    /// Must be called within a Tokio context.
    ///
    /// # Errors
    ///
    /// See [`TransportError`].
    pub async fn bootstrap_unchecked() -> Result<Self, TransportError> {
        // Derive from the current Tokio context — creating a fresh runtime
        // here would panic ("cannot start a runtime from within a runtime").
        let runtime = tor_rtcompat::PreferredRuntime::current().map_err(TransportError::Io)?;
        let client = TorClient::<tor_rtcompat::PreferredRuntime>::with_runtime(runtime)
            .create_unbootstrapped_async()
            .await?;
        Ok(Self { client })
    }

    /// Reports whether the client is ready to carry traffic.
    #[must_use]
    pub fn ready_for_traffic(&self) -> bool {
        self.client.bootstrap_status().ready_for_traffic()
    }

    /// The connect target for a peer: the `.onion`-suffixed service ID and
    /// the P2P port.
    ///
    /// The suffix is security-critical: without `.onion`, Arti would
    /// classify the hostname as an exit-resolved DNS name and leak the
    /// peer's service ID to an exit relay (ZERO_DATA_LEAKS, THREAT_MODEL
    /// "DNS/IPv6 leak" row).
    #[must_use]
    pub fn peer_target(peer: &OnionAddr) -> (String, u16) {
        (peer.to_string(), PROVISIONAL_PEER_PORT)
    }

    /// Opens an anonymized stream to `peer`'s onion service.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Tor`] on circuit/stream failure.
    pub async fn open_stream(&self, peer: &OnionAddr) -> Result<DataStream, TransportError> {
        self.client
            .connect(Self::peer_target(peer))
            .await
            .map_err(TransportError::Tor)
    }
}

impl Transport for TorTransport {
    /// Sends one sealed packet over a fresh anonymized stream.
    ///
    /// Torn-write semantics: if the stream dies mid-`write_all`, the peer
    /// holds a partial 1024-byte packet whose AEAD tag cannot verify; the
    /// receiver must discard it (SPECIFICATION framing). Fresh streams per
    /// send keep such damage from desynchronizing later packets.
    ///
    /// # Errors
    ///
    /// See [`TransportError`].
    async fn send(&self, peer: &OnionAddr, packet: &SealedPacket) -> Result<(), TransportError> {
        let mut stream = self.open_stream(peer).await?;
        stream
            .write_all(packet.as_bytes())
            .await
            .map_err(TransportError::Io)?;
        stream.flush().await.map_err(TransportError::Io)?;
        Ok(())
    }

    async fn recv(&self) -> Result<(OnionAddr, SealedPacket), TransportError> {
        Err(TransportError::Unsupported(
            "inbound onion service hosting lands with TODO A.2 second half",
        ))
    }
}

#[cfg(all(test, feature = "tor"))]
mod tests {
    use super::{PROVISIONAL_PEER_PORT, TorTransport};
    use crate::addr::OnionAddr;

    /// An unbootstrapped client constructs without any network contact and
    /// reports not-ready (hermetic; CONTRIBUTING §tests; storage goes to
    /// the ephemeral temp dir, not the user profile).
    #[tokio::test]
    async fn unbootstrapped_client_is_hermetic() -> Result<(), crate::error::TransportError> {
        let transport = TorTransport::bootstrap_unchecked().await?;
        assert!(!transport.ready_for_traffic());
        Ok(())
    }

    /// Peer targets MUST carry the `.onion` suffix, or Arti would route
    /// them through exit-resolved DNS (service-ID leak).
    #[test]
    fn peer_target_is_onion_suffixed() -> Result<(), crate::error::TransportError> {
        // Valid 56-char base32 v3 service ID (no suffix).
        let addr = OnionAddr::parse("5vzwalpq2cyjrhm5lvzhcjn6mbnwbv42xakxiqhunwpgz6hr32f7gxad")?;
        let (host, port) = TorTransport::peer_target(&addr);
        assert!(host.ends_with(".onion"));
        assert_eq!(port, PROVISIONAL_PEER_PORT);
        Ok(())
    }
}
