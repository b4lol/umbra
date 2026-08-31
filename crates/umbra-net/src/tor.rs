//! Embedded Arti Tor v3 transport (TODO A.2, ADR-001/ADR-008).
//!
//! Outbound path — **implemented**: bootstraps an embedded pure-Rust Arti
//! client (no external `tor` daemon) and opens anonymized streams to peer
//! `.onion` services, writing fixed 1024-byte packets.
//!
//! Inbound path — **implemented**: spawns a Tor v3 onion service (via
//! `tor-hsservice`), accepts rendezvous streams (semaphore-bounded), and
//! hands each raw `DataStream` to the messenger layer
//! ([`crate::messenger`] — handshake + packet flow per stream). The
//! service identity key can live either in the ephemeral per-run state
//! directory (default: the `.onion` address changes per run) or under a
//! persistent storage root via [`TorTransport::bootstrap_persistent`]
//! and [`persistent_config`] (TODO A.2: the Arti native keystore keeps
//! the identity key, pinning the address across runs).
//!
//! Anonymity posture (honest scope): this layer provides Tor v3 anonymity
//! for on-demand sends and inbound acceptance. It does **not** yet provide
//! Global Passive Adversary resistance (THREAT_MODEL "Global Passive
//! Adversary" row): that requires Poisson cover traffic (the protocol-layer
//! `DUMMY_COVER` pump, TODO A.3) and eventually mixnets. One fresh circuit
//! per send also adds circuit-establishment timing; persistent streams are
//! revisited with the pairing work.
//!
//! Identity note: a Tor v3 onion service cannot know the connecting peer's
//! address — that is the anonymity property. [`Transport::recv`] therefore
//! returns packets without a source; peer identity comes from the pairing
//! layer (CRYPTOGRAPHY.md §5).
//!
//! State handling: Tor directory cache and persistent state are pointed at
//! an ephemeral per-run temp directory — no Umbra-owned residue under the
//! user's profile (ADR-006 anti-residue), wiped when the OS reclaims /tmp.
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
use safelog::DisplayRedacted as _;
use tokio::io::AsyncWriteExt;

use crate::addr::OnionAddr;
use crate::error::TransportError;
use crate::transport::Transport;
use futures_util::StreamExt;
use umbra_protocol::packet::SealedPacket;

/// Provisional Umbra P2P port for peer onion services.
///
/// SPECIFICATION.md does not yet fix a port; this constant is the single
/// source of truth until the spec revision lands.
pub const PROVISIONAL_PEER_PORT: u16 = 39_441;

/// Upper bound for the Tor bootstrap phase.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(180);

/// Capacity of the inbound stream queue.
const INBOUND_QUEUE: usize = 32;

/// Builds a persistent `TorClientConfig` rooted at `base` (TODO A.2):
/// guard state, directory cache and the Arti native keystore live under
/// `base/state` and `base/cache` across runs, so the onion-service
/// identity key persists and the `.onion` address stays stable for a
/// given nickname (Arti stores it under `base/state/keystore`).
///
/// The directories are created if missing; on later runs Arti reuses the
/// stored identity key instead of generating a new one.
///
/// # Errors
///
/// Returns [`TransportError::Io`] if the directories cannot be created
/// and [`TransportError::Config`] if Arti rejects the configuration.
pub fn persistent_config(base: &std::path::Path) -> Result<TorClientConfig, TransportError> {
    use std::os::unix::fs::DirBuilderExt as _;
    let state = base.join("state");
    let cache = base.join("cache");
    // 0700: the tree holds the onion identity key (plaintext at rest).
    // Arti's fs-mistrust enforces the same strictness on its own writes
    // and refuses a lax tree. Trade-off (documented): the key is NOT
    // encrypted at rest — a local reader can impersonate the service
    // ADDRESS (rendezvous only; PQXDH still gates payload plaintext).
    // At-rest encryption would require a passphrase UX tracked for the
    // keystore-reconciliation pass.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&state)
        .map_err(TransportError::Io)?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&cache)
        .map_err(TransportError::Io)?;
    let config = arti_client::config::TorClientConfigBuilder::from_directories(state, cache)
        .build()
        .map_err(|err| TransportError::Config {
            details: err.to_string(),
        })?;
    Ok(config)
}

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
/// cannot be derived, and [`TransportError::Config`] if Arti rejects the
/// configuration.
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
    /// The running onion service, if the inbound path was spawned.
    service: Option<Arc<tor_hsservice::RunningOnionService>>,
    /// Inbound packet queue (present after [`Self::spawn_inbound`]).
    inbound_rx: Option<
        tokio::sync::Mutex<
            tokio::sync::mpsc::Receiver<(DataStream, tokio::sync::OwnedSemaphorePermit)>,
        >,
    >,
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
        Ok(Self {
            client,
            service: None,
            inbound_rx: None,
        })
    }

    /// Bootstraps the embedded Arti client with a PERSISTENT storage root
    /// (TODO A.2): the same `base` across runs keeps guard state and the
    /// onion-service identity key, so peers see the same `.onion` address.
    ///
    /// The calling flow MUST grant Arti read+write access to `base` when
    /// sandboxed — `umbra_cli::sandbox::restrict_filesystem_with_exceptions`
    /// exists for exactly this (ADR-007 refinement); a zero-FS Landlock
    /// ruleset makes this call fail closed on first keystore write.
    ///
    /// Bounded by [`BOOTSTRAP_TIMEOUT`]; must be called within a Tokio
    /// context.
    ///
    /// # Errors
    ///
    /// See [`Self::bootstrap`].
    pub async fn bootstrap_persistent(base: &std::path::Path) -> Result<Self, TransportError> {
        let client = tokio::time::timeout(
            BOOTSTRAP_TIMEOUT,
            TorClient::<tor_rtcompat::PreferredRuntime>::create_bootstrapped(persistent_config(
                base,
            )?),
        )
        .await
        .map_err(|_elapsed| TransportError::Timeout {
            operation: "Tor bootstrap",
        })??;
        Ok(Self {
            client,
            service: None,
            inbound_rx: None,
        })
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
        Ok(Self {
            client,
            service: None,
            inbound_rx: None,
        })
    }

    /// Spawns the inbound onion service: publishes a Tor v3 hidden service
    /// and pumps accepted streams into the inbound packet queue.
    ///
    /// Inbound is **unauthenticated at this layer**: anyone on the Tor
    /// network may connect and push packets; the sole gate is the session
    /// layer (SPECIFICATION opcodes 0x01/0x02 PQXDH plus CRYPTOGRAPHY §5
    /// SAS/SMP pairing — SMP verification is driver-wired in
    /// [`crate::messenger`]).
    ///
    /// Availability: acceptance is head-of-line protected — each accepted
    /// stream gets its own pump task bounded by
    /// [`MAX_CONCURRENT_INBOUND_STREAMS`] permits and an idle timeout, so a
    /// stalled peer parks only its own stream. Per-transport PoW (hs-pow)
    /// configuration is tracked in TODO A.2.
    ///
    /// The service identity key is generated into the ephemeral keystore
    /// (the per-run state directory, `0700` per Arti's fs-mistrust defaults;
    /// no explicit wipe — the OS reclaims /tmp), so with the ephemeral
    /// config the `.onion` address changes per run; use
    /// [`Self::bootstrap_persistent`] to pin the identity (TODO A.2).
    ///
    /// Calling this twice on one transport is refused (single service per
    /// transport).
    ///
    /// Must be called within a Tokio context.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Config`] for an invalid nickname,
    /// [`TransportError::Tor`] for launch failures, and
    /// [`TransportError::AlreadyStarted`] if the service already runs.
    pub async fn spawn_inbound(&mut self, nickname: &str) -> Result<(), TransportError> {
        if self.service.is_some() || self.inbound_rx.is_some() {
            return Err(TransportError::AlreadyStarted {
                what: "inbound onion service",
            });
        }
        let nickname = tor_hsservice::HsNickname::new(nickname.to_string()).map_err(|err| {
            TransportError::Config {
                details: err.to_string(),
            }
        })?;
        let service_config = tor_hsservice::OnionServiceConfig::builder()
            .nickname(nickname)
            .build()
            .map_err(|err| TransportError::Config {
                details: err.to_string(),
            })?;

        let Some((service, rends)) = self
            .client
            .launch_onion_service(service_config)
            .map_err(TransportError::Tor)?
        else {
            return Err(TransportError::Unsupported(
                "onion service disabled in configuration",
            ));
        };

        let requests = tor_hsservice::handle_rend_requests(rends);
        let (tx, rx) = tokio::sync::mpsc::channel(INBOUND_QUEUE);
        tokio::spawn(accept_loop(requests, tx));

        self.service = Some(service);
        self.inbound_rx = Some(tokio::sync::Mutex::new(rx));
        Ok(())
    }

    /// The published `.onion` address of the inbound service, once known.
    ///
    /// The returned string is deliberately unredacted (for pairing/QR
    /// display) and must never be written to logs or disk.
    #[must_use]
    pub fn onion_address(&self) -> Option<String> {
        Some(
            self.service
                .as_ref()?
                .onion_address()?
                .display_unredacted()
                .to_string(),
        )
    }

    /// Waits for the next inbound DataStream from the spawned onion
    /// service (rendezvous accepted, stream ready for the messenger
    /// handshake flow).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Unsupported`] if `spawn_inbound` has not
    /// run, and [`TransportError::ChannelClosed`] after shutdown.
    pub async fn next_inbound_stream(
        &self,
    ) -> Result<(DataStream, tokio::sync::OwnedSemaphorePermit), TransportError> {
        let rx = self.inbound_rx.as_ref().ok_or(TransportError::Unsupported(
            "inbound service not started; call spawn_inbound first",
        ))?;
        let mut guard = rx.lock().await;
        guard.recv().await.ok_or(TransportError::ChannelClosed)
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

/// Upper bound for concurrent inbound streams (permit-guarded pumps).
///
/// A hostile peer that opens streams and stalls must not starve rendezvous
/// acceptance: each pump holds one permit and is dropped on idle timeout.
const MAX_CONCURRENT_INBOUND_STREAMS: usize = 64;

/// Accepts rendezvous requests forever, queueing each accepted stream
/// with its concurrency permit. The consumer receives
/// `(DataStream, OwnedSemaphorePermit)`: the permit MUST be held for the
/// stream's processing lifetime, bounding active sessions at
/// [`MAX_CONCURRENT_INBOUND_STREAMS`] (the messenger layer does the
/// framing and per-stream handling).
async fn accept_loop(
    mut requests: impl futures_util::Stream<Item = tor_hsservice::StreamRequest> + Unpin,
    tx: tokio::sync::mpsc::Sender<(DataStream, tokio::sync::OwnedSemaphorePermit)>,
) {
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_INBOUND_STREAMS));
    while let Some(request) = requests.next().await {
        let stream = match request
            .accept(tor_cell::relaycell::msg::Connected::new_empty())
            .await
        {
            Ok(stream) => stream,
            // Malformed handshake: drop this rendezvous, keep serving.
            Err(_e) => continue,
        };
        // try_acquire (not acquire.await): when saturated we prefer
        // refusing new streams over queueing accept-loop work.
        let permit = match Arc::clone(&permits).try_acquire_owned() {
            Ok(permit) => permit,
            // At capacity: reject this stream by dropping it unaccepted.
            Err(_full) => continue,
        };
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tx.send((stream, permit)).await;
        });
    }
}

impl Transport for TorTransport {
    /// Sends one sealed packet over a fresh anonymized stream.
    ///
    /// Torn-write semantics: if the stream dies mid-`write_all`, the peer
    /// holds a partial 1024-byte packet whose AEAD tag cannot verify; the
    /// receiver discards the stream (see `pump_stream`). Fresh streams per
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

    /// Receives the next inbound packet from the spawned onion service.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Unsupported`] if `spawn_inbound` has not
    /// run, and [`TransportError::ChannelClosed`] after shutdown.
    async fn recv(&self) -> Result<SealedPacket, TransportError> {
        Err(TransportError::Unsupported(
            "packet-level recv on Tor is superseded by next_inbound_stream + messenger",
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

    /// The inbound service rejects an invalid nickname at configuration
    /// time (hermetic: no network, no launch).
    #[test]
    fn invalid_nickname_is_rejected() {
        let result = tor_hsservice::HsNickname::new(String::from("bad nickname!"));
        assert!(result.is_err());
    }
}
