//! Live Tor session driver for the Android FFI (TODO B.4 Phase 2).
//!
//! Mirrors `umbra_cli::tui::background` (bootstrap -> spawn_inbound ->
//! wait_for_address -> inbound_loop + send commands) on a private Tokio
//! runtime owned by the controller, exposing a small poll-based surface:
//! Kotlin polls [`TorSession::next_event`] from ONE IO thread.
//!
//! Honest scope: inbound text is unattributed; `Sent` means Arti accepted
//! the frames, not delivery; the session lives only while the process does
//! (no foreground service yet); the group-inbound context is built with an
//! EMPTY passphrase so this session never retains the keystore passphrase
//! — group frames are unsupported on Android and surface as session errors.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use umbra_cli::group_inbound::{GroupInboundContext, InboundEvent};
use umbra_cli::pairing::PeerIdentity;
use umbra_crypto::keys::IdentitySeeds;
use umbra_net::tor::TorTransport;
use zeroize::Zeroizing;

use crate::controller::CoreControllerError;

/// Send ceiling (the documented v1.0 Tor-send bound).
pub const MAX_SEND_BYTES: usize = umbra_cli::tor_send::MAX_TOR_MESSAGE;
/// Capacity of the inbound session queue (mirrors the TUI).
const SESSION_QUEUE: usize = 32;
/// Capacity of the event queue to Kotlin; a full queue back-pressures the
/// driver rather than dropping a message (dropping would be a correctness lie).
const EVENT_QUEUE: usize = 256;

/// Events delivered to Kotlin (mirrors the TUI's `UiEvent`, minus groups).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SessionEvent {
    /// Tor bootstrap started (can take minutes).
    Bootstrapping,
    /// Own onion descriptor published: peers need this address to reach us.
    Ready {
        /// Our `.onion` service address.
        address: String,
    },
    /// Inbound text, sanitized, UNATTRIBUTED.
    Inbound {
        /// The sanitized message text.
        text: String,
    },
    /// A peer session failed (contained to its connection).
    SessionError {
        /// Display-ready failure description.
        message: String,
    },
    /// Arti accepted an outbound send (NOT a delivery acknowledgement).
    Sent {
        /// Target peer record name.
        peer: String,
        /// Number of data frames Arti accepted.
        frames: u64,
        /// Plaintext byte count.
        bytes: u64,
    },
    /// An outbound send failed.
    SendError {
        /// Target peer record name.
        peer: String,
        /// Display-ready failure description.
        message: String,
    },
    /// The session cannot continue.
    Fatal {
        /// Display-ready failure description.
        message: String,
    },
}

/// Strips what must never reach a UI from attacker-controlled text: C0/C1
/// controls (except `\n`, `\t`) and Unicode bidi override/isolate marks
/// (spoofing/visual-reordering). Invalid UTF-8 becomes U+FFFD.
#[must_use]
pub fn sanitize_inbound(plaintext: &[u8]) -> String {
    String::from_utf8_lossy(plaintext)
        .chars()
        .filter(|c| !is_display_hazard(*c))
        .collect()
}

/// True for characters that must not reach the UI (see [`sanitize_inbound`]).
fn is_display_hazard(c: char) -> bool {
    (c.is_control() && c != '\n' && c != '\t')
        || matches!(
            c,
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}'
        )
}

/// `<keystore dir>/tor`, derived from the peers directory (a sibling of it).
#[must_use]
pub fn tor_base_for(peers_dir: &Path) -> Option<PathBuf> {
    peers_dir.parent().map(|parent| parent.join("tor"))
}

/// Everything needed to enqueue one send, validated synchronously so the
/// caller gets an immediate error instead of a later event for bad input.
pub(crate) fn validate_send(
    peers_dir: &Path,
    peer_name: &str,
    text: &str,
) -> Result<(PeerIdentity, String, Zeroizing<Vec<u8>>), CoreControllerError> {
    if text.is_empty() {
        return Err(CoreControllerError::Keystore(
            "message is empty".to_string(),
        ));
    }
    if text.len() > MAX_SEND_BYTES {
        return Err(CoreControllerError::Keystore(format!(
            "message too long (max {MAX_SEND_BYTES} bytes)"
        )));
    }
    let peer = umbra_cli::peers::load_peer(peers_dir, peer_name)
        .map_err(|error| CoreControllerError::Keystore(error.to_string()))?;
    let Some(address) = peer.onion.clone() else {
        return Err(CoreControllerError::Keystore(
            "peer has no onion address on record - pair again with their .onion address"
                .to_string(),
        ));
    };
    Ok((peer, address, Zeroizing::new(text.as_bytes().to_vec())))
}

/// One-line privacy/trust summary of the Tor transport, for a persistent UI footer.
#[uniffi::export]
#[must_use]
pub fn privacy_brief_tor() -> String {
    umbra_cli::privacy::render_brief(&umbra_cli::privacy::profile(
        umbra_cli::privacy::TransportKind::Tor,
    ))
}

/// Commands from the FFI side to the driver task.
enum Command {
    /// Deliver one already-validated message.
    Send {
        /// Target peer record name (echoed back in the outcome event).
        peer_name: String,
        /// The peer's key material.
        peer: PeerIdentity,
        /// The peer's `.onion` address.
        address: String,
        /// The message bytes (zeroized on drop).
        plaintext: Zeroizing<Vec<u8>>,
    },
}

/// A running Tor session. Dropping it shuts the runtime down (in-flight
/// work is abandoned; the seeds it holds zeroize on drop).
pub struct TorSession {
    /// The private runtime; `None` only after `drop` took it.
    runtime: Option<tokio::runtime::Runtime>,
    /// Commands to the driver task.
    commands: mpsc::UnboundedSender<Command>,
    /// Events from the driver task (one consumer at a time).
    events: tokio::sync::Mutex<mpsc::Receiver<SessionEvent>>,
    /// Peer-record directory, read when validating a send.
    peers_dir: PathBuf,
}

impl TorSession {
    /// Starts the driver. Returns immediately; progress arrives as events.
    ///
    /// # Errors
    ///
    /// Returns an error if the Tokio runtime cannot be built.
    pub fn start(
        tor_base: PathBuf,
        keystore_dir: PathBuf,
        peers_dir: PathBuf,
        nickname: String,
        seeds: IdentitySeeds,
    ) -> Result<Self, CoreControllerError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("umbra-tor")
            .enable_all()
            .build()
            .map_err(|error| CoreControllerError::Keystore(format!("tokio runtime: {error}")))?;
        let (event_tx, event_rx) = mpsc::channel(EVENT_QUEUE);
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let group = Arc::new(GroupInboundContext {
            keystore_dir,
            passphrase: Zeroizing::new(Vec::new()),
        });
        runtime.spawn(drive(
            tor_base,
            nickname,
            Arc::new(seeds),
            group,
            event_tx,
            command_rx,
        ));
        Ok(Self {
            runtime: Some(runtime),
            commands: command_tx,
            events: tokio::sync::Mutex::new(event_rx),
            peers_dir,
        })
    }

    /// Validates and enqueues a send; the outcome arrives as `Sent`/`SendError`.
    ///
    /// # Errors
    ///
    /// Immediate validation failures, or the session already ended.
    pub fn send(&self, peer_name: &str, text: &str) -> Result<(), CoreControllerError> {
        let (peer, address, plaintext) = validate_send(&self.peers_dir, peer_name, text)?;
        self.commands
            .send(Command::Send {
                peer_name: peer_name.to_string(),
                peer,
                address,
                plaintext,
            })
            .map_err(|_closed| CoreControllerError::Keystore("session is not running".to_string()))
    }

    /// Waits up to `timeout` for the next event; `None` on timeout or if the
    /// session ended. Call from ONE thread that is not a runtime thread.
    #[must_use]
    pub fn next_event(&self, timeout: Duration) -> Option<SessionEvent> {
        let runtime = self.runtime.as_ref()?;
        runtime.block_on(async {
            let mut events = self.events.lock().await;
            tokio::time::timeout(timeout, events.recv())
                .await
                .ok()
                .flatten()
        })
    }
}

impl Drop for TorSession {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// Sends one event, ignoring a closed channel (the session is ending).
async fn emit(tx: &mpsc::Sender<SessionEvent>, event: SessionEvent) {
    let _ = tx.send(event).await;
}

/// The driver task: bootstrap, publish, then serve commands and inbound sessions.
async fn drive(
    tor_base: PathBuf,
    nickname: String,
    seeds: Arc<IdentitySeeds>,
    group: Arc<GroupInboundContext>,
    events: mpsc::Sender<SessionEvent>,
    mut commands: mpsc::UnboundedReceiver<Command>,
) {
    emit(&events, SessionEvent::Bootstrapping).await;
    let mut transport = match TorTransport::bootstrap_persistent(&tor_base).await {
        Ok(transport) => transport,
        Err(error) => {
            emit(
                &events,
                SessionEvent::Fatal {
                    message: format!("bootstrap failed: {error}"),
                },
            )
            .await;
            return;
        }
    };
    if let Err(error) = transport.spawn_inbound(&nickname).await {
        emit(
            &events,
            SessionEvent::Fatal {
                message: format!("inbound service: {error}"),
            },
        )
        .await;
        return;
    }
    let transport = Arc::new(transport);
    let address = match umbra_cli::serve::wait_for_address(&transport).await {
        Ok(address) => address,
        Err(error) => {
            emit(
                &events,
                SessionEvent::Fatal {
                    message: format!("onion publication: {error}"),
                },
            )
            .await;
            return;
        }
    };
    emit(&events, SessionEvent::Ready { address }).await;

    let (session_tx, mut session_rx) = mpsc::channel::<Result<InboundEvent, String>>(SESSION_QUEUE);
    tokio::spawn(umbra_cli::serve::inbound_loop(
        Arc::clone(&transport),
        seeds,
        group,
        session_tx,
        SESSION_QUEUE,
    ));

    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::Send { peer_name, peer, address, plaintext }) => {
                    let transport = Arc::clone(&transport);
                    let events = events.clone();
                    tokio::spawn(async move {
                        let outcome = umbra_cli::tor_send::send_over(
                            &transport, &peer, &address, &plaintext,
                        )
                        .await;
                        let event = match outcome {
                            Ok((frames, bytes)) => SessionEvent::Sent {
                                peer: peer_name,
                                frames,
                                bytes: u64::try_from(bytes).unwrap_or(u64::MAX),
                            },
                            Err(error) => SessionEvent::SendError {
                                peer: peer_name,
                                message: error.to_string(),
                            },
                        };
                        emit(&events, event).await;
                    });
                }
                None => break,
            },
            result = session_rx.recv() => match result {
                Some(Ok(InboundEvent::Text(plaintext))) => {
                    let plaintext = Zeroizing::new(plaintext);
                    emit(&events, SessionEvent::Inbound { text: sanitize_inbound(&plaintext) }).await;
                }
                Some(Ok(_group_event)) => {
                    emit(&events, SessionEvent::SessionError {
                        message: "ignored a group message (unsupported on Android)".to_string(),
                    }).await;
                }
                Some(Err(message)) => {
                    emit(&events, SessionEvent::SessionError { message }).await;
                }
                None => {
                    emit(&events, SessionEvent::Fatal {
                        message: "inbound accept loop ended".to_string(),
                    }).await;
                    break;
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbra_crypto::keys::IdentityBundle;

    const ONION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion";

    fn peers_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "umbra-ffi-session-test-{}-{label}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn save(
        dir: &Path,
        name: &str,
        onion: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let payload = umbra_cli::pairing::payload_for(&IdentityBundle::generate())?;
        umbra_cli::peers::save_peer(dir, name, &payload, onion, None, None)?;
        Ok(())
    }

    #[test]
    fn sanitize_keeps_ordinary_text_and_newlines() {
        assert_eq!(
            sanitize_inbound("héllo\nwörld\t!".as_bytes()),
            "héllo\nwörld\t!"
        );
    }

    #[test]
    fn sanitize_strips_controls_and_bidi_overrides() {
        let hostile = "a\u{0}b\u{1b}[31mc\u{202e}d\u{2066}e\u{200f}f";
        assert_eq!(sanitize_inbound(hostile.as_bytes()), "ab[31mcdef");
    }

    #[test]
    fn sanitize_replaces_invalid_utf8() {
        assert_eq!(sanitize_inbound(&[b'o', b'k', 0xff]), "ok\u{fffd}");
    }

    #[test]
    fn validate_send_rejects_empty_and_oversize_text() {
        let dir = peers_dir("size");
        assert!(validate_send(&dir, "alice", "").is_err());
        let too_big = "x".repeat(MAX_SEND_BYTES + 1);
        assert!(validate_send(&dir, "alice", &too_big).is_err());
    }

    #[test]
    fn validate_send_rejects_unknown_peer_and_missing_onion()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dir = peers_dir("peer");
        assert!(validate_send(&dir, "ghost", "hi").is_err());
        save(&dir, "noaddr", None)?;
        let error = validate_send(&dir, "noaddr", "hi")
            .err()
            .ok_or("expected an error")?;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            error.to_string().contains("onion"),
            "message should name the missing address: {error}"
        );
        Ok(())
    }

    #[test]
    fn validate_send_accepts_a_peer_with_an_onion()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dir = peers_dir("ok");
        save(&dir, "bob", Some(ONION))?;
        let (_peer, address, plaintext) = validate_send(&dir, "bob", "hello")?;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(address, ONION);
        assert_eq!(plaintext.as_slice(), b"hello");
        Ok(())
    }

    #[test]
    fn tor_base_is_a_sibling_of_the_peers_dir() {
        assert_eq!(
            tor_base_for(Path::new("/data/files/peers")),
            Some(PathBuf::from("/data/files/tor"))
        );
    }
}
