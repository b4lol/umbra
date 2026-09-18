//! IPC client for the Engine process (TODO B.3.1): spawns and talks to
//! `umbra-engine` over a private `AF_UNIX` socket so this process
//! never itself runs keystore/decoy-vault unlock logic. See
//! `docs/superpowers/specs/2026-09-15-engine-ui-separation-design.md`.
//!
//! # Duplicated wire types (deliberate)
//!
//! [`Request`]/[`Response`]/[`SessionLine`] below are field-for-field identical to
//! `umbra_engine::protocol`'s types, copied rather than imported via a
//! Cargo dependency on `umbra-engine`: that crate unconditionally
//! depends on `umbra-cli`/`umbra-crypto`/`landlock`/`seccompiler`
//! (Cargo links whole crates, not individual modules), and pulling
//! that graph into this GUI process would defeat this increment's own
//! point — the GUI no longer linking secret-handling/sandboxing code.
//! A field-level mismatch between the two sides fails the wire round
//! trip immediately (this module's own tests, plus
//! `crates/umbra-engine/tests/unlock_over_socket.rs`).

#[cfg(feature = "gui")]
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Child;
#[cfg(feature = "gui")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "gui")]
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// One request line, mirrors `umbra_engine::protocol::Request`.
#[derive(Debug, Serialize, Default)]
struct Request {
    /// The requested operation.
    op: String,
    /// The keystore or decoy-vault file to operate on.
    keystore_path: Option<PathBuf>,
    /// The passphrase to unlock with.
    passphrase: Option<String>,
    /// Path to the hardware token's PKCS#11 module (TODO B.3 FIDO2
    /// wiring), sent whenever this GUI process was launched with
    /// `--hw-module` — the Engine decides whether it's actually
    /// needed by inspecting the target file itself.
    hw_module: Option<PathBuf>,
    /// The hardware token's PIN, typed into the unlock screen's second
    /// masked field.
    hw_pin: Option<String>,
    /// Label of the token-held HMAC key, from `--hw-key-label`.
    hw_key_label: Option<String>,
    /// Local display name to save a peer under (`"pair_confirm"`).
    peer_name: Option<String>,
    /// A peer's base64url pairing payload (`"pair_import"` and
    /// `"pair_confirm"`).
    peer_payload: Option<String>,
    /// The peer's `.onion` service address, if recorded now
    /// (`"pair_confirm"`, optional).
    peer_onion: Option<String>,
    /// Present for every session-phase request once `start_session`
    /// has been called on this connection.
    request_id: Option<u64>,
    /// Message text for `"send"` (Phase 3: delivered as one PQXDH
    /// session over the shared, already-bootstrapped Tor transport).
    text: Option<String>,
}

/// One response line, mirrors `umbra_engine::protocol::Response`.
/// Used ONLY for the pre-session `"unlock"` exchange — session-phase
/// ops read tagged [`SessionLine`]s instead.
#[derive(Debug, Deserialize)]
struct Response {
    /// Whether the operation succeeded.
    ok: bool,
    /// The unlocked identity's fingerprint, present only when `ok`.
    #[serde(default)]
    fingerprint: Option<String>,
    /// A display-ready error message, present only when not `ok`.
    #[serde(default)]
    error: Option<String>,
}

/// One line the Engine writes during the session phase, mirrors
/// `umbra_engine::protocol::SessionLine`. Gated behind `gui`: the
/// whole session phase is wired to a GTK-bound event sink, so a
/// feature-less build (unlock-exchange only) never reads it.
#[cfg(feature = "gui")]
#[derive(Debug, Deserialize, Clone)]
struct SessionLine {
    /// `"response"` (carries `request_id`) or `"event"` (unprompted).
    kind: String,
    /// Present when `kind == "response"`: echoes the request's own
    /// `request_id`.
    #[serde(default)]
    request_id: Option<u64>,
    /// Present when `kind == "event"`: which event. `"ready"` means
    /// Tor bootstrap finished; `"inbound-text"`/`"session-error"`
    /// (Phase 4) are the others.
    #[serde(default)]
    event: Option<String>,
    /// Whether the operation succeeded (`kind == "response"`).
    #[serde(default)]
    ok: Option<bool>,
    /// A display-ready error message, present only when not `ok`.
    #[serde(default)]
    error: Option<String>,
    /// Paired peer names (`"list_peers"`), sorted.
    #[serde(default)]
    peer_names: Option<Vec<String>>,
    /// This session's own pairing payload (`"pair_payload"`).
    #[serde(default)]
    payload: Option<String>,
    /// The shared SAS code (`"pair_import"`).
    #[serde(default)]
    sas: Option<String>,
    /// The identity's own onion address (`"ready"` event).
    #[serde(default)]
    address: Option<String>,
    /// The `"inbound-text"` event's payload (Phase 4): decrypted
    /// plaintext, base64url-no-pad. No sender attribution exists at
    /// the Engine's layer, so there is deliberately no `peer` field.
    #[serde(default)]
    data: Option<String>,
}

/// Capacity of the GTK-side event channel (see
/// [`EngineClient::start_session`]) — bounded so a slow-to-drain GTK
/// main loop can never make this process's memory grow without
/// bound. Events are low-frequency (bootstrap ready, a handful of
/// sends/receives per user action) so this is generous headroom, not
/// a tight budget; overflow is dropped (see [`forward_or_drop`]), not
/// something normal operation should ever hit.
#[cfg(feature = "gui")]
pub const EVENT_CHANNEL_CAPACITY: usize = 256;

/// An event the GTK main loop can react to — the subset of
/// [`SessionLine`]'s `"event"` shapes this crate knows about, plus
/// send outcomes (a `"send"` response is routed through the pending
/// map like any response, but its caller is the send-worker thread,
/// which forwards the outcome here — mirrors `tui.rs`'s own
/// `UiEvent::Sent`/`UiEvent::SendError`).
#[derive(Debug, Clone)]
pub enum EngineEvent {
    /// Tor bootstrap finished; this is the identity's own onion
    /// address.
    Ready(String),
    /// A queued `"send"` completed: Arti's stream accepted the frames
    /// (NOT an end-to-end delivery confirmation — the same honest
    /// caveat `tui.rs`'s `UiEvent::Sent` carries).
    Sent(String),
    /// A queued `"send"` failed (peer has no onion address, Tor still
    /// bootstrapping, connect timeout, ...): `(peer_name, error)`.
    SendError(String, String),
    /// A decrypted two-party message arrived (Phase 4). The sender is
    /// NOT attributable at the Engine's layer, so the GUI renders this
    /// in the inbox pseudo-conversation, never inside a named peer's
    /// log.
    InboundText(String),
    /// Bootstrap or inbound-loop failure (Phase 4) — previously
    /// stderr-only on the Engine side.
    SessionError(String),
    /// The Engine connection died (EOF or a read/write error on the
    /// socket) — the Engine process is gone or unreachable. This is
    /// PERMANENT and terminal for the session: the GUI must show a
    /// clear, permanent error state and stop (no automatic reconnect
    /// — restarting a process that owns secret key material behind
    /// the GUI's back is not something to do silently). Sent right
    /// before the reader thread drains `pending`, so any in-flight
    /// [`EngineConnection::session_request`] caller unblocks with an
    /// error at the same time this event is delivered.
    ConnectionLost,
}

/// A protocol-level connection to the Engine, independent of how that
/// connection was established. Split out from [`EngineClient`] so the
/// wire-protocol logic is unit-testable against a plain `UnixListener`
/// fixture, with no real `umbra-engine` subprocess needed (see this
/// module's tests).
struct EngineConnection {
    /// The already-connected socket to the Engine process.
    stream: UnixStream,
}

impl EngineConnection {
    /// Sends one [`Request`] and returns the decoded [`Response`] —
    /// the shared write/read half of every operation below.
    fn request(&mut self, request: &Request) -> Result<Response, String> {
        let mut line = serde_json::to_string(request).map_err(|error| error.to_string())?;
        line.push('\n');
        self.stream
            .write_all(line.as_bytes())
            .map_err(|error| error.to_string())?;

        let mut reader = BufReader::new(&self.stream);
        let mut response_line = String::new();
        reader
            .read_line(&mut response_line)
            .map_err(|error| error.to_string())?;
        serde_json::from_str(response_line.trim_end()).map_err(|error| error.to_string())
    }

    /// Sends an `"unlock"` request for `keystore_path` with
    /// `passphrase`, and returns the unlocked identity's fingerprint
    /// as lowercase hex on success.
    fn unlock(
        &mut self,
        keystore_path: &Path,
        passphrase: &[u8],
        hw_module: Option<&Path>,
        hw_pin: &[u8],
        hw_key_label: Option<&str>,
    ) -> Result<String, String> {
        let passphrase = std::str::from_utf8(passphrase)
            .map_err(|_error| "passphrase must be valid UTF-8".to_string())?;
        let hw_pin = std::str::from_utf8(hw_pin)
            .map_err(|_error| "hardware key PIN must be valid UTF-8".to_string())?;
        let response = self.request(&Request {
            op: "unlock".to_string(),
            keystore_path: Some(keystore_path.to_path_buf()),
            passphrase: Some(passphrase.to_string()),
            hw_module: hw_module.map(std::path::Path::to_path_buf),
            hw_pin: if hw_pin.is_empty() {
                None
            } else {
                Some(hw_pin.to_string())
            },
            hw_key_label: hw_key_label.map(str::to_string),
            ..Request::default()
        })?;
        if response.ok {
            response
                .fingerprint
                .ok_or_else(|| "Engine returned ok without a fingerprint".to_string())
        } else {
            Err(response
                .error
                .unwrap_or_else(|| "Engine returned an error with no message".to_string()))
        }
    }

    /// Sends a tagged session-phase request (assigning `request_id`
    /// via `session`) and blocks until the reader thread delivers the
    /// matching tagged response. Panics-in-spirit avoided: if the
    /// reader thread has already exited (the Engine died), this
    /// blocks until `session` itself is dropped — the same
    /// no-timeout behavior this crate's pre-Phase-2 `request` already
    /// had for a hung Engine (accepted, unchanged trade — see the
    /// spec's own Honest Scope section).
    #[cfg(feature = "gui")]
    fn session_request(
        &mut self,
        session: &EngineSession,
        request: Request,
    ) -> Result<SessionLine, String> {
        let request_id = session.next_request_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = std::sync::mpsc::channel();
        {
            let mut pending = session
                .pending
                .lock()
                .map_err(|_error| "session state poisoned".to_string())?;
            pending.insert(request_id, tx);
        }
        let mut tagged_request = request;
        tagged_request.request_id = Some(request_id);
        let mut line = serde_json::to_string(&tagged_request).map_err(|error| error.to_string())?;
        line.push('\n');
        if let Err(error) = self.stream.write_all(line.as_bytes()) {
            // The request never reached the Engine, so no response
            // (tagged or otherwise) will ever arrive for this
            // request_id — remove the just-inserted waiter now,
            // rather than leaking one `pending` entry per failed
            // write (it would otherwise sit there forever, since
            // nothing else will ever remove it).
            if let Ok(mut pending) = session.pending.lock() {
                pending.remove(&request_id);
            }
            return Err(error.to_string());
        }
        rx.recv()
            .map_err(|_error| "Engine connection closed before responding".to_string())
    }
}

/// One queued outbound message (Phase 3): consumed by the send-worker
/// thread, which owns a cloned write half of the Engine socket so the
/// GTK main loop never blocks on a (bounded, but up-to-120 s) onion
/// connect.
#[cfg(feature = "gui")]
struct SendJob {
    /// Local peer name to send to.
    peer_name: String,
    /// Message text.
    text: String,
}

/// Live session-phase state, created once `unlock` succeeds
/// (TODO B.3 GUI messaging design, Phase 2): the background reader
/// thread's join handle plus the bookkeeping it shares with the GTK
/// thread to route tagged `"response"` lines back to their caller.
#[cfg(feature = "gui")]
struct EngineSession {
    /// Monotonically increasing, shared with the reader thread only
    /// for uniqueness (never read there).
    next_request_id: Arc<AtomicU64>,
    /// One entry per in-flight session request: `request_id` ->
    /// the one-shot sender the reader thread uses to deliver that
    /// request's matching `SessionLine` once it arrives.
    pending: Arc<Mutex<HashMap<u64, std::sync::mpsc::Sender<SessionLine>>>>,
    /// Kept alive for the session's lifetime; the thread exits on its
    /// own once the socket closes (EOF) or errors.
    _reader_thread: std::thread::JoinHandle<()>,
    /// Queue feeding the send-worker thread (Phase 3): `EngineClient::
    /// send` enqueues here and returns immediately; the worker owns the
    /// cloned write half of the socket and reports each outcome back as
    /// an [`EngineEvent::Sent`]/[`EngineEvent::SendError`].
    send_jobs: std::sync::mpsc::Sender<SendJob>,
    /// Kept alive for the session's lifetime; exits when `send_jobs`
    /// disconnects (session dropped) or the socket dies mid-send.
    _send_worker: std::thread::JoinHandle<()>,
}

/// Forwards `event` to `event_sender` WITHOUT ever blocking: a full
/// bounded channel means the GTK main loop is behind, not that the
/// reader thread should stall (stalling here would stop it from also
/// draining `"response"` lines, which OTHER in-flight
/// [`EngineConnection::session_request`] callers are blocked
/// waiting on — the exact freeze this module's `ConnectionLost`
/// handling exists to avoid). On overflow the event is dropped and
/// logged, with a running counter so a burst of drops doesn't spam
/// stderr silently. Returns `true` if the channel is closed (the GTK
/// side is gone), signalling the caller should exit its loop.
#[cfg(feature = "gui")]
fn forward_or_drop(
    event_sender: &async_channel::Sender<EngineEvent>,
    event: EngineEvent,
    dropped_count: &AtomicU64,
) -> bool {
    match event_sender.try_send(event) {
        Ok(()) => false,
        Err(async_channel::TrySendError::Full(_)) => {
            let total = dropped_count
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1);
            eprintln!(
                "umbra-gui: event channel full, dropping one Engine event ({total} dropped \
                 so far — the GTK main loop is not keeping up)"
            );
            false
        }
        Err(async_channel::TrySendError::Closed(_)) => true,
    }
}

/// Spawns the background reader thread: reads tagged NDJSON lines off
/// `read_stream` forever, routing `"response"` lines to their waiting
/// caller (via `pending`) and `"event"` lines to the GTK main loop
/// (via `event_sender`). Exits on EOF or any I/O/parse error on this
/// stream (the Engine process going away) — a malformed/unparseable
/// LINE is skipped and the loop continues (it can't carry a
/// trustworthy request_id or event either way), but a genuine
/// read failure or EOF is fatal for the connection and ends the loop.
///
/// On exit, BEFORE returning: sends [`EngineEvent::ConnectionLost`]
/// (so the GTK side can show a permanent error state), then locks
/// `pending` and drains it — dropping every waiting
/// [`std::sync::mpsc::Sender`], which makes every blocked
/// `rx.recv()` in [`EngineConnection::session_request`] return `Err`
/// immediately instead of hanging forever (the Engine dying used to
/// freeze the GTK main thread permanently, since `session_request`
/// runs on it and nothing else would ever signal those channels
/// closed).
///
/// `event_sender` is an [`async_channel::Sender`] rather than glib's
/// removed-in-0.22 `glib::Sender`: `try_send`/`send_blocking` work
/// from this non-async thread, and the GTK side consumes the paired
/// receiver in a `glib::MainContext::spawn_local` future (see
/// `main.rs`).
#[cfg(feature = "gui")]
fn spawn_reader_thread(
    read_stream: UnixStream,
    pending: Arc<Mutex<HashMap<u64, std::sync::mpsc::Sender<SessionLine>>>>,
    event_sender: async_channel::Sender<EngineEvent>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let dropped_count = AtomicU64::new(0);
        let mut reader = BufReader::new(read_stream);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => {
                    let _ = event_sender.try_send(EngineEvent::ConnectionLost);
                    if let Ok(mut pending) = pending.lock() {
                        // `drain()` drops every `Sender` it yields —
                        // exactly what unblocks each waiting
                        // `rx.recv()`.
                        let _ = pending.drain();
                    }
                    return;
                }
                Ok(_) => {}
            }
            let Ok(parsed) = serde_json::from_str::<SessionLine>(line.trim_end()) else {
                continue;
            };
            match parsed.kind.as_str() {
                "response" => {
                    let Some(request_id) = parsed.request_id else {
                        continue;
                    };
                    let waiter = pending
                        .lock()
                        .ok()
                        .and_then(|mut map| map.remove(&request_id));
                    if let Some(waiter) = waiter {
                        let _ = waiter.send(parsed);
                    }
                }
                "event" => {
                    let event = match parsed.event.as_deref() {
                        Some("ready") => parsed.address.clone().map(EngineEvent::Ready),
                        Some("inbound-text") => parsed.data.as_deref().and_then(|data| {
                            use base64::Engine as _;
                            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(data)
                                .ok()?;
                            // Matches `tui.rs`'s own established
                            // precedent for this exact payload type:
                            // a non-UTF-8 inbound text still produces
                            // a visible (if lossy) line rather than
                            // silently vanishing with no trace.
                            Some(EngineEvent::InboundText(
                                String::from_utf8_lossy(&bytes).into_owned(),
                            ))
                        }),
                        Some("session-error") => {
                            parsed.error.clone().map(EngineEvent::SessionError)
                        }
                        _ => None,
                    };
                    if let Some(event) = event
                        && forward_or_drop(&event_sender, event, &dropped_count)
                    {
                        return; // GTK main loop gone
                    }
                }
                _ => {}
            }
        }
    })
}

/// Spawns the send-worker thread (Phase 3): owns a CLONED write half
/// of the Engine socket and processes queued [`SendJob`]s strictly one
/// at a time — assigning the request id, registering the oneshot
/// waiter, writing the tagged `"send"` line, and blocking on the
/// reader thread's delivery. Serializing sends here (rather than
/// blocking the GTK main loop per send) is what keeps the UI
/// responsive during a slow onion connect; the outcome is forwarded
/// to the main loop as [`EngineEvent::Sent`]/[`EngineEvent::SendError`]
/// (mirrors `tui.rs`'s `UiEvent::Sent`/`SendError`). Exits when the
/// job queue disconnects (session dropped).
#[cfg(feature = "gui")]
fn spawn_send_worker(
    mut write_stream: UnixStream,
    next_request_id: Arc<AtomicU64>,
    pending: Arc<Mutex<HashMap<u64, std::sync::mpsc::Sender<SessionLine>>>>,
    event_sender: async_channel::Sender<EngineEvent>,
    jobs: std::sync::mpsc::Receiver<SendJob>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let dropped_count = AtomicU64::new(0);
        for job in jobs {
            let request_id = next_request_id.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = std::sync::mpsc::channel();
            {
                let Ok(mut pending_map) = pending.lock() else {
                    return; // poisoned session state: nothing more can work
                };
                pending_map.insert(request_id, tx);
            }
            let request = Request {
                op: "send".to_string(),
                peer_name: Some(job.peer_name.clone()),
                text: Some(job.text),
                request_id: Some(request_id),
                ..Request::default()
            };
            let write_result = serde_json::to_string(&request)
                .map_err(|error| error.to_string())
                .and_then(|line| {
                    let mut line = line;
                    line.push('\n');
                    write_stream
                        .write_all(line.as_bytes())
                        .map_err(|error| error.to_string())
                });
            let outcome = match write_result {
                Ok(()) => rx
                    .recv()
                    .map_err(|_error| "Engine connection closed mid-send".to_string()),
                Err(error) => {
                    // The request never reached the Engine, so no
                    // response will ever arrive for this request_id —
                    // remove the just-inserted waiter now, rather
                    // than leaking one `pending` entry per failed
                    // write (same fix as `EngineConnection::
                    // session_request`'s own analogous leak).
                    if let Ok(mut pending_map) = pending.lock() {
                        pending_map.remove(&request_id);
                    }
                    Err(error)
                }
            };
            let event = match outcome {
                Ok(line) if line.ok == Some(true) => EngineEvent::Sent(job.peer_name),
                Ok(line) => EngineEvent::SendError(
                    job.peer_name,
                    line.error
                        .unwrap_or_else(|| "Engine returned an error with no message".to_string()),
                ),
                Err(message) => EngineEvent::SendError(job.peer_name, message),
            };
            if forward_or_drop(&event_sender, event, &dropped_count) {
                return; // main loop gone
            }
        }
    })
}

/// A live connection to a spawned `umbra-engine` process.
///
/// Holds the spawned [`Child`] so `Drop` can kill it: a safety net
/// against an orphaned secret-holding process outliving this GUI (the
/// Engine also exits on its own once this struct's connection closes,
/// since it reads until EOF — this is belt-and-suspenders).
pub struct EngineClient {
    /// The wire-protocol connection to the spawned Engine process.
    connection: EngineConnection,
    /// The spawned `umbra-engine` child process, killed on [`Drop`].
    child: Child,
    /// Session-phase state, `Some` once [`EngineClient::start_session`]
    /// has been called after a successful unlock.
    #[cfg(feature = "gui")]
    session: Option<EngineSession>,
}

impl Drop for EngineClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl EngineClient {
    /// Spawns `umbra-engine` (located next to this process's own
    /// executable — never resolved via `$PATH`, so a same-named
    /// binary earlier on the caller's `$PATH` can never be spawned
    /// instead) and connects to it over a fresh, per-process `AF_UNIX`
    /// socket under `$XDG_RUNTIME_DIR/umbra/` (falling back to
    /// [`std::env::temp_dir`] with a stderr notice if
    /// `XDG_RUNTIME_DIR` is unset — unusual on a real desktop session
    /// but not fatal).
    ///
    /// `keystore_path` is canonicalized once, here: its canonicalized
    /// parent directory becomes the Engine's `--keystore-dir` sandbox
    /// scope, and the SAME canonicalized path (the second element of
    /// the returned tuple) is what every later [`EngineClient::unlock`]
    /// call must send as `keystore_path`, so the Engine's own
    /// directory check always compares like with like.
    ///
    /// # Errors
    ///
    /// Returns a display-ready error message if `keystore_path` cannot
    /// be canonicalized, the socket directory cannot be created, the
    /// Engine binary cannot be spawned, its socket never appears
    /// within a 2-second bound, or the connection cannot be
    /// established.
    pub fn spawn(
        keystore_path: &Path,
        hw_module: Option<&Path>,
    ) -> Result<(Self, PathBuf), String> {
        let canonical_keystore_path =
            std::fs::canonicalize(keystore_path).map_err(|error| error.to_string())?;
        let keystore_dir = canonical_keystore_path
            .parent()
            .ok_or_else(|| "keystore path has no parent directory".to_string())?
            .to_path_buf();

        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").map_or_else(
            || {
                eprintln!(
                    "umbra-gui: XDG_RUNTIME_DIR is unset, falling back to the system temp \
                     directory for the Engine socket"
                );
                std::env::temp_dir()
            },
            PathBuf::from,
        );
        let socket_dir = runtime_dir.join("umbra");
        std::fs::create_dir_all(&socket_dir).map_err(|error| error.to_string())?;
        std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        let socket_path = socket_dir.join(format!("engine-{}.sock", std::process::id()));

        let engine_binary = sibling_engine_binary_path()?;
        let mut command = std::process::Command::new(&engine_binary);
        command
            .arg("--socket")
            .arg(&socket_path)
            .arg("--keystore-dir")
            .arg(&keystore_dir);
        let tor_dir = keystore_dir.join("tor");
        command.arg("--tor-dir").arg(&tor_dir);
        if let Some(hw_module) = hw_module {
            let canonical_hw_module =
                std::fs::canonicalize(hw_module).map_err(|error| error.to_string())?;
            let hw_module_dir = canonical_hw_module
                .parent()
                .ok_or_else(|| "hw-module path has no parent directory".to_string())?;
            command.arg("--hw-module-dir").arg(hw_module_dir);
        }
        let child = command
            .spawn()
            .map_err(|error| format!("failed to spawn {}: {error}", engine_binary.display()))?;

        let deadline = std::time::Instant::now()
            .checked_add(Duration::from_secs(2))
            .ok_or_else(|| "system clock error computing Engine startup deadline".to_string())?;
        while !socket_path.exists() {
            if std::time::Instant::now() > deadline {
                return Err("timed out waiting for umbra-engine's socket to appear".to_string());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let stream = UnixStream::connect(&socket_path).map_err(|error| error.to_string())?;
        Ok((
            Self {
                connection: EngineConnection { stream },
                child,
                #[cfg(feature = "gui")]
                session: None,
            },
            canonical_keystore_path,
        ))
    }

    /// Sends an `"unlock"` request for `keystore_path` (MUST be the
    /// canonicalized path returned by [`EngineClient::spawn`]) with
    /// `passphrase`, and returns the unlocked identity's fingerprint
    /// as lowercase hex on success.
    ///
    /// # Errors
    ///
    /// Returns a display-ready error message on a wrong passphrase, a
    /// missing/corrupt keystore file, a non-UTF-8 passphrase, or any
    /// I/O failure talking to the Engine.
    pub fn unlock(
        &mut self,
        keystore_path: &Path,
        passphrase: &[u8],
        hw_module: Option<&Path>,
        hw_pin: &[u8],
        hw_key_label: Option<&str>,
    ) -> Result<String, String> {
        self.connection
            .unlock(keystore_path, passphrase, hw_module, hw_pin, hw_key_label)
    }

    /// Transitions this connection into the session phase after a
    /// successful `unlock`: spawns the background reader thread and
    /// wires it to forward events through `event_sender` (create one
    /// via `async_channel::bounded(EVENT_CHANNEL_CAPACITY)` — BOUNDED,
    /// not `async_channel::unbounded()`: an unbounded channel here
    /// would grow without limit if the GTK main loop ever fell behind
    /// draining it. Overflow is dropped, not blocked on, by both
    /// background threads that feed it — see [`forward_or_drop`]'s
    /// own doc comment for why blocking would risk the same freeze
    /// [`EngineEvent::ConnectionLost`] exists to fix. The GTK main
    /// loop consumes the paired receiver in a
    /// `glib::MainContext::spawn_local` future on its own thread —
    /// glib 0.22 removed `glib::MainContext::channel`, see
    /// `Cargo.toml`'s note).
    /// Must be called before any of `list_peers`/`pair_payload`/
    /// `pair_import`/`pair_confirm`/`send` (TODO B.3 GUI
    /// messaging design, Phase 2 — those methods now require an
    /// active session).
    ///
    /// # Errors
    ///
    /// Returns a display-ready error message if the socket's read
    /// half cannot be cloned.
    #[cfg(feature = "gui")]
    pub fn start_session(
        &mut self,
        event_sender: async_channel::Sender<EngineEvent>,
    ) -> Result<(), String> {
        let read_stream = self
            .connection
            .stream
            .try_clone()
            .map_err(|error| error.to_string())?;
        let write_stream = self
            .connection
            .stream
            .try_clone()
            .map_err(|error| error.to_string())?;
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let next_request_id = Arc::new(AtomicU64::new(1));
        let reader_thread = spawn_reader_thread(read_stream, pending.clone(), event_sender.clone());
        let (send_jobs, send_jobs_rx) = std::sync::mpsc::channel();
        let send_worker = spawn_send_worker(
            write_stream,
            next_request_id.clone(),
            pending.clone(),
            event_sender,
            send_jobs_rx,
        );
        self.session = Some(EngineSession {
            next_request_id,
            pending,
            _reader_thread: reader_thread,
            send_jobs,
            _send_worker: send_worker,
        });
        Ok(())
    }

    /// Lists the current session's paired peer names.
    ///
    /// # Errors
    ///
    /// Returns a display-ready error message if the session was never
    /// started (see [`EngineClient::start_session`]), or on any I/O
    /// failure talking to the Engine.
    #[cfg(feature = "gui")]
    pub fn list_peers(&mut self) -> Result<Vec<String>, String> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| "session not started".to_string())?;
        let response = self.connection.session_request(
            session,
            Request {
                op: "list_peers".to_string(),
                ..Request::default()
            },
        )?;
        if response.ok == Some(true) {
            Ok(response.peer_names.unwrap_or_default())
        } else {
            Err(response
                .error
                .unwrap_or_else(|| "Engine returned an error with no message".to_string()))
        }
    }

    /// Returns this session's own base64url pairing payload, to hand
    /// to a peer out of band.
    ///
    /// # Errors
    ///
    /// Returns a display-ready error message if the session was never
    /// started, or on any I/O failure talking to the Engine.
    #[cfg(feature = "gui")]
    pub fn pair_payload(&mut self) -> Result<String, String> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| "session not started".to_string())?;
        let response = self.connection.session_request(
            session,
            Request {
                op: "pair_payload".to_string(),
                ..Request::default()
            },
        )?;
        if response.ok == Some(true) {
            response
                .payload
                .ok_or_else(|| "Engine returned ok without a payload".to_string())
        } else {
            Err(response
                .error
                .unwrap_or_else(|| "Engine returned an error with no message".to_string()))
        }
    }

    /// Validates a peer's pairing payload and returns the shared SAS
    /// code for out-of-band verification. Does not persist a peer
    /// record — see [`EngineClient::pair_confirm`].
    ///
    /// # Errors
    ///
    /// Returns a display-ready error message on an invalid payload,
    /// if the session was never started, or on any I/O failure.
    #[cfg(feature = "gui")]
    pub fn pair_import(&mut self, peer_payload: &str) -> Result<String, String> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| "session not started".to_string())?;
        let response = self.connection.session_request(
            session,
            Request {
                op: "pair_import".to_string(),
                peer_payload: Some(peer_payload.to_string()),
                ..Request::default()
            },
        )?;
        if response.ok == Some(true) {
            response
                .sas
                .ok_or_else(|| "Engine returned ok without a SAS code".to_string())
        } else {
            Err(response
                .error
                .unwrap_or_else(|| "Engine returned an error with no message".to_string()))
        }
    }

    /// Persists a peer record under `peer_name`, once the operator has
    /// confirmed the SAS code from [`EngineClient::pair_import`]
    /// matches out of band.
    ///
    /// # Errors
    ///
    /// Returns a display-ready error message on an invalid name/
    /// payload/address, if the session was never started, or on
    /// any I/O failure.
    #[cfg(feature = "gui")]
    pub fn pair_confirm(
        &mut self,
        peer_name: &str,
        peer_payload: &str,
        peer_onion: Option<&str>,
    ) -> Result<(), String> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| "session not started".to_string())?;
        let response = self.connection.session_request(
            session,
            Request {
                op: "pair_confirm".to_string(),
                peer_name: Some(peer_name.to_string()),
                peer_payload: Some(peer_payload.to_string()),
                peer_onion: peer_onion.map(str::to_string),
                ..Request::default()
            },
        )?;
        if response.ok == Some(true) {
            Ok(())
        } else {
            Err(response
                .error
                .unwrap_or_else(|| "Engine returned an error with no message".to_string()))
        }
    }

    /// Queues a `"send"` of `text` to `peer_name` and returns
    /// IMMEDIATELY (TODO B.3 GUI messaging design, Phase 3): the
    /// send-worker thread performs the bounded onion connect off the
    /// GTK main loop, and the outcome arrives as an
    /// [`EngineEvent::Sent`]/[`EngineEvent::SendError`] on the session's
    /// event channel. Phase 2's blocking `send_stub` is gone — sending
    /// is real now.
    ///
    /// # Errors
    ///
    /// Returns a display-ready error message if the session was never
    /// started or the send worker is gone (engine died).
    #[cfg(feature = "gui")]
    pub fn send(&self, peer_name: &str, text: &str) -> Result<(), String> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| "session not started".to_string())?;
        session
            .send_jobs
            .send(SendJob {
                peer_name: peer_name.to_string(),
                text: text.to_string(),
            })
            .map_err(|_error| "send worker is gone (Engine connection closed)".to_string())
    }
}

/// Resolves the `umbra-engine` binary's path as a SIBLING of this
/// process's own executable (never via `$PATH` — see
/// [`EngineClient::spawn`]'s doc comment for why).
fn sibling_engine_binary_path() -> Result<PathBuf, String> {
    let current_exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let parent = current_exe
        .parent()
        .ok_or_else(|| "current executable has no parent directory".to_string())?;
    Ok(parent.join("umbra-engine"))
}

#[cfg(test)]
mod tests {
    use super::EngineConnection;
    #[cfg(feature = "gui")]
    use super::{EngineEvent, EngineSession, Request, spawn_reader_thread, spawn_send_worker};
    #[cfg(feature = "gui")]
    use std::cell::RefCell;
    #[cfg(feature = "gui")]
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    #[cfg(feature = "gui")]
    use std::rc::Rc;
    #[cfg(feature = "gui")]
    use std::sync::atomic::AtomicU64;
    #[cfg(feature = "gui")]
    use std::sync::{Arc, Mutex};

    /// Spins up a plain `UnixListener` fixture (a scripted fake
    /// Engine, no real `umbra-engine` subprocess) that accepts one
    /// connection, reads one NDJSON request line, and writes back
    /// `response_line` verbatim. Returns a connected
    /// [`EngineConnection`] wired to it. `label` gives the fixture
    /// socket a unique path per test (mirrors this codebase's
    /// established `temp_keystore_path`-style test helpers).
    fn connect_to_fake_engine(
        label: &str,
        response_line: &'static str,
    ) -> Result<EngineConnection, Box<dyn std::error::Error + Send + Sync>> {
        let socket_path = std::env::temp_dir().join(format!(
            "umbra-gui-engine-client-test-{}-{label}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path)?;
        std::thread::spawn(move || -> Result<(), std::io::Error> {
            let (stream, _peer_addr) = listener.accept()?;
            let mut reader = BufReader::new(stream.try_clone()?);
            let mut writer = stream;
            let mut request_line = String::new();
            reader.read_line(&mut request_line)?;
            writer.write_all(response_line.as_bytes())?;
            writer.write_all(b"\n")
        });
        let stream = UnixStream::connect(&socket_path)?;
        let _ = std::fs::remove_file(&socket_path);
        Ok(EngineConnection { stream })
    }

    #[test]
    fn unlock_parses_a_successful_response() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        let mut connection = connect_to_fake_engine(
            "success",
            r#"{"ok":true,"fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        )?;
        let fingerprint = connection
            .unlock(
                std::path::Path::new("/tmp/ks.enc"),
                b"whatever",
                None,
                b"",
                None,
            )
            .map_err(|error| format!("expected Ok, got Err: {error}"))?;
        assert_eq!(fingerprint.len(), 64);
        Ok(())
    }

    #[test]
    fn unlock_parses_a_failure_response() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut connection = connect_to_fake_engine(
            "failure",
            r#"{"ok":false,"error":"wrong passphrase or corrupted keystore"}"#,
        )?;
        let result = connection.unlock(
            std::path::Path::new("/tmp/ks.enc"),
            b"whatever",
            None,
            b"",
            None,
        );
        assert_eq!(
            result,
            Err("wrong passphrase or corrupted keystore".to_string())
        );
        Ok(())
    }

    #[test]
    fn unlock_rejects_a_non_utf8_passphrase() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        // The UTF-8 check happens before any socket I/O, so the fake
        // Engine's scripted response is never actually sent or read —
        // any well-formed response line works here.
        let mut connection =
            connect_to_fake_engine("non-utf8", r#"{"ok":true,"fingerprint":"x"}"#)?;
        let result = connection.unlock(
            std::path::Path::new("/tmp/ks.enc"),
            &[0xFF, 0xFE],
            None,
            b"",
            None,
        );
        assert_eq!(result, Err("passphrase must be valid UTF-8".to_string()));
        Ok(())
    }

    #[test]
    fn unlock_sends_hardware_key_fields_when_present()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // The fake engine ECHOES the request line back as the response
        // line's `error` field, so this test can assert on exactly
        // what was sent over the wire without a real Engine parsing it.
        let socket_path = std::env::temp_dir().join(format!(
            "umbra-gui-engine-client-test-{}-hw-fields.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path)?;
        std::thread::spawn(move || -> Result<(), std::io::Error> {
            let (stream, _peer_addr) = listener.accept()?;
            let mut reader = BufReader::new(stream.try_clone()?);
            let mut writer = stream;
            let mut request_line = String::new();
            reader.read_line(&mut request_line)?;
            let escaped = request_line.trim_end().replace('"', "\\\"");
            writer.write_all(format!("{{\"ok\":false,\"error\":\"{escaped}\"}}\n").as_bytes())?;
            Ok(())
        });
        let stream = UnixStream::connect(&socket_path)?;
        let _ = std::fs::remove_file(&socket_path);
        let mut connection = EngineConnection { stream };

        let result = connection.unlock(
            std::path::Path::new("/tmp/ks.enc"),
            b"whatever",
            Some(std::path::Path::new("/usr/lib64/pkcs11/libsofthsm2.so")),
            b"1234",
            Some("my-key"),
        );
        // The fake engine's own `.replace('"', "\\\"")` above embeds the
        // raw request JSON as a properly-escaped JSON STRING VALUE; once
        // THIS side's `serde_json::from_str::<Response>` decodes that
        // response, `response.error` (and so `echoed` here) holds the
        // request JSON back in its PLAIN, un-escaped form — JSON
        // decoding is exactly what undoes the fake engine's own
        // escaping. So the substrings checked for below use plain `"`,
        // not `\"`.
        let echoed = result.err().ok_or("expected an Err")?;
        assert!(echoed.contains("\"hw_module\":\"/usr/lib64/pkcs11/libsofthsm2.so\""));
        assert!(echoed.contains("\"hw_pin\":\"1234\""));
        assert!(echoed.contains("\"hw_key_label\":\"my-key\""));
        Ok(())
    }

    #[cfg(feature = "gui")]
    #[test]
    fn list_peers_parses_a_successful_tagged_response()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut connection, session) = connect_to_fake_session_engine(
            "list-peers",
            r#"{"kind":"response","request_id":1,"ok":true,"peer_names":["alice","bob"]}"#,
        )?;
        let response = connection.session_request(
            &session,
            Request {
                op: "list_peers".to_string(),
                ..Request::default()
            },
        )?;
        assert_eq!(response.ok, Some(true));
        assert_eq!(
            response.peer_names,
            Some(vec!["alice".to_string(), "bob".to_string()])
        );
        Ok(())
    }

    #[cfg(feature = "gui")]
    #[test]
    fn pair_payload_parses_a_successful_tagged_response()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut connection, session) = connect_to_fake_session_engine(
            "pair-payload",
            r#"{"kind":"response","request_id":1,"ok":true,"payload":"own-payload"}"#,
        )?;
        let response = connection.session_request(
            &session,
            Request {
                op: "pair_payload".to_string(),
                ..Request::default()
            },
        )?;
        assert_eq!(response.payload, Some("own-payload".to_string()));
        Ok(())
    }

    #[cfg(feature = "gui")]
    #[test]
    fn pair_import_parses_a_successful_tagged_response()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut connection, session) = connect_to_fake_session_engine(
            "pair-import",
            r#"{"kind":"response","request_id":1,"ok":true,"sas":"123456"}"#,
        )?;
        let response = connection.session_request(
            &session,
            Request {
                op: "pair_import".to_string(),
                peer_payload: Some("peer-payload".to_string()),
                ..Request::default()
            },
        )?;
        assert_eq!(response.sas, Some("123456".to_string()));
        Ok(())
    }

    #[cfg(feature = "gui")]
    #[test]
    fn pair_confirm_parses_a_successful_tagged_response()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut connection, session) = connect_to_fake_session_engine(
            "pair-confirm",
            r#"{"kind":"response","request_id":1,"ok":true}"#,
        )?;
        let response = connection.session_request(
            &session,
            Request {
                op: "pair_confirm".to_string(),
                peer_name: Some("alice".to_string()),
                peer_payload: Some("peer-payload".to_string()),
                peer_onion: Some("a".repeat(56)),
                ..Request::default()
            },
        )?;
        assert_eq!(response.ok, Some(true));
        Ok(())
    }

    #[cfg(feature = "gui")]
    #[test]
    fn pair_confirm_parses_a_failure_tagged_response()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut connection, session) = connect_to_fake_session_engine(
            "pair-confirm-fail",
            r#"{"kind":"response","request_id":1,"ok":false,"error":"not unlocked yet"}"#,
        )?;
        let response = connection.session_request(
            &session,
            Request {
                op: "pair_confirm".to_string(),
                peer_name: Some("alice".to_string()),
                peer_payload: Some("peer-payload".to_string()),
                ..Request::default()
            },
        )?;
        assert_eq!(response.ok, Some(false));
        assert_eq!(response.error, Some("not unlocked yet".to_string()));
        Ok(())
    }

    /// Session-phase variant of [`connect_to_fake_engine`]: the fake
    /// Engine writes ONE tagged `response_line` back (which must carry
    /// `"request_id":1`, the first id a fresh [`EngineSession`] hands
    /// out), and the returned [`EngineSession`] has the background
    /// reader thread already running against a cloned read stream.
    /// Requires the `gui` feature: the reader thread's event sink is a
    /// `gtk4::glib` channel.
    #[cfg(feature = "gui")]
    fn connect_to_fake_session_engine(
        label: &str,
        response_line: &'static str,
    ) -> Result<(EngineConnection, EngineSession), Box<dyn std::error::Error + Send + Sync>> {
        let socket_path = std::env::temp_dir().join(format!(
            "umbra-gui-engine-client-test-{}-{label}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path)?;
        std::thread::spawn(move || -> Result<(), std::io::Error> {
            let (stream, _peer_addr) = listener.accept()?;
            let mut reader = BufReader::new(stream.try_clone()?);
            let mut writer = stream;
            let mut request_line = String::new();
            reader.read_line(&mut request_line)?;
            writer.write_all(response_line.as_bytes())?;
            writer.write_all(b"\n")
        });
        let stream = UnixStream::connect(&socket_path)?;
        let _ = std::fs::remove_file(&socket_path);
        let read_stream = stream.try_clone()?;
        let write_stream = stream.try_clone()?;
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let (event_tx, _event_rx) = async_channel::unbounded();
        let reader_thread = spawn_reader_thread(read_stream, pending.clone(), event_tx.clone());
        let (send_jobs, send_jobs_rx) = std::sync::mpsc::channel();
        let send_worker = spawn_send_worker(
            write_stream,
            Arc::new(AtomicU64::new(10_000)),
            pending.clone(),
            event_tx,
            send_jobs_rx,
        );
        let session = EngineSession {
            next_request_id: Arc::new(AtomicU64::new(1)),
            pending,
            _reader_thread: reader_thread,
            send_jobs,
            _send_worker: send_worker,
        };
        Ok((EngineConnection { stream }, session))
    }

    #[cfg(feature = "gui")]
    #[test]
    fn session_request_receives_a_tagged_response_via_the_reader_thread()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // A fake Engine that reads one request line, then writes back
        // ONE tagged response line whose request_id echoes whatever
        // the client sent (extracted by a crude but sufficient scan,
        // since the fixture never needs a real JSON parser here).
        let socket_path = std::env::temp_dir().join(format!(
            "umbra-gui-engine-client-test-{}-session-request.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path)?;
        std::thread::spawn(move || -> Result<(), std::io::Error> {
            let (stream, _peer_addr) = listener.accept()?;
            let mut reader = BufReader::new(stream.try_clone()?);
            let mut writer = stream;
            let mut request_line = String::new();
            reader.read_line(&mut request_line)?;
            writer.write_all(
                br#"{"kind":"response","request_id":1,"ok":true,"peer_names":["alice"]}"#,
            )?;
            writer.write_all(b"\n")
        });
        let stream = UnixStream::connect(&socket_path)?;
        let _ = std::fs::remove_file(&socket_path);
        let read_stream = stream.try_clone()?;
        let write_stream = stream.try_clone()?;
        let mut connection = EngineConnection { stream };

        let pending = Arc::new(Mutex::new(HashMap::new()));
        let (event_tx, _event_rx) = async_channel::unbounded();
        let reader_thread = spawn_reader_thread(read_stream, pending.clone(), event_tx.clone());
        let (send_jobs, send_jobs_rx) = std::sync::mpsc::channel();
        let send_worker = spawn_send_worker(
            write_stream,
            Arc::new(AtomicU64::new(10_000)),
            pending.clone(),
            event_tx,
            send_jobs_rx,
        );
        let session = EngineSession {
            next_request_id: Arc::new(AtomicU64::new(1)),
            pending,
            _reader_thread: reader_thread,
            send_jobs,
            _send_worker: send_worker,
        };

        let response = connection.session_request(
            &session,
            Request {
                op: "list_peers".to_string(),
                ..Request::default()
            },
        )?;
        assert_eq!(response.kind, "response");
        assert_eq!(response.request_id, Some(1));
        assert_eq!(response.peer_names, Some(vec!["alice".to_string()]));
        Ok(())
    }

    #[cfg(feature = "gui")]
    #[test]
    fn event_lines_are_forwarded_to_the_glib_channel_not_the_pending_map()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let socket_path = std::env::temp_dir().join(format!(
            "umbra-gui-engine-client-test-{}-event-forward.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path)?;
        std::thread::spawn(move || -> Result<(), std::io::Error> {
            let (stream, _peer_addr) = listener.accept()?;
            let mut writer = stream;
            writer.write_all(br#"{"kind":"event","event":"ready","address":"test-address"}"#)?;
            writer.write_all(b"\n")
        });
        let stream = UnixStream::connect(&socket_path)?;
        let _ = std::fs::remove_file(&socket_path);

        let pending = Arc::new(Mutex::new(HashMap::new()));
        let (event_tx, event_rx) = async_channel::unbounded();
        let _reader_thread = spawn_reader_thread(stream, pending, event_tx);

        // No GTK main loop is running in this test, so the receiver is
        // consumed by a future spawned ONCE onto the default main
        // context, which is then pumped manually via
        // `iteration(false)`. The future hands events back out
        // through a shared `Rc<RefCell<_>>` — this crate's own
        // established pattern for GTK closures needing to report a
        // result (see `main.rs`). A `Vec`, not a single slot: the fake
        // engine closes its end of the socket right after writing the
        // one line, which is EOF from the reader thread's point of
        // view — since this fix pass, EOF also emits
        // `EngineEvent::ConnectionLost` (see `spawn_reader_thread`'s
        // own doc comment), so up to two events can legitimately
        // arrive here, and a single overwritten slot would race
        // between them.
        let context = gtk4::glib::MainContext::default();
        let observed: Rc<RefCell<Vec<EngineEvent>>> = Rc::new(RefCell::new(Vec::new()));
        let observed_for_task = observed.clone();
        context.spawn_local(async move {
            while let Ok(event) = event_rx.recv().await {
                observed_for_task.borrow_mut().push(event);
            }
        });
        let deadline = std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(2))
            .ok_or("system clock error computing test deadline")?;
        while std::time::Instant::now() < deadline {
            context.iteration(false);
            if observed.borrow().iter().any(
                |event| matches!(event, EngineEvent::Ready(address) if address == "test-address"),
            ) {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        Err("timed out waiting for the Ready event on the glib channel".into())
    }

    /// Phase 4: an `"inbound-text"` event line is base64-decoded by the
    /// reader thread and forwarded as [`EngineEvent::InboundText`];
    /// a `"session-error"` line becomes [`EngineEvent::SessionError`].
    #[cfg(feature = "gui")]
    #[test]
    fn inbound_text_and_session_error_events_are_decoded_and_forwarded()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let socket_path = std::env::temp_dir().join(format!(
            "umbra-gui-engine-client-test-{}-inbound-events.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path)?;
        std::thread::spawn(move || -> Result<(), std::io::Error> {
            let (stream, _peer_addr) = listener.accept()?;
            let mut writer = stream;
            // "aGVsbG8" is base64url-no-pad for "hello".
            writer.write_all(br#"{"kind":"event","event":"inbound-text","data":"aGVsbG8"}"#)?;
            writer.write_all(b"\n")?;
            writer.write_all(br#"{"kind":"event","event":"session-error","error":"boom"}"#)?;
            writer.write_all(b"\n")
        });
        let stream = UnixStream::connect(&socket_path)?;
        let _ = std::fs::remove_file(&socket_path);

        let pending = Arc::new(Mutex::new(HashMap::new()));
        let (event_tx, event_rx) = async_channel::unbounded();
        let _reader_thread = spawn_reader_thread(stream, pending, event_tx);

        // A FRESH context, not `MainContext::default()`: the default
        // context is owned by whichever test thread acquires it first,
        // and Rust's harness runs these tests in parallel (the
        // ready-event test above owns it when both run together).
        let context = gtk4::glib::MainContext::new();
        let observed: Rc<RefCell<Vec<EngineEvent>>> = Rc::new(RefCell::new(Vec::new()));
        let observed_for_task = observed.clone();
        context.spawn_local(async move {
            while let Ok(event) = event_rx.recv().await {
                observed_for_task.borrow_mut().push(event);
            }
        });
        let deadline = std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(2))
            .ok_or("system clock error computing test deadline")?;
        while std::time::Instant::now() < deadline {
            context.iteration(false);
            let events = observed.borrow();
            if events.len() >= 2 {
                let first = events.first().ok_or("missing first event")?;
                let second = events.get(1).ok_or("missing second event")?;
                assert!(
                    matches!(first, EngineEvent::InboundText(text) if text == "hello"),
                    "unexpected first event: {first:?}"
                );
                assert!(
                    matches!(second, EngineEvent::SessionError(error) if error == "boom"),
                    "unexpected second event: {second:?}"
                );
                return Ok(());
            }
            drop(events);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        Err("timed out waiting for inbound-text/session-error events".into())
    }
}
