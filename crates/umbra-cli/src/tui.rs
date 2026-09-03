//! # Umbra Interactive Terminal Client (TUI)
//!
//! Ratatui-based interactive client (ADR-027 MVP scope): a live inbound
//! onion feed, compose-and-send over Tor, and Tab-cycled peer selection.
//! The UI thread owns the terminal; a Tokio runtime runs bootstrap, the
//! shared inbound accept loop ([`crate::serve::inbound_loop`]), and
//! outbound sends in the background, communicating over channels so the
//! terminal never blocks on the network. Runs fully under the Landlock +
//! Seccomp sandbox (the caller hardens BEFORE `run`).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::Receiver;

use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use umbra_crypto::keys::IdentitySeeds;
use umbra_net::TransportError;
use umbra_net::tor::{PtProxyConfig, TorTransport};
use zeroize::Zeroizing;

use crate::cli::CliError;
use crate::pairing::PeerIdentity;

use thiserror::Error;

/// Upper bound for the message log: the oldest line is dropped first
/// (bounded-memory doctrine — an interactive session must not grow
/// without limit).
const MAX_LOG_LINES: usize = 400;

/// Poll interval for terminal events (keeps the UI responsive while
/// background tasks make progress).
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Capacity of the per-session result queue feeding the UI.
const SESSION_QUEUE: usize = 32;

/// Configuration for the interactive client.
pub struct TuiConfig {
    /// Identity seeds (loaded pre-sandbox; Arc-shared with the accept
    /// loop and the send path).
    pub seeds: Arc<IdentitySeeds>,
    /// Named peer records (loaded pre-sandbox, sorted by name).
    pub peers: Vec<(String, PeerIdentity)>,
    /// Tor storage root (Landlock rw exception; holds the persistent
    /// onion identity for [`TuiConfig::nickname`]).
    pub tor_base: PathBuf,
    /// Onion service nickname for the inbound service.
    pub nickname: String,
    /// Optional unmanaged PT proxy configuration (ADR-030); `None` is a
    /// direct guard connection.
    pub pt: Option<PtProxyConfig>,
}

/// Events flowing from the background runtime to the UI loop.
enum UiEvent {
    /// Bootstrap started.
    Bootstrapping,
    /// Descriptor published: the (redacted) own address.
    Ready(String),
    /// Inbound plaintext from a peer session.
    Inbound(Vec<u8>),
    /// A peer session failed (contained to its connection).
    SessionError(String),
    /// An outbound send was accepted by Arti's stream (NOT an
    /// end-to-end delivery acknowledgement).
    Sent {
        /// Target peer record name.
        peer: String,
        /// Number of data frames Arti accepted.
        frames: u64,
        /// Plaintext byte count.
        bytes: usize,
    },
    /// An outbound send failed.
    SendError {
        /// Target peer record name.
        peer: String,
        /// Failure detail (transport/session error text).
        error: String,
    },
    /// A background failure the user must see (the client keeps running
    /// so the terminal stays usable for quit).
    Fatal(String),
}

/// Commands flowing from the UI loop to the background runtime.
enum UiCommand {
    /// Send `plaintext` to the named peer at `address`.
    Send {
        /// Target peer record name.
        peer_name: String,
        /// Target onion address (from the peer record).
        address: String,
        /// Plaintext to deliver (already length-capped by the caller);
        /// `Zeroizing` so the in-flight copy is wiped on drop (ADR-025).
        plaintext: Zeroizing<Vec<u8>>,
    },
}

/// UI state: a bounded log line buffer, the compose line, and the peer
/// selection. Pure logic — unit-testable without a terminal.
struct UiState {
    /// Bounded message log (oldest line dropped past [`MAX_LOG_LINES`]).
    lines: Vec<String>,
    /// The in-progress compose line.
    compose: String,
    /// Index into `peers` of the selected send target.
    peer_index: usize,
    /// Named peer records (sorted by name at load time).
    peers: Vec<(String, PeerIdentity)>,
}

impl UiState {
    /// Builds the state for `peers` (sorted by the caller).
    fn new(peers: Vec<(String, PeerIdentity)>) -> Self {
        Self {
            lines: Vec::new(),
            compose: String::new(),
            peer_index: 0,
            peers,
        }
    }

    /// Appends one log line, dropping the oldest beyond the bound.
    fn push(&mut self, line: String) {
        if self.lines.len() >= MAX_LOG_LINES {
            self.lines.remove(0);
        }
        self.lines.push(line);
    }

    /// Appends a character to the compose line.
    fn compose_char(&mut self, c: char) {
        self.compose.push(c);
    }

    /// Removes the last composed character (no-op when empty).
    fn compose_backspace(&mut self) {
        self.compose.pop();
    }

    /// Takes the composed text, clearing the line.
    fn compose_take(&mut self) -> String {
        std::mem::take(&mut self.compose)
    }

    /// Cycles the peer selection (wraps; no-op with zero peers).
    fn cycle_peer(&mut self) {
        if !self.peers.is_empty() {
            // `peer_index < len` is the loop invariant; wrapping via
            // `rem_euclid` keeps the arithmetic checked (no bare `%`).
            self.peer_index = self
                .peer_index
                .checked_add(1)
                .unwrap_or(0)
                .rem_euclid(self.peers.len());
        }
    }

    /// The selected peer (name + identity), if any.
    fn selected(&self) -> Option<&(String, PeerIdentity)> {
        self.peers.get(self.peer_index)
    }

    /// Applies one runtime event to the log.
    fn apply(&mut self, event: UiEvent) {
        match event {
            UiEvent::Bootstrapping => {
                self.push("[…] bootstrapping Tor (up to ~3 minutes)…".to_string());
            }
            UiEvent::Ready(address) => {
                self.push(format!(
                    "[✓] own address: {} (verify SAS out of band)",
                    redact(&address)
                ));
            }
            UiEvent::Inbound(plaintext) => {
                let text = String::from_utf8_lossy(&plaintext).to_string();
                self.push(format!("◀ {text}"));
            }
            UiEvent::SessionError(error) => {
                self.push(format!("[!] inbound session failed: {error}"));
            }
            UiEvent::Sent {
                peer,
                frames,
                bytes,
            } => {
                self.push(format!("▶ {peer}: sent {frames} frames / {bytes} bytes"));
            }
            UiEvent::SendError { peer, error } => {
                self.push(format!("[✗] {peer}: send failed: {error}"));
            }
            UiEvent::Fatal(error) => {
                self.push(format!("[!!] {error}"));
            }
        }
    }
}

/// Redacts an onion address for operator output: first 8 and last 4
/// characters only (a controllable address must never be logged whole).
fn redact(address: &str) -> String {
    let bytes = address.as_bytes();
    if bytes.len() <= 12 {
        return "…redacted…".to_string();
    }
    let head = bytes
        .get(..8)
        .and_then(|slice| std::str::from_utf8(slice).ok())
        .unwrap_or("…");
    let tail_start = bytes.len().saturating_sub(4);
    let tail = bytes
        .get(tail_start..)
        .and_then(|slice| std::str::from_utf8(slice).ok())
        .unwrap_or("…");
    format!("{head}…{tail}")
}

/// Runs the interactive client until the user quits. NEVER returns
/// under normal chat operation — only on quit or a terminal failure.
///
/// # Errors
///
/// Returns [`CliError`] on terminal setup/teardown failure; background
/// runtime failures are reported as `[!!]` log lines and the UI stays
/// usable for quit.
pub fn run(cfg: TuiConfig) -> Result<(), CliError> {
    enable_raw_mode().map_err(|_e| CliError::Tui(TuiError::Terminal))?;
    let entered = std::io::stdout().execute(EnterAlternateScreen).is_ok();
    let terminal_result = Terminal::new(CrosstermBackend::new(std::io::stdout()));
    let mut terminal = match terminal_result {
        Ok(term) => term,
        Err(_e) => {
            restore(entered);
            return Err(CliError::Tui(TuiError::Terminal));
        }
    };

    let (event_tx, event_rx) = std::sync::mpsc::channel::<UiEvent>();
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<UiCommand>();
    let peers = cfg.peers.clone();
    let mut state = UiState::new(peers);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            restore(entered);
            CliError::Io(std::io::Error::other(format!("tokio runtime: {e}")))
        })?;
    runtime.spawn(background(cfg, event_tx.clone(), cmd_rx));

    let outcome = event_loop(&mut terminal, &mut state, &event_rx, &cmd_tx);

    restore(entered);
    drop(runtime);
    outcome
}

/// Draws and polls terminal events until the user quits.
fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    state: &mut UiState,
    event_rx: &Receiver<UiEvent>,
    cmd_tx: &tokio::sync::mpsc::UnboundedSender<UiCommand>,
) -> Result<(), CliError> {
    loop {
        // Drain background events into the log (non-blocking).
        while let Ok(event) = event_rx.try_recv() {
            state.apply(event);
        }

        terminal
            .draw(|frame| {
                let area = frame.area();
                let visible = usize::from(area.height);
                let skip = state.lines.len().saturating_sub(visible.saturating_sub(2));
                let mut lines: Vec<Line> = Vec::new();
                for line in state.lines.iter().skip(skip) {
                    lines.push(Line::from(line.clone()));
                }
                let selected = state
                    .selected()
                    .map_or("none".to_string(), |(name, _)| name.clone());
                lines.push(Line::from(format!(
                    "To: {selected} | compose: {}",
                    state.compose
                )));
                lines.push(Line::from(
                    "type text · Enter send · Tab peer · Backspace edit · Esc quit",
                ));
                frame.render_widget(Paragraph::new(lines), area);
            })
            .map_err(|_e| CliError::Tui(TuiError::Terminal))?;

        if event::poll(POLL_INTERVAL).map_err(|_e| CliError::Tui(TuiError::Terminal))?
            && let Ok(Event::Key(key)) = event::read()
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Esc => return Ok(()),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Ok(());
                }
                KeyCode::Enter => {
                    let text = state.compose_take();
                    if text.is_empty() {
                        state.push("[i] compose is empty".to_string());
                    } else {
                        let selection = state
                            .selected()
                            .map(|(name, peer)| (name.clone(), peer.clone()));
                        match selection {
                            Some((name, peer)) => match peer.onion {
                                Some(address) => {
                                    state.push(format!("▶ {name}: {text}"));
                                    let plaintext = Zeroizing::new(text.into_bytes());
                                    if cmd_tx
                                        .send(UiCommand::Send {
                                            peer_name: name.clone(),
                                            address,
                                            plaintext,
                                        })
                                        .is_err()
                                    {
                                        state.push(
                                            "[!!] background runtime gone; restart the client"
                                                .to_string(),
                                        );
                                    }
                                }
                                None => {
                                    // A missing onion record is a user-data
                                    // problem, not a terminal one: log it and
                                    // keep the client alive (Zero-Panic /
                                    // contained-failure doctrine).
                                    state.push(format!(
                                        "[i] {name} has no .onion address on record \
                                         (umbra pair --onion)"
                                    ));
                                }
                            },
                            None => {
                                state.push(
                                    "[i] no peer selected (add one with umbra pair)".to_string(),
                                );
                            }
                        }
                    }
                }
                KeyCode::Tab => state.cycle_peer(),
                KeyCode::Backspace => state.compose_backspace(),
                KeyCode::Char(c) => state.compose_char(c),
                _ => {}
            }
        }
    }
}

/// The background runtime side: bootstrap, inbound accept loop, and the
/// outbound command handler. All failures are reported as [`UiEvent`]
/// lines; this task never panics the UI.
async fn background(
    cfg: TuiConfig,
    event_tx: std::sync::mpsc::Sender<UiEvent>,
    mut cmd_rx: tokio::sync::mpsc::UnboundedReceiver<UiCommand>,
) {
    let _ = event_tx.send(UiEvent::Bootstrapping);
    let mut transport =
        match TorTransport::bootstrap_persistent_with_pt(&cfg.tor_base, cfg.pt.as_ref()).await {
            Ok(transport) => transport,
            Err(error) => {
                let _ = event_tx.send(UiEvent::Fatal(format!("bootstrap failed: {error}")));
                return;
            }
        };
    if let Err(error) = transport.spawn_inbound(&cfg.nickname).await {
        let _ = event_tx.send(UiEvent::Fatal(format!("inbound service: {error}")));
        return;
    }
    let transport = Arc::new(transport);

    let address = match crate::serve::wait_for_address(&transport).await {
        Ok(address) => address,
        Err(error) => {
            let _ = event_tx.send(UiEvent::Fatal(format!("onion publication: {error}")));
            return;
        }
    };
    let _ = event_tx.send(UiEvent::Ready(address));

    let (session_tx, mut session_rx) =
        tokio::sync::mpsc::channel::<Result<Vec<u8>, TransportError>>(SESSION_QUEUE);
    tokio::spawn(crate::serve::inbound_loop(
        transport.clone(),
        cfg.seeds.clone(),
        session_tx,
        SESSION_QUEUE,
    ));

    loop {
        tokio::select! {
            command = cmd_rx.recv() => match command {
                Some(UiCommand::Send { peer_name, address, plaintext }) => {
                    let transport = transport.clone();
                    let event_tx = event_tx.clone();
                    let peer = match cfg.peers.iter().find(|(name, _)| *name == peer_name) {
                        Some((_name, peer)) => peer.clone(),
                        None => {
                            let _ = event_tx.send(UiEvent::SendError {
                                peer: peer_name,
                                error: "peer record vanished".to_string(),
                            });
                            continue;
                        }
                    };
                    tokio::spawn(async move {
                        match crate::tor_send::send_over(&transport, &peer, &address, &plaintext)
                            .await
                        {
                            Ok((frames, bytes)) => {
                                let _ = event_tx.send(UiEvent::Sent {
                                    peer: peer_name,
                                    frames,
                                    bytes,
                                });
                            }
                            Err(error) => {
                                let _ = event_tx.send(UiEvent::SendError {
                                    peer: peer_name,
                                    error: error.to_string(),
                                });
                            }
                        }
                    });
                }
                None => break,
            },
            result = session_rx.recv() => match result {
                Some(Ok(plaintext)) => {
                    let plaintext = Zeroizing::new(plaintext);
                    let _ = event_tx.send(UiEvent::Inbound(plaintext.to_vec()));
                }
                Some(Err(error)) => {
                    let _ = event_tx.send(UiEvent::SessionError(error.to_string()));
                }
                None => {
                    let _ = event_tx.send(UiEvent::Fatal(
                        "inbound accept loop ended".to_string(),
                    ));
                    break;
                }
            },
        }
    }
}

/// Restores terminal state on every exit path.
fn restore(entered: bool) {
    if entered {
        let _ = std::io::stdout().execute(LeaveAlternateScreen);
    }
    let _ = disable_raw_mode();
}

/// TUI-specific error type.
#[derive(Debug, Error)]
pub enum TuiError {
    /// Terminal mode or backend failure.
    #[error("terminal failure")]
    Terminal,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_with_peers(count: usize) -> UiState {
        let peers = (0..count)
            .map(|i| {
                (
                    format!("peer{i}"),
                    crate::pairing::PeerIdentity {
                        ik: Vec::new(),
                        ik_arr: [0u8; 32],
                        spk_arr: [0u8; 32],
                        spk_signature: Vec::new(),
                        kem_arr: [0u8; 1184],
                        dsa: Vec::new(),
                        onion: None,
                    },
                )
            })
            .collect();
        UiState::new(peers)
    }

    #[test]
    fn compose_edit_cycle() {
        let mut state = state_with_peers(2);
        // Type "hi" -> compose = "hi"
        for c in "hi".chars() {
            state.compose_char(c);
        }
        // Backspace removes last character ('i'), leaving "h"
        state.compose_backspace();
        assert_eq!(state.compose, "h");
        // Add '!' -> "h!"
        state.compose_char('!');
        assert_eq!(state.compose_take(), "h!");
        assert!(state.compose.is_empty());
        // Backspace on an empty line is a no-op.
        state.compose_backspace();
        assert!(state.compose.is_empty());
    }

    /// Peer selection cycles with wraparound and is a no-op with zero
    /// peers.
    #[test]
    fn peer_cycling() {
        let mut none = state_with_peers(0);
        none.cycle_peer();
        assert!(none.selected().is_none());

        let mut state = state_with_peers(2);
        assert_eq!(
            state.selected().map(|(name, _)| name.as_str()),
            Some("peer0")
        );
        state.cycle_peer();
        assert_eq!(
            state.selected().map(|(name, _)| name.as_str()),
            Some("peer1")
        );
        state.cycle_peer();
        assert_eq!(
            state.selected().map(|(name, _)| name.as_str()),
            Some("peer0")
        );
    }

    /// The log is bounded: beyond `MAX_LOG_LINES` the oldest entries are
    /// dropped (bounded-memory doctrine).
    #[test]
    fn log_is_bounded() {
        let mut state = state_with_peers(0);
        for i in 0..(MAX_LOG_LINES + 25) {
            state.push(format!("line {i}"));
        }
        assert_eq!(state.lines.len(), MAX_LOG_LINES);
        assert_eq!(state.lines.first().map(String::as_str), Some("line 25"));
        assert_eq!(
            state.lines.last().map(String::as_str),
            Some(format!("line {}", MAX_LOG_LINES + 24).as_str())
        );
    }

    /// Onion addresses are never logged whole: short inputs collapse to
    /// a placeholder, long ones keep only an 8+4 character window.
    #[test]
    fn redact_hides_the_middle() {
        assert_eq!(redact("short"), "…redacted…");
        let addr = "5vzwalpq2cyjrhm5lvzhcjn6mbnwbv42xakxiqhunwpgz6hr32f7gxad";
        let out = redact(addr);
        assert_eq!(out, "5vzwalpq…gxad");
        assert!(out.len() < addr.len());
    }
}
