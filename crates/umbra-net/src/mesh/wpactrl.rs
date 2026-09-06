//! `wpa_supplicant` control-interface client (TODO B.1): the classic
//! `SOCK_DGRAM` Unix-socket text protocol
//! (https://w1.fi/wpa_supplicant/devel/ctrl_iface_page.html) — chosen
//! over shelling out to `wpa_cli`/`nmcli` (blocked by Umbra's
//! Seccomp `execve` ban) or the D-Bus API (heavier, and the project's
//! only existing D-Bus integration is itself unproven; see the design
//! spec's "Approaches considered").

use crate::addr::MeshPeerAddr;

/// Group role `wpa_supplicant` negotiated for a newly formed P2P group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupRole {
    /// We are the Group Owner — listen for the peer's TCP connection.
    GroupOwner,
    /// We are the P2P client — connect to the Group Owner.
    Client,
}

/// A parsed unsolicited `wpa_supplicant` control-interface event line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WpaEvent {
    /// `P2P-GROUP-STARTED <iface> <GO|client> ...` — a usable data
    /// interface now exists.
    GroupStarted {
        /// The new network interface name (e.g. `wlan0-p2p-0`).
        iface: String,
        /// Our role in the new group.
        role: GroupRole,
        /// The Group Owner's P2P Device Address (`go_dev_addr=` field),
        /// when present — needed by the client role to derive the GO's
        /// link-local address (see `mesh::mac_to_link_local`), since
        /// Umbra's no-DHCP design means nothing else ever learns it.
        go_dev_addr: Option<MeshPeerAddr>,
    },
    /// `P2P-GO-NEG-REQUEST <addr> dev_passwd_id=<n>` — a peer is asking
    /// to negotiate a group with us (the `serve-mesh` / responder path
    /// must answer this with its own `P2P_CONNECT <addr> pbc`).
    GoNegRequest {
        /// The requesting peer's P2P Device Address.
        peer: MeshPeerAddr,
    },
    /// `P2P-GROUP-FORMATION-FAILURE ...` — negotiation did not complete.
    GroupFormationFailure,
    /// Any other event line, kept verbatim (sans priority prefix) for
    /// diagnostics; the caller simply keeps waiting.
    Other(String),
}

/// Strips a leading `<N>` `wpa_supplicant` priority marker, if present.
fn strip_priority(line: &str) -> &str {
    if let Some(rest) = line.strip_prefix('<')
        && let Some(close) = rest.find('>')
    {
        return &rest[close.saturating_add(1)..];
    }
    line
}

/// Parses one line of unsolicited `wpa_supplicant` control-interface
/// output. Unrecognized or malformed lines fall back to
/// [`WpaEvent::Other`] rather than erroring: an event we don't
/// understand is not fatal, the caller ([`crate::mesh::wait_for_group`],
/// added in a later task) just keeps waiting, bounded by its own
/// timeout.
#[must_use]
pub fn parse_event_line(line: &str) -> WpaEvent {
    let body = strip_priority(line.trim());
    let mut parts = body.split_whitespace();
    match parts.next() {
        Some("P2P-GROUP-STARTED") => match (parts.next(), parts.next()) {
            (Some(iface), Some(role_str @ ("GO" | "client"))) => {
                let role = if role_str == "GO" {
                    GroupRole::GroupOwner
                } else {
                    GroupRole::Client
                };
                let go_dev_addr = parts
                    .find_map(|field| field.strip_prefix("go_dev_addr="))
                    .and_then(|addr| MeshPeerAddr::parse(addr).ok());
                WpaEvent::GroupStarted {
                    iface: iface.to_string(),
                    role,
                    go_dev_addr,
                }
            }
            _ => WpaEvent::Other(body.to_string()),
        },
        Some("P2P-GO-NEG-REQUEST") => {
            match parts.next().and_then(|s| MeshPeerAddr::parse(s).ok()) {
                Some(peer) => WpaEvent::GoNegRequest { peer },
                None => WpaEvent::Other(body.to_string()),
            }
        }
        Some("P2P-GROUP-FORMATION-FAILURE") => WpaEvent::GroupFormationFailure,
        _ => WpaEvent::Other(body.to_string()),
    }
}

use std::path::Path;
use std::time::Duration;

use tokio::net::UnixDatagram;

use crate::error::TransportError;

/// Maximum control-socket datagram this client will read.
/// `wpa_supplicant` replies and event lines are always short ASCII
/// text; this bound stops a misbehaving daemon from forcing an
/// unbounded allocation (hostile-input-style cap, matching every other
/// wire parser in this codebase).
const MAX_CTRL_MESSAGE: usize = 4096;

/// Bound on a single request/response round trip.
const CTRL_TIMEOUT: Duration = Duration::from_secs(5);

/// A client bound to `wpa_supplicant`'s control-interface `SOCK_DGRAM`
/// Unix socket. Mirrors the well-documented `wpa_ctrl` protocol AND its
/// standard two-connection pattern: one socket issues commands and
/// reads their synchronous replies, a SEPARATE socket is `ATTACH`ed
/// purely to receive unsolicited events — sharing one socket for both
/// would let an event be mistaken for a command's reply (or vice
/// versa), since both arrive as plain datagrams with no framing to tell
/// them apart.
pub struct WpaCtrl {
    /// Issues commands (`request`) and reads their synchronous replies.
    command: UnixDatagram,
    /// `ATTACH`ed purely to receive unsolicited P2P events
    /// (`next_event`) — never used for a command/reply round trip.
    monitor: UnixDatagram,
}

impl WpaCtrl {
    /// Binds two sockets derived from `own_path` (`own_path` itself for
    /// commands, `own_path` with `-mon` appended for the event monitor
    /// — neither may already exist) and connects both to the daemon's
    /// `ctrl_interface` socket at `daemon_path`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Mesh`] if either bind or connect fails.
    pub async fn connect(own_path: &Path, daemon_path: &Path) -> Result<Self, TransportError> {
        let command = Self::bind_and_connect(own_path, daemon_path)?;
        let monitor_path = Self::monitor_path(own_path);
        let monitor = Self::bind_and_connect(&monitor_path, daemon_path)?;
        Ok(Self { command, monitor })
    }

    /// Derives the monitor socket's bind path from the command socket's
    /// path (`<own_path>-mon`) — a single, well-known place shared by
    /// [`Self::connect`] and callers that need to clean the file up
    /// afterwards.
    #[must_use]
    pub fn monitor_path(own_path: &Path) -> std::path::PathBuf {
        let mut path = own_path.as_os_str().to_owned();
        path.push("-mon");
        std::path::PathBuf::from(path)
    }

    /// Binds `own_path` (must not already exist) and connects it to
    /// `daemon_path`. Shared by both sockets [`Self::connect`] creates.
    fn bind_and_connect(
        own_path: &Path,
        daemon_path: &Path,
    ) -> Result<UnixDatagram, TransportError> {
        let socket = UnixDatagram::bind(own_path)
            .map_err(|e| TransportError::Mesh(format!("bind {}: {e}", own_path.display())))?;
        socket
            .connect(daemon_path)
            .map_err(|e| TransportError::Mesh(format!("connect {}: {e}", daemon_path.display())))?;
        Ok(socket)
    }

    /// Sends one command line on the COMMAND socket and waits for the
    /// synchronous one-datagram reply (`OK`, `FAIL`, or a
    /// command-specific value).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Mesh`] on I/O failure, timeout, or a
    /// non-UTF-8 reply.
    pub async fn request(&self, command: &str) -> Result<String, TransportError> {
        self.command
            .send(command.as_bytes())
            .await
            .map_err(|e| TransportError::Mesh(format!("send {command}: {e}")))?;
        let mut buf = vec![0u8; MAX_CTRL_MESSAGE];
        let len = tokio::time::timeout(CTRL_TIMEOUT, self.command.recv(&mut buf))
            .await
            .map_err(|_elapsed| {
                TransportError::Mesh(format!("timed out waiting for a reply to {command}"))
            })?
            .map_err(|e| TransportError::Mesh(format!("recv: {e}")))?;
        let received = buf
            .get(..len)
            .ok_or_else(|| TransportError::Mesh("recv returned an out-of-range length".into()))?;
        String::from_utf8(received.to_vec())
            .map_err(|_e| TransportError::Mesh("reply was not valid UTF-8".into()))
    }

    /// Subscribes the MONITOR socket to unsolicited events (`ATTACH`) —
    /// required once before [`Self::next_event`] sees anything. Sent on
    /// the monitor socket, not the command socket, so a later `request`
    /// call is never confused with this handshake.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Mesh`] if the daemon does not answer
    /// `OK`.
    pub async fn attach(&self) -> Result<(), TransportError> {
        self.monitor
            .send(b"ATTACH")
            .await
            .map_err(|e| TransportError::Mesh(format!("send ATTACH: {e}")))?;
        let mut buf = vec![0u8; MAX_CTRL_MESSAGE];
        let len = tokio::time::timeout(CTRL_TIMEOUT, self.monitor.recv(&mut buf))
            .await
            .map_err(|_elapsed| TransportError::Mesh("timed out waiting for ATTACH reply".into()))?
            .map_err(|e| TransportError::Mesh(format!("recv: {e}")))?;
        let received = buf
            .get(..len)
            .ok_or_else(|| TransportError::Mesh("recv returned an out-of-range length".into()))?;
        match std::str::from_utf8(received).map(str::trim) {
            Ok("OK") => Ok(()),
            Ok(other) => Err(TransportError::Mesh(format!("ATTACH failed: {other}"))),
            Err(_e) => Err(TransportError::Mesh("ATTACH reply was not valid UTF-8".into())),
        }
    }

    /// Reads the next line the daemon sends unprompted (a P2P event) on
    /// the MONITOR socket.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Mesh`] on I/O failure, timeout, or a
    /// non-UTF-8 line.
    pub async fn next_event(&self, timeout: Duration) -> Result<WpaEvent, TransportError> {
        let mut buf = vec![0u8; MAX_CTRL_MESSAGE];
        let len = tokio::time::timeout(timeout, self.monitor.recv(&mut buf))
            .await
            .map_err(|_elapsed| TransportError::Mesh("timed out waiting for a P2P event".into()))?
            .map_err(|e| TransportError::Mesh(format!("recv: {e}")))?;
        let received = buf
            .get(..len)
            .ok_or_else(|| TransportError::Mesh("recv returned an out-of-range length".into()))?;
        let line = String::from_utf8(received.to_vec())
            .map_err(|_e| TransportError::Mesh("event line was not valid UTF-8".into()))?;
        Ok(parse_event_line(&line))
    }
}

#[cfg(test)]
mod event_parsing_tests {
    use super::{GroupRole, WpaEvent, parse_event_line};
    use crate::addr::MeshPeerAddr;

    #[test]
    fn parses_group_started_as_go() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let event = parse_event_line(
            r#"<3>P2P-GROUP-STARTED wlan0-p2p-0 GO ssid="DIRECT-ab" freq=2437 go_dev_addr=aa:bb:cc:dd:ee:ff"#,
        );
        assert_eq!(
            event,
            WpaEvent::GroupStarted {
                iface: "wlan0-p2p-0".to_string(),
                role: GroupRole::GroupOwner,
                go_dev_addr: Some(MeshPeerAddr::parse("aa:bb:cc:dd:ee:ff")?),
            }
        );
        Ok(())
    }

    #[test]
    fn parses_group_started_as_client() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let event = parse_event_line(
            r#"<3>P2P-GROUP-STARTED wlan0-p2p-0 client ssid="DIRECT-ab" freq=2437 go_dev_addr=aa:bb:cc:dd:ee:ff"#,
        );
        assert_eq!(
            event,
            WpaEvent::GroupStarted {
                iface: "wlan0-p2p-0".to_string(),
                role: GroupRole::Client,
                go_dev_addr: Some(MeshPeerAddr::parse("aa:bb:cc:dd:ee:ff")?),
            }
        );
        Ok(())
    }

    /// Also the regression case for a `P2P-GROUP-STARTED` line WITHOUT a
    /// `go_dev_addr` field: it must still parse as `GroupStarted` (not
    /// fall back to `Other`), with `go_dev_addr: None`.
    #[test]
    fn parses_without_priority_prefix() {
        let event = parse_event_line("P2P-GROUP-STARTED wlan0-p2p-0 GO ssid=\"x\"");
        assert_eq!(
            event,
            WpaEvent::GroupStarted {
                iface: "wlan0-p2p-0".to_string(),
                role: GroupRole::GroupOwner,
                go_dev_addr: None,
            }
        );
    }

    #[test]
    fn parses_go_neg_request() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let event = parse_event_line("<3>P2P-GO-NEG-REQUEST aa:bb:cc:dd:ee:ff dev_passwd_id=4");
        assert_eq!(
            event,
            WpaEvent::GoNegRequest {
                peer: MeshPeerAddr::parse("aa:bb:cc:dd:ee:ff")?
            }
        );
        Ok(())
    }

    #[test]
    fn parses_group_formation_failure() {
        let event = parse_event_line("<3>P2P-GROUP-FORMATION-FAILURE");
        assert_eq!(event, WpaEvent::GroupFormationFailure);
    }

    #[test]
    fn unrecognized_line_falls_back_to_other() {
        let event = parse_event_line("<3>CTRL-EVENT-SCAN-STARTED");
        assert_eq!(
            event,
            WpaEvent::Other("CTRL-EVENT-SCAN-STARTED".to_string())
        );
    }

    #[test]
    fn malformed_go_neg_request_falls_back_to_other() {
        let event = parse_event_line("<3>P2P-GO-NEG-REQUEST not-a-mac dev_passwd_id=4");
        assert_eq!(
            event,
            WpaEvent::Other("P2P-GO-NEG-REQUEST not-a-mac dev_passwd_id=4".to_string())
        );
    }

    #[test]
    fn empty_line_falls_back_to_other() {
        assert_eq!(parse_event_line(""), WpaEvent::Other(String::new()));
    }
}

#[cfg(test)]
mod wpa_ctrl_tests {
    use std::time::Duration;

    use tokio::net::UnixDatagram;

    use super::{GroupRole, WpaCtrl, WpaEvent};
    use crate::addr::MeshPeerAddr;

    /// Unique temp-file pair per test run (parallel `cargo test` runs
    /// must not collide on socket paths).
    fn socket_paths(label: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "umbra-wpactrl-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        (base.with_extension("client"), base.with_extension("daemon"))
    }

    /// Shorthand for the boxed error type every test in this module
    /// returns (the workspace denies `clippy::expect_used`, so tests
    /// propagate failures with `?` instead of panicking).
    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Joins a fake-daemon responder's `JoinHandle`, propagating either
    /// a task panic or the responder's own `Err` as a single `TestResult`.
    async fn join_responder(responder: tokio::task::JoinHandle<TestResult>) -> TestResult {
        responder.await??;
        Ok(())
    }

    #[tokio::test]
    async fn request_round_trips_through_a_fake_daemon() -> TestResult {
        let (client_path, daemon_path) = socket_paths("request");
        let daemon = UnixDatagram::bind(&daemon_path)?;
        let ctrl = WpaCtrl::connect(&client_path, &daemon_path).await?;

        let responder: tokio::task::JoinHandle<TestResult> = tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let (len, from) = daemon.recv_from(&mut buf).await?;
            let received = buf.get(..len).ok_or("recv buffer slice out of bounds")?;
            assert_eq!(received, b"PING");
            let from = from.as_pathname().ok_or("expected a named socket")?;
            daemon.send_to(b"PONG", from).await?;
            Ok(())
        });

        let reply = ctrl.request("PING").await?;
        assert_eq!(reply, "PONG");
        join_responder(responder).await?;

        let _ = std::fs::remove_file(&client_path);
        let _ = std::fs::remove_file(&daemon_path);
        Ok(())
    }

    #[tokio::test]
    async fn attach_succeeds_when_daemon_answers_ok() -> TestResult {
        let (client_path, daemon_path) = socket_paths("attach");
        let daemon = UnixDatagram::bind(&daemon_path)?;
        let ctrl = WpaCtrl::connect(&client_path, &daemon_path).await?;

        let responder: tokio::task::JoinHandle<TestResult> = tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let (len, from) = daemon.recv_from(&mut buf).await?;
            let received = buf.get(..len).ok_or("recv buffer slice out of bounds")?;
            assert_eq!(received, b"ATTACH");
            let from = from.as_pathname().ok_or("expected a named socket")?;
            daemon.send_to(b"OK", from).await?;
            Ok(())
        });

        ctrl.attach().await?;
        join_responder(responder).await?;

        let _ = std::fs::remove_file(&client_path);
        let _ = std::fs::remove_file(&daemon_path);
        Ok(())
    }

    #[tokio::test]
    async fn next_event_parses_an_unsolicited_line() -> TestResult {
        let (client_path, daemon_path) = socket_paths("event");
        let daemon = UnixDatagram::bind(&daemon_path)?;
        let ctrl = WpaCtrl::connect(&client_path, &daemon_path).await?;

        // The daemon needs the client's bound address to push an
        // unsolicited datagram; it learns that address from the ATTACH
        // request, exactly like real wpa_supplicant does. The daemon's
        // recv+reply runs concurrently with the client's `attach()`
        // call (mirroring the responder pattern used by the other
        // tests in this module): it acks ATTACH with "OK" first (so
        // `attach()`'s own recv consumes exactly that reply), then
        // separately pushes the event line as a second datagram, which
        // is what `next_event` below reads.
        let responder: tokio::task::JoinHandle<TestResult> = tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let (_len, from) = daemon.recv_from(&mut buf).await?;
            let from = from.as_pathname().ok_or("expected a named socket")?;
            daemon.send_to(b"OK", from).await?;
            daemon
                .send_to(
                    b"<3>P2P-GROUP-STARTED wlan0-p2p-0 client ssid=\"x\" go_dev_addr=aa:bb:cc:dd:ee:ff",
                    from,
                )
                .await?;
            Ok(())
        });

        ctrl.attach().await?;
        join_responder(responder).await?;

        let event = ctrl.next_event(Duration::from_secs(2)).await?;
        assert_eq!(
            event,
            WpaEvent::GroupStarted {
                iface: "wlan0-p2p-0".to_string(),
                role: GroupRole::Client,
                go_dev_addr: Some(MeshPeerAddr::parse("aa:bb:cc:dd:ee:ff")?),
            }
        );

        let _ = std::fs::remove_file(&client_path);
        let _ = std::fs::remove_file(&daemon_path);
        Ok(())
    }

    #[tokio::test]
    async fn request_times_out_when_daemon_never_answers() -> TestResult {
        let (client_path, daemon_path) = socket_paths("timeout");
        let _daemon = UnixDatagram::bind(&daemon_path)?;
        let ctrl = WpaCtrl::connect(&client_path, &daemon_path).await?;

        // CTRL_TIMEOUT is 5s in production; the test does not wait that
        // long for a pass/fail signal on a broken implementation, so
        // this asserts on the ERROR VARIANT via a bounded outer timeout
        // instead of waiting for the real 5s internal bound.
        let outcome = tokio::time::timeout(Duration::from_secs(7), ctrl.request("PING")).await;
        assert!(matches!(outcome, Ok(Err(_))), "must fail closed, not hang");

        let _ = std::fs::remove_file(&client_path);
        let _ = std::fs::remove_file(&daemon_path);
        Ok(())
    }
}
