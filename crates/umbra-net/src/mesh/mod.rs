//! Off-grid mesh transport: Wi-Fi Direct client-to-client, single-hop,
//! paired-peers-only (TODO B.1). See
//! `docs/superpowers/specs/2026-09-05-mesh-transport-design.md`.
//!
//! Honest scope: [`wpactrl`] (the `wpa_supplicant` control-socket
//! protocol) and [`linklocal`] (IPv6 link-local address resolution) are
//! hermetically unit-tested — no hardware needed, both parse fixed or
//! locally-generated text. The top-level P2P Group Negotiation
//! orchestration added in a later task needs a REAL `wpa_supplicant`
//! instance and a REAL second Wi-Fi Direct peer device to exercise end
//! to end; see `crates/umbra-net/tests/mesh_live.rs` (`#[ignore]`d).
//!
//! Unlike the Tor transport, mesh mode has NO onion routing: anyone in
//! radio range can observe the P2P device address and the fact that two
//! Umbra devices are communicating (THREAT_MODEL.md, "Off-Grid Mesh").

pub mod wpactrl;
pub mod linklocal;

use std::net::Ipv6Addr;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};

use crate::error::TransportError;
pub use crate::addr::MeshPeerAddr;
pub use wpactrl::{GroupRole, WpaCtrl, WpaEvent, parse_event_line};

/// TCP port the Group Owner listens on once the P2P link is up. Fixed
/// (not negotiated): the link is point-to-point and already
/// device-authenticated at the Wi-Fi Direct layer, so a fixed port
/// leaks nothing the P2P connection itself hasn't already.
pub const MESH_PORT: u16 = 7420;

/// Bound on how long P2P Group Negotiation may take (discovery + PBC
/// handshake + group startup) before giving up.
const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(60);

/// Initiator side (`umbra send --mesh`): discovers `peer`, starts Group
/// Negotiation, and returns a connected stream once the group is up.
///
/// # Errors
///
/// Returns [`TransportError::Mesh`] on any `wpa_supplicant` command
/// failure, negotiation timeout, or connect/accept failure.
pub async fn connect(ctrl: &WpaCtrl, peer: MeshPeerAddr) -> Result<TcpStream, TransportError> {
    ctrl.attach().await?;
    expect_ok(ctrl, "P2P_FIND").await?;
    expect_ok(ctrl, &format!("P2P_CONNECT {peer} pbc")).await?;
    let (iface, role) = wait_for_group(ctrl).await?;
    let address = linklocal::link_local_address(&iface)?;
    stream_for_role(address, role).await
}

/// Responder side (`umbra serve-mesh`): becomes discoverable, answers
/// any incoming negotiation request, and returns a connected stream
/// once a group is up.
///
/// # Errors
///
/// Returns [`TransportError::Mesh`] on any `wpa_supplicant` command
/// failure, negotiation timeout, or connect/accept failure.
pub async fn listen(ctrl: &WpaCtrl) -> Result<TcpStream, TransportError> {
    ctrl.attach().await?;
    expect_ok(ctrl, "P2P_LISTEN").await?;
    // `Instant + Duration` only panics on overflow, which a 60s timeout
    // added to "now" cannot reach in practice.
    #[allow(clippy::arithmetic_side_effects)]
    let deadline = tokio::time::Instant::now() + NEGOTIATION_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(TransportError::Mesh(
                "P2P group negotiation timed out".into(),
            ));
        }
        match ctrl.next_event(remaining).await? {
            WpaEvent::GoNegRequest { peer } => {
                expect_ok(ctrl, &format!("P2P_CONNECT {peer} pbc")).await?;
            }
            WpaEvent::GroupStarted { iface, role } => {
                let address = linklocal::link_local_address(&iface)?;
                return stream_for_role(address, role).await;
            }
            WpaEvent::GroupFormationFailure => {
                return Err(TransportError::Mesh("P2P group formation failed".into()));
            }
            WpaEvent::Other(_line) => continue,
        }
    }
}

/// Sends `command`, requiring the daemon's synchronous reply to be
/// exactly `OK` (used for every fire-and-forget control command in this
/// module — `P2P_FIND`, `P2P_CONNECT`, `P2P_LISTEN`).
async fn expect_ok(ctrl: &WpaCtrl, command: &str) -> Result<(), TransportError> {
    let reply = ctrl.request(command).await?;
    if reply.trim() == "OK" {
        Ok(())
    } else {
        Err(TransportError::Mesh(format!("{command} failed: {reply}")))
    }
}

/// Polls control-interface events until `P2P-GROUP-STARTED` (success) or
/// `P2P-GROUP-FORMATION-FAILURE`/the deadline (failure). Used by
/// [`connect`]; [`listen`] has its own loop (it must ALSO answer
/// `P2P-GO-NEG-REQUEST`, which [`connect`]'s initiator side never sees).
async fn wait_for_group(ctrl: &WpaCtrl) -> Result<(String, GroupRole), TransportError> {
    // `Instant + Duration` only panics on overflow, which a 60s timeout
    // added to "now" cannot reach in practice.
    #[allow(clippy::arithmetic_side_effects)]
    let deadline = tokio::time::Instant::now() + NEGOTIATION_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(TransportError::Mesh(
                "P2P group negotiation timed out".into(),
            ));
        }
        match ctrl.next_event(remaining).await? {
            WpaEvent::GroupStarted { iface, role } => return Ok((iface, role)),
            WpaEvent::GroupFormationFailure => {
                return Err(TransportError::Mesh("P2P group formation failed".into()));
            }
            WpaEvent::GoNegRequest { .. } | WpaEvent::Other(_) => continue,
        }
    }
}

/// Once a group exists on `address`: the Group Owner listens and
/// accepts one connection, the client dials it. Shared tail of
/// [`connect`] and [`listen`] (both end the same way once they know the
/// interface and role).
async fn stream_for_role(address: Ipv6Addr, role: GroupRole) -> Result<TcpStream, TransportError> {
    match role {
        GroupRole::GroupOwner => {
            let listener = TcpListener::bind((address, MESH_PORT))
                .await
                .map_err(|e| TransportError::Mesh(format!("bind {address}: {e}")))?;
            let (stream, _peer_addr) = listener
                .accept()
                .await
                .map_err(|e| TransportError::Mesh(format!("accept: {e}")))?;
            Ok(stream)
        }
        GroupRole::Client => TcpStream::connect((address, MESH_PORT))
            .await
            .map_err(|e| TransportError::Mesh(format!("connect {address}: {e}"))),
    }
}
