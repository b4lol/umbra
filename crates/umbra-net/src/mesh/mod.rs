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

pub mod linklocal;
pub mod wpactrl;

use std::net::Ipv6Addr;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};

pub use crate::addr::MeshPeerAddr;
use crate::error::TransportError;
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
    let (iface, role, go_dev_addr) = wait_for_group(ctrl).await?;
    stream_for_role(&iface, role, go_dev_addr).await
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
            WpaEvent::GroupStarted {
                iface,
                role,
                go_dev_addr,
            } => {
                return stream_for_role(&iface, role, go_dev_addr).await;
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
async fn wait_for_group(
    ctrl: &WpaCtrl,
) -> Result<(String, GroupRole, Option<MeshPeerAddr>), TransportError> {
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
            WpaEvent::GroupStarted {
                iface,
                role,
                go_dev_addr,
            } => return Ok((iface, role, go_dev_addr)),
            WpaEvent::GroupFormationFailure => {
                return Err(TransportError::Mesh("P2P group formation failed".into()));
            }
            WpaEvent::GoNegRequest { .. } | WpaEvent::Other(_) => continue,
        }
    }
}

/// Reads the kernel-assigned interface index for `iface` from sysfs —
/// needed as the IPv6 scope id: a bare link-local address is ambiguous
/// whenever more than one interface has one (the normal case here: the
/// P2P group interface coexists with the base station interface).
fn interface_index(iface: &str) -> Result<u32, TransportError> {
    let path = format!("/sys/class/net/{iface}/ifindex");
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| TransportError::Mesh(format!("read {path}: {e}")))?;
    contents
        .trim()
        .parse::<u32>()
        .map_err(|e| TransportError::Mesh(format!("malformed ifindex for {iface}: {e}")))
}

/// Derives the IPv6 link-local address a network interface with MAC
/// `mac` would self-assign via SLAAC (the standard "modified EUI-64"
/// transformation, RFC 4291 Appendix A): split the MAC's two 24-bit
/// halves, insert `ff:fe` between them, and flip the universal/local
/// bit of the first byte.
///
/// Used as a best-effort way to reach a Wi-Fi Direct Group Owner:
/// Umbra's no-DHCP design (see `linklocal`'s module docs) means the
/// client never learns the GO's actual assigned address any other way.
/// `wpa_supplicant`'s `P2P-GROUP-STARTED` event reports the GO's P2P
/// Device Address (`go_dev_addr`), which commonly — not guaranteed —
/// IS the group interface's own MAC. HONEST RESIDUAL: if a real
/// deployment assigns the group interface a different MAC than its P2P
/// Device Address, this prediction is wrong and the connect will fail;
/// this can only be confirmed against real hardware (see
/// `crates/umbra-net/tests/mesh_live.rs`), the same residual class as
/// the rest of this transport.
#[must_use]
pub fn mac_to_link_local(mac: [u8; 6]) -> Ipv6Addr {
    let eui64 = [
        mac[0] ^ 0x02,
        mac[1],
        mac[2],
        0xff,
        0xfe,
        mac[3],
        mac[4],
        mac[5],
    ];
    Ipv6Addr::new(
        0xfe80,
        0,
        0,
        0,
        u16::from_be_bytes([eui64[0], eui64[1]]),
        u16::from_be_bytes([eui64[2], eui64[3]]),
        u16::from_be_bytes([eui64[4], eui64[5]]),
        u16::from_be_bytes([eui64[6], eui64[7]]),
    )
}

/// Once a group exists on `iface`: the Group Owner listens on its OWN
/// link-local address and accepts one connection; the client dials the
/// Group Owner's address, derived from `go_dev_addr` since nothing else
/// in this no-DHCP design ever learns it (see [`mac_to_link_local`]).
/// Shared tail of [`connect`] and [`listen`] (both end the same way
/// once they know the interface, role, and the GO's device address).
async fn stream_for_role(
    iface: &str,
    role: GroupRole,
    go_dev_addr: Option<MeshPeerAddr>,
) -> Result<TcpStream, TransportError> {
    let scope_id = interface_index(iface)?;
    match role {
        GroupRole::GroupOwner => {
            let address = linklocal::link_local_address(iface)?;
            let socket_addr = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                address, MESH_PORT, 0, scope_id,
            ));
            let listener = TcpListener::bind(socket_addr)
                .await
                .map_err(|e| TransportError::Mesh(format!("bind {socket_addr}: {e}")))?;
            let (stream, _peer_addr) = listener
                .accept()
                .await
                .map_err(|e| TransportError::Mesh(format!("accept: {e}")))?;
            Ok(stream)
        }
        GroupRole::Client => {
            let peer = go_dev_addr.ok_or_else(|| {
                TransportError::Mesh(
                    "client role needs the Group Owner's device address to derive its link-local address"
                        .into(),
                )
            })?;
            let address = mac_to_link_local(peer.octets());
            let socket_addr = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                address, MESH_PORT, 0, scope_id,
            ));
            TcpStream::connect(socket_addr)
                .await
                .map_err(|e| TransportError::Mesh(format!("connect {socket_addr}: {e}")))
        }
    }
}

#[cfg(test)]
mod mac_to_link_local_tests {
    use super::mac_to_link_local;
    use std::net::Ipv6Addr;

    /// Textbook modified-EUI-64 example: MAC `00:0c:29:11:22:33` self-
    /// assigns link-local `fe80::20c:29ff:fe11:2233` (RFC 4291
    /// Appendix A — insert `fffe` between the two 24-bit halves, flip
    /// the universal/local bit of the first byte: `0x00 ^ 0x02 = 0x02`).
    #[test]
    fn matches_the_textbook_example() {
        let addr = mac_to_link_local([0x00, 0x0c, 0x29, 0x11, 0x22, 0x33]);
        assert_eq!(
            addr,
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0x020c, 0x29ff, 0xfe11, 0x2233)
        );
    }

    /// A MAC whose first byte already has the universal/local bit set
    /// gets it CLEARED (the transformation is its own inverse on that
    /// bit), not set again.
    #[test]
    fn flips_an_already_local_bit_off() {
        let addr = mac_to_link_local([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(
            addr,
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0000, 0x00ff, 0xfe00, 0x0001)
        );
    }
}
