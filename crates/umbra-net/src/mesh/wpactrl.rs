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
        && let Some(close) = rest.find('>') {
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
            (Some(iface), Some("GO")) => WpaEvent::GroupStarted {
                iface: iface.to_string(),
                role: GroupRole::GroupOwner,
            },
            (Some(iface), Some("client")) => WpaEvent::GroupStarted {
                iface: iface.to_string(),
                role: GroupRole::Client,
            },
            _ => WpaEvent::Other(body.to_string()),
        },
        Some("P2P-GO-NEG-REQUEST") => match parts.next().and_then(|s| MeshPeerAddr::parse(s).ok()) {
            Some(peer) => WpaEvent::GoNegRequest { peer },
            None => WpaEvent::Other(body.to_string()),
        },
        Some("P2P-GROUP-FORMATION-FAILURE") => WpaEvent::GroupFormationFailure,
        _ => WpaEvent::Other(body.to_string()),
    }
}

#[cfg(test)]
mod event_parsing_tests {
    use super::{GroupRole, WpaEvent, parse_event_line};
    use crate::addr::MeshPeerAddr;

    #[test]
    fn parses_group_started_as_go() {
        let event = parse_event_line(
            r#"<3>P2P-GROUP-STARTED wlan0-p2p-0 GO ssid="DIRECT-ab" freq=2437 go_dev_addr=aa:bb:cc:dd:ee:ff"#,
        );
        assert_eq!(
            event,
            WpaEvent::GroupStarted {
                iface: "wlan0-p2p-0".to_string(),
                role: GroupRole::GroupOwner,
            }
        );
    }

    #[test]
    fn parses_group_started_as_client() {
        let event = parse_event_line(
            r#"<3>P2P-GROUP-STARTED wlan0-p2p-0 client ssid="DIRECT-ab" freq=2437 go_dev_addr=aa:bb:cc:dd:ee:ff"#,
        );
        assert_eq!(
            event,
            WpaEvent::GroupStarted {
                iface: "wlan0-p2p-0".to_string(),
                role: GroupRole::Client,
            }
        );
    }

    #[test]
    fn parses_without_priority_prefix() {
        let event = parse_event_line("P2P-GROUP-STARTED wlan0-p2p-0 GO ssid=\"x\"");
        assert_eq!(
            event,
            WpaEvent::GroupStarted {
                iface: "wlan0-p2p-0".to_string(),
                role: GroupRole::GroupOwner,
            }
        );
    }

    #[test]
    fn parses_go_neg_request() {
        let event = parse_event_line("<3>P2P-GO-NEG-REQUEST aa:bb:cc:dd:ee:ff dev_passwd_id=4");
        assert_eq!(
            event,
            WpaEvent::GoNegRequest {
                peer: MeshPeerAddr::parse("aa:bb:cc:dd:ee:ff").expect("valid fixture")
            }
        );
    }

    #[test]
    fn parses_group_formation_failure() {
        let event = parse_event_line("<3>P2P-GROUP-FORMATION-FAILURE");
        assert_eq!(event, WpaEvent::GroupFormationFailure);
    }

    #[test]
    fn unrecognized_line_falls_back_to_other() {
        let event = parse_event_line("<3>CTRL-EVENT-SCAN-STARTED");
        assert_eq!(event, WpaEvent::Other("CTRL-EVENT-SCAN-STARTED".to_string()));
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
