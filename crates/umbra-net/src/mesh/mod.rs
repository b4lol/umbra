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
