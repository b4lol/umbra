//! LIVE Wi-Fi Direct mesh test (`#[ignore]` by default).
//!
//! Verifies TODO B.1's mesh transport against a REAL `wpa_supplicant`
//! and a REAL second Wi-Fi Direct peer device — neither exists in CI or
//! this development environment. See
//! `docs/superpowers/specs/2026-09-05-mesh-transport-design.md` for the
//! honest-scope rationale: `umbra_net::mesh::wpactrl` and
//! `umbra_net::mesh::linklocal` are hermetically unit-tested (protocol
//! parsing needs no hardware, see `crates/umbra-net/src/mesh/`); THIS
//! test is the only thing that exercises the actual OS/radio
//! integration, and it needs:
//!
//! - a running `wpa_supplicant` with a P2P-capable interface, its
//!   `ctrl_interface` socket path in `WPA_CTRL_PATH`;
//! - a second device listening for this one's `P2P_FIND`/`P2P_CONNECT`
//!   and running a PLAIN TCP ECHO LISTENER on the mesh port
//!   (`umbra_net::mesh::MESH_PORT`) on its group interface once the P2P
//!   group forms — e.g. `socat TCP6-LISTEN:7420,fork EXEC:cat` (the
//!   mesh transport dials an IPv6 link-local address; plain
//!   `TCP-LISTEN` defaults to IPv4 and would never accept it). This
//!   test exercises the mesh transport/negotiation layer in isolation;
//!   it deliberately does NOT run `umbra serve-mesh`, which performs a
//!   real PQXDH handshake (already exhaustively tested elsewhere, see
//!   `crates/umbra-net/tests/messenger.rs`) rather than echoing raw
//!   bytes;
//! - that peer's P2P Device Address in `MESH_PEER_ADDR`.
//!
//! ```sh
//! WPA_CTRL_PATH=/run/wpa_supplicant/p2p-dev-wlan0 \
//! MESH_PEER_ADDR=aa:bb:cc:dd:ee:ff \
//! cargo test -p umbra-net --features mesh --test mesh_live \
//!     -- --ignored --nocapture
//! ```
//!
//! NOT YET RUN against real hardware — no Wi-Fi Direct radio or second
//! device was available in any environment this feature was developed
//! in. This is the honestly-documented residual (mirrors `pt-proxy`'s
//! "live interop against a real censorship-path bridge" item in
//! `pt-proxy/README.md`).
//!
//! Known gap to watch for on a live run: `connect()` does not yet wait
//! for a `P2P-DEVICE-FOUND` event before issuing `P2P_CONNECT`, so a
//! real `wpa_supplicant` may reject the connect as an unknown peer —
//! see the mesh transport design/implementation history for this open item.

#![cfg(feature = "mesh")]

use umbra_net::mesh::{MeshPeerAddr, WpaCtrl, connect};

#[tokio::test]
#[ignore = "needs a real wpa_supplicant instance and a real second Wi-Fi Direct device"]
async fn connects_to_a_real_peer_and_echoes() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let ctrl_path = std::path::PathBuf::from(std::env::var("WPA_CTRL_PATH")?);
    let peer_addr_str = std::env::var("MESH_PEER_ADDR")?;
    let peer = MeshPeerAddr::parse(&peer_addr_str)?;

    let own_path = std::env::temp_dir().join(format!("umbra-mesh-ctrl-{}", std::process::id()));
    let ctrl = WpaCtrl::connect(&own_path, &ctrl_path).await?;

    let mut stream = connect(&ctrl, peer).await?;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let probe = b"umbra mesh live test\n";
    stream.write_all(probe).await?;
    let mut echoed = vec![0u8; probe.len()];
    stream.read_exact(&mut echoed).await?;
    assert_eq!(
        &echoed, probe,
        "peer must echo the probe back byte-for-byte"
    );

    let _ = std::fs::remove_file(&own_path);
    let _ = std::fs::remove_file(WpaCtrl::monitor_path(&own_path));
    Ok(())
}
