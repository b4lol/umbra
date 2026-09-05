//! Outbound Wi-Fi Direct mesh flow (`umbra send --mesh`, TODO B.1):
//! delivers stdin to a peer over a locally-negotiated P2P link. Mirrors
//! `tor_send.rs`'s structure; the only difference is HOW the byte
//! stream is obtained (P2P Group Negotiation vs. an onion-service
//! connect) — `umbra_net::messenger` is used identically either way.
//!
//! Honest scope: like the Tor path, the initiator is per-session
//! ephemeral (`Session::new` inside the messenger driver) — the
//! keystore identity is NOT read here. Unlike Tor, there is no onion
//! routing: anyone in radio range can observe the P2P device address
//! and the fact that two Umbra devices are communicating
//! (THREAT_MODEL.md, "Off-Grid Mesh").

use std::io::Read;
use std::path::Path;

use umbra_net::mesh::{MeshPeerAddr, WpaCtrl, connect};

use crate::cli::CliError;
use crate::pairing::PeerIdentity;

/// Upper bound for stdin under `mlockall`, matching the Tor-send
/// ceiling (`tor_send::MAX_TOR_MESSAGE`) — the mesh link's throughput
/// characteristics are not yet measured, so the same conservative bound
/// applies.
pub const MAX_MESH_MESSAGE: usize = 64 * 1024;

/// Emits one NDJSON event line (stdout is the requested data channel).
fn emit_event(event: &str, fields: &[(&str, String)]) -> Result<(), CliError> {
    let mut line = format!("{{\"event\":\"{event}\"");
    for (key, value) in fields {
        line.push_str(&format!(",\"{key}\":{value}"));
    }
    line.push_str("}\n");
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(line.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(CliError::Io)
}

/// Runs the outbound mesh flow; see the module docs.
///
/// # Errors
///
/// Returns [`CliError`] on oversized stdin, sandbox, negotiation, or
/// session failure.
pub fn run(
    wpa_ctrl_path: &Path,
    mesh_addr: &str,
    peer: &PeerIdentity,
    input: &mut impl Read,
) -> Result<(), CliError> {
    // Memory hardening FIRST: the bounded stdin read below lands in
    // locked, non-dumpable RAM (mlockall/MCL_FUTURE) — mirrors
    // tor_send::run.
    umbra_hardware::process::harden_process()?;

    let peer_addr = MeshPeerAddr::parse(mesh_addr)
        .map_err(|_e| CliError::Io(std::io::Error::other("invalid mesh address")))?;

    let mut plaintext =
        zeroize::Zeroizing::new(Vec::with_capacity(MAX_MESH_MESSAGE.saturating_add(1)));
    input
        .take((MAX_MESH_MESSAGE as u64).saturating_add(1))
        .read_to_end(&mut plaintext)
        .map_err(CliError::Io)?;
    if plaintext.len() > MAX_MESH_MESSAGE {
        return Err(CliError::Io(std::io::Error::other(format!(
            "stdin exceeds the {MAX_MESH_MESSAGE}-byte mesh-send ceiling"
        ))));
    }
    if plaintext.is_empty() {
        return Err(CliError::Io(std::io::Error::other(
            "empty stdin: nothing to send",
        )));
    }

    // Our own control-socket bind path: a fresh, process-unique file
    // under a dedicated directory the sandbox exception (Task 10)
    // grants MakeSock on.
    let own_ctrl_dir = wpa_ctrl_path
        .parent()
        .map_or_else(|| std::path::PathBuf::from("."), std::path::Path::to_path_buf)
        .join("umbra-mesh-ctrl");
    std::fs::create_dir_all(&own_ctrl_dir).map_err(CliError::Io)?;
    let own_ctrl_path = own_ctrl_dir.join(format!("client-{}", std::process::id()));

    crate::sandbox::restrict_filesystem_for_mesh(
        std::path::Path::new(
            wpa_ctrl_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("/")),
        ),
        &own_ctrl_dir,
    )?;
    crate::sandbox::restrict_syscalls_mesh()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::Io(std::io::Error::other(format!("tokio runtime: {e}"))))?;
    runtime.block_on(async move {
        let ctrl = WpaCtrl::connect(&own_ctrl_path, wpa_ctrl_path)
            .await
            .map_err(|e| CliError::Io(std::io::Error::other(format!("mesh transport: {e}"))))?;
        let mut stream = connect(&ctrl, peer_addr)
            .await
            .map_err(|e| CliError::Io(std::io::Error::other(format!("mesh transport: {e}"))))?;
        let peer_keys = umbra_net::messenger::PeerPqxdhKeys::from_parts(
            &peer.ik_arr,
            &peer.spk_arr,
            peer.spk_signature.clone(),
            peer.dsa.clone(),
            &peer.kem_arr,
        )
        .map_err(|e| CliError::Io(std::io::Error::other(format!("mesh transport: {e}"))))?;
        let bytes = plaintext.len();
        let frames = umbra_net::messenger::send_text_stream(&mut stream, &peer_keys, &plaintext)
            .await
            .map_err(|e| CliError::Io(std::io::Error::other(format!("mesh transport: {e}"))))?;
        emit_event(
            "sent",
            &[("bytes", bytes.to_string()), ("frames", frames.to_string())],
        )
    })
}
