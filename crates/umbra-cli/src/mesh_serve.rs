//! Inbound Wi-Fi Direct mesh flow (`umbra serve-mesh`, TODO B.1): waits
//! for an incoming P2P connection from any paired peer and decrypts one
//! message. Mirrors `serve.rs`'s inbound Tor flow: NDJSON on stdout
//! (the only requested output of a long-running daemon; diagnostics go
//! to stderr), and the responder is not told WHICH peer initiated — the
//! same "unauthenticated initiator, SAS-verified out of band" posture
//! `serve.rs`'s module docs already state for Tor.

use base64::Engine as _;

use umbra_crypto::keys::IdentityBundle;
use umbra_net::mesh::{WpaCtrl, listen};

use crate::cli::CliError;

/// Emits one NDJSON event line — copied from `serve.rs`'s private
/// `emit_event` (base64url, no padding, matching its `data` field
/// encoding exactly) rather than shared, since `serve.rs`'s version is
/// a private `fn`, not part of any public API.
fn emit_event(event: &str, data: Option<&[u8]>) -> Result<(), CliError> {
    let mut line = format!("{{\"event\":\"{event}\"");
    if let Some(bytes) = data {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        line.push_str(&format!(",\"data\":\"{b64}\""));
    }
    line.push_str("}\n");
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(line.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(CliError::Io)
}

/// Runs the inbound mesh flow: sandbox, negotiate, decrypt one message,
/// NDJSON `text` event on stdout.
///
/// # Errors
///
/// Returns [`CliError`] on sandbox, negotiation, or session failure.
pub fn run(wpa_ctrl_path: &std::path::Path, identity: IdentityBundle) -> Result<(), CliError> {
    // The operator must see the transport's privacy/trust profile
    // BEFORE anything else happens (always-on safety notice, stderr —
    // see `crate::privacy`'s module docs). Mesh's anonymity level is
    // NONE — this notice is the load-bearing warning for this mode.
    crate::privacy::print_notice(
        &crate::privacy::profile(crate::privacy::TransportKind::Mesh),
        "umbra",
    );

    let own_ctrl_dir = wpa_ctrl_path
        .parent()
        .map_or_else(
            || std::path::PathBuf::from("."),
            std::path::Path::to_path_buf,
        )
        .join("umbra-mesh-ctrl");
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&own_ctrl_dir)
            .map_err(CliError::Io)?;
    }
    let own_ctrl_path = own_ctrl_dir.join(format!("server-{}", std::process::id()));

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
    // Cloned so the cleanup below can still reach it after the `async
    // move` block below takes ownership of its own copy.
    let cleanup_path = own_ctrl_path.clone();
    let result = runtime.block_on(async move {
        let ctrl = WpaCtrl::connect(&own_ctrl_path, wpa_ctrl_path)
            .await
            .map_err(|e| CliError::Io(std::io::Error::other(format!("mesh transport: {e}"))))?;
        let mut stream = listen(&ctrl)
            .await
            .map_err(|e| CliError::Io(std::io::Error::other(format!("mesh transport: {e}"))))?;
        // Leading connection-type marker (TODO B.2 groundwork): no group
        // path exists yet, so anything other than a PQXDH handshake is
        // treated as a session failure.
        match umbra_net::messenger::peek_connection_type(&mut stream)
            .await
            .map_err(|e| CliError::Io(std::io::Error::other(format!("mesh transport: {e}"))))?
        {
            umbra_net::messenger::ConnectionType::PqxdhHandshake => {}
            umbra_net::messenger::ConnectionType::GroupFrame => {
                return Err(CliError::Io(std::io::Error::other(
                    "mesh transport: group frames are not yet handled",
                )));
            }
        }
        let plaintext = umbra_net::messenger::receive_message(identity, &mut stream)
            .await
            .map_err(|e| CliError::Io(std::io::Error::other(format!("mesh transport: {e}"))))?;
        emit_event("text", Some(&plaintext))
    });
    // Best-effort cleanup on every path (success or failure): a PID
    // reuse would otherwise make a later run's bind fail permanently
    // with EADDRINUSE. Never let a cleanup failure mask the real result.
    let _ = std::fs::remove_file(&cleanup_path);
    let _ = std::fs::remove_file(WpaCtrl::monitor_path(&cleanup_path));
    result
}
