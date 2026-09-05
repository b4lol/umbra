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
    let own_ctrl_dir = wpa_ctrl_path
        .parent()
        .map_or_else(|| std::path::PathBuf::from("."), std::path::Path::to_path_buf)
        .join("umbra-mesh-ctrl");
    std::fs::create_dir_all(&own_ctrl_dir).map_err(CliError::Io)?;
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
    runtime.block_on(async move {
        let ctrl = WpaCtrl::connect(&own_ctrl_path, wpa_ctrl_path)
            .await
            .map_err(|e| CliError::Io(std::io::Error::other(format!("mesh transport: {e}"))))?;
        let mut stream = listen(&ctrl)
            .await
            .map_err(|e| CliError::Io(std::io::Error::other(format!("mesh transport: {e}"))))?;
        let plaintext = umbra_net::messenger::receive_message(identity, &mut stream)
            .await
            .map_err(|e| CliError::Io(std::io::Error::other(format!("mesh transport: {e}"))))?;
        emit_event("text", Some(&plaintext))
    })
}
