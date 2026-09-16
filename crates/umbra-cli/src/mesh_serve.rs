//! Inbound Wi-Fi Direct mesh flow (`umbra serve-mesh`, TODO B.1): waits
//! for an incoming P2P connection from any paired peer and decrypts one
//! message. Mirrors `serve.rs`'s inbound Tor flow: NDJSON on stdout
//! (the only requested output of a long-running daemon; diagnostics go
//! to stderr), and the responder is not told WHICH peer initiated — the
//! same "unauthenticated initiator, SAS-verified out of band" posture
//! `serve.rs`'s module docs already state for Tor.
//!
//! Group-frame handling LANDED (TODO B.2.4, 2026-09-16): a
//! `CONNECTION_TYPE_GROUP` connection routes to `crate::group_inbound`'s
//! `handle_group_frame` — the SAME function Tor's inbound flow uses —
//! emitting the identical `group-text`/`group-joined`/`group-updated`/
//! `group-roster-synced` NDJSON events. The keystore's `groups/`/
//! `keypackages/` directories are granted to this process's Landlock
//! sandbox for exactly this purpose (`crate::sandbox::
//! restrict_filesystem_for_mesh`'s opt-in `group_dirs` parameter); the
//! keystore FILE itself is still never reachable post-sandbox.

use base64::Engine as _;

use umbra_crypto::keys::IdentityBundle;
use umbra_net::mesh::{WpaCtrl, listen};

use crate::cli::CliError;
use crate::group_inbound::{InboundEvent, group_text_line, handle_group_frame};

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

/// Emits the `group-text` NDJSON event (two fields, so it cannot go
/// through [`emit_event`]'s single-blob shape) — calls
/// `crate::group_inbound`'s `pub` `group_text_line` rather than
/// re-deriving the exact JSON shape.
fn emit_group_text_event(group_name: &str, plaintext: &[u8]) -> Result<(), CliError> {
    let line = group_text_line(group_name, plaintext);
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(line.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(CliError::Io)
}

/// Runs the inbound mesh flow: sandbox, negotiate, decrypt one message
/// (two-party or group), NDJSON event on stdout.
///
/// # Errors
///
/// Returns [`CliError`] on sandbox, negotiation, or session failure.
pub fn run(
    wpa_ctrl_path: &std::path::Path,
    keystore: &std::path::Path,
    passphrase: &[u8],
    identity: IdentityBundle,
) -> Result<(), CliError> {
    // The operator must see the transport's privacy/trust profile
    // BEFORE anything else happens (always-on safety notice, stderr —
    // see `crate::privacy`'s module docs). Mesh's anonymity level is
    // NONE — this notice is the load-bearing warning for this mode.
    crate::privacy::print_notice(
        &crate::privacy::profile(crate::privacy::TransportKind::Mesh),
        "umbra",
    );

    // TODO B.2.4: group-state directories must exist and the passphrase
    // must be captured BEFORE the sandbox installs — mirrors
    // `serve.rs::run`'s own ordering exactly (its own module docs:
    // "identity seeds are never re-read post-sandbox").
    let (groups_dir, keypackages_dir) = crate::group_inbound::prepare_group_paths(keystore)?;
    let group = crate::group_inbound::group_context_from_keystore(keystore, passphrase)?;

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
        Some((groups_dir.as_path(), keypackages_dir.as_path())),
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
        match umbra_net::messenger::peek_connection_type(&mut stream)
            .await
            .map_err(|e| CliError::Io(std::io::Error::other(format!("mesh transport: {e}"))))?
        {
            umbra_net::messenger::ConnectionType::PqxdhHandshake => {
                let plaintext = umbra_net::messenger::receive_message(identity, &mut stream)
                    .await
                    .map_err(|e| {
                        CliError::Io(std::io::Error::other(format!("mesh transport: {e}")))
                    })?;
                emit_event("text", Some(&plaintext))
            }
            umbra_net::messenger::ConnectionType::GroupFrame => {
                let event = handle_group_frame(&mut stream, &group)
                    .await
                    .map_err(|error| {
                        CliError::Io(std::io::Error::other(format!("mesh transport: {error}")))
                    })?;
                emit_group_result(event)
            }
        }
    });
    // Best-effort cleanup on every path (success or failure): a PID
    // reuse would otherwise make a later run's bind fail permanently
    // with EADDRINUSE. Never let a cleanup failure mask the real result.
    let _ = std::fs::remove_file(&cleanup_path);
    let _ = std::fs::remove_file(WpaCtrl::monitor_path(&cleanup_path));
    result
}

/// Emits the correct NDJSON event for one decoded [`InboundEvent`] —
/// the same event names Tor's `serve.rs`/`tui.rs` already emit for the
/// identical variants (TODO B.2.4: no transport-specific vocabulary).
fn emit_group_result(event: InboundEvent) -> Result<(), CliError> {
    match event {
        InboundEvent::Text(plaintext) => emit_event("text", Some(&plaintext)),
        InboundEvent::GroupText {
            group_name,
            plaintext,
        } => emit_group_text_event(&group_name, &plaintext),
        InboundEvent::GroupJoined { group_name } => {
            emit_event("group-joined", Some(group_name.as_bytes()))
        }
        InboundEvent::GroupUpdated { group_name } => {
            emit_event("group-updated", Some(group_name.as_bytes()))
        }
        InboundEvent::GroupRosterSynced { group_name } => {
            emit_event("group-roster-synced", Some(group_name.as_bytes()))
        }
    }
}
