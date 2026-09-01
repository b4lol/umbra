//! Outbound Tor onion-service flow (`umbra send --onion`, TODO A.2):
//! delivers stdin to a peer's `umbra serve` over embedded Arti —
//!
//! 1. the peer record supplies the PQXDH key set; the `.onion` address
//!    comes from `--onion` or the record;
//! 2. `harden_memory()` runs first; the Tor storage root (shared with
//!    `serve` for guard-state reuse) is created `0700` before the
//!    Landlock ruleset pins it; Seccomp applies last;
//! 3. `bootstrap_persistent` roots Arti state in that tree (the stored
//!    onion IDENTITY key is unused here — the initiator is per-session
//!    ephemeral by design, `Session::new`);
//! 4. one PQXDH session: handshake → stdin split into max-size ratchet
//!    messages → authenticated termination (messenger
//!    `send_text_stream`); NDJSON `sent` event on stdout.
//!
//! Honest scope: stdin is bounded (mlockall'd RAM — an unbounded read
//! would be a lock-exhaustion DoS against ourselves); no cover traffic
//! on this path; the responder is unauthenticated until SAS is verified
//! out of band. The `sent` event means "accepted by Arti's stream", NOT
//! delivered-and-acknowledged (no end-to-end ACK exists); retrying a
//! failed send therefore DUPLICATES the message at the responder — the
//! documented v1.0 trade-off. Arti's client state (guard descriptors,
//! consensus cache) persists under the shared Tor tree: a small,
//! documented disk footprint (THREAT_MODEL "RAM-only" applies to
//! messages, not transport state).

use std::io::Read;
use std::path::Path;

use umbra_net::tor::TorTransport;

use crate::cli::CliError;
use crate::pairing::PeerIdentity;

/// Upper bound for stdin under `mlockall` (the whole message is held in
/// locked RAM; 64 KiB is the documented v1.0 Tor-send ceiling).
pub const MAX_TOR_MESSAGE: usize = 64 * 1024;

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

/// Runs the outbound Tor flow; see the module docs. The keystore file is
/// NOT reopened (the sandbox would deny it) and the keystore identity is
/// NOT used — the outbound initiator is per-session ephemeral
/// (`Session::new` inside the messenger driver), which is the documented
/// deniability posture.
///
/// # Errors
///
/// Returns [`CliError`] on oversized stdin, sandbox, bootstrap, address,
/// or session failure.
pub fn run(
    keystore: &Path,
    peer: &PeerIdentity,
    onion_address: &str,
    input: &mut impl Read,
) -> Result<(), CliError> {
    // Memory hardening FIRST: the bounded stdin read below lands in
    // locked, non-dumpable RAM (mlockall/MCL_FUTURE).
    umbra_hardware::process::harden_process()?;

    // Bounded stdin: mlockall makes every byte locked RAM. The capacity
    // is reserved UP FRONT so read_to_end never reallocates — a grown
    // Vec would leave un-wiped plaintext copies in freed heap.
    let mut plaintext =
        zeroize::Zeroizing::new(Vec::with_capacity(MAX_TOR_MESSAGE.saturating_add(1)));
    input
        .take((MAX_TOR_MESSAGE as u64).saturating_add(1))
        .read_to_end(&mut plaintext)
        .map_err(CliError::Io)?;
    if plaintext.len() > MAX_TOR_MESSAGE {
        return Err(CliError::Io(std::io::Error::other(format!(
            "stdin exceeds the {MAX_TOR_MESSAGE}-byte Tor-send ceiling"
        ))));
    }
    if plaintext.is_empty() {
        // Zero data frames would be reported as success by the sender
        // while the responder fails — reject up front instead.
        return Err(CliError::Io(std::io::Error::other(
            "empty stdin: nothing to send",
        )));
    }

    // Tor storage root (exists BEFORE the Landlock ruleset opens it at
    // rule-add time).
    let tor_base = crate::serve::tor_base_from_keystore(keystore)?;
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&tor_base)
            .map_err(CliError::Io)?;
    }
    crate::sandbox::restrict_filesystem_with_exceptions(
        &[tor_base.as_path()],
        &[std::path::Path::new("/etc")],
    )?;
    crate::sandbox::restrict_syscalls()?;

    crate::peers::validate_onion(onion_address)?;
    let address = umbra_net::addr::OnionAddr::parse(onion_address)
        .map_err(|_e| CliError::Io(std::io::Error::other("invalid onion address")))?;
    let peer_keys = umbra_net::messenger::PeerPqxdhKeys::from_parts(
        &peer.ik_arr,
        &peer.spk_arr,
        peer.spk_signature.clone(),
        peer.dsa.clone(),
        &peer.kem_arr,
    )
    .map_err(|error| CliError::Io(std::io::Error::other(format!("peer keys: {error}"))))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::Io(std::io::Error::other(format!("tokio runtime: {e}"))))?;
    runtime.block_on(async move {
        let transport_error = |error: umbra_net::TransportError| {
            CliError::Io(std::io::Error::other(format!("tor transport: {error}")))
        };
        let transport = TorTransport::bootstrap_persistent(&tor_base)
            .await
            .map_err(transport_error)?;
        // Bounded connect: a dead or hostile service must not hang the
        // send indefinitely (mirrors the bootstrap/read bounds).
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            transport.open_stream(&address),
        )
        .await
        .map_err(|_elapsed| {
            CliError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "onion connect timed out",
            ))
        })?
        .map_err(transport_error)?;
        let bytes = plaintext.len();
        let frames = umbra_net::messenger::send_text_stream(&mut stream, &peer_keys, &plaintext)
            .await
            .map_err(transport_error)?;
        emit_event(
            "sent",
            &[("bytes", bytes.to_string()), ("frames", frames.to_string())],
        )
    })
}
