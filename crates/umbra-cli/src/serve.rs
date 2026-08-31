//! Inbound Tor onion-service flow (`umbra serve`, TODO A.2): the
//! PRODUCTION call site that wires the persistent-identity mechanisms
//! together —
//!
//! 1. identity seeds load ONCE (pre-sandbox), bundle rebuilt per
//!    connection via `IdentityBundle::from_seeds` (no Argon2 per peer);
//! 2. `harden_memory()` before any secret touches RAM (ADR-025);
//! 3. Landlock zero-FS with exactly two sanctioned exceptions — the Tor
//!    storage dir (Arti's guard state + native keystore keeping the
//!    `.onion` identity stable) and read-only `/etc` (the libc resolver
//!    may open `resolv.conf`-family files during bootstrap; all public
//!    content) — plus the full Seccomp allowlist;
//! 4. `TorTransport::bootstrap_persistent` + `spawn_inbound` (Vanguards-
//!    Lite pinning + hs-pow inbound hardening apply automatically);
//! 5. one session per accepted stream: `receive_message` (PQXDH + Double
//!    Ratchet), text payloads emitted as NDJSON on stdout.
//!
//! Honest scope: no outbound Tor flow yet (`send` stays on the pipe
//! transport); no cover traffic on this path (GPA resistance TODO); SMP
//! is not run on inbound streams (SAS verification is out of band).

use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use umbra_crypto::keys::{IdentityBundle, IdentitySeeds};
use umbra_net::tor::TorTransport;

use crate::cli::CliError;

/// Upper bound for waiting until the onion descriptor is published.
const ADDRESS_WAIT: Duration = Duration::from_secs(120);

/// Resolves the Tor storage root NEXT TO the keystore: `<keystore
/// parent>/tor`. Peer records and the Tor tree share the keystore
/// directory so a single Landlock exception covers the flow's own data.
///
/// # Errors
///
/// Returns [`CliError::Keystore`] if the keystore path has no parent.
pub fn tor_base_from_keystore(keystore: &std::path::Path) -> Result<PathBuf, CliError> {
    let parent = keystore
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| CliError::Keystore("keystore path has no parent directory".into()))?;
    Ok(parent.join("tor"))
}

/// Emits one NDJSON event line for the `serve` stream (the only requested
/// output of a long-running daemon; diagnostics go to stderr).
fn emit_event(event: &str, data: Option<&[u8]>) -> Result<(), CliError> {
    let mut line = format!("{{\"event\":\"{event}\"");
    if let Some(bytes) = data {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        line.push_str(&format!(",\"data\":\"{b64}\""));
    }
    line.push_str("}\n");
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(line.as_bytes());
    let _ = stdout.flush();
    Ok(())
}

/// Runs the `serve` flow. Never returns under normal operation: it loops
/// accepting inbound sessions until the process is terminated.
///
/// # Errors
///
/// Returns [`CliError`] on keystore, sandbox, bootstrap, or onion
/// publication failure. Per-connection failures are logged to stderr and
/// the accept loop continues.
pub fn run(keystore: &std::path::Path, passphrase: &[u8], nickname: &str) -> Result<(), CliError> {
    // 1. Memory hardening BEFORE secrets exist (ADR-025 ordering).
    umbra_hardware::process::harden_process()?;

    // 2. Identity seeds load ONCE; the keystore file is never opened
    //    again (it would be denied by the sandbox below).
    let seeds: IdentitySeeds = crate::keystore::load_seeds(keystore, passphrase)?;

    // 3. Tor storage root must EXIST before the Landlock ruleset pins
    //    the exception (PathFd opens the path at rule-add time).
    let tor_base = tor_base_from_keystore(keystore)?;
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&tor_base)
            .map_err(CliError::Io)?;
    }

    // 4. Sandbox: zero-FS + [tor tree, /etc read] exceptions, then the
    //    Seccomp allowlist (LAST; network family included for Arti).
    crate::sandbox::restrict_filesystem_with_exceptions(&[
        tor_base.as_path(),
        std::path::Path::new("/etc"),
    ])?;
    crate::sandbox::restrict_syscalls()?;

    // 5. Runtime + transport. `bootstrap_persistent` roots the Arti
    //    state/cache/keystore under `tor_base` — the `.onion` identity
    //    persists across runs for this nickname.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::Io(std::io::Error::other(format!("tokio runtime: {e}"))))?;
    runtime.block_on(async move {
        let transport_error = |error: umbra_net::TransportError| {
            CliError::Io(std::io::Error::other(format!("tor transport: {error}")))
        };
        let mut transport = TorTransport::bootstrap_persistent(&tor_base)
            .await
            .map_err(transport_error)?;
        transport
            .spawn_inbound(nickname)
            .await
            .map_err(transport_error)?;

        // Wait for descriptor publication, then announce the address.
        let started = tokio::time::Instant::now();
        let deadline = started
            .checked_add(ADDRESS_WAIT)
            .ok_or_else(|| publication_timeout("onion address publication"))?;
        let address = loop {
            if let Some(address) = transport.onion_address() {
                break address;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(publication_timeout("onion address publication"));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        emit_event("ready", Some(format!("onion:{address}").as_bytes()))?;

        // Accept loop: one PQXDH session per stream; every failure is
        // contained to its connection.
        loop {
            let (mut stream, _permit) = transport
                .next_inbound_stream()
                .await
                .map_err(transport_error)?;
            let bundle = IdentityBundle::from_seeds(&seeds);
            match umbra_net::messenger::receive_message(bundle, &mut stream).await {
                Ok(plaintext) => {
                    emit_event("text", Some(&plaintext))?;
                }
                Err(error) => {
                    eprintln!("umbra: inbound session failed: {error}");
                }
            }
        }
    })
}

/// Internal timeout error for the publication wait.
fn publication_timeout(operation: &str) -> CliError {
    CliError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("{operation} timed out"),
    ))
}
