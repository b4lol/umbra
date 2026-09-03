//! Inbound Tor onion-service flow (`umbra serve`, TODO A.2): the
//! PRODUCTION call site that wires the persistent-identity mechanisms
//! together —
//!
//! 1. identity seeds load ONCE (pre-sandbox), bundle rebuilt per
//!    connection via `IdentityBundle::from_seeds` (no Argon2 per peer;
//!    the per-connection ML-DSA keygen + SPK sign cost is accepted and
//!    bounded by the concurrent-stream semaphore);
//! 2. `harden_memory()` before any secret touches RAM (ADR-025);
//! 3. Landlock zero-FS with the sanctioned exceptions — the Tor
//!    storage dir (read+write: Arti's guard state + native keystore
//!    keeping the `.onion` identity stable), read-only `/etc` (the libc
//!    resolver may open `resolv.conf`-family files during bootstrap; all
//!    public content), and `/dev/tty` — plus the full Seccomp allowlist;
//! 4. `TorTransport::bootstrap_persistent` + `spawn_inbound` (Vanguards-
//!    Lite pinning + hs-pow inbound hardening apply automatically);
//! 5. one session per accepted stream: `receive_message` (PQXDH + Double
//!    Ratchet), text payloads emitted as NDJSON on stdout.
//!
//! Honest scope: the outbound counterpart is `send --onion`
//! (`tor_send`); inbound cover frames are destroyed silently (ADR-005),
//! while idle-gap cover between sessions is v2; SMP is not run on
//! inbound streams (SAS verification is out of band).

use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use umbra_crypto::keys::{IdentityBundle, IdentitySeeds};
use umbra_net::tor::TorTransport;

use crate::cli::CliError;

/// Upper bound for waiting until the onion descriptor is published.
const ADDRESS_WAIT: Duration = Duration::from_secs(120);

/// Capacity of the per-session result queue feeding the stdout writer.
const INBOUND_RESULT_QUEUE: usize = 32;

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
    stdout
        .write_all(line.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(CliError::Io)
}

/// Runs the `serve` flow. Never returns under normal operation: it loops
/// accepting inbound sessions until the process is terminated.
///
/// # Errors
///
/// Returns [`CliError`] on keystore, sandbox, bootstrap, or onion
/// publication failure. Per-connection failures are logged to stderr and
/// the accept loop continues.
pub fn run(
    keystore: &std::path::Path,
    passphrase: &[u8],
    nickname: &str,
    pt_args: &crate::pt::PtArgs,
) -> Result<(), CliError> {
    // 1. Memory hardening BEFORE secrets exist (ADR-025 ordering).
    umbra_hardware::process::harden_process()?;

    // 1b. PT configuration (ADR-030): bridge lines are operational
    //     secrets read pre-sandbox alongside the keystore material.
    let pt = crate::pt::load_config(keystore, pt_args)?;

    // 2. Identity seeds load ONCE; the keystore file is never opened
    //    again (it would be denied by the sandbox below). Arc-shared so
    //    the TUI can reuse the same cores for outbound sends.
    let seeds: std::sync::Arc<IdentitySeeds> =
        std::sync::Arc::new(crate::keystore::load_seeds(keystore, passphrase)?);

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
    crate::sandbox::restrict_filesystem_with_exceptions(
        &[tor_base.as_path()],
        // /etc is READ-ONLY: public resolver/config content only.
        &[std::path::Path::new("/etc")],
    )?;
    crate::sandbox::restrict_syscalls()?;

    // 5. Runtime + transport. `bootstrap_persistent_with_pt` roots the
    //    Arti state/cache/keystore under `tor_base` — the `.onion`
    //    identity persists across runs for this nickname — and wires the
    //    unmanaged PT proxy when configured (ADR-030).
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::Io(std::io::Error::other(format!("tokio runtime: {e}"))))?;
    runtime.block_on(async move {
        let transport_error = |error: umbra_net::TransportError| {
            CliError::Io(std::io::Error::other(format!("tor transport: {error}")))
        };
        let mut transport = TorTransport::bootstrap_persistent_with_pt(&tor_base, pt.as_ref())
            .await
            .map_err(transport_error)?;
        transport
            .spawn_inbound(nickname)
            .await
            .map_err(transport_error)?;
        let transport = std::sync::Arc::new(transport);

        let address = wait_for_address(&transport).await?;
        emit_event("ready", Some(format!("onion:{address}").as_bytes()))?;

        // Accept loop shared with the TUI; results serialize onto the
        // NDJSON stdout channel. Stdout failure is FATAL — dropping
        // inbound messages silently would be a correctness lie.
        let (results_tx, mut results_rx) = tokio::sync::mpsc::channel::<
            Result<Vec<u8>, umbra_net::TransportError>,
        >(INBOUND_RESULT_QUEUE);
        let loop_handle = tokio::spawn(inbound_loop(
            transport,
            seeds,
            results_tx,
            INBOUND_RESULT_QUEUE,
        ));
        while let Some(result) = results_rx.recv().await {
            match result {
                Ok(plaintext) => {
                    let plaintext = zeroize::Zeroizing::new(plaintext);
                    emit_event("text", Some(&plaintext))?;
                }
                Err(error) => {
                    eprintln!("umbra: inbound session failed: {error}");
                }
            }
        }
        loop_handle
            .await
            .map_err(|e| CliError::Io(std::io::Error::other(format!("accept loop: {e}"))))?
    })
}

/// Waits until the onion descriptor is published and returns the
/// address (bounded by [`ADDRESS_WAIT`]).
///
/// # Errors
///
/// Returns [`CliError::Io`] (timeout) if publication does not complete.
pub async fn wait_for_address(transport: &TorTransport) -> Result<String, CliError> {
    let started = tokio::time::Instant::now();
    let deadline = started
        .checked_add(ADDRESS_WAIT)
        .ok_or_else(|| publication_timeout("onion address publication"))?;
    loop {
        if let Some(address) = transport.onion_address() {
            return Ok(address);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(publication_timeout("onion address publication"));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// The accept loop shared by `serve` (NDJSON stdout) and the TUI
/// (message log): one PQXDH session per accepted stream, each handled
/// in its OWN task (the stream's semaphore permit moves with it,
/// keeping Arti's concurrency bound intact). Every session result flows
/// to `results_tx`; session failures are contained to their connection.
///
/// # Errors
///
/// Returns [`CliError`] on accept failures (the loop only ends on a
/// transport error or when the results channel closes).
pub async fn inbound_loop(
    transport: std::sync::Arc<TorTransport>,
    seeds: std::sync::Arc<IdentitySeeds>,
    forward_tx: tokio::sync::mpsc::Sender<Result<Vec<u8>, umbra_net::TransportError>>,
    queue_capacity: usize,
) -> Result<(), CliError> {
    let transport_error = |error: umbra_net::TransportError| {
        CliError::Io(std::io::Error::other(format!("tor transport: {error}")))
    };
    // Internal per-session result queue; the loop forwards to the
    // caller's channel (kept distinct to avoid self-delivery loops).
    let (session_tx, mut session_rx) = tokio::sync::mpsc::channel(queue_capacity);
    loop {
        tokio::select! {
            accepted = transport.next_inbound_stream() => {
                let (mut stream, permit) = accepted.map_err(transport_error)?;
                let bundle = IdentityBundle::from_seeds(&seeds);
                let tx = session_tx.clone();
                tokio::spawn(async move {
                    let _permit = permit; // held for the whole session
                    let result =
                        umbra_net::messenger::receive_message(bundle, &mut stream).await;
                    let _ = tx.send(result).await;
                });
            }
            result = session_rx.recv() => {
                match result {
                    Some(Ok(plaintext)) => {
                        let plaintext = zeroize::Zeroizing::new(plaintext);
                        if forward_tx.send(Ok(plaintext.to_vec())).await.is_err() {
                            return Ok(()); // consumer gone: stop the loop
                        }
                    }
                    Some(Err(error)) => {
                        let _ = forward_tx.send(Err(error)).await;
                    }
                    None => {
                        return Err(CliError::Io(std::io::Error::other(
                            "inbound session queue closed",
                        )));
                    }
                }
            }
        }
    }
}

/// Internal timeout error for the publication wait.
fn publication_timeout(operation: &str) -> CliError {
    CliError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("{operation} timed out"),
    ))
}
