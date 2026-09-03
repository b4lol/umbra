//! LIVE-NETWORK TUI background-path test (`#[ignore]` by default).
//!
//! Verifies the interactive client's network core against the REAL Tor
//! network via a SELF-SEND: the exact helpers the TUI background task
//! wires together — `bootstrap_persistent` + `spawn_inbound` +
//! `serve::wait_for_address` + `serve::inbound_loop` for inbound, and
//! `tor_send::send_over` for outbound — must deliver a message sent to
//! the client's OWN onion address back to the inbound channel. The
//! terminal half of the TUI is pure state logic covered by hermetic
//! unit tests; only this network path can regress against the live
//! network.
//!
//! NOT part of the hermetic CI set: needs live Tor connectivity and
//! several minutes of bootstrap. Run manually:
//!
//! ```sh
//! cargo test -p umbra-cli --features tor --test tui_live \
//!     -- --ignored --nocapture
//! ```
//!
//! OPSEC: every run uses a THROWAWAY identity (the storage root is wiped
//! afterwards — key destroyed, service never resurrected) and the
//! published address is REDACTED in test output; never log a
//! controllable address in full.

#![cfg(feature = "tor")]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use umbra_crypto::keys::IdentityBundle;
use umbra_net::tor::TorTransport;

/// Capacity of the inbound session queue (mirrors the TUI).
const SESSION_QUEUE: usize = 32;

/// Bound on the self-send round trip AFTER our own descriptor is
/// published (the send itself is already bounded inside `send_over`).
const DELIVERY_WAIT: Duration = Duration::from_secs(240);

/// Unique storage root for this test run. Arti's fs-mistrust refuses a
/// path chain containing a group/world-writable ancestor, so `/tmp` is
/// NOT eligible; the WORKSPACE-root `target/` (gitignored, user-owned)
/// is. Anchored via CARGO_MANIFEST_DIR so cargo's per-package working
/// directory can never scatter state into a committable path.
fn live_base() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map_or_else(std::env::temp_dir, Path::to_path_buf);
    let base = workspace
        .join("target")
        .join(format!("umbra-live-tui-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(&base);
    base
}

/// Self-send through the client's own onion service: bootstrap, publish,
/// run the shared accept loop, and deliver one message back to it.
#[test]
#[ignore = "requires the live Tor network and minutes of bootstrap time"]
fn tui_background_self_send() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let base = live_base();
    // OPSEC: the identity key is DESTROYED on every exit path — the
    // test's throwaway identity must never outlive the verification.
    let outcome = verify_self_send(&base);
    let _ = std::fs::remove_dir_all(&base);
    outcome
}

/// The self-send check proper (storage root wiped by the caller on
/// every path).
fn verify_self_send(base: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("bootstrapping (this can take minutes on the live network)…");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    runtime.block_on(self_send_once(base))
}

/// One bootstrap → publish → inbound-loop → send → receive cycle.
async fn self_send_once(base: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Throwaway identity, Arc-shared exactly as the TUI shares the
    // keystore seeds between the accept loop and the send path.
    let bundle = IdentityBundle::generate();
    let seeds = Arc::new(bundle.secret_seeds());
    // The TUI's peer list comes from the record store; a self-send uses
    // our OWN pairing payload as the peer record.
    let mut peer = umbra_cli::pairing::parse_payload(&umbra_cli::pairing::payload_for(&bundle)?)?;

    let mut transport = TorTransport::bootstrap_persistent(base).await?;
    transport.spawn_inbound("umbratuilivetest").await?;
    let transport = Arc::new(transport);
    let address = umbra_cli::serve::wait_for_address(&transport).await?;
    println!("published: {}", redact(&address));
    peer.onion = Some(address.clone());

    let (tx, mut rx) = tokio::sync::mpsc::channel(SESSION_QUEUE);
    let loop_handle = tokio::spawn(umbra_cli::serve::inbound_loop(
        transport.clone(),
        seeds,
        tx,
        SESSION_QUEUE,
    ));

    let message = b"umbra tui live self-send";
    let (frames, bytes) = umbra_cli::tor_send::send_over(&transport, &peer, &address, message)
        .await
        .map_err(|e| format!("send_over: {e}"))?;
    println!("sent {frames} frames / {bytes} bytes; waiting for inbound delivery…");

    let delivered = tokio::time::timeout(DELIVERY_WAIT, rx.recv())
        .await
        .map_err(|_elapsed| "inbound delivery timed out")?
        .ok_or("inbound channel closed before delivery")?
        .map_err(|e| format!("inbound session: {e}"))?;
    loop_handle.abort();
    assert_eq!(delivered, message, "the self-send must round-trip intact");
    println!("round-trip OK ({} bytes)", delivered.len());
    Ok(())
}

/// Redacts an onion address for operator output: first 8 and last 4
/// characters only (a controllable address must never be logged whole).
fn redact(address: &str) -> String {
    let bytes = address.as_bytes();
    if bytes.len() <= 12 {
        return "…redacted…".to_string();
    }
    let head = bytes
        .get(..8)
        .map_or("…", |slice| std::str::from_utf8(slice).unwrap_or("…"));
    let tail_start = bytes.len().saturating_sub(4);
    let tail = bytes
        .get(tail_start..)
        .map_or("…", |slice| std::str::from_utf8(slice).unwrap_or("…"));
    format!("{head}…{tail}")
}
