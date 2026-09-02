//! LIVE-NETWORK identity-persistence test (`#[ignore]` by default).
//!
//! Verifies the TODO A.2 persistent-onion-identity contract against the
//! REAL Tor network: two consecutive `bootstrap_persistent` runs sharing
//! one storage root must publish the SAME `.onion` address (the second
//! run loads the Ed25519 identity key the first run stored in Arti's
//! native keystore).
//!
//! NOT part of the hermetic CI set: needs live Tor connectivity and
//! several minutes of bootstrap. Run manually:
//!
//! ```sh
//! cargo test -p umbra-net --features tor --test serve_live \
//!     -- --ignored --nocapture
//! ```
//!
//! or `just live-test`. Until this passes on the real network, the
//! README honest-scope row keeps its "not live-verified" caveat.

#![cfg(feature = "tor")]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use umbra_net::tor::TorTransport;

/// Upper bound for waiting until the onion descriptor is published
/// (per run; bootstrap itself is bounded by the transport's 180 s).
const PUBLISH_WAIT: Duration = Duration::from_secs(240);

/// Unique temp storage root for this test run (cleaned up best-effort).
fn live_base() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!(
        "umbra-live-identity-{}-{nanos}",
        std::process::id()
    ))
}

/// Bootstraps against `base`, spawns the inbound service, and waits
/// until the `.onion` descriptor is published.
async fn boot_and_publish(
    base: &std::path::Path,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mut transport = TorTransport::bootstrap_persistent(base)
        .await
        .map_err(|e| format!("bootstrap failed: {e}"))?;
    transport
        .spawn_inbound("umbralivetest")
        .await
        .map_err(|e| format!("spawn_inbound failed: {e}"))?;

    let deadline = Instant::now().checked_add(PUBLISH_WAIT).ok_or("deadline")?;
    loop {
        if let Some(address) = transport.onion_address() {
            return Ok(address);
        }
        if Instant::now() >= deadline {
            return Err("onion address publication timed out".into());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Two consecutive bootstraps over the SAME storage root publish the
/// same `.onion` address. The first run generates and stores the
/// Ed25519 identity key in Arti's native keystore; the second run must
/// load it instead of generating a fresh one.
#[tokio::test]
#[ignore = "requires the live Tor network and ~5 minutes of bootstrap time"]
async fn onion_address_persists_across_runs() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let base = live_base();
    std::fs::create_dir_all(&base)?;

    println!("run 1: bootstrapping (this can take minutes on the live network)…");
    let first = boot_and_publish(&base).await?;
    println!("run 1 published: {first}");

    println!("run 2: bootstrapping again over the SAME storage root…");
    let second = boot_and_publish(&base).await?;
    println!("run 2 published: {second}");

    assert_eq!(
        first, second,
        "the onion identity must persist across runs (TODO A.2 contract)"
    );
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}
