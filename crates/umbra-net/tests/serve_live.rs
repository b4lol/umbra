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
//! or `just live-test`. FIRST REAL-NETWORK PASS: 2026-09 — two
//! consecutive runs published the same address. Known cosmetic noise:
//! arti's internal timer tasks panic during Tokio runtime teardown
//! AFTER a successful publish (upstream, non-fatal).
//!
//! OPSEC: every run generates a THROWAWAY identity (the storage root is
//! wiped afterwards — key destroyed, service never resurrected) and the
//! published address is REDACTED in test output; never log a controllable
//! address in full.

#![cfg(feature = "tor")]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use umbra_net::tor::TorTransport;

/// Upper bound for waiting until the onion descriptor is published
/// (per run; bootstrap itself is bounded by the transport's 180 s).
const PUBLISH_WAIT: Duration = Duration::from_secs(240);

/// Unique storage root for this test run. Arti's fs-mistrust refuses a
/// path chain containing a group/world-writable ancestor, so `/tmp` is
/// NOT eligible; the WORKSPACE-root `target/` (gitignored, user-owned)
/// is. Anchored via CARGO_MANIFEST_DIR so cargo's per-package working
/// directory can never scatter state into a committable path.
fn live_base() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map_or_else(|| std::env::temp_dir(), std::path::Path::to_path_buf);
    let base = workspace.join("target").join(format!(
        "umbra-live-identity-{}-{nanos}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&base);
    base
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
///
/// Each run gets its OWN Tokio runtime: dropping a runtime fully shuts
/// down its Arti tasks, which releases the onion-service lockfile the
/// next run needs (running both inside one runtime races the shutdown).
#[test]
#[ignore = "requires the live Tor network and ~5 minutes of bootstrap time"]
fn onion_address_persists_across_runs() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let base = live_base();
    // OPSEC: the identity key is DESTROYED on every exit path — the
    // test's throwaway identity must never outlive the verification.
    let outcome = verify_persistence(&base);
    let _ = std::fs::remove_dir_all(&base);
    outcome
}

/// The two-run persistence check proper (storage root wiped by the
/// caller on every path).
fn verify_persistence(
    base: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("run 1: bootstrapping (this can take minutes on the live network)…");
    let first = run_in_fresh_runtime(base)?;
    println!(
        "run 1 published: {}…{}",
        &first[..8],
        &first[(first.len() - 4)..]
    );

    // Belt-and-braces: let the previous runtime's Arti tasks finish
    // releasing the onion-service lockfile before the next launch.
    std::thread::sleep(Duration::from_secs(5));

    println!("run 2: bootstrapping again over the SAME storage root…");
    let second = run_in_fresh_runtime(base)?;
    println!(
        "run 2 published: {}…{}",
        &second[..8],
        &second[(second.len() - 4)..]
    );

    assert_eq!(
        first, second,
        "the onion identity must persist across runs (TODO A.2 contract)"
    );
    Ok(())
}

/// Runs one full bootstrap-publish cycle on a dedicated runtime.
fn run_in_fresh_runtime(
    base: &std::path::Path,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    runtime.block_on(boot_and_publish(base))
}
