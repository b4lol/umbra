//! Integration smoke tests for the `umbra-gui` binary (TODO B.3). One
//! hermetic test (works in any environment, including headless CI: the
//! binary exits before ever touching GTK) plus one `#[ignore]`d test
//! that needs a real Wayland compositor — mirrors this project's
//! existing `mesh_live.rs`/`nym_live.rs` precedent for
//! environment-dependent flows.
//!
//! Written in this crate family's `Result<(), Box<dyn Error + Send +
//! Sync>>`-returning test style (see e.g.
//! `crates/umbra-net/tests/mesh_live.rs`) rather than
//! panicking assertions in the failure paths below, since the
//! workspace's `clippy::panic` lint (`[workspace.lints.clippy]` in the
//! root `Cargo.toml`) applies to this crate's test targets too, not
//! just its production code.

use std::process::Command;

/// With `WAYLAND_DISPLAY` removed from its environment, the binary
/// must refuse to start, print the expected message to stderr, and
/// exit non-zero — all BEFORE touching GTK, so this runs in any
/// environment (no display server required).
#[test]
fn refuses_to_start_without_a_wayland_session()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let output = Command::new(env!("CARGO_BIN_EXE_umbra-gui"))
        .env_remove("WAYLAND_DISPLAY")
        .output()?;
    assert!(
        !output.status.success(),
        "must exit non-zero without a Wayland session"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Wayland-only"),
        "expected the Wayland-only rejection message on stderr, got: {stderr}"
    );
    Ok(())
}

/// Under a REAL Wayland session, the binary must start, stay running
/// (i.e. it opened the window and entered the GTK main loop rather than
/// crashing on startup), and be killable cleanly. Requires an actual
/// compositor — run explicitly:
/// `cargo test -p umbra-gui --test smoke -- --ignored`
#[test]
#[ignore = "requires a real Wayland compositor — see this test's own doc comment"]
fn opens_and_stays_running_under_a_real_wayland_session()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_umbra-gui")).spawn()?;

    std::thread::sleep(std::time::Duration::from_millis(500));

    let status = child.try_wait()?;
    assert!(
        status.is_none(),
        "umbra-gui exited early with status {status:?} instead of staying open"
    );

    child.kill()?;
    let _ = child.wait();
    Ok(())
}
