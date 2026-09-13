//! Hermetic PKCS#11 tests against a REAL SoftHSM2 token (TODO B.3) — no
//! mocks. `SOFTHSM2_CONF` is set via this workspace's root
//! `.cargo/config.toml` `[env]` table (not `std::env::set_var`, which
//! is `unsafe` on this toolchain and this workspace forbids
//! `unsafe_code`), pointing at `tests/fixtures/softhsm2-test.conf` — an
//! isolated token store under `/tmp`, separate from the host's own
//! `/etc/softhsm2.conf`.
//!
//! All assertions live in ONE test function deliberately: SoftHSM2's
//! config is process-wide state, and Rust's default test harness runs
//! `#[test]` functions in parallel threads within one process — a
//! second test touching the same token store concurrently would race.
//! This file is its own compiled test binary (Cargo gives every
//! `tests/*.rs` file its own process), so the hazard is fully
//! contained to this one file, and having exactly one test function in
//! it removes the hazard entirely.

use std::path::Path;
use std::process::Command;

/// The SoftHSM2 PKCS#11 module path on this (Fedora-family) host —
/// installed via `dnf install softhsm` (see this repo's
/// `CONTRIBUTING.md` for the full local dev-setup list, TODO B.3
/// addition).
const SOFTHSM2_MODULE: &str = "/usr/lib64/pkcs11/libsofthsm2.so";

/// The tokendir `tests/fixtures/softhsm2-test.conf` points at — kept as
/// a constant here so a mismatch between the two is a compile-adjacent,
/// single-source-of-truth-visible fact rather than a silent divergence.
const TOKEN_DIR: &str = "/tmp/umbra-hwkey-softhsm-test-tokens";

/// Builds a fresh SoftHSM2 token, then proves: (1) the same challenge
/// produces the same HMAC response across repeated calls (determinism);
/// (2) a different challenge produces a different response; (3) a
/// wrong PIN fails cleanly, not silently or with a panic.
#[test]
fn generate_and_use_a_real_softhsm2_token() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    // Fresh token store every run.
    let _ = std::fs::remove_dir_all(TOKEN_DIR);
    std::fs::create_dir_all(TOKEN_DIR)?;

    let init = Command::new("softhsm2-util")
        .args([
            "--init-token",
            "--free",
            "--label",
            "umbra-hwkey-test",
            "--pin",
            "1234",
            "--so-pin",
            "0000",
        ])
        .output()?;
    if !init.status.success() {
        return Err(format!(
            "softhsm2-util --init-token failed: {}",
            String::from_utf8_lossy(&init.stderr)
        )
        .into());
    }

    let module = Path::new(SOFTHSM2_MODULE);
    let label = "umbra-hwkey-test-key";
    umbra_hwkey::generate_hmac_key(module, b"1234", label)?;

    let challenge_a = b"first challenge";
    let response_1 = umbra_hwkey::challenge_response(module, b"1234", label, challenge_a)?;
    let response_2 = umbra_hwkey::challenge_response(module, b"1234", label, challenge_a)?;
    assert_eq!(
        response_1, response_2,
        "the same challenge must produce the same response"
    );

    let challenge_b = b"second, different challenge";
    let response_3 = umbra_hwkey::challenge_response(module, b"1234", label, challenge_b)?;
    assert_ne!(
        response_1, response_3,
        "a different challenge must produce a different response"
    );

    let wrong_pin_result = umbra_hwkey::challenge_response(module, b"0000", label, challenge_a);
    assert!(
        wrong_pin_result.is_err(),
        "a wrong PIN must fail cleanly, not succeed"
    );

    let _ = std::fs::remove_dir_all(TOKEN_DIR);
    Ok(())
}
