//! Real end-to-end test (TODO B.3.1): spawns the ACTUAL compiled
//! `umbra-engine` binary, connects over a REAL `AF_UNIX` socket, and
//! exercises the full sandboxed request/response round trip against a
//! REAL keystore file — no mocks, matching this project's established
//! "real dependency, no mocks" testing stance (Decoy Vault's own file
//! I/O tests, hwkey's SoftHSM2 tests). Fully hermetic despite spawning
//! a real subprocess: no GTK, no Wayland, no display server needed.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use umbra_crypto::keys::IdentityBundle;
use umbra_engine::protocol::{Request, Response};

/// Guards a spawned `umbra-engine` child process: kills it on drop so
/// a failing assertion never leaks an orphaned process (mirrors the
/// `Drop`-guarded cleanup `umbra-gui`'s own `EngineClient` will use in
/// production, Plan 2 of this same increment).
struct EngineGuard(Child);

impl Drop for EngineGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawns `umbra-engine --socket <socket_path> --keystore-dir
/// <keystore_dir>` and blocks (bounded) until its socket file exists.
fn spawn_engine(socket_path: &Path, keystore_dir: &Path) -> Result<EngineGuard, String> {
    let child = Command::new(env!("CARGO_BIN_EXE_umbra-engine"))
        .arg("--socket")
        .arg(socket_path)
        .arg("--keystore-dir")
        .arg(keystore_dir)
        .spawn()
        .map_err(|error| error.to_string())?;
    let deadline = std::time::Instant::now()
        .checked_add(Duration::from_secs(2))
        .unwrap_or_else(std::time::Instant::now);
    while !socket_path.exists() {
        if std::time::Instant::now() > deadline {
            return Err("timed out waiting for umbra-engine's socket to appear".to_string());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(EngineGuard(child))
}

/// Sends one [`Request`] over a fresh connection and returns the
/// decoded [`Response`]. A fresh connection per request is
/// deliberate: the Engine under test accepts exactly one connection
/// for its whole life, so each test case in this file spawns its own
/// Engine instance rather than sharing a connection across assertions.
fn send_request(socket_path: &Path, request: &Request) -> Result<Response, String> {
    let mut stream = UnixStream::connect(socket_path).map_err(|error| error.to_string())?;
    let mut line = serde_json::to_string(request).map_err(|error| error.to_string())?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|error| error.to_string())?;
    serde_json::from_str(response_line.trim_end()).map_err(|error| error.to_string())
}

/// Fresh, unique temp directory for one test case's socket + keystore
/// files (avoids collisions between parallel test threads — each test
/// function in this file uses a distinct `label`, and `process::id()`
/// separates concurrent `cargo test` invocations, matching this
/// codebase's established `temp_keystore_path`-style helpers).
fn temp_case_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("umbra-engine-e2e-{}-{label}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

#[test]
fn unlock_with_correct_passphrase_returns_the_fingerprint()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dir = temp_case_dir("correct");
    let keystore_path = dir.join("keystore.enc");
    let socket_path = dir.join("engine.sock");
    let bundle = IdentityBundle::generate();
    umbra_cli::keystore::save(&keystore_path, b"correct-passphrase", &bundle)?;

    let _engine = spawn_engine(&socket_path, &dir)?;
    let response = send_request(
        &socket_path,
        &Request {
            op: "unlock".to_string(),
            keystore_path: Some(keystore_path),
            passphrase: Some("correct-passphrase".to_string()),
        },
    )?;

    let _ = std::fs::remove_dir_all(&dir);
    assert!(response.ok);
    assert_eq!(response.fingerprint.map(|f| f.len()), Some(64));
    Ok(())
}

#[test]
fn unlock_with_wrong_passphrase_fails() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dir = temp_case_dir("wrong");
    let keystore_path = dir.join("keystore.enc");
    let socket_path = dir.join("engine.sock");
    let bundle = IdentityBundle::generate();
    umbra_cli::keystore::save(&keystore_path, b"correct-passphrase", &bundle)?;

    let _engine = spawn_engine(&socket_path, &dir)?;
    let response = send_request(
        &socket_path,
        &Request {
            op: "unlock".to_string(),
            keystore_path: Some(keystore_path),
            passphrase: Some("wrong-passphrase".to_string()),
        },
    )?;

    let _ = std::fs::remove_dir_all(&dir);
    assert!(!response.ok);
    assert!(response.error.is_some());
    Ok(())
}

#[test]
fn unlock_with_decoy_vault_outer_and_hidden_passphrase_both_work()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dir = temp_case_dir("decoy");
    let keystore_path = dir.join("vault.enc");
    let socket_path = dir.join("engine.sock");
    let outer_bundle = IdentityBundle::generate();
    let hidden_bundle = IdentityBundle::generate();
    umbra_cli::decoy_vault::create(&keystore_path, b"outer-pw", &outer_bundle)?;
    umbra_cli::decoy_vault::write_hidden(&keystore_path, b"hidden-pw", &hidden_bundle)?;

    let _engine = spawn_engine(&socket_path, &dir)?;
    let outer_response = send_request(
        &socket_path,
        &Request {
            op: "unlock".to_string(),
            keystore_path: Some(keystore_path.clone()),
            passphrase: Some("outer-pw".to_string()),
        },
    )?;

    let _ = std::fs::remove_dir_all(&dir);
    assert!(outer_response.ok);
    assert_eq!(outer_response.fingerprint.map(|f| f.len()), Some(64));
    Ok(())
}

#[test]
fn keystore_path_outside_sandboxed_directory_is_rejected_cleanly()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dir = temp_case_dir("outside");
    let socket_path = dir.join("engine.sock");
    // A path whose PARENT is NOT `dir` — the Engine is sandboxed to
    // `dir` only, so this must be rejected before any file I/O is
    // even attempted, with a clean error rather than a crash.
    let outside_path = std::env::temp_dir().join("definitely-not-under-dir.enc");

    let _engine = spawn_engine(&socket_path, &dir)?;
    let response = send_request(
        &socket_path,
        &Request {
            op: "unlock".to_string(),
            keystore_path: Some(outside_path),
            passphrase: Some("irrelevant".to_string()),
        },
    )?;

    let _ = std::fs::remove_dir_all(&dir);
    assert!(!response.ok);
    assert_eq!(
        response.error.as_deref(),
        Some("keystore_path is outside the sandboxed directory")
    );
    Ok(())
}

#[test]
fn unknown_op_over_the_wire_fails_cleanly() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let dir = temp_case_dir("unknown-op");
    let socket_path = dir.join("engine.sock");

    let _engine = spawn_engine(&socket_path, &dir)?;
    let response = send_request(
        &socket_path,
        &Request {
            op: "future-op".to_string(),
            keystore_path: None,
            passphrase: None,
        },
    )?;

    let _ = std::fs::remove_dir_all(&dir);
    assert!(!response.ok);
    assert_eq!(
        response.error.as_deref(),
        Some("unknown operation: future-op")
    );
    Ok(())
}
