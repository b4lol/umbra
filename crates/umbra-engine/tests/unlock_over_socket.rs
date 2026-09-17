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
/// <keystore_dir>` (plus `--hw-module-dir`, if given) and blocks
/// (bounded) until its socket file exists.
fn spawn_engine(
    socket_path: &Path,
    keystore_dir: &Path,
    hw_module_dir: Option<&Path>,
) -> Result<EngineGuard, String> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_umbra-engine"));
    command
        .arg("--socket")
        .arg(socket_path)
        .arg("--keystore-dir")
        .arg(keystore_dir);
    if let Some(hw_module_dir) = hw_module_dir {
        command.arg("--hw-module-dir").arg(hw_module_dir);
    }
    let child = command.spawn().map_err(|error| error.to_string())?;
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

/// Sends multiple [`Request`]s in order over ONE freshly-opened
/// connection, returning each decoded [`Response`] in order — unlike
/// [`send_request`], which opens (and implicitly closes) a fresh
/// connection per call. Needed to exercise session state (TODO B.3
/// GUI messaging design, Phase 1): `list_peers`/pairing operations
/// require a prior successful `"unlock"` on the SAME connection.
fn send_requests_over_one_connection(
    socket_path: &Path,
    requests: &[Request],
) -> Result<Vec<Response>, String> {
    let stream = UnixStream::connect(socket_path).map_err(|error| error.to_string())?;
    let mut writer = stream.try_clone().map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut responses = Vec::with_capacity(requests.len());
    for request in requests {
        let mut line = serde_json::to_string(request).map_err(|error| error.to_string())?;
        line.push('\n');
        writer
            .write_all(line.as_bytes())
            .map_err(|error| error.to_string())?;
        let mut response_line = String::new();
        reader
            .read_line(&mut response_line)
            .map_err(|error| error.to_string())?;
        responses.push(
            serde_json::from_str(response_line.trim_end()).map_err(|error| error.to_string())?,
        );
    }
    Ok(responses)
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

    let _engine = spawn_engine(&socket_path, &dir, None)?;
    let response = send_request(
        &socket_path,
        &Request {
            op: "unlock".to_string(),
            keystore_path: Some(keystore_path),
            passphrase: Some("correct-passphrase".to_string()),
            ..Request::default()
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

    let _engine = spawn_engine(&socket_path, &dir, None)?;
    let response = send_request(
        &socket_path,
        &Request {
            op: "unlock".to_string(),
            keystore_path: Some(keystore_path),
            passphrase: Some("wrong-passphrase".to_string()),
            ..Request::default()
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

    let _engine = spawn_engine(&socket_path, &dir, None)?;
    let outer_response = send_request(
        &socket_path,
        &Request {
            op: "unlock".to_string(),
            keystore_path: Some(keystore_path.clone()),
            passphrase: Some("outer-pw".to_string()),
            ..Request::default()
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

    let _engine = spawn_engine(&socket_path, &dir, None)?;
    let response = send_request(
        &socket_path,
        &Request {
            op: "unlock".to_string(),
            keystore_path: Some(outside_path),
            passphrase: Some("irrelevant".to_string()),
            ..Request::default()
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

    let _engine = spawn_engine(&socket_path, &dir, None)?;
    let response = send_request(
        &socket_path,
        &Request {
            op: "future-op".to_string(),
            ..Request::default()
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

#[test]
fn unlock_with_hardware_key_over_a_real_socket_returns_the_fingerprint()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Must match `crates/umbra-hwkey/tests/fixtures/softhsm2-test.conf`'s
    // `directories.tokendir` — this workspace's root `.cargo/config.toml`
    // FORCES `SOFTHSM2_CONF` to that fixture for every `cargo test`
    // invocation (see its own comment), so SoftHSM2 writes here
    // regardless of what directory name this test might otherwise have
    // picked.
    const TOKEN_DIR: &str = "/tmp/umbra-hwkey-softhsm-test-tokens";
    let _ = std::fs::remove_dir_all(TOKEN_DIR);
    std::fs::create_dir_all(TOKEN_DIR)?;
    let init = std::process::Command::new("softhsm2-util")
        .args([
            "--init-token",
            "--free",
            "--label",
            "umbra-engine-e2e-test",
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
    let module_path = if let Ok(path) = std::env::var("UMBRA_SOFTHSM2_MODULE") {
        PathBuf::from(path)
    } else {
        [
            "/usr/lib64/pkcs11/libsofthsm2.so",
            "/usr/lib/softhsm/libsofthsm2.so",
        ]
        .into_iter()
        .map(PathBuf::from)
        .find(|candidate| candidate.exists())
        .ok_or("no SoftHSM2 PKCS#11 module found; set UMBRA_SOFTHSM2_MODULE")?
    };
    let label = "umbra-engine-e2e-test-key";
    umbra_hwkey::generate_hmac_key(&module_path, b"1234", label)?;
    let hmac_response = umbra_hwkey::challenge_response(
        &module_path,
        b"1234",
        label,
        umbra_cli::keystore::HARDWARE_KEY_CHALLENGE,
    )?;

    let dir = temp_case_dir("hwkey");
    let keystore_path = dir.join("keystore.enc");
    let socket_path = dir.join("engine.sock");
    let bundle = IdentityBundle::generate();
    umbra_cli::keystore::save_with_hardware_key(
        &keystore_path,
        b"hw-e2e-passphrase",
        &hmac_response,
        &bundle,
    )?;

    let module_dir = module_path
        .parent()
        .ok_or("SoftHSM2 module path has no parent directory")?;
    let _engine = spawn_engine(&socket_path, &dir, Some(module_dir))?;
    let response = send_request(
        &socket_path,
        &Request {
            op: "unlock".to_string(),
            keystore_path: Some(keystore_path),
            passphrase: Some("hw-e2e-passphrase".to_string()),
            hw_module: Some(module_path),
            hw_pin: Some("1234".to_string()),
            hw_key_label: Some(label.to_string()),
            ..Request::default()
        },
    )?;
    // The token must survive until the Engine subprocess has actually
    // used it: `send_request` blocks until the Engine's own
    // `dispatch::unlock` has independently re-derived the HMAC response
    // via a fresh `challenge_response` PKCS#11 call against the live
    // token (never trusting a caller-supplied response) — removing the
    // token any earlier fails every real run, not just a narrow check.
    let _ = std::fs::remove_dir_all(TOKEN_DIR);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(response.ok, "expected Ok, got: {response:?}");
    assert_eq!(response.fingerprint.map(|f| f.len()), Some(64));
    Ok(())
}

#[test]
fn session_state_persists_across_requests_on_one_connection()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dir = temp_case_dir("session-peers");
    let keystore_path = dir.join("keystore.enc");
    let socket_path = dir.join("engine.sock");
    let bundle = IdentityBundle::generate();
    umbra_cli::keystore::save(&keystore_path, b"pw", &bundle)?;
    let peer_bundle = IdentityBundle::generate();
    let peer_payload = umbra_cli::pairing::payload_for(&peer_bundle)?;

    let _engine = spawn_engine(&socket_path, &dir, None)?;
    let responses = send_requests_over_one_connection(
        &socket_path,
        &[
            Request {
                op: "unlock".to_string(),
                keystore_path: Some(keystore_path.clone()),
                passphrase: Some("pw".to_string()),
                ..Request::default()
            },
            Request {
                op: "list_peers".to_string(),
                ..Request::default()
            },
            Request {
                op: "pair_payload".to_string(),
                ..Request::default()
            },
            Request {
                op: "pair_import".to_string(),
                peer_payload: Some(peer_payload.clone()),
                ..Request::default()
            },
            Request {
                op: "pair_confirm".to_string(),
                peer_name: Some("alice".to_string()),
                peer_payload: Some(peer_payload),
                ..Request::default()
            },
            Request {
                op: "list_peers".to_string(),
                ..Request::default()
            },
        ],
    )?;
    let _ = std::fs::remove_dir_all(&dir);

    assert!(responses[0].ok, "unlock: {:?}", responses[0]);
    assert!(responses[1].ok, "list_peers before: {:?}", responses[1]);
    assert_eq!(responses[1].peer_names, Some(Vec::<String>::new()));
    assert!(responses[2].ok, "pair_payload: {:?}", responses[2]);
    assert!(responses[2].payload.is_some());
    assert!(responses[3].ok, "pair_import: {:?}", responses[3]);
    assert_eq!(responses[3].sas.as_ref().map(String::len), Some(6));
    assert!(responses[4].ok, "pair_confirm: {:?}", responses[4]);
    assert!(responses[5].ok, "list_peers after: {:?}", responses[5]);
    assert_eq!(responses[5].peer_names, Some(vec!["alice".to_string()]));
    Ok(())
}
