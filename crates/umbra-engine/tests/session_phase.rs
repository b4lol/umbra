//! Hermetic session-phase protocol tests (TODO B.3 GUI messaging
//! design, Phase 2): proves the tagging retrofit — every response
//! after a successful `"unlock"` is wrapped in a `SessionLine` —
//! WITHOUT touching real Tor (bootstrap is exercised separately, in
//! an `#[ignore]`d manual test, since it needs the real network).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use umbra_crypto::keys::IdentityBundle;
use umbra_engine::protocol::{Request, SessionLine};

struct EngineGuard(Child);

impl Drop for EngineGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn temp_case_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "umbra-engine-session-phase-{}-{label}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn spawn_engine(
    socket_path: &Path,
    keystore_dir: &Path,
    tor_dir: &Path,
) -> Result<EngineGuard, String> {
    let child = Command::new(env!("CARGO_BIN_EXE_umbra-engine"))
        .arg("--socket")
        .arg(socket_path)
        .arg("--keystore-dir")
        .arg(keystore_dir)
        .arg("--tor-dir")
        .arg(tor_dir)
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

/// Sends `request` (pre-serialized JSON line minus the trailing
/// newline) over `writer` and reads back exactly one response line
/// from `reader`, decoded as whichever caller-chosen type `T`.
fn send_and_read<T: serde::de::DeserializeOwned>(
    writer: &mut impl Write,
    reader: &mut impl BufRead,
    request: &Request,
) -> Result<T, String> {
    let mut line = serde_json::to_string(request).map_err(|error| error.to_string())?;
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .map_err(|error| error.to_string())?;
    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|error| error.to_string())?;
    serde_json::from_str(response_line.trim_end()).map_err(|error| error.to_string())
}

#[test]
fn responses_are_untagged_before_unlock_and_tagged_after()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dir = temp_case_dir("tagging");
    let keystore_path = dir.join("keystore.enc");
    let socket_path = dir.join("engine.sock");
    let tor_dir = dir.join("tor");
    let bundle = IdentityBundle::generate();
    umbra_cli::keystore::save(&keystore_path, b"pw", &bundle)?;

    let _engine = spawn_engine(&socket_path, &dir, &tor_dir)?;
    let stream = UnixStream::connect(&socket_path)?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    // Pre-unlock: a malformed/unknown op still gets a BARE, untagged
    // Response — proves nothing tagging-related leaks before session
    // start.
    let pre_unlock: serde_json::Value = send_and_read(
        &mut writer,
        &mut reader,
        &Request {
            op: "list_peers".to_string(),
            ..Request::default()
        },
    )?;
    assert!(
        pre_unlock.get("kind").is_none(),
        "expected an untagged response before unlock, got: {pre_unlock:?}"
    );
    assert_eq!(
        pre_unlock.get("error").and_then(|v| v.as_str()),
        Some("not unlocked yet")
    );

    // Unlock: still untagged (spec: "the EXISTING unlock request/
    // response exchange is untouched").
    let unlock_response: serde_json::Value = send_and_read(
        &mut writer,
        &mut reader,
        &Request {
            op: "unlock".to_string(),
            keystore_path: Some(keystore_path),
            passphrase: Some("pw".to_string()),
            ..Request::default()
        },
    )?;
    assert!(unlock_response.get("kind").is_none());
    assert_eq!(
        unlock_response
            .get("ok")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );

    // Post-unlock: list_peers is now TAGGED.
    let tagged: SessionLine = send_and_read(
        &mut writer,
        &mut reader,
        &Request {
            op: "list_peers".to_string(),
            request_id: Some(1),
            ..Request::default()
        },
    )?;
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(tagged.kind, "response");
    assert_eq!(tagged.request_id, Some(1));
    assert_eq!(tagged.ok, Some(true));
    assert_eq!(tagged.peer_names, Some(Vec::<String>::new()));
    Ok(())
}

#[test]
fn send_to_an_unknown_peer_is_tagged_and_fails_cleanly()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dir = temp_case_dir("send-unknown-peer");
    let keystore_path = dir.join("keystore.enc");
    let socket_path = dir.join("engine.sock");
    let tor_dir = dir.join("tor");
    let bundle = IdentityBundle::generate();
    umbra_cli::keystore::save(&keystore_path, b"pw", &bundle)?;

    let _engine = spawn_engine(&socket_path, &dir, &tor_dir)?;
    let stream = UnixStream::connect(&socket_path)?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    let _unlock: serde_json::Value = send_and_read(
        &mut writer,
        &mut reader,
        &Request {
            op: "unlock".to_string(),
            keystore_path: Some(keystore_path),
            passphrase: Some("pw".to_string()),
            ..Request::default()
        },
    )?;
    let send_response: SessionLine = send_and_read(
        &mut writer,
        &mut reader,
        &Request {
            op: "send".to_string(),
            request_id: Some(2),
            peer_name: Some("alice".to_string()),
            text: Some("hi".to_string()),
            ..Request::default()
        },
    )?;
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(send_response.kind, "response");
    assert_eq!(send_response.request_id, Some(2));
    assert_eq!(send_response.ok, Some(false));
    // Phase 3: real send — the peer record does not exist, so the
    // peer lookup fails before any network work.
    assert!(
        send_response
            .error
            .as_deref()
            .is_some_and(|error| !error.is_empty())
    );
    Ok(())
}

/// Real Tor bootstrap over the live network — NOT run by default
/// (`cargo test`). Run manually with `cargo test -p umbra-engine
/// --test session_phase -- --ignored bootstrap_and_ready_event
/// --nocapture`, matching this project's `tests/tui_live.rs` /
/// `mesh_live.rs` precedent for anything that needs a real Tor
/// circuit. Bounded at 3 minutes (matches `serve.rs`'s own
/// `ADDRESS_WAIT`).
#[test]
#[ignore]
fn bootstrap_and_ready_event() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dir = temp_case_dir("bootstrap-live");
    let keystore_path = dir.join("keystore.enc");
    let socket_path = dir.join("engine.sock");
    let tor_dir = dir.join("tor");
    let bundle = IdentityBundle::generate();
    umbra_cli::keystore::save(&keystore_path, b"pw", &bundle)?;

    let _engine = spawn_engine(&socket_path, &dir, &tor_dir)?;
    let stream = UnixStream::connect(&socket_path)?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    let _unlock: serde_json::Value = send_and_read(
        &mut writer,
        &mut reader,
        &Request {
            op: "unlock".to_string(),
            keystore_path: Some(keystore_path),
            passphrase: Some("pw".to_string()),
            ..Request::default()
        },
    )?;

    // The "ready" event arrives UNPROMPTED, asynchronously, once
    // real Tor bootstrap completes — read lines until we see it or
    // time out.
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let parsed: SessionLine = serde_json::from_str(line.trim_end())?;
        if parsed.kind == "event" && parsed.event.as_deref() == Some("ready") {
            let _ = std::fs::remove_dir_all(&dir);
            assert!(
                parsed
                    .address
                    .is_some_and(|address| address.ends_with(".onion") || address.len() > 10)
            );
            return Ok(());
        }
        if std::time::Instant::now() > deadline {
            let _ = std::fs::remove_dir_all(&dir);
            return Err("timed out waiting for the ready event".into());
        }
    }
}
