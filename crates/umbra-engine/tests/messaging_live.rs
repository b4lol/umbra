//! Live-network, two-`umbra-engine`-process messaging test — NOT run
//! by default (`cargo test`). This closes a real documentation gap
//! found in review: `docs/TODO.md`'s B.3 entry claimed send/receive
//! were "verified against the live Tor network between two Engine
//! processes, both directions" with no reproducible test artifact in
//! the repo backing that claim — unlike Phase 2's own
//! `bootstrap_and_ready_event` (`tests/session_phase.rs`), which IS a
//! real `#[ignore]`d test. This file is that artifact: it spawns TWO
//! real `umbra-engine` processes, each with its own throwaway
//! identity, waits for both to bootstrap and publish an onion
//! address over the REAL Tor network, has one send a message to the
//! other's address, and asserts the receiving side gets a decoded
//! `"inbound-text"` event carrying the exact plaintext.
//!
//! Mirrors `session_phase.rs`'s own `bootstrap_and_ready_event`
//! structure/bounds/timeout handling, and `crates/umbra-cli/tests/
//! tui_live.rs`'s precedent for anything needing a real Tor circuit
//! (two real bootstraps here, ~3 minutes each — this is a genuinely
//! long-running test).
//!
//! Run manually:
//! ```sh
//! cargo test -p umbra-engine --test messaging_live \
//!     -- --ignored two_engines_send_and_receive --nocapture
//! ```

use std::io::{self, BufRead, BufReader, Write};
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

/// Unique storage root for one side of this test run — one call per
/// identity, "a" and "b" never share a directory. Anchored under the
/// WORKSPACE-root `target/` (gitignored, user-owned), NOT
/// `std::env::temp_dir()`: Arti's fs-mistrust refuses a path chain
/// containing a group/world-writable ancestor, which rules out `/tmp`
/// entirely — this is `crates/umbra-cli/tests/tui_live.rs`'s own
/// established `live_base()` precedent for exactly this reason
/// (confirmed the hard way in this same fix pass: `temp_case_dir`'s
/// first draft used `std::env::temp_dir()`, matching
/// `session_phase.rs`'s own non-live-bootstrap helper, and a real run
/// failed immediately with Arti's "problem with filesystem
/// permissions: Error while trying to access persistent state").
fn temp_case_dir(label: &str) -> PathBuf {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map_or_else(std::env::temp_dir, Path::to_path_buf);
    let dir = workspace.join("target").join(format!(
        "umbra-engine-messaging-live-{}-{label}",
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

/// Sends `request` (assumed already correctly tagged/untagged for the
/// connection's current phase) over `writer` and reads back exactly
/// one response line from `reader`, decoded as whichever caller-chosen
/// type `T`.
///
/// `reader`'s underlying stream is assumed to have [`READ_POLL_TIMEOUT`]
/// set (every caller in this file sets it before any `send_and_read`
/// call) — a `read_line` timeout is routine, not fatal, and this
/// function keeps retrying until `deadline` passes. This matters for
/// EVERY call site in this file, not just the ones that "feel slow":
/// `"pair_confirm"` dispatches synchronously and is genuinely fast, but
/// `"send"` waits on a real Tor rendezvous connect that can legitimately
/// exceed one `READ_POLL_TIMEOUT` window — a single non-retrying read
/// would spuriously fail that call even when the Engine and network are
/// behaving correctly.
fn send_and_read<T: serde::de::DeserializeOwned>(
    writer: &mut impl Write,
    reader: &mut impl BufRead,
    request: &Request,
    deadline: std::time::Instant,
) -> Result<T, String> {
    let mut line = serde_json::to_string(request).map_err(|error| error.to_string())?;
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .map_err(|error| error.to_string())?;
    loop {
        let mut response_line = String::new();
        match reader.read_line(&mut response_line) {
            Ok(_) if !response_line.trim_end().is_empty() => {
                return serde_json::from_str(response_line.trim_end())
                    .map_err(|error| error.to_string());
            }
            Ok(_) => {}
            Err(error) if is_read_timeout(&error) => {}
            Err(error) => return Err(error.to_string()),
        }
        if std::time::Instant::now() > deadline {
            return Err("timed out waiting for a response to the request".to_string());
        }
    }
}

/// Per-read socket timeout used by [`wait_for_ready_address`] and
/// [`wait_for_inbound_text`]'s underlying `UnixStream`s. Deliberately
/// short relative to those functions' own multi-minute deadlines: the
/// socket has no timeout by default, so without this a hung/silent
/// Engine (stuck Tor bootstrap, or a genuinely blocked network) would
/// block `read_line` forever and the deadline check below it would
/// never actually run — this bounds each blocking read so the
/// deadline loop gets to re-check itself repeatedly instead of once.
const READ_POLL_TIMEOUT: Duration = Duration::from_secs(5);

/// A `read_line` timeout is an expected, routine event of this
/// polling loop (see [`READ_POLL_TIMEOUT`]) — not a fatal error like a
/// genuine socket failure. `WouldBlock` is included because some
/// platforms report a `SO_RCVTIMEO` expiry that way rather than as
/// `TimedOut`.
fn is_read_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// Reads lines off `reader` until the `"ready"` event arrives (or
/// `deadline` passes), returning its published onion address.
/// Skips over anything else that might interleave (there shouldn't be
/// anything, this early in a fresh connection, but the tagging
/// protocol allows it in principle) — including a `"session-error"`
/// event, treated as fatal exactly like [`wait_for_inbound_text`]
/// does, so a bootstrap failure reported here is surfaced immediately
/// instead of spinning until the deadline.
///
/// `reader`'s underlying stream must have a read timeout set (see
/// [`READ_POLL_TIMEOUT`]) — a timeout error is treated as "keep
/// checking the deadline," not as fatal.
fn wait_for_ready_address(
    reader: &mut impl BufRead,
    deadline: std::time::Instant,
) -> Result<String, String> {
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(_) => {
                if !line.trim_end().is_empty() {
                    let parsed: SessionLine =
                        serde_json::from_str(line.trim_end()).map_err(|error| error.to_string())?;
                    if parsed.kind == "event" {
                        match parsed.event.as_deref() {
                            Some("ready") => {
                                return parsed
                                    .address
                                    .ok_or_else(|| "ready event carried no address".to_string());
                            }
                            Some("session-error") => {
                                return Err(format!(
                                    "engine reported a session error while bootstrapping: {:?}",
                                    parsed.error
                                ));
                            }
                            _ => {}
                        }
                    }
                }
            }
            Err(error) if is_read_timeout(&error) => {}
            Err(error) => return Err(error.to_string()),
        }
        if std::time::Instant::now() > deadline {
            return Err("timed out waiting for the ready event".to_string());
        }
    }
}

/// Reads lines off `reader` until an `"inbound-text"` event arrives
/// (or `deadline` passes), returning its DECODED plaintext.
///
/// `reader`'s underlying stream must have a read timeout set (see
/// [`READ_POLL_TIMEOUT`]) — a timeout error is treated as "keep
/// checking the deadline," not as fatal.
fn wait_for_inbound_text(
    reader: &mut impl BufRead,
    deadline: std::time::Instant,
) -> Result<String, String> {
    use base64::Engine as _;
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(_) => {
                if !line.trim_end().is_empty() {
                    let parsed: SessionLine =
                        serde_json::from_str(line.trim_end()).map_err(|error| error.to_string())?;
                    if parsed.kind == "event" {
                        match parsed.event.as_deref() {
                            Some("inbound-text") => {
                                let data = parsed.data.ok_or_else(|| {
                                    "inbound-text event carried no data".to_string()
                                })?;
                                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                                    .decode(data)
                                    .map_err(|error| error.to_string())?;
                                return String::from_utf8(bytes).map_err(|error| error.to_string());
                            }
                            Some("session-error") => {
                                return Err(format!(
                                    "receiving side reported a session error while waiting: {:?}",
                                    parsed.error
                                ));
                            }
                            _ => {}
                        }
                    }
                }
            }
            Err(error) if is_read_timeout(&error) => {}
            Err(error) => return Err(error.to_string()),
        }
        if std::time::Instant::now() > deadline {
            return Err("timed out waiting for the inbound-text event".to_string());
        }
    }
}

/// Two real `umbra-engine` processes, two real throwaway identities,
/// one live two-party Tor send/receive round trip. Bounded at 3
/// minutes per bootstrap (matches `serve.rs`'s own `ADDRESS_WAIT` and
/// `session_phase.rs`'s `bootstrap_and_ready_event`), sequentially —
/// both engine PROCESSES bootstrap concurrently in real time (they
/// are independent OS processes), this test's own I/O is just
/// sequential about which socket it reads from first.
#[test]
#[ignore = "requires the live Tor network and several minutes of bootstrap time (two identities)"]
fn two_engines_send_and_receive() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dir_a = temp_case_dir("a");
    let dir_b = temp_case_dir("b");
    let outcome = run(&dir_a, &dir_b);
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
    outcome
}

fn run(dir_a: &Path, dir_b: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let keystore_a = dir_a.join("keystore.enc");
    let keystore_b = dir_b.join("keystore.enc");
    let socket_a = dir_a.join("engine.sock");
    let socket_b = dir_b.join("engine.sock");
    let tor_a = dir_a.join("tor");
    let tor_b = dir_b.join("tor");

    let bundle_a = IdentityBundle::generate();
    let bundle_b = IdentityBundle::generate();
    umbra_cli::keystore::save(&keystore_a, b"pw-a", &bundle_a)?;
    umbra_cli::keystore::save(&keystore_b, b"pw-b", &bundle_b)?;
    // B's own pairing payload — this is what A needs on record to
    // address a "send" to B; matches the GUI's own `pair_import`/
    // `pair_confirm` flow, just driven directly over the wire here
    // rather than through a pairing dialog.
    let payload_b = umbra_cli::pairing::payload_for(&bundle_b)?;

    let _engine_a = spawn_engine(&socket_a, dir_a, &tor_a)?;
    let _engine_b = spawn_engine(&socket_b, dir_b, &tor_b)?;

    let stream_a = UnixStream::connect(&socket_a)?;
    let mut writer_a = stream_a.try_clone()?;
    let mut reader_a = BufReader::new(stream_a);
    let stream_b = UnixStream::connect(&socket_b)?;
    let mut writer_b = stream_b.try_clone()?;
    let mut reader_b = BufReader::new(stream_b);

    // Set on both sockets BEFORE any read (including the unlock
    // exchange below): every `read_line` in this file — direct or via
    // `send_and_read`/`wait_for_*` — needs a bounded per-read timeout
    // so a hung/silent Engine can't block forever and skip past a
    // caller's own deadline check (see READ_POLL_TIMEOUT).
    // `send_and_read` retries on a timeout up to its own `deadline`
    // parameter, so this is transparent to genuinely-fast local calls
    // (unlock, pair_confirm) and correctly tolerant of slower ones
    // (send, which waits on a real Tor connect).
    reader_a
        .get_ref()
        .set_read_timeout(Some(READ_POLL_TIMEOUT))?;
    reader_b
        .get_ref()
        .set_read_timeout(Some(READ_POLL_TIMEOUT))?;

    let local_deadline = std::time::Instant::now()
        .checked_add(Duration::from_secs(30))
        .ok_or("system clock error computing local-call deadline")?;
    let _unlock_a: serde_json::Value = send_and_read(
        &mut writer_a,
        &mut reader_a,
        &Request {
            op: "unlock".to_string(),
            keystore_path: Some(keystore_a),
            passphrase: Some("pw-a".to_string()),
            ..Request::default()
        },
        local_deadline,
    )?;
    let _unlock_b: serde_json::Value = send_and_read(
        &mut writer_b,
        &mut reader_b,
        &Request {
            op: "unlock".to_string(),
            keystore_path: Some(keystore_b),
            passphrase: Some("pw-b".to_string()),
            ..Request::default()
        },
        local_deadline,
    )?;

    // Both engines bootstrap concurrently (independent processes) from
    // this point; we just wait for each address sequentially.
    let bootstrap_deadline = std::time::Instant::now()
        .checked_add(Duration::from_secs(180))
        .ok_or("system clock error computing bootstrap deadline")?;
    println!("waiting for engine A's onion address (bootstrapping, up to 3 minutes)…");
    let _address_a = wait_for_ready_address(&mut reader_a, bootstrap_deadline)?;
    let bootstrap_deadline_b = std::time::Instant::now()
        .checked_add(Duration::from_secs(180))
        .ok_or("system clock error computing bootstrap deadline")?;
    println!("waiting for engine B's onion address (bootstrapping, up to 3 minutes)…");
    let address_b = wait_for_ready_address(&mut reader_b, bootstrap_deadline_b)?;
    println!("both engines published; recording B as a peer of A and sending…");

    let local_deadline_2 = std::time::Instant::now()
        .checked_add(Duration::from_secs(30))
        .ok_or("system clock error computing local-call deadline")?;
    let pair_response: SessionLine = send_and_read(
        &mut writer_a,
        &mut reader_a,
        &Request {
            op: "pair_confirm".to_string(),
            request_id: Some(1),
            peer_name: Some("bob".to_string()),
            peer_payload: Some(payload_b),
            peer_onion: Some(address_b),
            ..Request::default()
        },
        local_deadline_2,
    )?;
    if pair_response.ok != Some(true) {
        return Err(format!("pair_confirm on engine A failed: {:?}", pair_response.error).into());
    }

    // "send" waits on a real Tor rendezvous connect (bounded at ~120s
    // by `tor_send.rs`'s own connect timeout) before the Engine
    // answers — give it real headroom past that bound, unlike the
    // local/fast calls above.
    let send_deadline = std::time::Instant::now()
        .checked_add(Duration::from_secs(130))
        .ok_or("system clock error computing send deadline")?;
    let message = "umbra-engine live messaging test: hello from A";
    let send_response: SessionLine = send_and_read(
        &mut writer_a,
        &mut reader_a,
        &Request {
            op: "send".to_string(),
            request_id: Some(2),
            peer_name: Some("bob".to_string()),
            text: Some(message.to_string()),
            ..Request::default()
        },
        send_deadline,
    )?;
    if send_response.ok != Some(true) {
        return Err(format!("send from engine A failed: {:?}", send_response.error).into());
    }
    println!("A's send accepted by Arti; waiting for B's inbound-text event…");

    let delivery_deadline = std::time::Instant::now()
        .checked_add(Duration::from_secs(120))
        .ok_or("system clock error computing delivery deadline")?;
    let received = wait_for_inbound_text(&mut reader_b, delivery_deadline)?;
    assert_eq!(
        received, message,
        "engine B's decrypted inbound-text payload did not match what A sent"
    );
    println!("PASS: engine B received exactly what engine A sent.");
    Ok(())
}
