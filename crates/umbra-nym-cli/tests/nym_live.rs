//! Live-network proof that `nym-sdk` v1.21.6's confirmed API actually
//! works end to end against Nym's real, free Sandbox testnet (TODO
//! B.1). `#[ignore]`d — never runs under default `cargo test`; run
//! explicitly: `cargo test --manifest-path crates/umbra-nym-cli/Cargo.toml
//! --test nym_live -- --ignored --nocapture`.
//!
//! `self_send_round_trip_over_sandbox` proves Sandbox connectivity and
//! the send/receive API shape only.
//!
//! `send_nym_to_serve_nym` is the plan's CENTRAL acceptance criterion: a
//! live, two-PROCESS integration test driving the real `umbra` and
//! `umbra-nym` CLI binaries end to end against the live Sandbox testnet,
//! proving a full PQXDH handshake plus one message actually round-trips
//! over the live mixnet. It:
//!
//! 1. Creates two temp identities, A (sender) and B (receiver), each
//!    with its own keystore + passphrase file, via the real `umbra
//!    init` subcommand (invoked through `cargo run -p umbra-cli --bin
//!    umbra` against the MAIN workspace, since this crate is a
//!    deliberately separate Cargo workspace — see `Cargo.toml`'s
//!    package description).
//! 2. Spawns `umbra-nym serve-nym` for B as a background child process
//!    (the built binary, via `CARGO_BIN_EXE_umbra-nym`, which DOES work
//!    here since this test is part of the SAME standalone workspace),
//!    and reads its NDJSON stdout on a background thread until the
//!    `"ready"` event yields B's real, live Sandbox Nym address.
//! 3. Runs `umbra export-pairing` for B and `umbra pair` from A to
//!    record B's peer entry (name `"b"`) with that real address.
//! 4. Runs `umbra-nym send-nym` from A with a known plaintext piped to
//!    its stdin.
//! 5. Waits for the `"text"` event on B's stdout and asserts the
//!    decoded payload is byte-for-byte the plaintext sent in step 4.
//! 6. Kills B's `serve-nym` child and cleans up all temp directories.

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use base64::Engine as _;
use futures::StreamExt as _;
use nym_sdk::mixnet::{MixnetClientBuilder, MixnetMessageSender};
use umbra_nym_cli::nym_network::sandbox_network_details;

#[tokio::test]
#[ignore = "requires live network access to Nym's Sandbox testnet"]
async fn self_send_round_trip_over_sandbox() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let mut client = MixnetClientBuilder::new_ephemeral()
        .network_details(sandbox_network_details())
        .build()?
        .connect_to_mixnet()
        .await?;

    let my_address = *client.nym_address();
    client
        .send_plain_message(my_address, b"umbra-nym-live-probe".to_vec())
        .await?;

    let received = tokio::time::timeout(std::time::Duration::from_secs(60), client.next())
        .await?
        .ok_or("mixnet client stream ended before delivering the message")?;
    assert_eq!(received.message, b"umbra-nym-live-probe");

    client.disconnect().await;
    Ok(())
}

/// Absolute path to the built `umbra-nym` binary (this crate's own
/// workspace, so `CARGO_BIN_EXE_umbra-nym` is set for this integration
/// test).
const UMBRA_NYM_BIN: &str = env!("CARGO_BIN_EXE_umbra-nym");

/// Locates the MAIN Umbra workspace's `Cargo.toml`, two directories up
/// from this crate's manifest dir (`crates/umbra-nym-cli/../..`),
/// canonicalized so relative-path surprises never bite. Computed at
/// runtime rather than hardcoded, per the task brief.
fn main_workspace_manifest() -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.join("../..").canonicalize()?;
    let manifest = root.join("Cargo.toml");
    if !manifest.is_file() {
        return Err(format!(
            "main workspace Cargo.toml not found at {}",
            manifest.display()
        )
        .into());
    }
    Ok(manifest)
}

/// Runs the MAIN `umbra` binary (via `cargo run -p umbra-cli --bin
/// umbra` against the main workspace) with the given arguments,
/// returning captured stdout as a `String` on success. Fails loudly
/// (including stdout/stderr) on a non-zero exit, so a failure here
/// shows up as a clear test failure rather than a silent empty string.
fn run_umbra(
    main_manifest: &Path,
    args: &[&str],
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mut full_args: Vec<&str> = vec![
        "run",
        "--quiet",
        "--manifest-path",
        main_manifest
            .to_str()
            .ok_or("main workspace manifest path is not valid UTF-8")?,
        "-p",
        "umbra-cli",
        "--bin",
        "umbra",
        "--",
    ];
    full_args.extend_from_slice(args);

    let output = Command::new("cargo").args(&full_args).output()?;
    if !output.status.success() {
        return Err(format!(
            "`cargo run ... umbra {}` failed (status {}): stdout={} stderr={}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

/// Writes `passphrase` to a fresh file at `path` with mode 0600,
/// matching `umbra`/`umbra-nym`'s own `--passphrase-file` convention
/// (first line only; no trailing newline needed since there is nothing
/// after it).
fn write_passphrase_file(
    path: &Path,
    passphrase: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(passphrase)?;
    Ok(())
}

/// One decoded NDJSON event line from `serve-nym`'s stdout: the raw
/// `event` name and the `data` field's DECODED bytes (base64url,
/// no-pad, per this crate's `cli.rs` module docs), if present.
struct ServeEvent {
    /// The event's name (`"ready"` or `"text"`).
    event: String,
    /// The event's `data` field, base64url-decoded (empty if the line
    /// carried no `data` field).
    data: Vec<u8>,
}

/// Parses one `serve-nym` NDJSON stdout line (`{"event":"...","data":"..."}`
/// or `{"event":"..."}`) without pulling in a JSON dependency: the
/// format is fixed and simple enough (see `cli.rs`'s `emit_event`) to
/// parse by hand with plain string slicing.
fn parse_serve_event(line: &str) -> Result<ServeEvent, Box<dyn std::error::Error + Send + Sync>> {
    let event_key = "\"event\":\"";
    let event_start = line
        .find(event_key)
        .ok_or("malformed serve-nym event line: no \"event\" field")?
        .checked_add(event_key.len())
        .ok_or("overflow locating event field")?;
    let event_end = line
        .get(event_start..)
        .and_then(|rest| rest.find('"'))
        .map(|offset| offset.checked_add(event_start))
        .ok_or("malformed serve-nym event line: unterminated event value")?
        .ok_or("overflow locating event field end")?;
    let event = line
        .get(event_start..event_end)
        .ok_or("malformed serve-nym event line: bad event span")?
        .to_string();

    let data = if let Some(data_key_pos) = line.find("\"data\":\"") {
        let data_start = data_key_pos
            .checked_add("\"data\":\"".len())
            .ok_or("overflow locating data field")?;
        let data_end = line
            .get(data_start..)
            .and_then(|rest| rest.find('"'))
            .map(|offset| offset.checked_add(data_start))
            .ok_or("malformed serve-nym event line: unterminated data value")?
            .ok_or("overflow locating data field end")?;
        let b64 = line
            .get(data_start..data_end)
            .ok_or("malformed serve-nym event line: bad data span")?;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64)?
    } else {
        Vec::new()
    };

    Ok(ServeEvent { event, data })
}

/// Reads lines from `reader`, forwarding each successfully parsed
/// [`ServeEvent`] over `tx`. Runs on a background thread for the
/// lifetime of the `serve-nym` child process; stops silently once the
/// pipe closes (child killed) or the channel's receiver is dropped.
fn spawn_event_reader(reader: impl std::io::Read + Send + 'static, tx: mpsc::Sender<ServeEvent>) {
    std::thread::spawn(move || {
        let buffered = BufReader::new(reader);
        for line in buffered.lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(event) = parse_serve_event(&line) {
                if tx.send(event).is_err() {
                    break;
                }
            }
        }
    });
}

/// Blocks until an event named `want_event` arrives on `rx`, or
/// `timeout` elapses. Other event names seen along the way are ignored
/// (there are none expected here, but this keeps the wait robust).
fn wait_for_event(
    rx: &mpsc::Receiver<ServeEvent>,
    want_event: &str,
    timeout: Duration,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .ok_or("timeout duration overflowed while computing serve-nym event deadline")?;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "timed out after {timeout:?} waiting for serve-nym \"{want_event}\" event"
            )
            .into());
        }
        match rx.recv_timeout(remaining) {
            Ok(event) if event.event == want_event => return Ok(event.data),
            Ok(_other) => continue,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err(format!(
                    "timed out after {timeout:?} waiting for serve-nym \"{want_event}\" event"
                )
                .into());
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(format!(
                    "serve-nym's stdout closed before emitting a \"{want_event}\" event"
                )
                .into());
            }
        }
    }
}

/// Ensures the child is killed and reaped even if an earlier assertion
/// in the test body returns early via `?`. Used as an RAII guard so
/// `send_nym_to_serve_nym` never leaks a live `serve-nym` process on
/// failure.
struct ChildGuard(
    /// The guarded `serve-nym` child process.
    Child,
);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The plan's CENTRAL acceptance criterion: a live, two-process
/// integration test driving the real `umbra` and `umbra-nym` CLI
/// binaries end to end against Nym's real, free Sandbox testnet,
/// proving a full PQXDH handshake plus one message round-trips over the
/// live mixnet.
#[test]
#[ignore = "requires live network access to Nym's Sandbox testnet"]
fn send_nym_to_serve_nym() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let main_manifest = main_workspace_manifest()?;

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let root = std::env::temp_dir().join(format!(
        "umbra-nym-live-interop-{}-{nanos}",
        std::process::id()
    ));
    let a_dir = root.join("a");
    let b_dir = root.join("b");
    std::fs::create_dir_all(&a_dir)?;
    std::fs::create_dir_all(&b_dir)?;

    let a_keystore = a_dir.join("umbra.enc");
    let a_pass = a_dir.join("pass");
    let b_keystore = b_dir.join("umbra.enc");
    let b_pass = b_dir.join("pass");
    let b_nym_config = b_dir.join("nym-cfg");

    let passphrase = b"umbra-nym-live-interop-test-passphrase";
    write_passphrase_file(&a_pass, passphrase)?;
    write_passphrase_file(&b_pass, passphrase)?;

    // Cleanup runs at the end via this guard so a failed assertion still
    // removes the temp tree; wrapped in a closure invoked from every
    // return path is awkward in a plain `fn`, so a small drop guard is
    // used instead.
    struct DirGuard(
        /// Root temp directory to remove (recursively) on drop.
        PathBuf,
    );
    impl Drop for DirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _dir_guard = DirGuard(root.clone());

    let a_keystore_str = a_keystore
        .to_str()
        .ok_or("A's keystore path is not valid UTF-8")?;
    let a_pass_str = a_pass
        .to_str()
        .ok_or("A's passphrase path is not valid UTF-8")?;
    let b_keystore_str = b_keystore
        .to_str()
        .ok_or("B's keystore path is not valid UTF-8")?;
    let b_pass_str = b_pass
        .to_str()
        .ok_or("B's passphrase path is not valid UTF-8")?;

    // Step 1: create both identities via the real `umbra init`.
    run_umbra(
        &main_manifest,
        &[
            "--keystore",
            a_keystore_str,
            "--passphrase-file",
            a_pass_str,
            "init",
        ],
    )?;
    run_umbra(
        &main_manifest,
        &[
            "--keystore",
            b_keystore_str,
            "--passphrase-file",
            b_pass_str,
            "init",
        ],
    )?;

    // Step 2: spawn B's `serve-nym` as a background child process and
    // read its NDJSON stdout on a background thread.
    let mut serve_child = Command::new(UMBRA_NYM_BIN)
        .args([
            "serve-nym",
            "--keystore",
            b_keystore_str,
            "--passphrase-file",
            b_pass_str,
            "--nym-config",
            b_nym_config
                .to_str()
                .ok_or("B's nym-config path is not valid UTF-8")?,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let serve_stdout = serve_child
        .stdout
        .take()
        .ok_or("serve-nym child had no captured stdout")?;
    let (tx, rx) = mpsc::channel();
    spawn_event_reader(serve_stdout, tx);
    let serve_child = ChildGuard(serve_child);

    // Live Sandbox connection setup is not instant (Task 3's own live
    // test needed real time to connect) — allow generously.
    let ready_data = wait_for_event(&rx, "ready", Duration::from_secs(90))?;
    let ready_str = String::from_utf8(ready_data)?;
    let b_nym_addr = ready_str
        .strip_prefix("nym:")
        .ok_or("serve-nym's \"ready\" event data did not start with \"nym:\"")?
        .to_string();
    assert!(
        !b_nym_addr.is_empty(),
        "B's decoded Nym address must not be empty"
    );

    // Step 3: export B's pairing payload and pair it into A's peer
    // records under the name "b", using B's REAL live Nym address.
    let b_payload = run_umbra(
        &main_manifest,
        &[
            "--keystore",
            b_keystore_str,
            "--passphrase-file",
            b_pass_str,
            "export-pairing",
        ],
    )?
    .trim()
    .to_string();
    assert!(
        !b_payload.is_empty(),
        "B's pairing payload must not be empty"
    );

    let pair_stdout = run_umbra(
        &main_manifest,
        &[
            "--keystore",
            a_keystore_str,
            "--passphrase-file",
            a_pass_str,
            "pair",
            "--peer-name",
            "b",
            "--peer-payload",
            &b_payload,
            "--nym-addr",
            &b_nym_addr,
        ],
    )?;
    assert!(
        pair_stdout.trim_start().starts_with("sas="),
        "umbra pair must print sas=...: got {pair_stdout:?}"
    );

    // Step 4: send one known plaintext from A to B over the live
    // mixnet via `umbra-nym send-nym`.
    let plaintext: &[u8] = b"hello from umbra-nym live interop test";
    let mut send_child = Command::new(UMBRA_NYM_BIN)
        .args(["send-nym", "--keystore", a_keystore_str, "--peer", "b"])
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    send_child
        .stdin
        .take()
        .ok_or("send-nym child had no captured stdin")?
        .write_all(plaintext)?;
    let send_status = send_child.wait()?;
    assert!(
        send_status.success(),
        "umbra-nym send-nym must exit successfully: {send_status}"
    );

    // Step 5: wait for B to receive it over the live mixnet and decode
    // the exact plaintext — the full PQXDH handshake plus one message
    // round-trip proof.
    let received = wait_for_event(&rx, "text", Duration::from_secs(90))?;
    assert_eq!(
        received, plaintext,
        "B must receive EXACTLY the plaintext A sent"
    );

    // Step 6: stop B's server (the `ChildGuard`/`DirGuard` drops below
    // also handle this on any earlier early return via `?`).
    drop(serve_child);

    Ok(())
}
