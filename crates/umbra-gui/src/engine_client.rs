//! IPC client for the Engine process (TODO B.3.1): spawns and talks to
//! `umbra-engine` over a private `AF_UNIX` socket so this process
//! never itself runs keystore/decoy-vault unlock logic. See
//! `docs/superpowers/specs/2026-09-15-engine-ui-separation-design.md`.
//!
//! # Duplicated wire types (deliberate)
//!
//! [`Request`]/[`Response`] below are field-for-field identical to
//! `umbra_engine::protocol`'s types, copied rather than imported via a
//! Cargo dependency on `umbra-engine`: that crate unconditionally
//! depends on `umbra-cli`/`umbra-crypto`/`landlock`/`seccompiler`
//! (Cargo links whole crates, not individual modules), and pulling
//! that graph into this GUI process would defeat this increment's own
//! point — the GUI no longer linking secret-handling/sandboxing code.
//! A field-level mismatch between the two sides fails the wire round
//! trip immediately (this module's own tests, plus
//! `crates/umbra-engine/tests/unlock_over_socket.rs`).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// One request line, mirrors `umbra_engine::protocol::Request`.
#[derive(Debug, Serialize)]
struct Request {
    /// The requested operation. Only `"unlock"` is ever sent today.
    op: String,
    /// The keystore or decoy-vault file to operate on.
    keystore_path: Option<PathBuf>,
    /// The passphrase to unlock with.
    passphrase: Option<String>,
}

/// One response line, mirrors `umbra_engine::protocol::Response`.
#[derive(Debug, Deserialize)]
struct Response {
    /// Whether the operation succeeded.
    ok: bool,
    /// The unlocked identity's fingerprint, present only when `ok`.
    #[serde(default)]
    fingerprint: Option<String>,
    /// A display-ready error message, present only when not `ok`.
    #[serde(default)]
    error: Option<String>,
}

/// A protocol-level connection to the Engine, independent of how that
/// connection was established. Split out from [`EngineClient`] so the
/// wire-protocol logic is unit-testable against a plain `UnixListener`
/// fixture, with no real `umbra-engine` subprocess needed (see this
/// module's tests).
struct EngineConnection {
    /// The already-connected socket to the Engine process.
    stream: UnixStream,
}

impl EngineConnection {
    /// Sends an `"unlock"` request for `keystore_path` with
    /// `passphrase`, and returns the unlocked identity's fingerprint
    /// as lowercase hex on success.
    fn unlock(&mut self, keystore_path: &Path, passphrase: &[u8]) -> Result<String, String> {
        let passphrase = std::str::from_utf8(passphrase)
            .map_err(|_error| "passphrase must be valid UTF-8".to_string())?;
        let request = Request {
            op: "unlock".to_string(),
            keystore_path: Some(keystore_path.to_path_buf()),
            passphrase: Some(passphrase.to_string()),
        };
        let mut line = serde_json::to_string(&request).map_err(|error| error.to_string())?;
        line.push('\n');
        self.stream
            .write_all(line.as_bytes())
            .map_err(|error| error.to_string())?;

        let mut reader = BufReader::new(&self.stream);
        let mut response_line = String::new();
        reader
            .read_line(&mut response_line)
            .map_err(|error| error.to_string())?;
        let response: Response =
            serde_json::from_str(response_line.trim_end()).map_err(|error| error.to_string())?;
        if response.ok {
            response
                .fingerprint
                .ok_or_else(|| "Engine returned ok without a fingerprint".to_string())
        } else {
            Err(response
                .error
                .unwrap_or_else(|| "Engine returned an error with no message".to_string()))
        }
    }
}

/// A live connection to a spawned `umbra-engine` process.
///
/// Holds the spawned [`Child`] so `Drop` can kill it: a safety net
/// against an orphaned secret-holding process outliving this GUI (the
/// Engine also exits on its own once this struct's connection closes,
/// since it reads until EOF — this is belt-and-suspenders).
pub struct EngineClient {
    /// The wire-protocol connection to the spawned Engine process.
    connection: EngineConnection,
    /// The spawned `umbra-engine` child process, killed on [`Drop`].
    child: Child,
}

impl Drop for EngineClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl EngineClient {
    /// Spawns `umbra-engine` (located next to this process's own
    /// executable — never resolved via `$PATH`, so a same-named
    /// binary earlier on the caller's `$PATH` can never be spawned
    /// instead) and connects to it over a fresh, per-process `AF_UNIX`
    /// socket under `$XDG_RUNTIME_DIR/umbra/` (falling back to
    /// [`std::env::temp_dir`] with a stderr notice if
    /// `XDG_RUNTIME_DIR` is unset — unusual on a real desktop session
    /// but not fatal).
    ///
    /// `keystore_path` is canonicalized once, here: its canonicalized
    /// parent directory becomes the Engine's `--keystore-dir` sandbox
    /// scope, and the SAME canonicalized path (the second element of
    /// the returned tuple) is what every later [`EngineClient::unlock`]
    /// call must send as `keystore_path`, so the Engine's own
    /// directory check always compares like with like.
    ///
    /// # Errors
    ///
    /// Returns a display-ready error message if `keystore_path` cannot
    /// be canonicalized, the socket directory cannot be created, the
    /// Engine binary cannot be spawned, its socket never appears
    /// within a 2-second bound, or the connection cannot be
    /// established.
    pub fn spawn(keystore_path: &Path) -> Result<(Self, PathBuf), String> {
        let canonical_keystore_path =
            std::fs::canonicalize(keystore_path).map_err(|error| error.to_string())?;
        let keystore_dir = canonical_keystore_path
            .parent()
            .ok_or_else(|| "keystore path has no parent directory".to_string())?
            .to_path_buf();

        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").map_or_else(
            || {
                eprintln!(
                    "umbra-gui: XDG_RUNTIME_DIR is unset, falling back to the system temp \
                     directory for the Engine socket"
                );
                std::env::temp_dir()
            },
            PathBuf::from,
        );
        let socket_dir = runtime_dir.join("umbra");
        std::fs::create_dir_all(&socket_dir).map_err(|error| error.to_string())?;
        std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        let socket_path = socket_dir.join(format!("engine-{}.sock", std::process::id()));

        let engine_binary = sibling_engine_binary_path()?;
        let child = std::process::Command::new(&engine_binary)
            .arg("--socket")
            .arg(&socket_path)
            .arg("--keystore-dir")
            .arg(&keystore_dir)
            .spawn()
            .map_err(|error| format!("failed to spawn {}: {error}", engine_binary.display()))?;

        let deadline = std::time::Instant::now()
            .checked_add(Duration::from_secs(2))
            .ok_or_else(|| "system clock error computing Engine startup deadline".to_string())?;
        while !socket_path.exists() {
            if std::time::Instant::now() > deadline {
                return Err("timed out waiting for umbra-engine's socket to appear".to_string());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let stream = UnixStream::connect(&socket_path).map_err(|error| error.to_string())?;
        Ok((
            Self {
                connection: EngineConnection { stream },
                child,
            },
            canonical_keystore_path,
        ))
    }

    /// Sends an `"unlock"` request for `keystore_path` (MUST be the
    /// canonicalized path returned by [`EngineClient::spawn`]) with
    /// `passphrase`, and returns the unlocked identity's fingerprint
    /// as lowercase hex on success.
    ///
    /// # Errors
    ///
    /// Returns a display-ready error message on a wrong passphrase, a
    /// missing/corrupt keystore file, a non-UTF-8 passphrase, or any
    /// I/O failure talking to the Engine.
    pub fn unlock(&mut self, keystore_path: &Path, passphrase: &[u8]) -> Result<String, String> {
        self.connection.unlock(keystore_path, passphrase)
    }
}

/// Resolves the `umbra-engine` binary's path as a SIBLING of this
/// process's own executable (never via `$PATH` — see
/// [`EngineClient::spawn`]'s doc comment for why).
fn sibling_engine_binary_path() -> Result<PathBuf, String> {
    let current_exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let parent = current_exe
        .parent()
        .ok_or_else(|| "current executable has no parent directory".to_string())?;
    Ok(parent.join("umbra-engine"))
}

#[cfg(test)]
mod tests {
    use super::EngineConnection;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::{UnixListener, UnixStream};

    /// Spins up a plain `UnixListener` fixture (a scripted fake
    /// Engine, no real `umbra-engine` subprocess) that accepts one
    /// connection, reads one NDJSON request line, and writes back
    /// `response_line` verbatim. Returns a connected
    /// [`EngineConnection`] wired to it. `label` gives the fixture
    /// socket a unique path per test (mirrors this codebase's
    /// established `temp_keystore_path`-style test helpers).
    fn connect_to_fake_engine(
        label: &str,
        response_line: &'static str,
    ) -> Result<EngineConnection, Box<dyn std::error::Error + Send + Sync>> {
        let socket_path = std::env::temp_dir().join(format!(
            "umbra-gui-engine-client-test-{}-{label}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path)?;
        std::thread::spawn(move || -> Result<(), std::io::Error> {
            let (stream, _peer_addr) = listener.accept()?;
            let mut reader = BufReader::new(stream.try_clone()?);
            let mut writer = stream;
            let mut request_line = String::new();
            reader.read_line(&mut request_line)?;
            writer.write_all(response_line.as_bytes())?;
            writer.write_all(b"\n")
        });
        let stream = UnixStream::connect(&socket_path)?;
        let _ = std::fs::remove_file(&socket_path);
        Ok(EngineConnection { stream })
    }

    #[test]
    fn unlock_parses_a_successful_response() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        let mut connection = connect_to_fake_engine(
            "success",
            r#"{"ok":true,"fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        )?;
        let fingerprint = connection
            .unlock(std::path::Path::new("/tmp/ks.enc"), b"whatever")
            .map_err(|error| format!("expected Ok, got Err: {error}"))?;
        assert_eq!(fingerprint.len(), 64);
        Ok(())
    }

    #[test]
    fn unlock_parses_a_failure_response() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut connection = connect_to_fake_engine(
            "failure",
            r#"{"ok":false,"error":"wrong passphrase or corrupted keystore"}"#,
        )?;
        let result = connection.unlock(std::path::Path::new("/tmp/ks.enc"), b"whatever");
        assert_eq!(
            result,
            Err("wrong passphrase or corrupted keystore".to_string())
        );
        Ok(())
    }

    #[test]
    fn unlock_rejects_a_non_utf8_passphrase() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        // The UTF-8 check happens before any socket I/O, so the fake
        // Engine's scripted response is never actually sent or read —
        // any well-formed response line works here.
        let mut connection =
            connect_to_fake_engine("non-utf8", r#"{"ok":true,"fingerprint":"x"}"#)?;
        let result = connection.unlock(std::path::Path::new("/tmp/ks.enc"), &[0xFF, 0xFE]);
        assert_eq!(result, Err("passphrase must be valid UTF-8".to_string()));
        Ok(())
    }
}
