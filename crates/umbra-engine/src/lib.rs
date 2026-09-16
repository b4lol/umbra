//! # `umbra-engine`
//!
//! The Engine half of TODO B.3.1's first increment (`docs/PROJECT.md`'s
//! "Discrete Process Isolation / Rule of Separation" principle): a
//! minimal, sandboxed process that owns keystore/decoy-vault secret
//! material on behalf of `umbra-gui`, served over one `AF_UNIX` socket
//! connection. See
//! `docs/superpowers/specs/2026-09-15-engine-ui-separation-design.md`.
//!
//! This increment implements exactly one operation, `"unlock"` — the
//! only secret-touching operation `umbra-gui` has today. [`protocol`]
//! defines the wire format, [`dispatch`] implements `"unlock"`, and
//! [`run`] owns the socket/sandbox lifecycle below.
//!
//! # Trust boundary (honest scope)
//!
//! The socket lives under a `0700` directory (created by `umbra-gui`
//! before spawning this process) with the socket file itself `0600`,
//! so only the same OS user can connect at all — the same trust
//! boundary this codebase already relies on everywhere else (file
//! permissions on the keystore itself, `/dev/tty` ownership, etc.).
//! This increment does not add peer-credential (`SO_PEERCRED`)
//! verification on top of that: a malicious process already running
//! as the same user could do far worse than race a socket connection,
//! so that check would defend against a threat model this codebase
//! does not otherwise defend against either.

pub mod dispatch;
pub mod protocol;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use protocol::Request;

/// Top-level Engine error — every variant here is a STARTUP failure.
/// A per-request failure is never an `EngineError`; it becomes an
/// `Ok` [`protocol::Response`] with `ok: false` instead (see
/// [`serve_connection`]).
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// Socket bind/accept/read/write failure.
    #[error("socket I/O failure: {0}")]
    Io(#[from] std::io::Error),
    /// JSON encoding failure while building a response (never expected
    /// in practice for this protocol's simple types, but `serde_json`
    /// returns `Result`, so this variant exists to propagate it rather
    /// than `unwrap`, which this workspace's lints forbid).
    #[error("JSON encoding failure: {0}")]
    Json(#[from] serde_json::Error),
    /// Sandboxing (Landlock/Seccomp) setup failure.
    #[error("sandbox failure: {0}")]
    Sandbox(String),
    /// Memory-hardening (ADR-025) failure.
    #[error("memory hardening failure: {0}")]
    Hardware(String),
}

/// Runs the Engine: binds `socket_path`, sandboxes itself to
/// READ-ONLY access under `keystore_dir` (which MUST be the
/// canonicalized parent directory of every `keystore_path` this
/// session's requests will ever send — see the module doc and the
/// spec's Sandboxing section for why this is a startup argument
/// rather than learned from the first request), accepts one
/// connection, and serves it until EOF.
///
/// # Errors
///
/// Returns [`EngineError`] if memory hardening, the socket bind, or
/// sandbox setup fails.
pub fn run(socket_path: &Path, keystore_dir: &Path) -> Result<(), EngineError> {
    // Core-dump suppression only — NOT `umbra_hardware::process::
    // harden_process()`'s full bundle, which also calls `mlockall
    // (MCL_CURRENT | MCL_FUTURE)`. That call locks every FUTURE
    // allocation into RAM too, and this process's own unlock dispatch
    // (`dispatch::unlock`) drives Argon2id at the production cost
    // (`m_cost_kib = 1 << 18` = 256 MiB, `crates/umbra-crypto/src/
    // keystore.rs`) — an allocation far larger than a constrained
    // `RLIMIT_MEMLOCK` (8 MiB, empirically confirmed in this project's
    // own dev sandbox) can lock, which fails Argon2id itself with
    // `ENOMEM` well after `mlockall` already "succeeded" (mlockall
    // only marks future allocations for locking; the failure surfaces
    // later, at the large allocation). `crates/umbra-cli/src/cli.rs`'s
    // `init_with` already hit and documented this exact conflict for
    // `umbra init`/`keygen` and deliberately skips hardening there for
    // the same reason. This function keeps the free, unrelated
    // protections (`disable_core_dumps`/`limit_core_dumps`) and drops
    // only `lock_all_memory`.
    umbra_hardware::process::disable_core_dumps()
        .map_err(|error| EngineError::Hardware(error.to_string()))?;
    umbra_hardware::process::limit_core_dumps()
        .map_err(|error| EngineError::Hardware(error.to_string()))?;

    // A stale socket file (e.g. left behind by an ungraceful prior
    // crash at the same PID) would make bind() fail with AddrInUse;
    // removing it first is standard AF_UNIX server hygiene. Ignoring
    // the error is correct here: NotFound is the overwhelmingly common
    // case (fresh, PID-qualified path — see umbra-gui's spawn logic),
    // and any OTHER removal failure will simply surface as bind()'s
    // own error immediately below.
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    // 0600: this socket carries a passphrase in cleartext; only this
    // process and its parent (which created the 0700 directory it
    // lives in) should ever be able to connect.
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;

    // Landlock/Seccomp restriction happens AFTER the socket is bound
    // (binding creates a filesystem special file, which the
    // zero-access Landlock default would otherwise deny) but BEFORE
    // accept() — see the module doc's "Sandboxing order is fixed and
    // load-bearing" note.
    // `let _status =` (not a bare statement) matches this codebase's own
    // existing call-site convention for this function (see
    // `crates/umbra-cli/src/cli.rs`'s `let _status =
    // crate::sandbox::restrict_filesystem()?;`).
    let _status = umbra_cli::sandbox::restrict_filesystem_with_exceptions(&[], &[keystore_dir])
        .map_err(|error| EngineError::Sandbox(error.to_string()))?;
    umbra_cli::sandbox::restrict_syscalls()
        .map_err(|error| EngineError::Sandbox(error.to_string()))?;

    let (stream, _peer_addr) = listener.accept()?;
    serve_connection(stream, keystore_dir)
}

/// Serves one connection: reads one NDJSON [`Request`] line at a time,
/// dispatches it, writes back one NDJSON [`protocol::Response`] line,
/// until the peer disconnects (EOF).
fn serve_connection(stream: UnixStream, keystore_dir: &Path) -> Result<(), EngineError> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut line = String::new();
    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            return Ok(());
        }
        let response = match serde_json::from_str::<Request>(line.trim_end()) {
            Ok(request) => dispatch_checked(&request, keystore_dir),
            Err(error) => protocol::Response::err(format!("malformed request: {error}")),
        };
        let mut encoded = serde_json::to_string(&response)?;
        encoded.push('\n');
        writer.write_all(encoded.as_bytes())?;
    }
}

/// Rejects a request whose `keystore_path` falls outside the
/// sandboxed `keystore_dir` with a clean [`protocol::Response`] error
/// (rather than letting it fall through to a Landlock `EACCES`
/// surprise inside `dispatch::dispatch`), then delegates to
/// `dispatch::dispatch` for everything else.
fn dispatch_checked(request: &Request, keystore_dir: &Path) -> protocol::Response {
    if let Some(path) = request.keystore_path.as_deref() {
        match path.parent() {
            Some(parent) if parent == keystore_dir => {}
            _ => {
                return protocol::Response::err("keystore_path is outside the sandboxed directory");
            }
        }
    }
    dispatch::dispatch(request)
}
