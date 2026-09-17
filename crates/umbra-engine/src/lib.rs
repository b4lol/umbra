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
pub fn run(
    socket_path: &Path,
    keystore_dir: &Path,
    hw_module_dir: Option<&Path>,
) -> Result<(), EngineError> {
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
    // TODO B.3 FIDO2 wiring: `hw_module_dir` (from `--hw-module-dir`,
    // present only if `umbra-gui` was launched with `--hw-module`) and
    // any `SOFTHSM2_CONF`-configured token directory (test-only — see
    // `softhsm2_tokendir_from_env`'s own docs) are BOTH learned here,
    // before the Landlock ruleset installs — Landlock can only ever
    // narrow access, never widen it again, so anything the hardware-key
    // path might need must be granted in this same call.
    let mut read_only = vec![keystore_dir];
    // Owned in this outer scope (not inside the `if let Some(...)`
    // below) purely so the `PathBuf`s they may hold outlive
    // `read_only`'s borrows of them further down. Both stay `None` —
    // and are never even looked up — when `hw_module_dir` is `None`.
    let mut softhsm2_tokendir: Option<std::path::PathBuf> = None;
    let mut softhsm2_conf_dir: Option<std::path::PathBuf> = None;
    if let Some(hw_module_dir) = hw_module_dir {
        read_only.push(hw_module_dir);
        // Empirically required (this increment's own testing, matching
        // the spec's own disclosed uncertainty about exact Landlock
        // rights for the module grant): `dlopen()`ing the PKCS#11
        // module triggers the dynamic linker to ALSO resolve the
        // module's own transitive shared-library dependencies (for the
        // SoftHSM2 module tested here: libcrypto, libsqlite3,
        // libstdc++, libz, ...) — real vendor PKCS#11 drivers have
        // their own such dependencies too, not just this project's own
        // SoftHSM2 test module. `hw_module_dir` alone (the module's own
        // parent directory) does not cover these; without this grant,
        // `dlopen()` fails closed with a Landlock-caused "Permission
        // denied" partway through resolving the module's dependency
        // chain, rather than at the module's own `open()`. These are
        // ordinary, world-readable system library directories (the OS's
        // own DAC permissions already allow any process to read them;
        // Landlock only takes away access the OS would otherwise grant,
        // it never adds any), so granting them read-only is not a
        // meaningful widening versus running unsandboxed — the same
        // reasoning this module's existing `/etc` and `/proc`/`/sys`
        // grants already rely on.
        for candidate in [
            "/usr/lib64",
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib",
            "/lib64",
            "/lib",
        ] {
            let path = std::path::Path::new(candidate);
            if path.is_dir() && !read_only.contains(&path) {
                read_only.push(path);
            }
        }
        // Test-only plumbing (see `softhsm2_tokendir_from_env`'s own
        // docs): looked up ONLY when this session was actually launched
        // with `--hw-module-dir` — never unconditionally. A session
        // that never touches hardware keys must not have its startup
        // depend on the ambient `SOFTHSM2_CONF` env var (workspace-wide
        // during `cargo test`, inherited by every spawned Engine
        // regardless of whether that particular session needs it) or
        // on whatever transient directory it happens to name existing
        // right now — `restrict_filesystem_with_exceptions` fails
        // closed on a missing exception path, so an unconditional
        // lookup here would crash every hw-agnostic Engine instance
        // whenever a concurrently-running hardware-key test's token
        // directory doesn't currently exist (found empirically while
        // implementing this very feature: an unrelated Engine spawn
        // failed startup this way while an hw test elsewhere in the
        // same test binary was mid-setup/-teardown).
        //
        // Two grants here, both READ-ONLY (also empirically confirmed —
        // a read-write grant on the token directory was tried first, on
        // the hypothesis that SoftHSM2's file-backed objectstore writes
        // lock/generation files even for read-only PKCS#11 operations,
        // but testing showed read-only suffices once the SECOND grant
        // below is present too):
        // 1. `directories.tokendir` (SoftHSM2's own on-disk token
        //    store).
        // 2. The `SOFTHSM2_CONF` file's own PARENT DIRECTORY — easy to
        //    miss since it's a wholly separate directory from the
        //    tokendir (this project's fixture lives under
        //    `crates/umbra-hwkey/tests/fixtures/`, nowhere near `/tmp`).
        //    Without it, SoftHSM2's own `C_Initialize` cannot even OPEN
        //    its config file to parse it, and fails with an opaque,
        //    generic PKCS#11 error that does not name the real cause —
        //    only SoftHSM2's own syslog output ("Could not open the
        //    config file: ...") revealed it during this increment's
        //    testing. Granted as a directory (not the file itself):
        //    `restrict_filesystem_with_exceptions`'s read-only grant
        //    always requests `ReadFile | ReadDir` together, and
        //    Landlock rejects `ReadDir` on a rule whose target isn't a
        //    directory — matches this codebase's existing convention of
        //    directory-level (never single-file) Landlock exceptions
        //    everywhere else.
        softhsm2_tokendir = softhsm2_tokendir_from_env();
        softhsm2_conf_dir = std::env::var_os("SOFTHSM2_CONF")
            .map(std::path::PathBuf::from)
            .and_then(|conf_path| conf_path.parent().map(std::path::Path::to_path_buf));
    }
    if let Some(tokendir) = softhsm2_tokendir.as_deref()
        && !read_only.contains(&tokendir)
    {
        read_only.push(tokendir);
    }
    if let Some(conf_dir) = softhsm2_conf_dir.as_deref()
        && !read_only.contains(&conf_dir)
    {
        read_only.push(conf_dir);
    }
    let _status = umbra_cli::sandbox::restrict_filesystem_with_exceptions(&[], &read_only)
        .map_err(|error| EngineError::Sandbox(error.to_string()))?;
    umbra_cli::sandbox::restrict_syscalls()
        .map_err(|error| EngineError::Sandbox(error.to_string()))?;

    let (stream, _peer_addr) = listener.accept()?;
    serve_connection(stream, keystore_dir, hw_module_dir)
}

/// Reads `SOFTHSM2_CONF`'s configured `directories.tokendir` value, if
/// the environment variable is set and the file is a parseable
/// SoftHSM2 config. Test-only plumbing: a real physical FIDO2/YubiKey
/// PKCS#11 module never sets this variable (SoftHSM2 is a SOFTWARE
/// token backed by on-disk files; this project's own hermetic
/// hardware-key tests are SoftHSM2's only user in this codebase — see
/// `crates/umbra-hwkey/tests/fixtures/softhsm2-test.conf`), so this
/// function returns `None` — a complete no-op — in a real deployment.
fn softhsm2_tokendir_from_env() -> Option<std::path::PathBuf> {
    let conf_path = std::env::var_os("SOFTHSM2_CONF")?;
    let contents = std::fs::read_to_string(conf_path).ok()?;
    contents.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        if key.trim() == "directories.tokendir" {
            Some(std::path::PathBuf::from(value.trim()))
        } else {
            None
        }
    })
}

/// Serves one connection: reads one NDJSON [`Request`] line at a time,
/// dispatches it, writes back one NDJSON [`protocol::Response`] line,
/// until the peer disconnects (EOF).
fn serve_connection(
    stream: UnixStream,
    keystore_dir: &Path,
    hw_module_dir: Option<&Path>,
) -> Result<(), EngineError> {
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
            Ok(request) => dispatch_checked(&request, keystore_dir, hw_module_dir),
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
fn dispatch_checked(
    request: &Request,
    keystore_dir: &Path,
    hw_module_dir: Option<&Path>,
) -> protocol::Response {
    if let Some(path) = request.keystore_path.as_deref() {
        match path.parent() {
            Some(parent) if parent == keystore_dir => {}
            _ => {
                return protocol::Response::err("keystore_path is outside the sandboxed directory");
            }
        }
    }
    if let Some(path) = request.hw_module.as_deref() {
        let module_dir_ok = match (path.parent(), hw_module_dir) {
            (Some(parent), Some(granted)) => parent == granted,
            _ => false,
        };
        if !module_dir_ok {
            return protocol::Response::err(
                "hw_module is outside the sandboxed directory (was --hw-module-dir set at \
                 umbra-engine startup?)",
            );
        }
    }
    dispatch::dispatch(request)
}
