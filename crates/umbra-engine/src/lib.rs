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
    tor_dir: &Path,
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
    // `/etc` READ-ONLY mirrors `umbra serve`'s own grant
    // (`crates/umbra-cli/src/serve.rs`): Arti's fs-mistrust consults the
    // passwd/group databases (`getpwuid` → `/etc/passwd`) when verifying
    // the Tor state tree's ownership, and the libc resolver may open
    // public configuration files there during bootstrap — public,
    // world-readable config content only.
    let mut read_only = vec![keystore_dir, std::path::Path::new("/etc")];
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
    // TODO B.3 GUI messaging design, Phase 1: `keystore_dir/peers` must
    // exist and be READ-WRITE before Landlock installs (it can only
    // narrow access afterward, never widen it later) — `"pair_confirm"`
    // writes new peer-record files here for the rest of this
    // connection's life, and `"list_peers"`/`"pair_import"` read them
    // back. Unconditional (unlike the hardware-key grants above): every
    // session may pair a peer, not just hardware-key-gated ones.
    let peers_dir = keystore_dir.join("peers");
    std::fs::create_dir_all(&peers_dir)?;
    // TODO B.3 GUI messaging design, Phase 2: `tor_dir` must exist and
    // be READ-WRITE before Landlock installs (it can only narrow
    // access afterward) — the background bootstrap task spawned after
    // a successful unlock (below) persists the onion service's own
    // identity keys and descriptor cache here for the rest of this
    // connection's life. Unconditional, same reasoning as `peers_dir`
    // above: every session may start messaging. Created 0700 (the tree
    // holds the onion-service identity key at rest), mirroring `umbra
    // serve`'s `tor_base` creation in `crates/umbra-cli/src/serve.rs` —
    // Arti's fs-mistrust refuses a lax tree.
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(tor_dir)?;
    }
    let _status = umbra_cli::sandbox::restrict_filesystem_with_exceptions(
        &[peers_dir.as_path(), tor_dir],
        &read_only,
    )
    .map_err(|error| EngineError::Sandbox(error.to_string()))?;
    umbra_cli::sandbox::restrict_syscalls()
        .map_err(|error| EngineError::Sandbox(error.to_string()))?;

    let (stream, _peer_addr) = listener.accept()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| EngineError::Io(std::io::Error::other(error.to_string())))?;
    runtime.block_on(serve_connection(
        stream,
        keystore_dir,
        hw_module_dir,
        tor_dir.to_path_buf(),
    ))
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

/// Serves one connection: reads one NDJSON [`Request`] line at a
/// time, dispatches it, writes back one NDJSON line, until the peer
/// disconnects (EOF). Before the first successful `"unlock"`, every
/// response is a bare, untagged [`protocol::Response`] line, exactly
/// as before TODO B.3 GUI messaging design's Phase 2. On a
/// SUCCESSFUL `"unlock"`, this function spawns a background Tor
/// bootstrap task (writing the `"ready"` [`protocol::SessionLine`]
/// event once bootstrap completes) and, from that point on, wraps
/// EVERY later response in a tagged [`protocol::SessionLine`] too —
/// matching the spec's "in the session phase, every line the Engine
/// writes is tagged" rule for all five session-phase ops, not just
/// the new `"send"` stub.
///
/// A dedicated writer task owns the socket's write half exclusively
/// (fed by an internal channel), so both this loop's own responses
/// and the background bootstrap task's unprompted `"ready"` event can
/// write without racing each other.
///
/// Every exit path (EOF, a read/JSON-encode error, or the writer
/// task's own receiver having already closed) funnels through the
/// same `loop { ... break Err(_)/Ok(()) }` structure and shared
/// cleanup tail below — matching Task 2's own fixed version, whose
/// first draft skipped this on early-return paths (write failures
/// silently swallowed, `writer_handle` not always awaited) and had to
/// be corrected in a second round. This version has MORE exit paths
/// than Task 2's (the pre-session/session-phase branch adds two more
/// `line_tx.send` call sites), so preserving "every path breaks out
/// of the loop rather than returning early" is what keeps `drop
/// (line_tx)` / `writer_handle.await` unconditional here too.
async fn serve_connection(
    stream: UnixStream,
    keystore_dir: &Path,
    hw_module_dir: Option<&Path>,
    tor_dir: std::path::PathBuf,
) -> Result<(), EngineError> {
    stream.set_nonblocking(true)?;
    let tokio_stream = tokio::net::UnixStream::from_std(stream)?;
    let (read_half, write_half) = tokio_stream.into_split();
    let mut reader = tokio::io::BufReader::new(read_half);

    // BOUNDED, not `unbounded_channel`: this channel carries both this
    // loop's own responses AND unprompted events from the background
    // bootstrap/inbound-accept task (`run_tor_bootstrap`), which has
    // no other backpressure signal of its own. An unbounded channel
    // would let a GUI that's slow to read grow this process's memory
    // without limit.
    //
    // Backpressure (`.send(...).await`), not drop-on-full, is the
    // correct choice here — traced deliberately, not assumed: EVERY
    // line on this channel either answers a specific `request_id`
    // (which `umbra-gui`'s `session_request` blocks on, unbounded, no
    // timeout) or is an event the GUI has no other way to learn about
    // (`ready`/`inbound-text`/`session-error`). Silently dropping a
    // "response" line would hang that caller forever — reintroducing
    // exactly the freeze this same fix pass closes on the GUI side
    // (see `engine_client.rs`'s `ConnectionLost`) — and dropping an
    // event line would lose a message with no trace. Blocking the
    // sender instead cannot deadlock: the only consumer is
    // `writer_handle` below, a plain forward-to-socket loop with no
    // dependency back on this read loop or on `run_tor_bootstrap`, so
    // backpressure here only ever slows the producer down to the
    // GUI's own read rate — it never cycles back on itself.
    let (line_tx, mut line_rx) = tokio::sync::mpsc::channel::<String>(LINE_QUEUE_CAPACITY);
    let writer_handle: tokio::task::JoinHandle<Result<(), std::io::Error>> =
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt as _;
            let mut write_half = write_half;
            while let Some(line) = line_rx.recv().await {
                write_half.write_all(line.as_bytes()).await?;
            }
            Ok(())
        });

    let mut session = dispatch::Session::default();
    let mut session_started = false;
    // Filled by the background bootstrap task once Tor is ready
    // (TODO B.3 GUI messaging design, Phase 3): `"send"` ops read the
    // shared transport from here rather than owning a second
    // bootstrapped client.
    let transport_cell = std::sync::Arc::new(tokio::sync::OnceCell::<
        std::sync::Arc<umbra_net::tor::TorTransport>,
    >::new());
    let mut read_buf = String::new();
    let loop_result: Result<(), EngineError> = loop {
        read_buf.clear();
        use tokio::io::AsyncBufReadExt as _;
        let bytes_read = match reader.read_line(&mut read_buf).await {
            Ok(n) => n,
            Err(error) => break Err(EngineError::Io(error)),
        };
        if bytes_read == 0 {
            break Ok(());
        }
        let request = match serde_json::from_str::<Request>(read_buf.trim_end()) {
            Ok(request) => request,
            Err(error) => {
                // A malformed line can't carry a trustworthy
                // request_id, so it always gets a bare, untagged
                // Response, regardless of session phase.
                let response = protocol::Response::err(format!("malformed request: {error}"));
                let encoded = match serde_json::to_string(&response) {
                    Ok(mut encoded) => {
                        encoded.push('\n');
                        encoded
                    }
                    Err(error) => break Err(EngineError::Json(error)),
                };
                if line_tx.send(encoded).await.is_err() {
                    break Ok(());
                }
                continue;
            }
        };
        let request_id = request.request_id;
        let is_unlock = request.op == "unlock";
        // Phase 3 fix (this review pass): `"send"` awaits a bounded
        // (up to ~120 s) onion connect, so it must NOT be awaited
        // inline here — doing so used to stall this WHOLE read loop
        // (including every OTHER in-flight request on this same
        // connection, none of which have a timeout on the GUI side
        // either) for as long as the connect takes. Spawn it instead:
        // the spawned task writes its own tagged (or, pre-session,
        // bare) response line through the SAME `line_tx` every other
        // response already goes through, using the existing
        // `request_id` correlation the GUI's `session_request` relies
        // on — an out-of-order response is already handled correctly
        // by that mechanism, this just produces one. Only an OWNED
        // `peers_dir` (never the whole `Session`, which holds secret
        // identity/passphrase material) and a CLONED `Arc<TorTransport>`
        // cross into the spawned task.
        if request.op == "send" {
            let session_started_at_request = session_started;
            let peers_dir = session.peers_dir().map(Path::to_path_buf);
            let transport = transport_cell.get().cloned();
            let request_for_send = request;
            let send_line_tx = line_tx.clone();
            tokio::spawn(async move {
                let response = dispatch::dispatch_async(
                    &request_for_send,
                    peers_dir.as_deref(),
                    transport.as_ref(),
                )
                .await;
                let encoded = if session_started_at_request {
                    serde_json::to_string(&protocol::SessionLine::from_response(
                        request_id, response,
                    ))
                } else {
                    serde_json::to_string(&response)
                };
                if let Ok(mut encoded) = encoded {
                    encoded.push('\n');
                    let _ = send_line_tx.send(encoded).await;
                }
                // A JSON-encode failure or a closed `line_tx` here has
                // no loop left to `break` out of (this is a detached
                // task) — silently dropping is the correct terminal
                // behavior, mirroring every other `Err(_) => return`/
                // `continue` swallow already in this file for the
                // same "never expected in practice, and there is no
                // right corrective action anyway" reason.
            });
            continue;
        }
        let response = dispatch_checked(&request, keystore_dir, hw_module_dir, &mut session);

        if session_started {
            // Session phase: every response is tagged.
            let session_line = protocol::SessionLine::from_response(request_id, response);
            let encoded = match serde_json::to_string(&session_line) {
                Ok(mut encoded) => {
                    encoded.push('\n');
                    encoded
                }
                Err(error) => break Err(EngineError::Json(error)),
            };
            if line_tx.send(encoded).await.is_err() {
                break Ok(());
            }
        } else {
            // Pre-session: untagged, exactly as before Phase 2.
            let response_ok = response.ok;
            let encoded = match serde_json::to_string(&response) {
                Ok(mut encoded) => {
                    encoded.push('\n');
                    encoded
                }
                Err(error) => break Err(EngineError::Json(error)),
            };
            if line_tx.send(encoded).await.is_err() {
                break Ok(());
            }
            // Captured before encoding (rather than re-reading
            // `response.ok` here) purely for symmetry with the
            // session-phase branch above, which moves `response` into
            // `SessionLine::from_response`.
            if is_unlock && response_ok {
                session_started = true;
                let bootstrap_tor_dir = tor_dir.clone();
                let bootstrap_line_tx = line_tx.clone();
                let bootstrap_transport_cell = transport_cell.clone();
                let inbound_material = session.inbound_material();
                tokio::spawn(async move {
                    run_tor_bootstrap(
                        bootstrap_tor_dir,
                        bootstrap_line_tx,
                        bootstrap_transport_cell,
                        inbound_material,
                    )
                    .await;
                });
            }
        }
    };

    drop(line_tx);
    let writer_result = writer_handle.await;

    loop_result?;
    match writer_result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(io_error)) => Err(EngineError::Io(io_error)),
        // The writer task can only panic on a bug this workspace's
        // own lints already forbid (no unwrap/expect/panic in
        // non-test code) — treated as a clean exit rather than
        // inventing a new EngineError variant for an unreachable case.
        Err(_join_error) => Ok(()),
    }
}

/// Inbound-event queue capacity for the engine's accept loop (mirrors
/// `tui.rs`'s `SESSION_QUEUE`/`serve.rs`'s `INBOUND_RESULT_QUEUE`,
/// both 32).
const INBOUND_QUEUE_CAPACITY: usize = 32;

/// Capacity of `serve_connection`'s own `line_tx`/`line_rx` channel
/// (see its construction site's own doc comment for why this is
/// bounded, and why backpressure rather than drop-on-full). Mirrors
/// [`INBOUND_QUEUE_CAPACITY`]'s own precedent.
const LINE_QUEUE_CAPACITY: usize = 32;

/// Bootstraps Tor under `tor_dir`, publishes the shared transport into
/// `transport_cell` (Phase 3: `"send"` ops use it), emits the
/// `"ready"` event, then runs the inbound accept loop for the rest of
/// the session (Phase 4): decrypted two-party texts become
/// `"inbound-text"` events and per-session/loop failures become
/// `"session-error"` events (this closes Phase 2's documented gap of
/// bootstrap failures being stderr-only). Group (PQ-MLS) inbound
/// events are received by the shared loop but not forwarded — group
/// chat is a tracked, separate GUI increment (TODO B.3 GUI messaging
/// design, "out of scope").
async fn run_tor_bootstrap(
    tor_dir: std::path::PathBuf,
    line_tx: tokio::sync::mpsc::Sender<String>,
    transport_cell: std::sync::Arc<
        tokio::sync::OnceCell<std::sync::Arc<umbra_net::tor::TorTransport>>,
    >,
    inbound_material: Option<(
        umbra_crypto::keys::IdentitySeeds,
        umbra_cli::group_inbound::GroupInboundContext,
    )>,
) {
    use base64::Engine as _;

    // Fixed, not operator-configurable: the Engine's onion-service
    // identity lives under `tor_dir`, which is already scoped
    // per-keystore (one `keystore_dir/tor` per identity) — the
    // nickname only needs to be a valid identifier WITHIN that
    // directory, not globally unique or user-visible.
    const ENGINE_ONION_NICKNAME: &str = "umbra-gui";

    let mut transport =
        match umbra_net::tor::TorTransport::bootstrap_persistent_with_pt(&tor_dir, None).await {
            Ok(transport) => transport,
            Err(error) => {
                emit_session_error(&line_tx, format!("Tor bootstrap failed: {error}")).await;
                return;
            }
        };
    if let Err(error) = transport.spawn_inbound(ENGINE_ONION_NICKNAME).await {
        emit_session_error(&line_tx, format!("onion inbound service failed: {error}")).await;
        return;
    }
    let address = match umbra_cli::serve::wait_for_address(&transport).await {
        Ok(address) => address,
        Err(error) => {
            emit_session_error(
                &line_tx,
                format!("onion address publication failed: {error}"),
            )
            .await;
            return;
        }
    };
    let transport = std::sync::Arc::new(transport);
    // Publish the transport BEFORE the ready event: a client that
    // reacts to `"ready"` with an immediate `"send"` must already find
    // it here.
    let _ = transport_cell.set(transport.clone());
    let session_line = protocol::SessionLine::ready(address);
    let Ok(mut encoded) = serde_json::to_string(&session_line) else {
        return;
    };
    encoded.push('\n');
    let _ = line_tx.send(encoded).await;

    // Phase 4: the inbound accept loop. `inbound_material` is `Some`
    // on every real unlock; `None` is unreachable (unlock populates it
    // before the ready event can exist) but handled without a panic
    // per this workspace's lints.
    let Some((seeds, group_context)) = inbound_material else {
        emit_session_error(
            &line_tx,
            "inbound loop material missing after unlock".to_string(),
        )
        .await;
        return;
    };
    let (inbound_tx, mut inbound_rx) = tokio::sync::mpsc::channel::<
        Result<umbra_cli::group_inbound::InboundEvent, String>,
    >(INBOUND_QUEUE_CAPACITY);
    let loop_handle = tokio::spawn(umbra_cli::serve::inbound_loop(
        transport,
        std::sync::Arc::new(seeds),
        std::sync::Arc::new(group_context),
        inbound_tx,
        INBOUND_QUEUE_CAPACITY,
    ));
    while let Some(result) = inbound_rx.recv().await {
        let event_line = match result {
            Ok(umbra_cli::group_inbound::InboundEvent::Text(plaintext)) => {
                let encoded_text =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&plaintext);
                Some(protocol::SessionLine::inbound_text(encoded_text))
            }
            Ok(
                umbra_cli::group_inbound::InboundEvent::GroupText { .. }
                | umbra_cli::group_inbound::InboundEvent::GroupJoined { .. }
                | umbra_cli::group_inbound::InboundEvent::GroupUpdated { .. }
                | umbra_cli::group_inbound::InboundEvent::GroupRosterSynced { .. },
            ) => None, // group chat: separate, tracked GUI increment
            Err(error) => Some(protocol::SessionLine::session_error(error)),
        };
        let Some(event_line) = event_line else {
            continue;
        };
        let Ok(mut encoded) = serde_json::to_string(&event_line) else {
            continue;
        };
        encoded.push('\n');
        if line_tx.send(encoded).await.is_err() {
            return; // GUI side gone
        }
    }
    // The forward channel closed — the accept loop ended; surface its
    // own terminal error, if any.
    if let Ok(Err(error)) = loop_handle.await {
        emit_session_error(&line_tx, format!("inbound loop ended: {error}")).await;
    }
}

/// Encodes and sends one `"session-error"` [`protocol::SessionLine`]
/// through `line_tx`, also logging it to stderr (this closes Phase
/// 2's documented gap of bootstrap failures being stderr-only, while
/// keeping a local trace too). A plain `async fn` rather than a
/// shared closure over `line_tx`: [`run_tor_bootstrap`]'s several
/// call sites all `.await` a BOUNDED channel send now (see
/// `line_tx`'s own construction site in `serve_connection` for why
/// backpressure, not drop, is correct here), and async closures are
/// more ceremony than a small free function for the same effect.
async fn emit_session_error(line_tx: &tokio::sync::mpsc::Sender<String>, message: String) {
    eprintln!("umbra-engine: {message}");
    let Ok(mut encoded) = serde_json::to_string(&protocol::SessionLine::session_error(message))
    else {
        return;
    };
    encoded.push('\n');
    let _ = line_tx.send(encoded).await;
}

/// Rejects a request whose `keystore_path` falls outside the
/// sandboxed `keystore_dir` with a clean [`protocol::Response`] error
/// (rather than letting it fall through to a Landlock `EACCES`
/// surprise inside `dispatch::dispatch`), then delegates to
/// `dispatch::dispatch` (threading this connection's `session`) for
/// everything else.
fn dispatch_checked(
    request: &Request,
    keystore_dir: &Path,
    hw_module_dir: Option<&Path>,
    session: &mut dispatch::Session,
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
    dispatch::dispatch(request, session)
}
