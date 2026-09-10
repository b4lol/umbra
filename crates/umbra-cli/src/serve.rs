//! Inbound Tor onion-service flow (`umbra serve`, TODO A.2): the
//! PRODUCTION call site that wires the persistent-identity mechanisms
//! together —
//!
//! 1. identity seeds load ONCE (pre-sandbox), bundle rebuilt per
//!    connection via `IdentityBundle::from_seeds` (no Argon2 per peer;
//!    the per-connection ML-DSA keygen + SPK sign cost is accepted and
//!    bounded by the concurrent-stream semaphore);
//! 2. `harden_memory()` before any secret touches RAM (ADR-025);
//! 3. Landlock zero-FS with the sanctioned exceptions — the Tor
//!    storage dir (read+write: Arti's guard state + native keystore
//!    keeping the `.onion` identity stable), the group-state directories
//!    `<keystore dir>/groups` and `<keystore dir>/keypackages`
//!    (read+write: an inbound group frame is decrypted and re-persisted
//!    post-sandbox, and an inbound Welcome consumes a stored key
//!    package, TODO B.2 — deliberately those two directories ONLY, never
//!    the keystore file itself), read-only `/etc` (the libc resolver may
//!    open `resolv.conf`-family files during bootstrap; all public
//!    content), and `/dev/tty` — plus the full Seccomp allowlist;
//! 4. `TorTransport::bootstrap_persistent` + `spawn_inbound` (Vanguards-
//!    Lite pinning + hs-pow inbound hardening apply automatically);
//! 5. one session per accepted stream, branched on the leading
//!    connection-type marker byte: a PQXDH handshake continues into
//!    `receive_message` (PQXDH + Double Ratchet) with its text payload
//!    emitted as an NDJSON `text` event, while a group frame (TODO B.2)
//!    is read length-prefixed off the wire and handed to
//!    `umbra_group::inbound::process_inbound_group_frame`, emitting
//!    `group-text`/`group-joined`/`group-updated` instead.
//!
//! Honest scope: the outbound counterpart is `send --onion`
//! (`tor_send`); inbound cover frames are destroyed silently (ADR-005),
//! while idle-gap cover between sessions is v2; SMP is not run on
//! inbound streams (SAS verification is out of band). The mesh inbound
//! flow (`mesh_serve.rs`) has its own, separate accept path and still
//! rejects group frames — group receipt is Tor-only for now.

use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use umbra_crypto::keys::{IdentityBundle, IdentitySeeds};
use umbra_group::inbound::{InboundGroupEvent, process_inbound_group_frame};
use umbra_net::tor::TorTransport;

use crate::cli::CliError;

/// Upper bound for waiting until the onion descriptor is published.
const ADDRESS_WAIT: Duration = Duration::from_secs(120);

/// Capacity of the per-session result queue feeding the stdout writer.
const INBOUND_RESULT_QUEUE: usize = 32;

/// Subdirectory (under the keystore directory) holding one encrypted
/// group-state file per group — mirrors `umbra-group`'s own private
/// `GROUPS_DIR_NAME` copies (`create.rs`/`add.rs`/`send.rs`/
/// `inbound.rs`), duplicated here for the same reason they duplicate it
/// among themselves: the constant is private to each module.
const GROUPS_DIR_NAME: &str = "groups";

/// Subdirectory (under the keystore directory) holding this peer's
/// persisted key-package storage (`keypackages/store.enc`), which an
/// inbound `Welcome` reads and re-saves. Mirrors the directory half of
/// `umbra-group`'s own private `KEYPACKAGES_FILE_NAME`
/// (`keypackage.rs`/`inbound.rs`) — only the DIRECTORY is named here,
/// because that is what the sandbox grants (the store is written via a
/// same-directory temp file plus a rename, which needs rights on the
/// parent).
const KEYPACKAGES_DIR_NAME: &str = "keypackages";

/// Upper bound on EITHER length-prefixed field of one inbound group
/// frame (`group_id` and the MLS message). These lengths arrive from an
/// unauthenticated peer BEFORE any MLS-level authentication, so a
/// claimed 4 GiB must never become a 4 GiB allocation under `mlockall`.
/// 1 MiB comfortably exceeds both real cases — application messages are
/// independently capped at 64 KiB by `group::MAX_GROUP_MESSAGE`, and a
/// `Welcome` (which embeds the full ratchet tree for larger groups) is
/// still orders of magnitude below this — while staying a real, finite
/// bound.
const MAX_GROUP_FRAME_FIELD: usize = 1024 * 1024;

/// Wall-clock bound on reading ONE complete inbound group frame: a peer
/// that sends a length prefix and then stalls must not park the session
/// task forever (mirrors `umbra_net::messenger`'s own per-read
/// `READ_IDLE_TIMEOUT` value for the two-party path).
const GROUP_FRAME_READ_TIMEOUT: Duration = Duration::from_secs(300);

/// One decrypted inbound result flowing out of [`inbound_loop`] to its
/// consumer (`serve`'s NDJSON writer, or the TUI's message log).
pub enum InboundEvent {
    /// A two-party PQXDH text message (the existing behavior; payload
    /// unchanged).
    Text(Vec<u8>),
    /// A group application message decrypted for a known group.
    GroupText {
        /// Local name (file stem) of the group it belongs to.
        group_name: String,
        /// The decrypted plaintext bytes.
        plaintext: Vec<u8>,
    },
    /// This device joined a new group via an inbound `Welcome`.
    GroupJoined {
        /// Local name minted for the newly joined group.
        group_name: String,
    },
    /// A known group's membership/state advanced via an inbound Commit.
    GroupUpdated {
        /// Local name (file stem) of the updated group.
        group_name: String,
    },
}

/// The keystore material the inbound loop's group branch needs AFTER
/// the sandbox is installed: `process_inbound_group_frame` does its own
/// file I/O against `<keystore_dir>/groups/*.enc` and
/// `<keystore_dir>/keypackages/store.enc`, both of which are decrypted
/// with the keystore passphrase.
///
/// The passphrase therefore stays resident for the daemon's lifetime —
/// which it already did (`serve`/`tui` never return, and their caller
/// owns it for the whole run) — under `harden_process`'s memory locks,
/// wrapped in `Zeroizing` so it is wiped when the process tears down.
/// The keystore FILE itself is still never reopened: only `groups/` and
/// `keypackages/` are granted post-sandbox.
pub struct GroupInboundContext {
    /// Directory holding `groups/` and `keypackages/` (the keystore
    /// file's parent).
    pub keystore_dir: PathBuf,
    /// Keystore passphrase, used to decrypt group state files.
    pub passphrase: zeroize::Zeroizing<Vec<u8>>,
}

/// The keystore's parent directory — the root every Umbra-owned
/// artifact (Tor tree, peer records, group state) hangs off.
///
/// # Errors
///
/// Returns [`CliError::Keystore`] if the keystore path has no parent.
fn keystore_parent(keystore: &Path) -> Result<&Path, CliError> {
    keystore
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| CliError::Keystore("keystore path has no parent directory".into()))
}

/// Resolves the Tor storage root NEXT TO the keystore: `<keystore
/// parent>/tor`. Peer records and the Tor tree share the keystore
/// directory so a single Landlock exception covers the flow's own data.
///
/// # Errors
///
/// Returns [`CliError::Keystore`] if the keystore path has no parent.
pub fn tor_base_from_keystore(keystore: &Path) -> Result<PathBuf, CliError> {
    Ok(keystore_parent(keystore)?.join("tor"))
}

/// Builds the [`GroupInboundContext`] for `keystore`/`passphrase`
/// (pre-sandbox; the passphrase is copied into locked, zeroizing
/// memory).
///
/// # Errors
///
/// Returns [`CliError::Keystore`] if the keystore path has no parent.
pub fn group_context_from_keystore(
    keystore: &Path,
    passphrase: &[u8],
) -> Result<GroupInboundContext, CliError> {
    Ok(GroupInboundContext {
        keystore_dir: keystore_parent(keystore)?.to_path_buf(),
        passphrase: zeroize::Zeroizing::new(passphrase.to_vec()),
    })
}

/// Ensures the two directories the inbound group branch writes to EXIST
/// (`<keystore parent>/groups` and `<keystore parent>/keypackages`,
/// both `0o700`) and returns them, in the order they are handed to
/// [`crate::sandbox::restrict_filesystem_with_exceptions`]'s
/// `read_write` list.
///
/// They must exist before the ruleset is built — Landlock's `PathFd` is
/// an `O_PATH` open at rule-add time, so a missing path fails the whole
/// sandbox call closed (exactly why `tor_base` is already created
/// first). A peer may legitimately run `serve`/`tui` before ever
/// creating or joining a group, hence the create-if-missing; an empty
/// directory is a normal state and, unlike an empty store FILE, cannot
/// be mistaken for a malformed store by anything that later writes one.
///
/// # Why DIRECTORIES, never the store file itself
///
/// Both writers persist through a same-directory temp file plus an
/// atomic rename (`persistence::save_group_state`,
/// `keypackage::save_keypackage_storage`), so the create/rename rights
/// are needed on the PARENT. A regular file cannot stand in for that:
/// this exception list's right-set is directory-shaped
/// (`ReadDir|MakeDir|MakeReg|RemoveDir|RemoveFile|Refer`), which
/// Landlock rejects on a non-directory — and under this crate's
/// `CompatLevel::HardRequirement` that is a hard error, i.e. `serve`
/// and `tui` would refuse to start (pinned by
/// `tests/sandbox_landlock.rs::file_exception_path_fails_closed`).
/// Granting the keystore directory instead would re-expose the
/// two-party keystore file, so the key-package store lives in its own
/// grantable directory (`umbra-group`'s `KEYPACKAGES_FILE_NAME` is
/// `keypackages/store.enc` for exactly this reason).
///
/// # Errors
///
/// Returns [`CliError::Keystore`] if the keystore path has no parent
/// and [`CliError::Io`] if either directory cannot be created.
pub fn prepare_group_paths(keystore: &Path) -> Result<(PathBuf, PathBuf), CliError> {
    let base = keystore_parent(keystore)?;
    let groups_dir = base.join(GROUPS_DIR_NAME);
    let keypackages_dir = base.join(KEYPACKAGES_DIR_NAME);
    use std::os::unix::fs::DirBuilderExt as _;
    for dir in [&groups_dir, &keypackages_dir] {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(CliError::Io)?;
    }
    Ok((groups_dir, keypackages_dir))
}

/// Emits one NDJSON event line for the `serve` stream (the only requested
/// output of a long-running daemon; diagnostics go to stderr).
fn emit_event(event: &str, data: Option<&[u8]>) -> Result<(), CliError> {
    let mut line = format!("{{\"event\":\"{event}\"");
    if let Some(bytes) = data {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        line.push_str(&format!(",\"data\":\"{b64}\""));
    }
    line.push_str("}\n");
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(line.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(CliError::Io)
}

/// Escapes a string for inclusion in a JSON string literal: the two
/// mandatory escapes plus every control character (a group name is a
/// local file stem, so it can legitimately contain a quote or a
/// backslash — emitting it raw would produce invalid NDJSON).
fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other if other.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", u32::from(other)));
            }
            other => escaped.push(other),
        }
    }
    escaped
}

/// Builds the single NDJSON line for a decrypted group application
/// message. Split from [`emit_group_text_event`] so the exact wire text
/// is unit-testable without capturing stdout.
fn group_text_line(group_name: &str, plaintext: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(plaintext);
    format!(
        "{{\"event\":\"group-text\",\"group\":\"{}\",\"data\":\"{b64}\"}}\n",
        json_escape(group_name)
    )
}

/// Emits the `group-text` NDJSON event, which — unlike every other
/// event — carries TWO fields (the group name alongside the base64
/// payload) and so cannot go through [`emit_event`]'s single-blob
/// shape. Deliberately narrow rather than a generic multi-field
/// emitter: this is the only such event.
fn emit_group_text_event(group_name: &str, plaintext: &[u8]) -> Result<(), CliError> {
    let line = group_text_line(group_name, plaintext);
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(line.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(CliError::Io)
}

/// Runs the `serve` flow. Never returns under normal operation: it loops
/// accepting inbound sessions until the process is terminated.
///
/// # Errors
///
/// Returns [`CliError`] on keystore, sandbox, bootstrap, or onion
/// publication failure. Per-connection failures are logged to stderr and
/// the accept loop continues.
pub fn run(
    keystore: &std::path::Path,
    passphrase: &[u8],
    nickname: &str,
    pt_args: &crate::pt::PtArgs,
) -> Result<(), CliError> {
    // The operator must see the transport's privacy/trust profile
    // BEFORE anything else happens (always-on safety notice, stderr —
    // see `crate::privacy`'s module docs).
    crate::privacy::print_notice(
        &crate::privacy::profile(crate::privacy::TransportKind::Tor),
        "umbra",
    );

    // 1. Memory hardening BEFORE secrets exist (ADR-025 ordering).
    umbra_hardware::process::harden_process()?;

    // 1b. PT configuration (ADR-030): bridge lines are operational
    //     secrets read pre-sandbox alongside the keystore material.
    let pt = crate::pt::load_config(keystore, pt_args)?;

    // 2. Identity seeds load ONCE; the keystore file is never opened
    //    again (it would be denied by the sandbox below). Arc-shared so
    //    the TUI can reuse the same cores for outbound sends.
    let seeds: std::sync::Arc<IdentitySeeds> =
        std::sync::Arc::new(crate::keystore::load_seeds(keystore, passphrase)?);

    // 2b. Group state material (TODO B.2): the inbound group branch
    //     decrypts `groups/*.enc` and `keypackages/store.enc` AFTER the
    //     sandbox, so the passphrase is captured here, pre-sandbox.
    let group = std::sync::Arc::new(group_context_from_keystore(keystore, passphrase)?);

    // 3. Tor storage root and the group-state paths must EXIST before
    //    the Landlock ruleset pins the exceptions (PathFd opens each
    //    path at rule-add time).
    let tor_base = tor_base_from_keystore(keystore)?;
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&tor_base)
            .map_err(CliError::Io)?;
    }
    let (groups_dir, keypackages_dir) = prepare_group_paths(keystore)?;

    // 4. Sandbox: zero-FS + [tor tree, groups/, keypackages/, /etc
    //    read] exceptions, then the Seccomp allowlist (LAST; network
    //    family included for Arti). The grant stays NARROW on purpose:
    //    the keystore file itself is deliberately NOT reachable, so the
    //    "identity seeds are never re-read post-sandbox" invariant above
    //    still holds.
    crate::sandbox::restrict_filesystem_with_exceptions(
        &[
            tor_base.as_path(),
            groups_dir.as_path(),
            keypackages_dir.as_path(),
        ],
        // /etc is READ-ONLY: public resolver/config content only.
        &[std::path::Path::new("/etc")],
    )?;
    crate::sandbox::restrict_syscalls()?;

    // 5. Runtime + transport. `bootstrap_persistent_with_pt` roots the
    //    Arti state/cache/keystore under `tor_base` — the `.onion`
    //    identity persists across runs for this nickname — and wires the
    //    unmanaged PT proxy when configured (ADR-030).
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::Io(std::io::Error::other(format!("tokio runtime: {e}"))))?;
    runtime.block_on(async move {
        let transport_error = |error: umbra_net::TransportError| {
            CliError::Io(std::io::Error::other(format!("tor transport: {error}")))
        };
        let mut transport = TorTransport::bootstrap_persistent_with_pt(&tor_base, pt.as_ref())
            .await
            .map_err(transport_error)?;
        transport
            .spawn_inbound(nickname)
            .await
            .map_err(transport_error)?;
        let transport = std::sync::Arc::new(transport);

        let address = wait_for_address(&transport).await?;
        emit_event("ready", Some(format!("onion:{address}").as_bytes()))?;

        // Accept loop shared with the TUI; results serialize onto the
        // NDJSON stdout channel. Stdout failure is FATAL — dropping
        // inbound messages silently would be a correctness lie.
        let (results_tx, mut results_rx) =
            tokio::sync::mpsc::channel::<Result<InboundEvent, String>>(INBOUND_RESULT_QUEUE);
        let loop_handle = tokio::spawn(inbound_loop(
            transport,
            seeds,
            group,
            results_tx,
            INBOUND_RESULT_QUEUE,
        ));
        while let Some(result) = results_rx.recv().await {
            match result {
                Ok(InboundEvent::Text(plaintext)) => {
                    let plaintext = zeroize::Zeroizing::new(plaintext);
                    emit_event("text", Some(&plaintext))?;
                }
                Ok(InboundEvent::GroupText {
                    group_name,
                    plaintext,
                }) => {
                    let plaintext = zeroize::Zeroizing::new(plaintext);
                    emit_group_text_event(&group_name, &plaintext)?;
                }
                Ok(InboundEvent::GroupJoined { group_name }) => {
                    emit_event("group-joined", Some(group_name.as_bytes()))?;
                }
                Ok(InboundEvent::GroupUpdated { group_name }) => {
                    emit_event("group-updated", Some(group_name.as_bytes()))?;
                }
                Err(error) => {
                    eprintln!("umbra: inbound session failed: {error}");
                }
            }
        }
        loop_handle
            .await
            .map_err(|e| CliError::Io(std::io::Error::other(format!("accept loop: {e}"))))?
    })
}

/// Waits until the onion descriptor is published and returns the
/// address (bounded by [`ADDRESS_WAIT`]).
///
/// # Errors
///
/// Returns [`CliError::Io`] (timeout) if publication does not complete.
pub async fn wait_for_address(transport: &TorTransport) -> Result<String, CliError> {
    let started = tokio::time::Instant::now();
    let deadline = started
        .checked_add(ADDRESS_WAIT)
        .ok_or_else(|| publication_timeout("onion address publication"))?;
    loop {
        if let Some(address) = transport.onion_address() {
            return Ok(address);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(publication_timeout("onion address publication"));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Reads one length-prefixed group frame body off `stream` — the
/// remainder of a `CONNECTION_TYPE_GROUP` connection, after
/// [`umbra_net::messenger::peek_connection_type`] has consumed the
/// marker byte — and returns it EXACTLY as
/// [`process_inbound_group_frame`] expects it: `[group_id_len: u32 BE]
/// [group_id][mls_len: u32 BE][mls_bytes]`, both length prefixes
/// included verbatim (that function re-parses them itself).
///
/// Both claimed lengths are checked against [`MAX_GROUP_FRAME_FIELD`]
/// BEFORE anything is allocated or read, and the whole read is bounded
/// by [`GROUP_FRAME_READ_TIMEOUT`]: this is unauthenticated network
/// input. Every failure is a plain `String` (this connection's session
/// error), never a panic.
async fn read_group_frame<S>(stream: &mut S) -> Result<Vec<u8>, String>
where
    S: tokio::io::AsyncRead + Unpin + Send,
{
    tokio::time::timeout(GROUP_FRAME_READ_TIMEOUT, read_group_frame_unbounded(stream))
        .await
        .map_err(|_elapsed| {
            format!(
                "inbound group frame stalled for more than {}s",
                GROUP_FRAME_READ_TIMEOUT.as_secs()
            )
        })?
}

/// [`read_group_frame`] without the wall-clock bound (applied by its
/// caller, which owns the timeout so a partial read cannot leave the
/// stream half-consumed inside a retry).
async fn read_group_frame_unbounded<S>(stream: &mut S) -> Result<Vec<u8>, String>
where
    S: tokio::io::AsyncRead + Unpin + Send,
{
    use tokio::io::AsyncReadExt as _;

    let mut frame = Vec::new();
    for field in ["group id", "MLS message"] {
        let mut length_prefix = [0u8; 4];
        stream
            .read_exact(&mut length_prefix)
            .await
            .map_err(|error| format!("inbound group frame ({field} length): {error}"))?;
        let length = usize::try_from(u32::from_be_bytes(length_prefix))
            .map_err(|_error| format!("inbound group frame: {field} length exceeds usize"))?;
        if length > MAX_GROUP_FRAME_FIELD {
            return Err(format!(
                "inbound group frame: {field} length {length} exceeds the \
                 {MAX_GROUP_FRAME_FIELD}-byte ceiling"
            ));
        }
        let mut body = vec![0u8; length];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|error| format!("inbound group frame ({field}): {error}"))?;
        frame.extend_from_slice(&length_prefix);
        frame.extend_from_slice(&body);
    }
    Ok(frame)
}

/// Handles one accepted `CONNECTION_TYPE_GROUP` connection: reads its
/// frame (bounded, see [`read_group_frame`]) and processes it against
/// this peer's own keystore.
///
/// `process_inbound_group_frame` is synchronous and may block briefly
/// (Argon2id KDF + group-state file I/O). That cost is accepted here
/// for the same reason the two-party path's per-connection ML-DSA
/// keygen is (module docs): it runs in this connection's OWN spawned
/// task, bounded by the accept loop's concurrency permit.
async fn handle_group_frame<S>(
    stream: &mut S,
    group: &GroupInboundContext,
) -> Result<InboundEvent, String>
where
    S: tokio::io::AsyncRead + Unpin + Send,
{
    let frame = read_group_frame(stream).await?;
    match process_inbound_group_frame(&group.keystore_dir, &group.passphrase, &frame) {
        Ok(InboundGroupEvent::Joined { group_name }) => {
            Ok(InboundEvent::GroupJoined { group_name })
        }
        Ok(InboundGroupEvent::MembershipUpdated { group_name }) => {
            Ok(InboundEvent::GroupUpdated { group_name })
        }
        Ok(InboundGroupEvent::ApplicationMessage {
            group_name,
            plaintext,
        }) => Ok(InboundEvent::GroupText {
            group_name,
            plaintext,
        }),
        Err(error) => Err(format!("inbound group frame: {error}")),
    }
}

/// The accept loop shared by `serve` (NDJSON stdout) and the TUI
/// (message log): one session per accepted stream, each handled in its
/// OWN task (the stream's semaphore permit moves with it, keeping
/// Arti's concurrency bound intact). The leading connection-type marker
/// byte selects the path — PQXDH handshake (two-party text) or group
/// frame (TODO B.2). Every session result flows to `results_tx`;
/// session failures are contained to their connection and forwarded as
/// an already-rendered error string (the two error sources,
/// `TransportError` and `GroupError`, have no common type, and every
/// consumer only ever displays the text).
///
/// # Errors
///
/// Returns [`CliError`] on accept failures (the loop only ends on a
/// transport error or when the results channel closes).
pub async fn inbound_loop(
    transport: std::sync::Arc<TorTransport>,
    seeds: std::sync::Arc<IdentitySeeds>,
    group: std::sync::Arc<GroupInboundContext>,
    forward_tx: tokio::sync::mpsc::Sender<Result<InboundEvent, String>>,
    queue_capacity: usize,
) -> Result<(), CliError> {
    let transport_error = |error: umbra_net::TransportError| {
        CliError::Io(std::io::Error::other(format!("tor transport: {error}")))
    };
    // Internal per-session result queue; the loop forwards to the
    // caller's channel (kept distinct to avoid self-delivery loops).
    let (session_tx, mut session_rx) = tokio::sync::mpsc::channel(queue_capacity);
    loop {
        tokio::select! {
            accepted = transport.next_inbound_stream() => {
                let (mut stream, permit) = accepted.map_err(transport_error)?;
                let bundle = IdentityBundle::from_seeds(&seeds);
                let tx = session_tx.clone();
                let group = std::sync::Arc::clone(&group);
                tokio::spawn(async move {
                    let _permit = permit; // held for the whole session
                    // Leading connection-type marker: two-party PQXDH
                    // handshake, or a group (PQ-MLS) frame (TODO B.2).
                    let result = match umbra_net::messenger::peek_connection_type(&mut stream)
                        .await
                    {
                        Ok(umbra_net::messenger::ConnectionType::PqxdhHandshake) => {
                            umbra_net::messenger::receive_message(bundle, &mut stream)
                                .await
                                .map(InboundEvent::Text)
                                .map_err(|error| error.to_string())
                        }
                        Ok(umbra_net::messenger::ConnectionType::GroupFrame) => {
                            handle_group_frame(&mut stream, &group).await
                        }
                        Err(error) => Err(error.to_string()),
                    };
                    let _ = tx.send(result).await;
                });
            }
            result = session_rx.recv() => {
                match result {
                    // The event MOVES to the consumer: unlike the previous
                    // `Zeroizing` round-trip (which wiped a temporary copy
                    // of a payload it had just cloned), no second copy of
                    // any plaintext exists in this loop to wipe.
                    Some(Ok(event)) => {
                        if forward_tx.send(Ok(event)).await.is_err() {
                            return Ok(()); // consumer gone: stop the loop
                        }
                    }
                    Some(Err(error)) => {
                        let _ = forward_tx.send(Err(error)).await;
                    }
                    None => {
                        return Err(CliError::Io(std::io::Error::other(
                            "inbound session queue closed",
                        )));
                    }
                }
            }
        }
    }
}

/// Internal timeout error for the publication wait.
fn publication_timeout(operation: &str) -> CliError {
    CliError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("{operation} timed out"),
    ))
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;

    use tokio::io::{AsyncWrite, AsyncWriteExt as _, DuplexStream};
    use tokio::sync::Mutex;
    use umbra_group::GroupError;
    use umbra_group::delivery::PeerTransportAddress;
    use umbra_group::{add, create, keypackage, send};

    use super::*;

    /// Boxed, `Send` error result — this workspace denies
    /// `unwrap`/`expect` even in test code.
    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// `?`-friendly alias for helpers returning a value.
    type TestResult2<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    /// The future type returned by [`single_use_stream`]'s closure
    /// (mirrors `umbra-group`'s own test helpers of the same shape).
    type ConnectFuture = Pin<
        Box<
            dyn std::future::Future<Output = Result<Box<dyn AsyncWrite + Unpin + Send>, GroupError>>
                + Send,
        >,
    >;

    /// Hands out one end of a `tokio::io::duplex` pair from an `Fn`
    /// closure (mirrors `umbra-group`'s `add`/`send` test helpers).
    fn single_use_stream(stream: DuplexStream) -> impl Fn(&PeerTransportAddress) -> ConnectFuture {
        let slot = Arc::new(Mutex::new(Some(stream)));
        move |_address: &PeerTransportAddress| {
            let slot = Arc::clone(&slot);
            Box::pin(async move {
                let taken = slot.lock().await.take().ok_or_else(|| {
                    GroupError::Malformed("connect() called more than once in this test".into())
                })?;
                Ok(Box::new(taken) as Box<dyn AsyncWrite + Unpin + Send>)
            })
        }
    }

    /// Sorted names of the direct entries of `dir` (used to prove that
    /// a code path wrote nothing new at the keystore-directory level).
    fn entries(dir: &Path) -> TestResult2<Vec<String>> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            names.push(entry?.file_name().to_string_lossy().to_string());
        }
        names.sort();
        Ok(names)
    }

    /// Fresh temp dir, unique per test/label pair.
    fn temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "umbra-cli-serve-test-{}-{label}",
            std::process::id()
        ))
    }

    /// Drives one accepted connection through EXACTLY the branch
    /// `inbound_loop` takes: `peek_connection_type` first, then (for a
    /// group frame) [`handle_group_frame`]. Asserts the marker routed to
    /// the group path rather than the PQXDH one.
    async fn route_connection<S>(
        stream: &mut S,
        group: &GroupInboundContext,
    ) -> Result<InboundEvent, String>
    where
        S: tokio::io::AsyncRead + Unpin + Send,
    {
        match umbra_net::messenger::peek_connection_type(stream).await {
            Ok(umbra_net::messenger::ConnectionType::GroupFrame) => {
                handle_group_frame(stream, group).await
            }
            Ok(umbra_net::messenger::ConnectionType::PqxdhHandshake) => {
                Err("expected a group frame, got a PQXDH handshake marker".to_string())
            }
            Err(error) => Err(error.to_string()),
        }
    }

    /// Serves `bytes` as one inbound connection: the writer half is
    /// dropped after the write, so a truncated frame surfaces as EOF
    /// rather than hanging the test.
    fn connection_carrying(bytes: Vec<u8>) -> DuplexStream {
        let (reader, mut writer) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let _ = writer.write_all(&bytes).await;
            let _ = writer.shutdown().await;
        });
        reader
    }

    /// Builds a real 2-member group (Alice creates, Bob is added via the
    /// real `add_member` flow) and returns Bob's captured, marker-
    /// stripped Welcome frame. Mirrors `umbra-group`'s own fixtures.
    async fn welcome_frame_for_bob(
        alice_dir: &Path,
        alice_pw: &[u8],
        bob_dir: &Path,
        bob_pw: &[u8],
    ) -> TestResult2<Vec<u8>> {
        create::create_group(alice_dir, alice_pw, "cell")?;
        let bob_kp = keypackage::export_keypackage(bob_dir, bob_pw)?;
        let (bob_member_side, bob_observer_side) = tokio::io::duplex(64 * 1024);
        let connect = single_use_stream(bob_member_side);
        let peer_lookup = move |name: &str| {
            if name == "bob" {
                Some(PeerTransportAddress::Mesh("bob-mesh".to_string()))
            } else {
                None
            }
        };
        add::add_member(
            alice_dir,
            alice_pw,
            "cell",
            "bob",
            &bob_kp,
            peer_lookup,
            connect,
        )
        .await?;
        capture_frame(bob_observer_side).await
    }

    /// Reads a whole delivered connection (marker byte INCLUDED — the
    /// inbound loop's own entry point consumes it) off `stream`.
    async fn capture_connection<S>(mut stream: S) -> TestResult2<Vec<u8>>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        use tokio::io::AsyncReadExt as _;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        Ok(buf)
    }

    /// Same, minus the leading `CONNECTION_TYPE_GROUP` marker byte.
    async fn capture_frame<S>(stream: S) -> TestResult2<Vec<u8>>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut bytes = capture_connection(stream).await?;
        if bytes.first().copied() != Some(umbra_net::messenger::CONNECTION_TYPE_GROUP) {
            return Err("delivered connection did not start with the group marker byte".into());
        }
        bytes.remove(0);
        Ok(bytes)
    }

    /// A `GroupFrame`-marked connection carrying a REAL Welcome routes
    /// to `process_inbound_group_frame` and yields `GroupJoined`.
    #[tokio::test]
    async fn group_frame_welcome_routes_to_a_joined_event() -> TestResult {
        let alice_dir = temp_dir("welcome-alice");
        let bob_dir = temp_dir("welcome-bob");
        std::fs::create_dir_all(&alice_dir)?;
        std::fs::create_dir_all(&bob_dir)?;
        let (alice_pw, bob_pw) = (b"alice-pw".as_slice(), b"bob-pw".as_slice());

        let welcome = welcome_frame_for_bob(&alice_dir, alice_pw, &bob_dir, bob_pw).await?;
        let mut connection = {
            let mut bytes = vec![umbra_net::messenger::CONNECTION_TYPE_GROUP];
            bytes.extend_from_slice(&welcome);
            connection_carrying(bytes)
        };

        let group = GroupInboundContext {
            keystore_dir: bob_dir.clone(),
            passphrase: zeroize::Zeroizing::new(bob_pw.to_vec()),
        };
        let event = route_connection(&mut connection, &group).await?;
        let InboundEvent::GroupJoined { group_name } = event else {
            return Err("expected a GroupJoined event".into());
        };
        assert!(
            bob_dir
                .join("groups")
                .join(format!("{group_name}.enc"))
                .exists(),
            "the joined group's state file must have been persisted"
        );

        std::fs::remove_dir_all(&alice_dir)?;
        std::fs::remove_dir_all(&bob_dir)?;
        Ok(())
    }

    /// A REAL application message (built with `send_group_message`)
    /// routes to `GroupText` with the exact plaintext and group name.
    #[tokio::test]
    async fn group_frame_application_message_routes_to_group_text() -> TestResult {
        let alice_dir = temp_dir("appmsg-alice");
        let bob_dir = temp_dir("appmsg-bob");
        std::fs::create_dir_all(&alice_dir)?;
        std::fs::create_dir_all(&bob_dir)?;
        let (alice_pw, bob_pw) = (b"alice-pw".as_slice(), b"bob-pw".as_slice());
        let group = GroupInboundContext {
            keystore_dir: bob_dir.clone(),
            passphrase: zeroize::Zeroizing::new(bob_pw.to_vec()),
        };

        // Bob joins for real, through the branch under test.
        let welcome = welcome_frame_for_bob(&alice_dir, alice_pw, &bob_dir, bob_pw).await?;
        let mut join_connection = {
            let mut bytes = vec![umbra_net::messenger::CONNECTION_TYPE_GROUP];
            bytes.extend_from_slice(&welcome);
            connection_carrying(bytes)
        };
        let InboundEvent::GroupJoined {
            group_name: bob_group_name,
        } = route_connection(&mut join_connection, &group).await?
        else {
            return Err("expected a GroupJoined event".into());
        };

        // Alice sends a real group message; Bob's delivered connection
        // (marker byte included) is replayed into the same branch.
        let plaintext = b"hello group from alice".to_vec();
        let delivered = {
            let (bob_member_side, bob_observer_side) = tokio::io::duplex(64 * 1024);
            let connect = single_use_stream(bob_member_side);
            let peer_lookup = move |name: &str| {
                if name == "bob" {
                    Some(PeerTransportAddress::Mesh("bob-mesh".to_string()))
                } else {
                    None
                }
            };
            send::send_group_message(
                &alice_dir,
                alice_pw,
                "cell",
                &plaintext,
                peer_lookup,
                connect,
            )
            .await?;
            capture_connection(bob_observer_side).await?
        };
        let mut connection = connection_carrying(delivered);

        let event = route_connection(&mut connection, &group).await?;
        let InboundEvent::GroupText {
            group_name,
            plaintext: received,
        } = event
        else {
            return Err("expected a GroupText event".into());
        };
        assert_eq!(group_name, bob_group_name);
        assert_eq!(received, plaintext);

        std::fs::remove_dir_all(&alice_dir)?;
        std::fs::remove_dir_all(&bob_dir)?;
        Ok(())
    }

    /// An attacker-controlled length prefix beyond the ceiling is
    /// rejected cleanly — no allocation, no panic, no hang (the frame
    /// body is never even sent).
    #[tokio::test]
    async fn oversized_length_prefix_is_rejected_cleanly() -> TestResult {
        let oversized = u32::try_from(MAX_GROUP_FRAME_FIELD)?
            .checked_add(1)
            .ok_or("ceiling + 1 overflows u32")?;
        for prefix in [
            // Oversized group id length (first field).
            oversized.to_be_bytes().to_vec(),
            // Plausible group id, oversized MLS message length.
            {
                let mut bytes = 4u32.to_be_bytes().to_vec();
                bytes.extend_from_slice(b"gid1");
                bytes.extend_from_slice(&u32::MAX.to_be_bytes());
                bytes
            },
        ] {
            let mut connection = connection_carrying(prefix);
            let error = read_group_frame(&mut connection)
                .await
                .err()
                .ok_or("an oversized length prefix must be rejected")?;
            assert!(
                error.contains("exceeds the"),
                "expected a ceiling rejection, got: {error}"
            );
        }
        Ok(())
    }

    /// A truncated frame ends the session with a clean error rather
    /// than a panic or an endless wait.
    #[tokio::test]
    async fn truncated_group_frame_is_a_clean_error() -> TestResult {
        let mut connection = connection_carrying(vec![0u8, 0u8, 0u8]);
        assert!(read_group_frame(&mut connection).await.is_err());
        Ok(())
    }

    /// The `group-text` line carries both fields, and a group name with
    /// JSON metacharacters stays valid JSON.
    #[test]
    fn group_text_line_is_well_formed() {
        let line = group_text_line("cell", b"hi");
        assert_eq!(
            line,
            "{\"event\":\"group-text\",\"group\":\"cell\",\"data\":\"aGk\"}\n"
        );
        let quoted = group_text_line("a\"b\\c\nd", b"");
        assert!(
            quoted.starts_with("{\"event\":\"group-text\",\"group\":\"a\\\"b\\\\c\\nd\","),
            "unescaped group name in: {quoted}"
        );
    }

    /// Both sandbox exception DIRECTORIES are created if missing
    /// (Landlock's `PathFd` requires them to exist) and reported back
    /// for the `read_write` list — and no store FILE is pre-created:
    /// `export_keypackage` branches on the store file's mere existence
    /// and would reject an empty one as malformed, so an empty
    /// directory (not an empty file) is the correct "nothing here yet"
    /// state.
    #[test]
    fn prepare_group_paths_creates_both_directories() -> TestResult {
        let dir = temp_dir("sandbox-paths");
        std::fs::create_dir_all(&dir)?;
        let keystore = dir.join("keystore.enc");

        let (groups_dir, keypackages_dir) = prepare_group_paths(&keystore)?;
        assert_eq!(groups_dir, dir.join("groups"));
        assert_eq!(keypackages_dir, dir.join("keypackages"));
        assert!(groups_dir.is_dir());
        assert!(keypackages_dir.is_dir());
        assert!(!keypackages_dir.join("store.enc").exists());

        // Idempotent on existing directories.
        let again = prepare_group_paths(&keystore)?;
        assert_eq!(again, (groups_dir, keypackages_dir));

        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    /// The Welcome path writes ONLY inside the two granted directories:
    /// after a real inbound Welcome, the keystore directory contains
    /// nothing new beside `groups/` and `keypackages/` (plus the group
    /// identity this peer already wrote when it exported its key
    /// package, pre-sandbox). This is what makes the sandbox exception
    /// set sufficient rather than merely plausible.
    #[tokio::test]
    async fn welcome_path_writes_only_inside_the_granted_directories() -> TestResult {
        let alice_dir = temp_dir("granted-alice");
        let bob_dir = temp_dir("granted-bob");
        std::fs::create_dir_all(&alice_dir)?;
        std::fs::create_dir_all(&bob_dir)?;
        let (alice_pw, bob_pw) = (b"alice-pw".as_slice(), b"bob-pw".as_slice());

        let welcome = welcome_frame_for_bob(&alice_dir, alice_pw, &bob_dir, bob_pw).await?;
        // Exactly what `serve`/`tui` do before sandboxing: both granted
        // directories exist up front (`process_welcome`'s own
        // `create_dir_all(groups/)` is then a no-op, which is what makes
        // it survive the sandbox — pinned separately in
        // `tests/sandbox_landlock.rs`).
        let _prepared = prepare_group_paths(&bob_dir.join("keystore.enc"))?;
        // Snapshot AFTER that and after the pre-sandbox
        // `export_keypackage`, so only what the Welcome itself writes is
        // compared.
        let before = entries(&bob_dir)?;

        let mut connection = {
            let mut bytes = vec![umbra_net::messenger::CONNECTION_TYPE_GROUP];
            bytes.extend_from_slice(&welcome);
            connection_carrying(bytes)
        };
        let group = GroupInboundContext {
            keystore_dir: bob_dir.clone(),
            passphrase: zeroize::Zeroizing::new(bob_pw.to_vec()),
        };
        let InboundEvent::GroupJoined { .. } = route_connection(&mut connection, &group).await?
        else {
            return Err("expected a GroupJoined event".into());
        };

        assert_eq!(
            entries(&bob_dir)?,
            before,
            "the Welcome path must not create anything directly in the keystore \
             directory: everything it writes belongs under groups/ or keypackages/"
        );
        assert!(bob_dir.join("keypackages").join("store.enc").is_file());

        std::fs::remove_dir_all(&alice_dir)?;
        std::fs::remove_dir_all(&bob_dir)?;
        Ok(())
    }
}
