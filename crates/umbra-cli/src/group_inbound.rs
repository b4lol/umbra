//! Transport-agnostic inbound group-frame handling (TODO B.2, TODO
//! B.2.4): originally part of `serve.rs` (Tor), extracted here because
//! `serve.rs` is `#[cfg(feature = "tor")]`-gated while this logic is
//! not Tor-specific at all — `mesh_serve.rs` (`mesh` feature) and
//! `umbra-nym-cli` (a separate crate that may not enable `tor`) both
//! need it too. This module has NO feature gate: it depends only on
//! `umbra_group`, already an unconditional dependency of this crate.
//!
//! `process_inbound_group_frame` (from `umbra_group::inbound`) is the
//! actual protocol logic; everything here is READ-THE-WIRE-FORMAT,
//! CALL-IT, and NDJSON-EVENT-SHAPING plumbing shared by every
//! transport that can carry a `CONNECTION_TYPE_GROUP` connection.

use std::path::{Path, PathBuf};
use std::time::Duration;

use umbra_group::inbound::{InboundGroupEvent, process_inbound_group_frame};

use crate::cli::CliError;

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

/// One decrypted inbound result flowing out of a transport's inbound
/// accept path (Tor's `serve::inbound_loop`, `mesh_serve::run`,
/// `umbra-nym-cli`'s `bridge::receive_via_nym`) to its NDJSON writer.
/// `PartialEq` is test-only in practice (asserting on a received
/// event) but costs nothing to derive unconditionally.
#[derive(Debug, PartialEq)]
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
    /// A known group's roster was replaced by an inbound RosterSync.
    GroupRosterSynced {
        /// Local name (file stem) of the group whose roster changed.
        group_name: String,
    },
}

/// The keystore material an inbound accept path's group branch needs
/// AFTER the sandbox is installed: `process_inbound_group_frame` does
/// its own file I/O against `<keystore_dir>/groups/*.enc` and
/// `<keystore_dir>/keypackages/store.enc`, both of which are decrypted
/// with the keystore passphrase.
///
/// The passphrase therefore stays resident for the daemon's lifetime —
/// which it already did (`serve`/`tui`/`serve-mesh`/`serve-nym` never
/// return, and their caller owns it for the whole run) — under
/// `harden_process`'s memory locks, wrapped in `Zeroizing` so it is
/// wiped when the process tears down. The keystore FILE itself is
/// still never reopened: only `groups/` and `keypackages/` are granted
/// post-sandbox.
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
pub(crate) fn keystore_parent(keystore: &Path) -> Result<&Path, CliError> {
    keystore
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| CliError::Keystore("keystore path has no parent directory".into()))
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

/// Creates (if missing) and returns `<keystore parent>/groups` and
/// `<keystore parent>/keypackages`, mode `0700`.
///
/// # Errors
///
/// Returns [`CliError::Keystore`] if the keystore path has no parent,
/// or [`CliError::Io`] if either directory cannot be created.
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
/// message: `{"event":"group-text","group":"<name>","data":"<b64>"}`.
/// `pub` so every transport's own local stdout-writer can emit the
/// IDENTICAL wire shape without duplicating the JSON-escaping logic.
pub fn group_text_line(group_name: &str, plaintext: &[u8]) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(plaintext);
    format!(
        "{{\"event\":\"group-text\",\"group\":\"{}\",\"data\":\"{b64}\"}}\n",
        json_escape(group_name)
    )
}

/// Reads one length-prefixed group frame body off `stream` — the
/// remainder of a `CONNECTION_TYPE_GROUP` connection, after
/// `umbra_net::messenger::peek_connection_type` has consumed the
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
/// this peer's own keystore. Called identically by every transport's
/// inbound accept path after its own `peek_connection_type` dispatch,
/// so frame parsing and its security-relevant bounds checks
/// ([`MAX_GROUP_FRAME_FIELD`], [`GROUP_FRAME_READ_TIMEOUT`]) exist in
/// exactly one place.
///
/// `process_inbound_group_frame` is synchronous and may block briefly
/// (Argon2id KDF + group-state file I/O). That cost is accepted here
/// for the same reason the two-party path's per-connection ML-DSA
/// keygen is accepted elsewhere: it runs in this connection's own
/// task, bounded by whatever concurrency limit that transport already
/// enforces.
///
/// # Errors
///
/// Returns a plain `String` session error — never a panic — on a
/// malformed frame, a stalled peer, or `process_inbound_group_frame`
/// itself failing (unknown group, decryption failure, etc.).
pub async fn handle_group_frame<S>(
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
        Ok(InboundGroupEvent::RosterSync { group_name, .. }) => {
            Ok(InboundEvent::GroupRosterSynced { group_name })
        }
        Err(error) => Err(format!("inbound group frame: {error}")),
    }
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
            "umbra-cli-group-inbound-test-{}-{label}",
            std::process::id()
        ))
    }

    /// Drives one accepted connection through EXACTLY the branch an
    /// inbound accept loop takes: `peek_connection_type` first, then
    /// (for a group frame) [`handle_group_frame`]. Asserts the marker
    /// routed to the group path rather than the PQXDH one.
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
        create::create_group(alice_dir, alice_pw, "cell", "alice")?;
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
        // Exactly what an inbound accept loop does before sandboxing:
        // both granted directories exist up front (`process_welcome`'s
        // own `create_dir_all(groups/)` is then a no-op, which is what
        // makes it survive the sandbox — pinned separately in
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
