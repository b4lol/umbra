//! Inbound Wi-Fi Direct mesh flow (`umbra serve-mesh`, TODO B.1/B.2.4):
//! waits for an incoming P2P connection from any paired peer and
//! decrypts one message. Mirrors `serve.rs`'s inbound Tor flow: NDJSON
//! on stdout (the only requested output of a long-running daemon;
//! diagnostics go to stderr), and the responder is not told WHICH peer
//! initiated — the same "unauthenticated initiator, SAS-verified out of
//! band" posture `serve.rs`'s module docs already state for Tor.
//!
//! Group frames (TODO B.2.4): the leading connection-type marker byte
//! (`umbra_net::messenger::peek_connection_type`) is branched exactly
//! the way `serve.rs`'s inbound accept loop branches it — a group frame
//! is handed to `crate::group_inbound::handle_group_frame` (the same
//! transport-agnostic parsing/processing `serve` uses, reused rather
//! than duplicated: it is security-sensitive, unauthenticated-input
//! parsing code, and a second copy would be a second place for the two
//! to drift apart). Mesh has no persistent accept loop (one connection,
//! one message, then exit), so [`route_connection`] plays the role
//! `serve.rs`'s `inbound_loop` per-connection body plays there — it IS
//! the production entry point, not merely a test harness.

use base64::Engine as _;

use umbra_crypto::keys::IdentityBundle;
use umbra_net::mesh::{WpaCtrl, listen};

use crate::cli::CliError;
use crate::group_inbound::{GroupInboundContext, InboundEvent};

/// Emits one NDJSON event line — copied from `serve.rs`'s private
/// `emit_event` (base64url, no padding, matching its `data` field
/// encoding exactly) rather than shared, since `serve.rs`'s version is
/// a private `fn`, not part of any public API.
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

/// Escapes a string for inclusion in a JSON string literal — copied from
/// `serve.rs`'s private `json_escape`, same reason as [`emit_event`].
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
/// message — copied from `serve.rs`'s private `group_text_line`, same
/// reason as [`emit_event`]. Split out so the exact wire text is
/// unit-testable without capturing stdout.
fn group_text_line(group_name: &str, plaintext: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(plaintext);
    format!(
        "{{\"event\":\"group-text\",\"group\":\"{}\",\"data\":\"{b64}\"}}\n",
        json_escape(group_name)
    )
}

/// Emits the `group-text` NDJSON event — copied from `serve.rs`'s
/// private `emit_group_text_event`, same reason as [`emit_event`].
fn emit_group_text_event(group_name: &str, plaintext: &[u8]) -> Result<(), CliError> {
    let line = group_text_line(group_name, plaintext);
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(line.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(CliError::Io)
}

/// Routes one accepted mesh connection to the two-party PQXDH path or
/// the group-frame path, branched on the leading connection-type marker
/// byte — the same branch `serve.rs`'s inbound accept loop takes per
/// session. Mesh's one-shot flow has no accept loop of its own, so this
/// function IS that per-connection body, not a test-only stand-in.
///
/// `receive_message`/`handle_group_frame` both only read from `stream`
/// (mesh's two-party path, like Tor's, is receive-only per connection —
/// the reply, if any, is a separate outbound session).
async fn route_connection<S>(
    stream: &mut S,
    identity: IdentityBundle,
    group: &GroupInboundContext,
) -> Result<InboundEvent, String>
where
    S: tokio::io::AsyncRead + Unpin + Send,
{
    match umbra_net::messenger::peek_connection_type(stream).await {
        Ok(umbra_net::messenger::ConnectionType::PqxdhHandshake) => {
            umbra_net::messenger::receive_message(identity, stream)
                .await
                .map(InboundEvent::Text)
                .map_err(|error| error.to_string())
        }
        Ok(umbra_net::messenger::ConnectionType::GroupFrame) => {
            crate::group_inbound::handle_group_frame(stream, group).await
        }
        Err(error) => Err(error.to_string()),
    }
}

/// Runs the inbound mesh flow: sandbox, negotiate, decrypt one message
/// (two-party or, TODO B.2.4, one group frame), NDJSON event on stdout.
///
/// # Errors
///
/// Returns [`CliError`] on keystore, sandbox, negotiation, or session
/// failure.
pub fn run(
    wpa_ctrl_path: &std::path::Path,
    keystore: &std::path::Path,
    passphrase: &[u8],
    identity: IdentityBundle,
) -> Result<(), CliError> {
    // The operator must see the transport's privacy/trust profile
    // BEFORE anything else happens (always-on safety notice, stderr —
    // see `crate::privacy`'s module docs). Mesh's anonymity level is
    // NONE — this notice is the load-bearing warning for this mode.
    crate::privacy::print_notice(
        &crate::privacy::profile(crate::privacy::TransportKind::Mesh),
        "umbra",
    );

    // The identity is loaded by the caller (`cli.rs`'s `load_identity`)
    // so hardware-key-gated (UMKS\x02) keystores unlock here too.
    // Group state material (TODO B.2.4): mirrors `serve::run`'s step 2b
    // — captured pre-sandbox, since the inbound group branch decrypts
    // `groups/*.enc` and `keypackages/store.enc` AFTER the sandbox
    // installs.
    let group = crate::group_inbound::group_context_from_keystore(keystore, passphrase)?;
    let (groups_dir, keypackages_dir) = crate::group_inbound::prepare_group_paths(keystore)?;

    let own_ctrl_dir = wpa_ctrl_path
        .parent()
        .map_or_else(
            || std::path::PathBuf::from("."),
            std::path::Path::to_path_buf,
        )
        .join("umbra-mesh-ctrl");
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&own_ctrl_dir)
            .map_err(CliError::Io)?;
    }
    let own_ctrl_path = own_ctrl_dir.join(format!("server-{}", std::process::id()));

    crate::sandbox::restrict_filesystem_for_mesh(
        std::path::Path::new(
            wpa_ctrl_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("/")),
        ),
        &own_ctrl_dir,
        &[groups_dir.as_path(), keypackages_dir.as_path()],
    )?;
    crate::sandbox::restrict_syscalls_mesh()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::Io(std::io::Error::other(format!("tokio runtime: {e}"))))?;
    // Cloned so the cleanup below can still reach it after the `async
    // move` block below takes ownership of its own copy.
    let cleanup_path = own_ctrl_path.clone();
    let result = runtime.block_on(async move {
        let ctrl = WpaCtrl::connect(&own_ctrl_path, wpa_ctrl_path)
            .await
            .map_err(|e| CliError::Io(std::io::Error::other(format!("mesh transport: {e}"))))?;
        let mut stream = listen(&ctrl)
            .await
            .map_err(|e| CliError::Io(std::io::Error::other(format!("mesh transport: {e}"))))?;
        match route_connection(&mut stream, identity, &group).await {
            Ok(InboundEvent::Text(plaintext)) => {
                let plaintext = zeroize::Zeroizing::new(plaintext);
                emit_event("text", Some(&plaintext))
            }
            Ok(InboundEvent::GroupText {
                group_name,
                plaintext,
            }) => {
                let plaintext = zeroize::Zeroizing::new(plaintext);
                emit_group_text_event(&group_name, &plaintext)
            }
            Ok(InboundEvent::GroupJoined { group_name }) => {
                emit_event("group-joined", Some(group_name.as_bytes()))
            }
            Ok(InboundEvent::GroupUpdated { group_name }) => {
                emit_event("group-updated", Some(group_name.as_bytes()))
            }
            Ok(InboundEvent::GroupRosterSynced { group_name }) => {
                emit_event("group-roster-synced", Some(group_name.as_bytes()))
            }
            Err(error) => Err(CliError::Io(std::io::Error::other(format!(
                "mesh transport: {error}"
            )))),
        }
    });
    // Best-effort cleanup on every path (success or failure): a PID
    // reuse would otherwise make a later run's bind fail permanently
    // with EADDRINUSE. Never let a cleanup failure mask the real result.
    let _ = std::fs::remove_file(&cleanup_path);
    let _ = std::fs::remove_file(WpaCtrl::monitor_path(&cleanup_path));
    result
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::sync::Arc;

    use tokio::io::{AsyncWrite, AsyncWriteExt as _, DuplexStream};
    use tokio::sync::Mutex;
    use umbra_group::GroupError;
    use umbra_group::delivery::PeerTransportAddress;
    use umbra_group::{add, create, keypackage};

    use super::*;

    /// Boxed, `Send` error result — this workspace denies
    /// `unwrap`/`expect` even in test code.
    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
    type TestResult2<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    /// The future type returned by [`single_use_stream`]'s closure
    /// (mirrors `serve.rs`'s and `umbra-group`'s own test helpers of the
    /// same shape).
    type ConnectFuture = Pin<
        Box<
            dyn std::future::Future<Output = Result<Box<dyn AsyncWrite + Unpin + Send>, GroupError>>
                + Send,
        >,
    >;

    /// Hands out one end of a `tokio::io::duplex` pair from an `Fn`
    /// closure (mirrors `serve.rs`'s identical helper).
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

    /// Fresh temp dir, unique per test/label pair.
    fn temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "umbra-cli-mesh-serve-test-{}-{label}",
            std::process::id()
        ))
    }

    /// Serves `bytes` as one inbound connection: the writer half is
    /// dropped after the write, so a truncated frame surfaces as EOF
    /// rather than hanging the test (mirrors `serve.rs`'s identical
    /// helper).
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
    /// stripped Welcome frame (mirrors `serve.rs`'s identical helper).
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

    /// Reads a whole delivered connection off `stream`, minus the
    /// leading `CONNECTION_TYPE_GROUP` marker byte (mirrors `serve.rs`'s
    /// `capture_connection` + `capture_frame`, collapsed into one since
    /// this module has no PQXDH-marker capture case to share it with).
    async fn capture_frame<S>(mut stream: S) -> TestResult2<Vec<u8>>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        use tokio::io::AsyncReadExt as _;
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await?;
        if bytes.first().copied() != Some(umbra_net::messenger::CONNECTION_TYPE_GROUP) {
            return Err("delivered connection did not start with the group marker byte".into());
        }
        bytes.remove(0);
        Ok(bytes)
    }

    /// A `GroupFrame`-marked connection carrying a REAL Welcome routes
    /// through [`route_connection`] to `GroupJoined`, proving the mesh
    /// entry point (not just `serve.rs`'s) reaches the shared group
    /// path.
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
        let identity = IdentityBundle::generate();
        let event = route_connection(&mut connection, identity, &group).await?;
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
    /// routes through [`route_connection`] to `GroupText` with the
    /// exact plaintext and group name.
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
        } = route_connection(&mut join_connection, IdentityBundle::generate(), &group).await?
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
            umbra_group::send::send_group_message(
                &alice_dir,
                alice_pw,
                "cell",
                &plaintext,
                peer_lookup,
                connect,
            )
            .await?;
            let mut bytes = Vec::new();
            {
                use tokio::io::AsyncReadExt as _;
                let mut side = bob_observer_side;
                side.read_to_end(&mut bytes).await?;
            }
            bytes
        };
        let mut connection = connection_carrying(delivered);

        let event = route_connection(&mut connection, IdentityBundle::generate(), &group).await?;
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

    /// The `group-text` line carries both fields, and a group name with
    /// JSON metacharacters stays valid JSON (mirrors `serve.rs`'s
    /// identical test for its own copy of this helper).
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
}
