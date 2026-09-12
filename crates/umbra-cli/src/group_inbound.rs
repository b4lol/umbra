//! Transport-agnostic inbound group-cell (PQ-MLS) plumbing shared by
//! every transport that can carry a group frame (TODO B.2.4):
//! `serve.rs` (Tor), `mesh_serve.rs` (Wi-Fi Direct mesh), and, cross-
//! crate, `umbra-nym-cli`'s bridge. Deliberately NOT gated behind the
//! `tor` or `mesh` feature — `umbra-nym-cli` builds `umbra-cli` with
//! neither feature enabled (its whole reason for being a separate
//! Cargo workspace is to avoid `nym-sdk`'s SQLite dependency chain
//! conflicting with `tor`'s, so it cannot ask for the `tor` feature just
//! to reach this), and a mesh-only build (`--features mesh`, no `tor`)
//! must also keep working. This module holds exactly the parts that are
//! genuinely transport-agnostic: frame parsing against unauthenticated
//! network input, and the call into
//! `umbra_group::inbound::process_inbound_group_frame`. Presentation
//! (NDJSON emission) stays duplicated per transport, per this crate's
//! established convention (see `serve.rs`'s own private `emit_event`
//! and its doc comment) — this module has no opinion on stdout.

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
/// bound. `pub(crate)`: `serve.rs`'s own hermetic tests pin the ceiling
/// against this exact value.
pub(crate) const MAX_GROUP_FRAME_FIELD: usize = 1024 * 1024;

/// Wall-clock bound on reading ONE complete inbound group frame: a peer
/// that sends a length prefix and then stalls must not park the session
/// task forever (mirrors `umbra_net::messenger`'s own per-read
/// `READ_IDLE_TIMEOUT` value for the two-party path).
const GROUP_FRAME_READ_TIMEOUT: Duration = Duration::from_secs(300);

/// One decrypted inbound result flowing out of a transport's group
/// branch (`serve.rs`'s accept loop, `mesh_serve.rs`'s one-shot flow, or
/// `umbra-nym-cli`'s bridge) to its NDJSON writer — or, for the two-
/// party `Text` variant, the pre-existing PQXDH payload each transport
/// already emitted before TODO B.2.4.
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
    /// A known group's roster was updated via an inbound roster sync
    /// (TODO B.2.1 — control traffic riding the group's own AEAD
    /// channel; no user-visible plaintext).
    GroupRosterSynced {
        /// Local name (file stem) of the group whose roster changed.
        group_name: String,
    },
}

/// The keystore material an inbound group branch needs AFTER the
/// sandbox is installed: `process_inbound_group_frame` does its own
/// file I/O against `<keystore_dir>/groups/*.enc` and
/// `<keystore_dir>/keypackages/store.enc`, both of which are decrypted
/// with the keystore passphrase.
///
/// The passphrase therefore stays resident for the daemon's lifetime —
/// which it already did (`serve`/`tui`/`serve-mesh`/`serve-nym` never
/// return, and their caller owns it for the whole run) — under
/// `harden_process`'s memory locks, wrapped in `Zeroizing` so it is
/// wiped when the process tears down. The keystore FILE itself is still
/// never reopened: only `groups/` and `keypackages/` are granted
/// post-sandbox.
pub struct GroupInboundContext {
    /// Directory holding `groups/` and `keypackages/` (the keystore
    /// file's parent).
    pub keystore_dir: PathBuf,
    /// Keystore passphrase, used to decrypt group state files.
    pub passphrase: zeroize::Zeroizing<Vec<u8>>,
}

/// The keystore's parent directory — the root every Umbra-owned
/// artifact (transport storage, peer records, group state) hangs off.
///
/// `pub(crate)`: `serve.rs`'s own `tor_base_from_keystore` needs it too,
/// for the same reason (deriving a sibling directory from the keystore
/// path).
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

/// Ensures the two directories the inbound group branch writes to EXIST
/// (`<keystore parent>/groups` and `<keystore parent>/keypackages`,
/// both `0o700`) and returns them, in the order they are handed to
/// [`crate::sandbox::restrict_filesystem_with_exceptions`]'s
/// `read_write` list (or, for mesh, [`crate::sandbox::restrict_filesystem_for_mesh`]'s
/// `group_state_dirs`).
///
/// They must exist before the ruleset is built — Landlock's `PathFd` is
/// an `O_PATH` open at rule-add time, so a missing path fails the whole
/// sandbox call closed (exactly why the transport's own storage root is
/// already created first). A peer may legitimately run a serve flow
/// before ever creating or joining a group, hence the create-if-missing;
/// an empty directory is a normal state and, unlike an empty store
/// FILE, cannot be mistaken for a malformed store by anything that
/// later writes one.
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
pub async fn read_group_frame<S>(stream: &mut S) -> Result<Vec<u8>, String>
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
/// for the same reason a two-party path's per-connection ML-DSA keygen
/// is (see e.g. `serve.rs`'s module docs): each caller runs this inside
/// the connection's OWN task/session, bounded by that transport's own
/// concurrency control (Tor's accept-loop permit; mesh and Nym handle
/// one connection/message at a time regardless).
///
/// # Errors
///
/// Returns a plain `String` session error on a malformed frame or a
/// `process_inbound_group_frame` failure — never a panic, since this
/// runs against unauthenticated network input.
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
        Ok(InboundGroupEvent::RosterSynced { group_name }) => {
            Ok(InboundEvent::GroupRosterSynced { group_name })
        }
        Err(error) => Err(format!("inbound group frame: {error}")),
    }
}
