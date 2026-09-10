//! Inbound Welcome/Commit/application-message frame processing (Task 9,
//! TODO B.2): the DEcode side of `delivery.rs`'s wire format. This
//! module builds the PROCESSING logic in isolation, hermetically
//! testable without any real network — Task 12 wires it into the
//! actual `serve.rs` inbound loop, after stripping the
//! `CONNECTION_TYPE_GROUP` marker byte that one inbound connection
//! carries ahead of this module's own frame format (mirrors
//! `umbra_net::messenger`'s own `peek_connection_type`/`receive_message`
//! split).
//!
//! # Ruling: resolving an inbound `group_id` to a local group file
//! (binding, given before this task's implementation)
//!
//! The wire format `delivery.rs` defines carries only the MLS-level
//! `group_id` bytes, never a human-chosen group name — but groups are
//! persisted by name (`<keystore_dir>/groups/<group_name>.enc`). Two
//! sub-cases:
//!
//! 1. **Existing group receiving a Commit or an application message:**
//!    [`resolve_existing_group`] resolves `group_id` to the right file
//!    by listing `<keystore_dir>/groups/`, attempting
//!    [`persistence::load_group_state`] on each `*.enc` entry (the file
//!    stem is the candidate `group_name`) until one whose
//!    `group.group_id()` (bytes, via `GroupId::as_slice()` — verified
//!    against the installed `openmls-0.9.0` source,
//!    `src/group/mod.rs`) equals the target `group_id`. A candidate
//!    file that fails to load (wrong passphrase for some *other*
//!    peer's stray file, corruption, etc.) is skipped rather than
//!    aborting the whole scan — one bad file must not make every other
//!    locally known group unreachable. Returns
//!    [`GroupError::GroupNotFound`] if no candidate matches (or the
//!    `groups/` directory does not exist at all). This is O(n) in the
//!    number of locally known groups, which is fine at this scale (a
//!    peer belongs to a handful of groups) — no index file, no other
//!    optimization.
//! 2. **A Welcome for a group this device isn't a member of yet:**
//!    there is no existing name to look up, so [`process_welcome`]
//!    mints one deterministically: `format!("joined-{}",
//!    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(group_id))`,
//!    used as both the file stem and the `group_name` in
//!    [`InboundGroupEvent::Joined`]. Before creating it, this still
//!    refuses (mirroring [`crate::create::create_group`]'s own
//!    `AlreadyExists` guard, for the same data-loss reason Task 8's
//!    review flagged) if that exact path already exists — processing
//!    the same Welcome twice must error, not silently re-create or
//!    overwrite.
//!
//! # A freshly joined group has no roster yet (small, related ruling)
//!
//! [`GroupRoster`] is Umbra's own bookkeeping (Umbra peer name ->
//! MLS leaf index), never transmitted over MLS itself. A `Welcome`
//! carries no such mapping, so [`process_welcome`] persists a brand
//! new group with [`GroupRoster::default`] (empty) — exactly what
//! [`crate::create::create_group`] already does for a freshly created
//! group. Populating it is left to whatever future mechanism
//! bootstraps peer-name knowledge for a newly joined group; out of
//! scope here.
//!
//! # Re-persisting storage after EVERY processed message, not just Commits
//!
//! `MlsGroup::process_message` mutates the underlying
//! `MemoryStorage` even for an application message that leaves the
//! group's epoch/tree unchanged: the secret tree (ratchet state used to
//! decrypt future messages, and to prevent reuse) is advanced and
//! written into storage as a required step of decryption (verified
//! against the installed source, `src/group/mls_group/processing.rs`'s
//! `unprotect_message`, which calls `provider.storage().
//! write_message_secrets(...)` whenever a `PrivateMessage` is
//! decrypted, unconditionally — not gated on the message turning out to
//! be a Commit). If [`process_protocol_message`] only re-saved on the
//! Commit branch, every processed application message's forward-secrecy
//! advancement would be silently lost on process restart. So this
//! module calls [`persistence::save_group_state`] after processing
//! EITHER a Commit or an application message.
//!
//! # Verified OpenMLS API shapes (installed `openmls` 0.9.0 source)
//!
//! - `MlsMessageIn` has a hand-written `tls_codec::DeserializeBytes`
//!   impl (`src/framing/codec.rs`), so
//!   `MlsMessageIn::tls_deserialize_exact_bytes` works exactly like
//!   `KeyPackageIn::tls_deserialize_exact_bytes` already used in
//!   `add.rs`, despite `MlsMessageIn` itself only deriving
//!   `TlsSerialize`/`TlsSize` (the `Deserialize`/`DeserializeBytes`
//!   impls are on `MlsMessageBodyIn`, a distinct nested type, and hand
//!   written for `MlsMessageIn` in terms of it).
//! - `MlsMessageIn::extract(self) -> MlsMessageBodyIn` (`src/framing/
//!   message_in.rs`) with variants `Welcome(Welcome)`,
//!   `PublicMessage(PublicMessageIn)`, `PrivateMessage(PrivateMessageIn)`,
//!   plus `GroupInfo`/`KeyPackage` (and a feature-gated
//!   `TargetedMessage`, not enabled here) — all treated as unsupported/
//!   malformed by this module. `From<PublicMessageIn> for
//!   ProtocolMessage` and `From<PrivateMessageIn> for ProtocolMessage`
//!   are both unconditionally public (not gated behind `test-utils`),
//!   so no `try_into_protocol_message`/`TryFrom` dance is needed.
//! - `StagedWelcome::new_from_welcome(provider, &MlsGroupJoinConfig,
//!   welcome, ratchet_tree: Option<RatchetTreeIn>) -> Result<Self,
//!   WelcomeError<Provider::StorageError>>` and `StagedWelcome::
//!   into_group(self, provider) -> Result<MlsGroup,
//!   WelcomeError<Provider::StorageError>>` (`src/group/mls_group/
//!   creation.rs`). `ratchet_tree: None` is correct here: this
//!   codebase's own `create_group`/`add_member` always build with
//!   `use_ratchet_tree_extension(true)`, so the tree already travels
//!   embedded in the Welcome's own `GroupInfo` extensions — verified at
//!   `into_staged_welcome_inner`'s ratchet-tree resolution (checks the
//!   embedded extension first, only consults the `ratchet_tree`
//!   parameter as a fallback).
//! - `MlsGroup::process_message(&mut self, provider, message: impl
//!   Into<ProtocolMessage>) -> Result<ProcessedMessage,
//!   ProcessMessageError<Provider::StorageError>>` and
//!   `MlsGroup::merge_staged_commit(&mut self, provider, StagedCommit)
//!   -> Result<(), MergeCommitError<Provider::StorageError>>`
//!   (`src/group/mls_group/processing.rs`) — a DIFFERENT error type
//!   from `add.rs`'s `merge_pending_commit`/`MergePendingCommitError`,
//!   hence this crate's new, distinct `GroupError::StagedCommitMerge`
//!   variant.
//! - `ProcessedMessage::into_content(self) -> ProcessedMessageContent`
//!   (`src/framing/validation.rs`), whose relevant variants are
//!   `StagedCommitMessage(Box<StagedCommit>)` and
//!   `ApplicationMessage(ApplicationMessage)`;
//!   `ApplicationMessage::into_bytes(self) -> Vec<u8>` is the plaintext
//!   accessor. All other variants (proposals, own-commit echoes, etc.)
//!   are treated as unsupported/malformed by this module.
//! - `GroupId::as_slice(&self) -> &[u8]` / `to_vec(&self) -> Vec<u8>`
//!   (`src/group/mod.rs`) — both exist, confirming the group-id
//!   resolution ruling above is implementable as specified.
//! - `openmls::prelude::{ProcessMessageError, MergeCommitError,
//!   WelcomeError}` are all reachable despite living in `pub(crate)`
//!   submodules (`group::mls_group::errors`): `group::errors.rs`'s own
//!   `pub use super::mls_group::errors::*;` re-exports them into the
//!   public `group::errors` module, which `group/mod.rs`'s `pub use
//!   errors::*;` and `openmls::prelude`'s own glob re-export then carry
//!   the rest of the way — the same chain this crate's existing
//!   `GroupError::{GroupCreation, MembershipAddition, CommitMerge}`
//!   variants already rely on for `NewGroupError`/`AddMembersError`/
//!   `MergePendingCommitError`.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use openmls::prelude::tls_codec::DeserializeBytes as _;
use openmls::prelude::{
    MlsGroup, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider as _,
    ProcessedMessageContent, ProtocolMessage, StagedWelcome, Welcome,
};

use crate::error::GroupError;
use crate::keypackage;
use crate::persistence::{self, GroupRoster, RestoredProvider};

/// Subdirectory (relative to the keystore directory) holding one
/// encrypted group-state file per group, named `<group_name>.enc`
/// (mirrors `create.rs`/`add.rs`'s own private `GROUPS_DIR_NAME`
/// copies — this task adds a fourth rather than consolidating, per the
/// dispatch ruling: the existing duplication is an already-reviewed
/// pattern, not something to fix here).
const GROUPS_DIR_NAME: &str = "groups";

/// Path (relative to the keystore directory) of the persisted
/// key-package storage snapshot (mirrors `keypackage.rs`'s own private
/// `KEYPACKAGES_FILE_NAME` — that constant is private to its module, so
/// it is duplicated here rather than imported, consistent with this
/// crate's existing file-name-constant duplication pattern; it lives in
/// its own subdirectory so the sandboxed client can be granted that
/// directory, see `keypackage.rs`'s copy for the full reasoning).
///
/// Note: this path changed from a flat `<keystore_dir>/keypackages.enc`
/// and there is NO migration — a pre-existing file at the old location
/// is silently ignored, so a `Welcome` for a key package exported under
/// the old layout will fail to find its private material (acceptable
/// pre-release; see `keypackage.rs`'s copy of this constant).
const KEYPACKAGES_FILE_NAME: &str = "keypackages/store.enc";

/// The outcome of successfully processing one inbound group frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundGroupEvent {
    /// A `Welcome` was processed: a brand-new group state file was
    /// created at `<keystore_dir>/groups/<group_name>.enc`, with an
    /// empty [`GroupRoster`] (see module docs).
    Joined {
        /// The newly minted group name (file stem), deterministically
        /// derived from the group id (module docs, ruling sub-case 2).
        group_name: String,
    },
    /// A `Commit` was processed and merged into an existing group's
    /// persisted state.
    MembershipUpdated {
        /// The resolved group name (file stem) whose state was updated.
        group_name: String,
    },
    /// An application message was decrypted.
    ApplicationMessage {
        /// The resolved group name (file stem) the message belongs to.
        group_name: String,
        /// The decrypted plaintext bytes.
        plaintext: Vec<u8>,
    },
}

/// Decodes `frame_bytes` (the `[group_id_len][group_id][mls_len]
/// [mls_bytes]` frame `delivery.rs` defines, with any transport-level
/// `CONNECTION_TYPE_GROUP` marker byte already stripped by the caller)
/// and processes the enclosed MLS message: a `Welcome` creates a new,
/// locally joined group; a `Commit` updates an existing group's
/// persisted state; an application message is decrypted and returned.
///
/// `keystore_dir`/`passphrase` identify this peer's own keystore,
/// exactly as `create_group`/`add_member`/`export_keypackage` already
/// use them.
///
/// # Errors
///
/// Returns [`GroupError::Malformed`] if `frame_bytes` is truncated or
/// structurally invalid, or if the enclosed MLS message is a type this
/// function does not process (a bare `KeyPackage` or `GroupInfo`, or a
/// Commit/application-message frame whose outer frame `group_id` does
/// not match its own enclosed MLS message's group id).
/// Returns [`GroupError::Codec`] if the enclosed bytes are not a valid
/// TLS-codec-encoded `MlsMessageIn`.
/// Returns [`GroupError::AlreadyExists`] if a `Welcome`'s deterministic
/// group name already has a persisted state file (this Welcome was
/// already processed once).
/// Returns [`GroupError::GroupNotFound`] if a Commit/application-message
/// frame's group id matches no locally known group.
/// Returns [`GroupError::WelcomeProcessing`], [`GroupError::
/// MessageProcessing`], or [`GroupError::StagedCommitMerge`] for the
/// corresponding OpenMLS processing failures, and other [`GroupError`]
/// variants for keystore I/O/crypto/(de)serialization failures.
pub fn process_inbound_group_frame(
    keystore_dir: &Path,
    passphrase: &[u8],
    frame_bytes: &[u8],
) -> Result<InboundGroupEvent, GroupError> {
    let (group_id, mls_bytes) = decode_frame(frame_bytes)?;

    let message_in =
        MlsMessageIn::tls_deserialize_exact_bytes(mls_bytes).map_err(GroupError::Codec)?;

    match message_in.extract() {
        MlsMessageBodyIn::Welcome(welcome) => {
            process_welcome(keystore_dir, passphrase, &group_id, welcome)
        }
        MlsMessageBodyIn::PublicMessage(public_message) => process_protocol_message(
            keystore_dir,
            passphrase,
            &group_id,
            ProtocolMessage::from(public_message),
        ),
        MlsMessageBodyIn::PrivateMessage(private_message) => process_protocol_message(
            keystore_dir,
            passphrase,
            &group_id,
            ProtocolMessage::from(private_message),
        ),
        _ => Err(GroupError::Malformed(
            "unsupported MLS message type in inbound group frame (expected Welcome, \
             PublicMessage, or PrivateMessage)"
                .into(),
        )),
    }
}

/// Splits `frame_bytes` into `(group_id, mls_message_bytes)` per
/// `delivery.rs`'s wire format (module docs). Bounds/length-prefix
/// failures are reported as [`GroupError::Malformed`] (or, for the
/// fixed-size length-prefix reads themselves,
/// [`GroupError::Crypto`] via `umbra_crypto::kdf::read_at`'s own
/// truncation error — the same helper `persistence.rs` already reuses
/// for its own length-prefixed header fields).
fn decode_frame(frame_bytes: &[u8]) -> Result<(Vec<u8>, &[u8]), GroupError> {
    let group_id_len_bytes: [u8; 4] = umbra_crypto::kdf::read_at(frame_bytes, 0)?;
    let group_id_len = usize::try_from(u32::from_be_bytes(group_id_len_bytes))
        .map_err(|_| GroupError::Malformed("group id length does not fit in usize".into()))?;

    let group_id_start = 4usize;
    let group_id_end = group_id_start
        .checked_add(group_id_len)
        .ok_or_else(|| GroupError::Malformed("group id length overflow".into()))?;
    let group_id = frame_bytes
        .get(group_id_start..group_id_end)
        .ok_or_else(|| GroupError::Malformed("truncated inbound group frame (group id)".into()))?
        .to_vec();

    let mls_len_bytes: [u8; 4] = umbra_crypto::kdf::read_at(frame_bytes, group_id_end)?;
    let mls_len = usize::try_from(u32::from_be_bytes(mls_len_bytes))
        .map_err(|_| GroupError::Malformed("MLS message length does not fit in usize".into()))?;

    let mls_start = group_id_end
        .checked_add(4)
        .ok_or_else(|| GroupError::Malformed("MLS message offset overflow".into()))?;
    let mls_end = mls_start
        .checked_add(mls_len)
        .ok_or_else(|| GroupError::Malformed("MLS message length overflow".into()))?;
    let mls_bytes = frame_bytes.get(mls_start..mls_end).ok_or_else(|| {
        GroupError::Malformed("truncated inbound group frame (MLS message)".into())
    })?;

    Ok((group_id, mls_bytes))
}

/// Processes an inbound `Welcome`: mints a deterministic group name
/// from `group_id` (ruling sub-case 2), refuses if that group's state
/// file already exists, loads this peer's persisted key-package
/// storage (the private material `StagedWelcome::new_from_welcome`
/// needs to decrypt the Welcome's group secrets — see
/// `keypackage.rs`'s own module docs), stages and joins the group, and
/// persists the resulting state with an empty [`GroupRoster`].
///
/// Also re-saves the key-package storage afterward: consuming a
/// (non-last-resort) key package during `StagedWelcome::new_from_welcome`
/// deletes it from storage as a side effect (verified against the
/// installed source, `src/group/mls_group/creation.rs`'s
/// `keys_for_welcome`), and that deletion must survive process restart
/// just like the original export did.
fn process_welcome(
    keystore_dir: &Path,
    passphrase: &[u8],
    group_id: &[u8],
    welcome: Welcome,
) -> Result<InboundGroupEvent, GroupError> {
    let group_name = format!(
        "joined-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(group_id)
    );
    let groups_dir = keystore_dir.join(GROUPS_DIR_NAME);
    let group_state_path = groups_dir.join(format!("{group_name}.enc"));
    if group_state_path.exists() {
        return Err(GroupError::AlreadyExists(format!(
            "group {group_name:?} already exists at {} (this Welcome was likely already \
             processed)",
            group_state_path.display()
        )));
    }

    let keypackages_path = keystore_dir.join(KEYPACKAGES_FILE_NAME);
    let provider = keypackage::load_keypackage_storage(&keypackages_path, passphrase)?;

    let join_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let staged_welcome = StagedWelcome::new_from_welcome(&provider, &join_config, welcome, None)
        .map_err(GroupError::WelcomeProcessing)?;
    let group = staged_welcome
        .into_group(&provider)
        .map_err(GroupError::WelcomeProcessing)?;

    fs::create_dir_all(&groups_dir)?;
    persistence::save_group_state(
        &group_state_path,
        passphrase,
        &group,
        provider.storage(),
        &GroupRoster::default(),
    )?;

    // Re-save: the consumed key package's private material was removed
    // from `provider`'s storage as a side effect above (module docs).
    keypackage::save_keypackage_storage(&keypackages_path, passphrase, provider.storage())?;

    Ok(InboundGroupEvent::Joined { group_name })
}

/// Processes an inbound Commit or application-message frame: resolves
/// `group_id` to a locally known group (ruling sub-case 1), processes
/// the message, and — for either outcome — re-persists the group's
/// state (module docs' "re-persist after EVERY processed message"
/// section covers why this is not conditional on the Commit branch).
fn process_protocol_message(
    keystore_dir: &Path,
    passphrase: &[u8],
    group_id: &[u8],
    protocol_message: ProtocolMessage,
) -> Result<InboundGroupEvent, GroupError> {
    if protocol_message.group_id().as_slice() != group_id {
        return Err(GroupError::Malformed(
            "inbound group frame's outer group id does not match its enclosed MLS message's \
             group id"
                .into(),
        ));
    }

    let (group_name, mut group, roster, provider, group_state_path) =
        resolve_existing_group(keystore_dir, passphrase, group_id)?;

    let processed = group
        .process_message(&provider, protocol_message)
        .map_err(GroupError::MessageProcessing)?;

    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            group
                .merge_staged_commit(&provider, *staged_commit)
                .map_err(GroupError::StagedCommitMerge)?;
            persistence::save_group_state(
                &group_state_path,
                passphrase,
                &group,
                provider.storage(),
                &roster,
            )?;
            Ok(InboundGroupEvent::MembershipUpdated { group_name })
        }
        ProcessedMessageContent::ApplicationMessage(application_message) => {
            let plaintext = application_message.into_bytes();
            persistence::save_group_state(
                &group_state_path,
                passphrase,
                &group,
                provider.storage(),
                &roster,
            )?;
            Ok(InboundGroupEvent::ApplicationMessage {
                group_name,
                plaintext,
            })
        }
        _ => Err(GroupError::Malformed(
            "unsupported processed message content in inbound group frame (expected a Commit \
             or an application message)"
                .into(),
        )),
    }
}

/// Resolves `target_group_id` to a locally persisted group by scanning
/// `<keystore_dir>/groups/*.enc` (ruling sub-case 1, module docs).
/// Returns the group's name (file stem), a live `MlsGroup` handle, its
/// [`GroupRoster`], a usable [`RestoredProvider`], and the file path it
/// was loaded from (so the caller can re-save to the same file).
fn resolve_existing_group(
    keystore_dir: &Path,
    passphrase: &[u8],
    target_group_id: &[u8],
) -> Result<(String, MlsGroup, GroupRoster, RestoredProvider, PathBuf), GroupError> {
    let groups_dir = keystore_dir.join(GROUPS_DIR_NAME);
    if !groups_dir.is_dir() {
        return Err(GroupError::GroupNotFound);
    }

    for entry in fs::read_dir(&groups_dir)? {
        let path = entry?.path();
        if path.extension() != Some(OsStr::new("enc")) {
            continue;
        }
        let Some(group_name) = path.file_stem().and_then(OsStr::to_str) else {
            continue;
        };

        let Ok((group, roster, provider)) = persistence::load_group_state(&path, passphrase) else {
            // Not this peer's own group state (wrong passphrase, a
            // stray/corrupt file, etc.) — skip rather than abort the
            // whole scan (module docs).
            continue;
        };

        if group.group_id().as_slice() == target_group_id {
            return Ok((group_name.to_string(), group, roster, provider, path));
        }
    }

    Err(GroupError::GroupNotFound)
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;

    use openmls::prelude::{Ciphersuite, CredentialWithKey, KeyPackage};
    use openmls_libcrux_crypto::CryptoProvider;
    use openmls_memory_storage::MemoryStorage;
    use tokio::io::{AsyncReadExt, AsyncWrite, DuplexStream};
    use tokio::sync::Mutex;

    use super::*;
    use crate::add;
    use crate::create;
    use crate::delivery::PeerTransportAddress;
    use crate::identity;
    use crate::keypackage as kp;

    /// Shorthand for a boxed, `Send`, `Send`-error result — matches this
    /// crate's other test modules (`unwrap()`/`expect()` are denied even
    /// in test code by this workspace's clippy lints).
    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// The future type returned by [`single_use_stream`]'s closure.
    type ConnectFuture = Pin<
        Box<
            dyn std::future::Future<Output = Result<Box<dyn AsyncWrite + Unpin + Send>, GroupError>>
                + Send,
        >,
    >;

    const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

    /// Hands out one end of a `tokio::io::duplex` pair from an `Fn`
    /// closure (mirrors `add.rs`/`delivery.rs`'s own test helper of the
    /// same shape).
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

    /// Reads the `CONNECTION_TYPE_GROUP` marker byte off `stream`, then
    /// everything after it (until the writer side closes, which
    /// `deliver_to_one` triggers by dropping its stream handle once its
    /// write completes) — exactly `process_inbound_group_frame`'s own
    /// `frame_bytes` argument (marker already stripped).
    async fn capture_frame<S>(
        mut stream: S,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let marker = stream.read_u8().await?;
        assert_eq!(marker, umbra_net::messenger::CONNECTION_TYPE_GROUP);
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        Ok(buf)
    }

    /// Builds a real `MlsMessageOut` wrapping a bare `KeyPackage` — the
    /// simplest way to get a well-formed-but-unsupported frame payload
    /// (mirrors `delivery.rs`'s own `sample_mls_message` test helper).
    fn sample_keypackage_message()
    -> Result<openmls::prelude::MlsMessageOut, Box<dyn std::error::Error + Send + Sync>> {
        let identity = identity::generate_group_identity()?;
        let provider =
            RestoredProvider::from_parts(CryptoProvider::new()?, MemoryStorage::default());
        let credential_with_key = CredentialWithKey {
            credential: identity.credential.into(),
            signature_key: identity.signature_key_pair.public().into(),
        };
        let key_package_bundle = KeyPackage::builder().build(
            CIPHERSUITE,
            &provider,
            &identity.signature_key_pair,
            credential_with_key,
        )?;
        Ok(key_package_bundle.key_package().clone().into())
    }

    /// Sets up a fresh temp dir under `std::env::temp_dir()`, unique per
    /// test/label pair (mirrors this crate's existing test style).
    fn temp_dir(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "umbra-group-inbound-test-{}-{label}",
            std::process::id()
        ))
    }

    /// Creates Alice's group, exports and adds `peer_name` (capturing
    /// only `peer_name`'s own delivered frame — every other roster
    /// member's delivery is left to fail silently, which `add_member`
    /// tolerates per its own documented semantics), and returns that
    /// captured, marker-stripped frame bytes (a Welcome the first time
    /// a peer is added, a Commit for every subsequent add).
    async fn add_member_and_capture_frame(
        alice_dir: &std::path::Path,
        alice_pw: &[u8],
        group_name: &str,
        peer_name: &str,
        peer_key_package_blob: &str,
    ) -> TestResult2<Vec<u8>> {
        let (member_side, observer_side) = tokio::io::duplex(8192);
        let address = PeerTransportAddress::Mesh(format!("{peer_name}-mesh"));
        let connect = single_use_stream(member_side);
        let peer_lookup = {
            let address = address.clone();
            let peer_name = peer_name.to_string();
            move |name: &str| {
                if name == peer_name {
                    Some(address.clone())
                } else {
                    None
                }
            }
        };

        add::add_member(
            alice_dir,
            alice_pw,
            group_name,
            peer_name,
            peer_key_package_blob,
            peer_lookup,
            connect,
        )
        .await?;

        capture_frame(observer_side).await
    }

    /// This test module's own `?`-friendly result alias for functions
    /// that return something other than `()`.
    type TestResult2<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    #[tokio::test]
    async fn welcome_frame_creates_and_persists_a_new_joined_group() -> TestResult {
        let alice_dir = temp_dir("welcome-alice");
        let bob_dir = temp_dir("welcome-bob");
        std::fs::create_dir_all(&alice_dir)?;
        std::fs::create_dir_all(&bob_dir)?;
        let alice_pw = b"alice-pw";
        let bob_pw = b"bob-pw";

        create::create_group(&alice_dir, alice_pw, "cell")?;
        let bob_kp = kp::export_keypackage(&bob_dir, bob_pw)?;

        let welcome_frame =
            add_member_and_capture_frame(&alice_dir, alice_pw, "cell", "bob", &bob_kp).await?;

        let (alice_group, _roster, _provider) =
            persistence::load_group_state(&alice_dir.join("groups").join("cell.enc"), alice_pw)?;
        let group_id = alice_group.group_id().to_vec();
        let expected_group_name = format!(
            "joined-{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&group_id)
        );

        let event = process_inbound_group_frame(&bob_dir, bob_pw, &welcome_frame)?;
        assert_eq!(
            event,
            InboundGroupEvent::Joined {
                group_name: expected_group_name.clone()
            }
        );

        let bob_group_path = bob_dir
            .join("groups")
            .join(format!("{expected_group_name}.enc"));
        assert!(bob_group_path.exists());
        let (bob_group, bob_roster, _provider) =
            persistence::load_group_state(&bob_group_path, bob_pw)?;
        assert_eq!(bob_group.group_id().to_vec(), group_id);
        assert_eq!(bob_group.members().count(), 2);
        assert!(
            bob_roster.members.is_empty(),
            "a freshly joined group has no roster yet"
        );

        std::fs::remove_dir_all(&alice_dir)?;
        std::fs::remove_dir_all(&bob_dir)?;
        Ok(())
    }

    #[tokio::test]
    async fn processing_the_same_welcome_twice_is_rejected() -> TestResult {
        let alice_dir = temp_dir("welcome-twice-alice");
        let bob_dir = temp_dir("welcome-twice-bob");
        std::fs::create_dir_all(&alice_dir)?;
        std::fs::create_dir_all(&bob_dir)?;
        let alice_pw = b"alice-pw";
        let bob_pw = b"bob-pw";

        create::create_group(&alice_dir, alice_pw, "cell")?;
        let bob_kp = kp::export_keypackage(&bob_dir, bob_pw)?;
        let welcome_frame =
            add_member_and_capture_frame(&alice_dir, alice_pw, "cell", "bob", &bob_kp).await?;

        let first = process_inbound_group_frame(&bob_dir, bob_pw, &welcome_frame);
        assert!(first.is_ok());

        let second = process_inbound_group_frame(&bob_dir, bob_pw, &welcome_frame);
        assert!(
            matches!(second, Err(GroupError::AlreadyExists(_))),
            "expected AlreadyExists, got {second:?}"
        );

        std::fs::remove_dir_all(&alice_dir)?;
        std::fs::remove_dir_all(&bob_dir)?;
        Ok(())
    }

    #[tokio::test]
    async fn commit_frame_updates_an_existing_members_persisted_state() -> TestResult {
        let alice_dir = temp_dir("commit-alice");
        let bob_dir = temp_dir("commit-bob");
        let charlie_dir = temp_dir("commit-charlie");
        std::fs::create_dir_all(&alice_dir)?;
        std::fs::create_dir_all(&bob_dir)?;
        std::fs::create_dir_all(&charlie_dir)?;
        let alice_pw = b"alice-pw";
        let bob_pw = b"bob-pw";
        let charlie_pw = b"charlie-pw";

        create::create_group(&alice_dir, alice_pw, "cell")?;
        let bob_kp = kp::export_keypackage(&bob_dir, bob_pw)?;
        let welcome_frame =
            add_member_and_capture_frame(&alice_dir, alice_pw, "cell", "bob", &bob_kp).await?;

        // Bob actually joins (via the function under test) so his own
        // group file exists under its ruling-derived name, not a name
        // this test chose — the next step's resolution must find it
        // purely by group id.
        let joined_event = process_inbound_group_frame(&bob_dir, bob_pw, &welcome_frame)?;
        let InboundGroupEvent::Joined {
            group_name: bob_group_name,
        } = joined_event
        else {
            return Err("expected Joined event".into());
        };

        // Adding a THIRD member now delivers the resulting Commit to
        // the previously-existing members, Alice and Bob — captured
        // here for Bob. `add_member_and_capture_frame`'s helper only
        // fits the "capture the WELCOME recipient's frame" shape used
        // above, so this 3-party add (capturing an old member's COMMIT
        // instead) is wired up directly.
        let charlie_kp = kp::export_keypackage(&charlie_dir, charlie_pw)?;
        let bob_frame_from_second_add = {
            let (bob_member_side, bob_observer_side) = tokio::io::duplex(8192);
            let (charlie_member_side, _charlie_observer_side) = tokio::io::duplex(8192);
            let bob_addr = PeerTransportAddress::Mesh("bob-mesh".to_string());
            let charlie_addr = PeerTransportAddress::Mesh("charlie-mesh".to_string());
            let bob_slot = Arc::new(Mutex::new(Some(bob_member_side)));
            let charlie_slot = Arc::new(Mutex::new(Some(charlie_member_side)));
            let connect = {
                let bob_addr = bob_addr.clone();
                let charlie_addr = charlie_addr.clone();
                move |address: &PeerTransportAddress| {
                    let address = address.clone();
                    let bob_addr = bob_addr.clone();
                    let charlie_addr = charlie_addr.clone();
                    let bob_slot = Arc::clone(&bob_slot);
                    let charlie_slot = Arc::clone(&charlie_slot);
                    Box::pin(async move {
                        let slot = if address == bob_addr {
                            bob_slot
                        } else if address == charlie_addr {
                            charlie_slot
                        } else {
                            return Err(GroupError::Malformed(format!(
                                "unexpected connect() address in test: {address:?}"
                            )));
                        };
                        let taken = slot.lock().await.take().ok_or_else(|| {
                            GroupError::Malformed(
                                "connect() called more than once for this address in test".into(),
                            )
                        })?;
                        Ok(Box::new(taken) as Box<dyn AsyncWrite + Unpin + Send>)
                    }) as ConnectFuture
                }
            };
            let peer_lookup = move |name: &str| match name {
                "bob" => Some(bob_addr.clone()),
                "charlie" => Some(charlie_addr.clone()),
                _ => None,
            };

            add::add_member(
                &alice_dir,
                alice_pw,
                "cell",
                "charlie",
                &charlie_kp,
                peer_lookup,
                connect,
            )
            .await?;

            capture_frame(bob_observer_side).await?
        };

        let event = process_inbound_group_frame(&bob_dir, bob_pw, &bob_frame_from_second_add)?;
        assert_eq!(
            event,
            InboundGroupEvent::MembershipUpdated {
                group_name: bob_group_name.clone()
            }
        );

        let bob_group_path = bob_dir.join("groups").join(format!("{bob_group_name}.enc"));
        let (bob_group, _roster, _provider) =
            persistence::load_group_state(&bob_group_path, bob_pw)?;
        assert_eq!(bob_group.members().count(), 3);

        std::fs::remove_dir_all(&alice_dir)?;
        std::fs::remove_dir_all(&bob_dir)?;
        std::fs::remove_dir_all(&charlie_dir)?;
        Ok(())
    }

    #[tokio::test]
    async fn application_message_frame_decrypts_via_group_id_resolved_file() -> TestResult {
        let alice_dir = temp_dir("appmsg-alice");
        let bob_dir = temp_dir("appmsg-bob");
        std::fs::create_dir_all(&alice_dir)?;
        std::fs::create_dir_all(&bob_dir)?;
        let alice_pw = b"alice-pw";
        let bob_pw = b"bob-pw";

        create::create_group(&alice_dir, alice_pw, "cell")?;
        let bob_kp = kp::export_keypackage(&bob_dir, bob_pw)?;
        let welcome_frame =
            add_member_and_capture_frame(&alice_dir, alice_pw, "cell", "bob", &bob_kp).await?;
        let joined_event = process_inbound_group_frame(&bob_dir, bob_pw, &welcome_frame)?;
        let InboundGroupEvent::Joined {
            group_name: bob_group_name,
        } = joined_event
        else {
            return Err("expected Joined event".into());
        };

        // Alice sends a real, encrypted application message.
        let alice_group_path = alice_dir.join("groups").join("cell.enc");
        let (mut alice_group, _roster, alice_provider) =
            persistence::load_group_state(&alice_group_path, alice_pw)?;
        let alice_identity =
            identity::load_group_identity(&alice_dir.join("group-identity.enc"), alice_pw)?;
        let plaintext = b"hello from alice".to_vec();
        let app_message_out = alice_group.create_message(
            &alice_provider,
            &alice_identity.signature_key_pair,
            &plaintext,
        )?;

        let group_id = alice_group.group_id().to_vec();
        let mls_bytes = {
            use openmls::prelude::tls_codec::Serialize as _;
            app_message_out.tls_serialize_detached()?
        };
        let mut frame = Vec::new();
        frame.extend_from_slice(&u32::try_from(group_id.len())?.to_be_bytes());
        frame.extend_from_slice(&group_id);
        frame.extend_from_slice(&u32::try_from(mls_bytes.len())?.to_be_bytes());
        frame.extend_from_slice(&mls_bytes);

        let event = process_inbound_group_frame(&bob_dir, bob_pw, &frame)?;
        assert_eq!(
            event,
            InboundGroupEvent::ApplicationMessage {
                group_name: bob_group_name.clone(),
                plaintext: plaintext.clone(),
            }
        );

        // Bob's state must still be loadable afterward (the re-persist
        // succeeded, not just the in-memory decrypt).
        let bob_group_path = bob_dir.join("groups").join(format!("{bob_group_name}.enc"));
        let (bob_group, _roster, _provider) =
            persistence::load_group_state(&bob_group_path, bob_pw)?;
        assert_eq!(bob_group.members().count(), 2);

        std::fs::remove_dir_all(&alice_dir)?;
        std::fs::remove_dir_all(&bob_dir)?;
        Ok(())
    }

    #[test]
    fn empty_frame_is_a_clean_error_not_a_panic() {
        let dir = temp_dir("malformed-empty");
        let result = process_inbound_group_frame(&dir, b"pw", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn truncated_length_prefix_is_a_clean_error_not_a_panic() {
        let dir = temp_dir("malformed-truncated");
        let result = process_inbound_group_frame(&dir, b"pw", &[0u8, 1u8]);
        assert!(result.is_err());
    }

    #[test]
    fn garbage_mls_payload_is_a_clean_error_not_a_panic() -> TestResult {
        let dir = temp_dir("malformed-garbage");
        let group_id = b"g";
        let junk = b"not a valid tls-codec MlsMessageIn payload at all, just junk bytes";
        let mut frame = Vec::new();
        frame.extend_from_slice(&u32::try_from(group_id.len())?.to_be_bytes());
        frame.extend_from_slice(group_id);
        frame.extend_from_slice(&u32::try_from(junk.len())?.to_be_bytes());
        frame.extend_from_slice(junk);

        let result = process_inbound_group_frame(&dir, b"pw", &frame);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn unsupported_message_type_is_a_clean_error_not_a_panic()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dir = temp_dir("malformed-unsupported-type");
        let message = sample_keypackage_message()?;
        let mls_bytes = {
            use openmls::prelude::tls_codec::Serialize as _;
            message.tls_serialize_detached()?
        };
        let group_id = b"whatever-group-id";
        let mut frame = Vec::new();
        frame.extend_from_slice(&u32::try_from(group_id.len())?.to_be_bytes());
        frame.extend_from_slice(group_id);
        frame.extend_from_slice(&u32::try_from(mls_bytes.len())?.to_be_bytes());
        frame.extend_from_slice(&mls_bytes);

        let result = process_inbound_group_frame(&dir, b"pw", &frame);
        assert!(
            matches!(result, Err(GroupError::Malformed(_))),
            "got {result:?}"
        );
        Ok(())
    }
}
