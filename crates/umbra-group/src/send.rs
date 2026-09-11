//! `umbra group send`: encrypts an application message with the
//! group's current MLS epoch state and fans it out to every member of
//! the group's roster over each member's own transport (spec Decision
//! 6, TODO B.2).
//!
//! The plaintext is framed as a TYPED application payload (tag `0x00`
//! = user text) before encryption, so Umbra-level control traffic —
//! the TODO B.2.1 roster sync, tag `0x01` — rides the group's own
//! AEAD channel through the same code path rather than a side channel.
//! See [`crate::roster_sync`]'s module docs for the tag table and
//! framing.
//!
//! # Corrections to the original task brief (ruled before dispatch)
//!
//! The original brief sketched `send_group_message` as `pub fn`
//! resolving `peer_lookup` alone. Both are stale for the same reason
//! Task 7/8 already established: delivery goes over a caller-supplied
//! `connect` closure via [`delivery::deliver_to_members`], which is
//! `async`, so this function is `pub async fn` and takes both
//! `peer_lookup` *and* `connect`, matching [`crate::add::add_member`]'s
//! shape exactly.
//!
//! # Delivery-failure semantics (ruled, binding — same as `add.rs`)
//!
//! `MlsGroup::create_message` mutates the group's own secret-tree/
//! ratchet state as a required step of encryption (it advances the
//! sender's own ratchet generation and writes that into storage,
//! exactly as `inbound.rs`'s own module docs describe happening on the
//! RECEIVING side for every processed message — the sending side is no
//! different: forward secrecy requires the used key material to be
//! consumed and persisted immediately, not left to be regenerated on
//! next load). So [`send_group_message`] durably saves the group's
//! updated state via [`persistence::save_group_state`] BEFORE
//! attempting any delivery, and returns `Ok(())` once that save
//! succeeds REGARDLESS of individual member delivery outcomes — a
//! delivery failure must never turn a successful send (the ciphertext
//! was produced and the group's own state already advanced past it)
//! into an `Err` return, which would misleadingly suggest nothing
//! happened. This mirrors [`crate::add::add_member`]'s own ruling
//! exactly; see that module's docs for the fuller discussion of why
//! per-member delivery results are intentionally not threaded back out
//! through this function's `Result<(), GroupError>` return type.
//!
//! # Verified OpenMLS API shape (installed `openmls-0.9.0` source)
//!
//! This workspace does not enable the `virtual-clients-draft` feature
//! (checked against `crates/umbra-group/Cargo.toml` and the workspace
//! root `Cargo.toml`'s `openmls` feature list), so the applicable
//! overload of `MlsGroup::create_message` (`src/group/mls_group/
//! application.rs`, `#[cfg(not(feature = "virtual-clients-draft"))]`)
//! is:
//!
//! ```text
//! pub fn create_message<Provider: OpenMlsProvider>(
//!     &mut self,
//!     provider: &Provider,
//!     signer: &impl Signer,
//!     message: &[u8],
//! ) -> Result<MlsMessageOut, CreateMessageError>
//! ```
//!
//! `CreateMessageError` here is the plain, NON-generic enum defined at
//! `src/group/mls_group/errors.rs` under the same
//! `#[cfg(not(feature = "virtual-clients-draft"))]` gate (`LibraryError`/
//! `MlsGroupStateError` variants only) — a different, simpler type from
//! the `virtual-clients-draft`-only `CreateMessageError<StorageError>`
//! generic form that only exists behind that feature. This exact
//! signature is also already exercised (unassigned to a `GroupError`
//! variant, just propagated via `?` inside a `Result<(), Box<dyn
//! Error>>`-returning test) by `persistence.rs`'s own
//! `save_and_load_round_trips_group_and_roster` test and `inbound.rs`'s
//! `application_message_frame_decrypts_via_group_id_resolved_file`
//! test, both of which already call
//! `group.create_message(&provider, &signer, &plaintext)` with this
//! exact argument shape — this task adds the first real `GroupError`
//! variant (`GroupError::MessageCreation`) wrapping the error type that
//! `?` finds there.

use std::path::Path;

use openmls::prelude::OpenMlsProvider as _;

use crate::delivery::{self, PeerTransportAddress};
use crate::error::GroupError;
use crate::identity::{self, GROUP_IDENTITY_FILE_NAME};
use crate::persistence;
use crate::roster_sync;

/// Subdirectory (relative to the keystore directory) holding one
/// encrypted group-state file per group, named `<group_name>.enc`
/// (mirrors `create.rs`/`add.rs`/`inbound.rs`'s own private
/// `GROUPS_DIR_NAME` copies — this task adds a fifth rather than
/// consolidating, consistent with this crate's existing file-name-
/// constant duplication pattern; see `add.rs`'s own module docs for why
/// that pattern is left alone rather than fixed incidentally here).
const GROUPS_DIR_NAME: &str = "groups";

/// Encrypts `plaintext` as an MLS application message under the group
/// named `group_name`'s current epoch state, then fans it out to every
/// member of the group's persisted [`persistence::GroupRoster`].
///
/// Loads the group's persisted state and this peer's group identity
/// from `keystore_dir` (production Argon2id costs — like
/// [`crate::create::create_group`]/[`crate::add::add_member`], this is
/// a CLI-facing entry point with no cost-param seam), calls
/// `MlsGroup::create_message` to produce the ciphertext, and persists
/// the resulting (ratchet-advanced) group state — all BEFORE attempting
/// any delivery (see the module docs' "Delivery-failure semantics"
/// section for why).
///
/// The resulting application-message frame is then delivered to every
/// member of the roster via [`delivery::deliver_to_members`];
/// `peer_lookup` resolves an Umbra peer name to a transport address and
/// `connect` resolves that address to an already-usable, boxed stream,
/// both exactly as documented on [`delivery::deliver_to_members`].
///
/// # Errors
///
/// Returns [`GroupError`] if the group state or peer identity cannot be
/// loaded, if `MlsGroup::create_message` itself fails (e.g. this peer
/// has been evicted from the group, or a pending proposal blocks
/// sending), or if the updated state cannot be persisted. Does NOT
/// return an error for a per-member delivery failure once the state
/// mutation has already been durably saved.
pub async fn send_group_message<F, Fut>(
    keystore_dir: &Path,
    passphrase: &[u8],
    group_name: &str,
    plaintext: &[u8],
    peer_lookup: impl Fn(&str) -> Option<PeerTransportAddress>,
    connect: F,
) -> Result<(), GroupError>
where
    F: Fn(&PeerTransportAddress) -> Fut,
    Fut: std::future::Future<
            Output = Result<Box<dyn tokio::io::AsyncWrite + Unpin + Send>, GroupError>,
        >,
{
    let group_state_path = keystore_dir
        .join(GROUPS_DIR_NAME)
        .join(format!("{group_name}.enc"));
    let (mut group, roster, provider) =
        persistence::load_group_state(&group_state_path, passphrase)?;

    // The group identity must already exist — sending from a group this
    // peer never created/joined with an identity is a real error, not
    // something to paper over (same reasoning as `add_member`'s
    // identical load, never generate-on-the-fly here).
    let identity_path = keystore_dir.join(GROUP_IDENTITY_FILE_NAME);
    let identity = identity::load_group_identity(&identity_path, passphrase)?;

    // The payload is framed as a TYPED application payload (the user-
    // text tag), so control traffic (roster syncs, TODO B.2.1) and user
    // text share the group's own AEAD channel with no side channel —
    // see `roster_sync.rs`'s module docs.
    let framed = roster_sync::encode_user_text(plaintext);
    let message = group.create_message(&provider, &identity.signature_key_pair, &framed)?;

    // The state mutation (ratchet/generation advancement) is now
    // durable. Nothing after this point may turn a successful save into
    // an `Err` return (ruled semantics — see module docs).
    persistence::save_group_state(
        &group_state_path,
        passphrase,
        &group,
        provider.storage(),
        &roster,
    )?;

    let group_id_bytes = group.group_id().to_vec();

    // Per-member outcomes are intentionally discarded (module docs).
    let _results =
        delivery::deliver_to_members(&roster, &peer_lookup, &connect, &group_id_bytes, &message)
            .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWrite, DuplexStream};
    use tokio::sync::Mutex;

    use super::*;
    use crate::inbound::{self, InboundGroupEvent};
    use crate::{add, create, keypackage};

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

    /// Hands out one end of a `tokio::io::duplex` pair from an `Fn`
    /// closure (mirrors `add.rs`/`delivery.rs`/`inbound.rs`'s own test
    /// helper of the same shape).
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
    /// everything after it (until the writer side closes) — exactly
    /// `process_inbound_group_frame`'s own `frame_bytes` argument
    /// (marker already stripped). Mirrors `inbound.rs`'s own
    /// `capture_frame` test helper.
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

    /// Sets up a fresh temp dir under `std::env::temp_dir()`, unique per
    /// test/label pair (mirrors this crate's existing test style).
    fn temp_dir(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "umbra-group-send-test-{}-{label}",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn send_group_message_delivers_a_frame_that_decrypts_to_the_exact_plaintext() -> TestResult
    {
        let alice_dir = temp_dir("alice");
        let bob_dir = temp_dir("bob");
        std::fs::create_dir_all(&alice_dir)?;
        std::fs::create_dir_all(&bob_dir)?;
        let alice_pw = b"alice-pw";
        let bob_pw = b"bob-pw";

        // Real 2-member group, built via Tasks 5/6/8's own real flow —
        // exactly as `inbound.rs`'s own tests do (rather than hand-
        // assembling an `MlsGroup` the way `add.rs`'s own test fixture
        // does): `create_group` + `export_keypackage` + `add_member`.
        //
        // Note: `add_member` now also sends a RosterSync to the new
        // member (TODO B.2.1) as a SECOND connection; this test's
        // single-use `connect` closure deliberately lets that second
        // connection fail (per-member delivery failures are non-fatal
        // by `add_member`'s ruled semantics) — this test's subject is
        // the application-message path, not the sync.
        create::create_group(&alice_dir, alice_pw, "cell", "alice")?;
        let bob_kp = keypackage::export_keypackage(&bob_dir, bob_pw)?;

        let bob_addr = PeerTransportAddress::Mesh("bob-mesh".to_string());
        let welcome_frame = {
            let (bob_member_side, bob_observer_side) = tokio::io::duplex(8192);
            let connect = single_use_stream(bob_member_side);
            let peer_lookup = {
                let bob_addr = bob_addr.clone();
                move |name: &str| {
                    if name == "bob" {
                        Some(bob_addr.clone())
                    } else {
                        None
                    }
                }
            };

            add::add_member(
                &alice_dir,
                alice_pw,
                "cell",
                "bob",
                &bob_kp,
                peer_lookup,
                connect,
            )
            .await?;

            capture_frame(bob_observer_side).await?
        };

        // Bob actually joins (via the real inbound path) so his own
        // group file exists under its ruling-derived name.
        let joined_event = inbound::process_inbound_group_frame(&bob_dir, bob_pw, &welcome_frame)?;
        let InboundGroupEvent::Joined {
            group_name: bob_group_name,
        } = joined_event
        else {
            return Err("expected Joined event".into());
        };

        // Now exercise the function under test: Alice sends a real
        // application message, fanned out to the group's roster (which,
        // after `add_member`, contains only "bob" — `create_group`
        // persists an empty initial member list; the local member is
        // never listed in their own roster).
        let plaintext = b"hello from alice via send_group_message".to_vec();
        let application_frame = {
            let (bob_member_side, bob_observer_side) = tokio::io::duplex(8192);
            let connect = single_use_stream(bob_member_side);
            let peer_lookup = {
                let bob_addr = bob_addr.clone();
                move |name: &str| {
                    if name == "bob" {
                        Some(bob_addr.clone())
                    } else {
                        None
                    }
                }
            };

            send_group_message(
                &alice_dir,
                alice_pw,
                "cell",
                &plaintext,
                peer_lookup,
                connect,
            )
            .await?;

            capture_frame(bob_observer_side).await?
        };

        let event = inbound::process_inbound_group_frame(&bob_dir, bob_pw, &application_frame)?;
        assert_eq!(
            event,
            InboundGroupEvent::ApplicationMessage {
                group_name: bob_group_name,
                plaintext: plaintext.clone(),
            }
        );

        std::fs::remove_dir_all(&alice_dir)?;
        std::fs::remove_dir_all(&bob_dir)?;
        Ok(())
    }
}
