//! `umbra group add`: adds a new member to an existing PQ-MLS group by
//! processing a peer's exported `KeyPackage`, committing the addition,
//! persisting the updated group state, and fanning out the resulting
//! `Commit` (to the previously-existing members) and `Welcome` (to the
//! new member) over each member's own transport (spec Decision 6, TODO
//! B.2).
//!
//! # Corrections to the original task brief (ruled before dispatch)
//!
//! The original brief sketched `add_member` as `pub fn` delivering over
//! `LoopbackTransport`, and its own signature took only a `peer_lookup`
//! closure. Both are stale: Task 7 was corrected to deliver over a raw
//! byte stream via a caller-supplied `connect` closure (see
//! `delivery.rs`'s own module docs for the full trace), so this
//! function is `pub async fn` and takes both `peer_lookup` *and*
//! `connect`, matching [`delivery::deliver_to_members`]'s shape
//! exactly.
//!
//! # Delivery-failure semantics (ruled, binding)
//!
//! [`add_member`] returns `Ok(())` once the group-state mutation is
//! durably saved via [`persistence::save_group_state`], REGARDLESS of
//! individual Commit/Welcome delivery outcomes — a delivery failure
//! must never turn a successful state mutation into an `Err` return,
//! which would misleadingly imply nothing happened when the group's
//! tree/roster genuinely changed. This extends
//! [`delivery::deliver_to_members`]'s own "one member's failure never
//! aborts delivery to the rest" philosophy one level up.
//!
//! The per-member `Vec<(String, Result<(), GroupError>)>` results from
//! both delivery calls (Commit fan-out to the old members, Welcome to
//! the new member) are intentionally NOT threaded back out through this
//! function's own `Result<(), GroupError>` — the ruled, binding
//! signature below has no room for them (adding an `Ok(AddOutcome)`
//! payload type was considered and is a legitimate future refinement,
//! but the dispatch prompt for this task gave the exact
//! `Result<(), GroupError>`-returning signature as binding). A future
//! caller that needs per-member delivery telemetry (e.g. the CLI
//! printing a warning per failed delivery) would need this function
//! restructured to return that data — not attempted here to keep this
//! task's diff matching its given signature exactly.
//!
//! # Untrusted key-package validation
//!
//! `key_package_blob` is externally supplied (delivered out of band
//! from whoever is being added) and MUST be validated, not merely
//! decoded: [`openmls::prelude::KeyPackageIn::validate`] checks the
//! leaf-node signature, protocol version, and that the init/encryption
//! keys differ (verified against installed `openmls-0.9.0` source,
//! `src/key_packages/key_package_in.rs`). The unchecked `From<KeyPackageIn>
//! for KeyPackage` conversion that also exists in that file is
//! deliberately never used here — it skips all of this.
//!
//! # `GROUP_IDENTITY_FILE_NAME` duplication (resolved for this task)
//!
//! `create.rs` and `keypackage.rs` each independently define a private
//! `GROUP_IDENTITY_FILE_NAME` constant for the same file name. This
//! function is a third call site needing that exact path fragment, so
//! the constant was extracted into `identity.rs` itself (`pub(crate)
//! GROUP_IDENTITY_FILE_NAME`, since that module already owns the
//! group-identity concept) rather than duplicated a third time.
//! `create.rs`/`keypackage.rs` were left untouched (still using their
//! own already-reviewed private copies of the identical value) to keep
//! this task's diff scoped to membership addition; a future pass could
//! migrate them to the shared constant with no behavior change.

use std::path::Path;

use base64::Engine as _;
use openmls::prelude::tls_codec::DeserializeBytes as _;
use openmls::prelude::{KeyPackageIn, OpenMlsProvider as _, ProtocolVersion};

use crate::delivery::{self, PeerTransportAddress};
use crate::error::GroupError;
use crate::identity::{self, GROUP_IDENTITY_FILE_NAME};
use crate::persistence::{self, GroupRoster};
use crate::roster_sync;

/// Subdirectory (relative to the keystore directory) holding one
/// encrypted group-state file per group, named `<group_name>.enc`
/// (mirrors `create.rs`'s private `GROUPS_DIR_NAME` — duplicated rather
/// than imported since that constant is private to `create.rs`; both
/// name the same subdirectory by design).
const GROUPS_DIR_NAME: &str = "groups";

/// Adds `peer_name` (whose exported `KeyPackage` is `key_package_blob`,
/// base64 `URL_SAFE_NO_PAD` — matching [`crate::keypackage::export_keypackage`]'s
/// own encoding exactly) to the group named `group_name`.
///
/// Loads the group's persisted state and this peer's group identity
/// from `keystore_dir` (production Argon2id costs — like
/// [`crate::create::create_group`], this is a CLI-facing entry point
/// with no cost-param seam), validates the incoming key package,
/// commits the addition via `MlsGroup::add_members`, merges the
/// pending commit, extends the roster with `peer_name` mapped to the
/// new member's leaf index, and persists the updated state — all
/// BEFORE attempting any delivery (see the module docs' "Delivery-
/// failure semantics" section for why).
///
/// The resulting `Commit` is then delivered to every member of the
/// group's roster AS IT WAS BEFORE this call (the previously-existing
/// members — the new member gets a `Welcome` instead, per RFC 9420
/// semantics, never a `Commit` for their own addition), and the
/// `Welcome` is delivered to `peer_name` alone. `peer_lookup` resolves
/// an Umbra peer name to a transport address; `connect` resolves that
/// address to an already-usable, boxed stream — both exactly as
/// documented on [`delivery::deliver_to_members`], which this function
/// calls twice (once per message).
///
/// # Errors
///
/// Returns [`GroupError`] if the group state or peer identity cannot be
/// loaded, if `key_package_blob` is not valid base64 or not a validly
/// signed `KeyPackage`, if `MlsGroup::add_members`/`merge_pending_commit`
/// itself fails, if the newly added member cannot be found in the group
/// after the merge (should be unreachable — see the inline comment at
/// that call site), or if the updated state cannot be persisted. Does
/// NOT return an error for a Commit/Welcome delivery failure once the
/// state mutation has already been durably saved.
pub async fn add_member<F, Fut>(
    keystore_dir: &Path,
    passphrase: &[u8],
    group_name: &str,
    peer_name: &str,
    key_package_blob: &str,
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
    let (mut group, old_roster, provider) =
        persistence::load_group_state(&group_state_path, passphrase)?;

    // The group identity must already exist — adding a member to a
    // group this peer never created/joined with an identity is a real
    // error, not something to paper over by generating one on the fly
    // (unlike `create_group`/`export_keypackage`'s load-or-generate
    // behavior, which is appropriate for THEIR first-use cases).
    let identity_path = keystore_dir.join(GROUP_IDENTITY_FILE_NAME);
    let identity = identity::load_group_identity(&identity_path, passphrase)?;

    // Untrusted, externally-supplied bytes: decode, then VALIDATE
    // (never trust an unvalidated `KeyPackageIn` — see module docs).
    let key_package_bytes =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(key_package_blob)?;
    let key_package_in = KeyPackageIn::tls_deserialize_exact_bytes(&key_package_bytes)?;
    let key_package = key_package_in.validate(provider.crypto(), ProtocolVersion::Mls10)?;

    let (commit_msg, welcome_msg, _group_info) = group.add_members(
        &provider,
        &identity.signature_key_pair,
        std::slice::from_ref(&key_package),
    )?;
    group.merge_pending_commit(&provider)?;

    // No simpler direct accessor exists (verified against installed
    // source): the new member's leaf index is found by matching
    // credentials against the post-merge member list.
    let new_leaf_index = group
        .members()
        .find(|member| &member.credential == key_package.leaf_node().credential())
        .map(|member| member.index)
        .ok_or_else(|| {
            GroupError::Malformed("newly added member not found in group after merge".into())
        })?;

    let mut new_roster = old_roster.clone();
    new_roster
        .members
        .push((peer_name.to_string(), new_leaf_index));

    // Build the RosterSync application message BEFORE the durable
    // save below: `create_message` advances the sender's own
    // secret-tree/ratchet state as a required step of encryption
    // (the same rule `send.rs`'s own module docs establish — forward
    // secrecy requires the used key material to be consumed and
    // persisted immediately), so this message's ratchet advancement
    // must be captured in the SAME save as the Commit-merge's storage
    // state, not a separate later one.
    let roster_sync_message = group.create_message(
        &provider,
        &identity.signature_key_pair,
        &roster_sync::encode(&new_roster)?,
    )?;

    // The state mutation is now durable. Nothing after this point may
    // turn a successful save into an `Err` return (ruled semantics —
    // see module docs).
    persistence::save_group_state(
        &group_state_path,
        passphrase,
        &group,
        provider.storage(),
        &new_roster,
    )?;

    let group_id_bytes = group.group_id().to_vec();

    // Fan out the Commit to the PREVIOUSLY-existing members (`old_roster`,
    // not `new_roster`) — the new member receives the Welcome instead,
    // never a Commit for their own addition (RFC 9420 semantics).
    // Per-member outcomes are intentionally discarded (module docs).
    let _commit_results = delivery::deliver_to_members(
        &old_roster,
        &peer_lookup,
        &connect,
        &group_id_bytes,
        &commit_msg,
    )
    .await;

    // Fan out the Welcome to ONLY the new member.
    let welcome_roster = GroupRoster {
        members: vec![(peer_name.to_string(), new_leaf_index)],
    };
    let _welcome_results = delivery::deliver_to_members(
        &welcome_roster,
        &peer_lookup,
        &connect,
        &group_id_bytes,
        &welcome_msg,
    )
    .await;

    // Fan out the RosterSync to EVERYONE in the post-add roster (the
    // previously-existing members AND the new member) — TODO B.2.1's
    // own scoping: "immediately after the Welcome, and again to ALL
    // members after every subsequent add." Per-member outcomes are
    // intentionally discarded, matching this function's own
    // already-established delivery-failure semantics (module docs).
    let _roster_sync_results = delivery::deliver_to_members(
        &new_roster,
        &peer_lookup,
        &connect,
        &group_id_bytes,
        &roster_sync_message,
    )
    .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;

    use openmls::prelude::{
        Capabilities, Ciphersuite, CredentialWithKey, MlsGroup, MlsGroupCreateConfig,
        OpenMlsProvider as _,
    };
    use openmls_libcrux_crypto::Provider;
    use tokio::io::{AsyncReadExt, AsyncWrite, DuplexStream};
    use tokio::sync::Mutex;

    use super::*;
    use crate::keypackage;

    /// Shorthand for a boxed, `Send`, `Send`-error result — matches this
    /// crate's other test modules (`unwrap()`/`expect()` are denied even
    /// in test code by this workspace's clippy lints).
    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// The future type returned by [`queued_streams`]'s closure —
    /// factored into its own alias to satisfy `clippy::type_complexity`.
    type ConnectFuture = Pin<
        Box<
            dyn std::future::Future<Output = Result<Box<dyn AsyncWrite + Unpin + Send>, GroupError>>
                + Send,
        >,
    >;

    const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

    /// A `connect` closure routing to a per-address QUEUE of
    /// single-use `DuplexStream` halves — generalizes the old
    /// `dual_stream` helper now that `add_member` delivers THREE
    /// messages per call (Commit, Welcome, RosterSync) and a roster
    /// member can appear in more than one of those deliveries (e.g. an
    /// old member gets both the Commit and the RosterSync, on two
    /// SEPARATE connections — `deliver_to_members` opens a fresh
    /// connection per delivery call, never reuses one). Each address's
    /// queue is popped in the order its streams were registered,
    /// matching the order `add_member` performs its delivery calls
    /// (Commit-to-old-members, Welcome-to-new-member,
    /// RosterSync-to-everyone).
    fn queued_streams(
        streams: Vec<(
            PeerTransportAddress,
            std::collections::VecDeque<DuplexStream>,
        )>,
    ) -> impl Fn(&PeerTransportAddress) -> ConnectFuture {
        let state = Arc::new(Mutex::new(streams));
        move |address: &PeerTransportAddress| {
            let address = address.clone();
            let state = Arc::clone(&state);
            Box::pin(async move {
                let mut state = state.lock().await;
                let (_, queue) = state
                    .iter_mut()
                    .find(|(candidate, _)| candidate == &address)
                    .ok_or_else(|| {
                        GroupError::Malformed(format!(
                            "unexpected connect() address in test: {address:?}"
                        ))
                    })?;
                let stream = queue.pop_front().ok_or_else(|| {
                    GroupError::Malformed(format!(
                        "connect() called more times than expected for {address:?} in test"
                    ))
                })?;
                Ok(Box::new(stream) as Box<dyn AsyncWrite + Unpin + Send>)
            })
        }
    }

    /// Reads back one `[marker][group_id_len][group_id][mls_len][mls_bytes]`
    /// frame (per `delivery.rs`'s wire format) from `stream` and asserts
    /// the marker and group id match; the MLS payload is only asserted
    /// non-empty (its exact bytes are `delivery.rs`'s own concern —
    /// this test's job is to confirm `add_member` actually drives real
    /// delivery, not to re-verify `deliver_to_members`'s own framing).
    async fn assert_frame_matches<S>(mut stream: S, expected_group_id: &[u8]) -> TestResult
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let marker = stream.read_u8().await?;
        assert_eq!(marker, umbra_net::messenger::CONNECTION_TYPE_GROUP);

        let group_id_len = stream.read_u32().await?;
        let mut group_id = vec![0u8; usize::try_from(group_id_len)?];
        stream.read_exact(&mut group_id).await?;
        assert_eq!(group_id, expected_group_id);

        let mls_len = stream.read_u32().await?;
        let mut mls_bytes = vec![0u8; usize::try_from(mls_len)?];
        stream.read_exact(&mut mls_bytes).await?;
        assert!(!mls_bytes.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn add_member_persists_roster_and_delivers_commit_and_welcome() -> TestResult {
        let dir = std::env::temp_dir().join(format!(
            "umbra-group-add-test-{}-{}",
            std::process::id(),
            "roundtrip"
        ));
        std::fs::create_dir_all(&dir)?;
        let passphrase = b"add-member-test-passphrase";

        // Alice's group identity + a real, single-member `MlsGroup`,
        // persisted exactly the way `create_group` does (production
        // Argon2id costs — `add_member` itself has no cost-param seam,
        // so the fixture must use the same costs it will load with).
        let alice_identity = identity::generate_group_identity()?;
        identity::save_group_identity(
            &dir.join(GROUP_IDENTITY_FILE_NAME),
            passphrase,
            &alice_identity,
        )?;

        let provider = Provider::new()?;
        let credential_with_key = CredentialWithKey {
            credential: alice_identity.credential.clone().into(),
            signature_key: alice_identity.signature_key_pair.public().into(),
        };
        let capabilities = Capabilities::for_provider(provider.crypto());
        let group_create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .capabilities(capabilities)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new(
            &provider,
            &alice_identity.signature_key_pair,
            &group_create_config,
            credential_with_key,
        )?;
        let group_id = group.group_id().to_vec();

        let groups_dir = dir.join("groups");
        std::fs::create_dir_all(&groups_dir)?;
        let group_state_path = groups_dir.join("my-cell.enc");
        let initial_roster = GroupRoster {
            members: vec![("alice".to_string(), group.own_leaf_index())],
        };
        persistence::save_group_state(
            &group_state_path,
            passphrase,
            &group,
            provider.storage(),
            &initial_roster,
        )?;

        // Bob's key package, from a fully separate identity directory —
        // simulating a different peer, the same way `keypackage.rs`'s
        // own tests build one.
        let bob_dir = std::env::temp_dir().join(format!(
            "umbra-group-add-test-{}-{}",
            std::process::id(),
            "bob"
        ));
        std::fs::create_dir_all(&bob_dir)?;
        let key_package_blob = keypackage::export_keypackage(&bob_dir, b"bob-pw")?;

        let alice_addr = PeerTransportAddress::Onion("alice.onion".to_string());
        let bob_addr = PeerTransportAddress::Mesh("bob-mesh".to_string());
        // Alice (an old member, present in `old_roster`) receives 2
        // messages: the Commit, then the RosterSync. Bob (the new
        // member) also receives 2: the Welcome, then the RosterSync.
        let (alice_commit_member, alice_commit_observer) = tokio::io::duplex(8192);
        let (alice_roster_sync_member, alice_roster_sync_observer) = tokio::io::duplex(8192);
        let (bob_welcome_member, bob_welcome_observer) = tokio::io::duplex(8192);
        let (bob_roster_sync_member, bob_roster_sync_observer) = tokio::io::duplex(8192);
        let connect = queued_streams(vec![
            (
                alice_addr.clone(),
                std::collections::VecDeque::from([alice_commit_member, alice_roster_sync_member]),
            ),
            (
                bob_addr.clone(),
                std::collections::VecDeque::from([bob_welcome_member, bob_roster_sync_member]),
            ),
        ]);
        let peer_lookup = move |name: &str| match name {
            "alice" => Some(alice_addr.clone()),
            "bob" => Some(bob_addr.clone()),
            _ => None,
        };

        add_member(
            &dir,
            passphrase,
            "my-cell",
            "bob",
            &key_package_blob,
            peer_lookup,
            connect,
        )
        .await?;

        let (loaded_group, loaded_roster, _restored_provider) =
            persistence::load_group_state(&group_state_path, passphrase)?;
        assert_eq!(loaded_group.members().count(), 2);
        assert!(
            loaded_roster
                .members
                .iter()
                .any(|(name, _)| name == "alice")
        );
        let bob_leaf = loaded_roster
            .leaf_index_for("bob")
            .ok_or("bob missing from persisted roster")?;
        assert!(
            loaded_group
                .members()
                .any(|member| member.index == bob_leaf)
        );

        // The Commit (to alice), the Welcome (to bob), and the
        // RosterSync (to both) all actually made it onto their
        // respective streams.
        assert_frame_matches(alice_commit_observer, &group_id).await?;
        assert_frame_matches(alice_roster_sync_observer, &group_id).await?;
        assert_frame_matches(bob_welcome_observer, &group_id).await?;
        assert_frame_matches(bob_roster_sync_observer, &group_id).await?;

        std::fs::remove_dir_all(&dir)?;
        std::fs::remove_dir_all(&bob_dir)?;
        Ok(())
    }
}
