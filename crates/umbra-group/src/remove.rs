//! `umbra group remove`: removes a member from an existing PQ-MLS
//! group via OpenMLS's `remove_members`, persists the updated state,
//! and broadcasts the resulting roster (with the removed peer's entry
//! gone) to the REMAINING members via RosterSync (TODO B.2.1) — the
//! removed peer receives nothing (RFC 9420 semantics), mirroring
//! `add_member`'s own Welcome-only-to-the-new-member precedent for the
//! opposite direction (spec Decision 6, TODO B.2.2).
//!
//! # Delivery-failure semantics (mirrors `add_member`/`send_group_message`)
//!
//! Returns `Ok(())` once the group-state mutation is durably saved,
//! regardless of individual Commit/RosterSync delivery outcomes — see
//! `add.rs`'s own module docs for the fuller discussion.
//!
//! # Verified OpenMLS API shape (installed `openmls-0.9.0` source)
//!
//! ```text
//! pub fn remove_members<Provider: OpenMlsProvider>(
//!     &mut self,
//!     provider: &Provider,
//!     signer: &impl Signer,
//!     members: &[LeafNodeIndex],
//! ) -> Result<
//!     (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>),
//!     RemoveMembersError<Provider::StorageError>,
//! >
//! ```
//! (`src/group/mls_group/membership.rs`). The `Option<MlsMessageOut>`
//! Welcome is `Some` only when the queue of pending proposals ALSO
//! contained Add proposals — never the case in this crate's flows
//! (each of `add_member`/`remove_member`/`rotate_key` always merges
//! its own commit immediately, leaving no pending proposals behind),
//! so it is always `None` here and discarded.

use std::path::Path;

use openmls::prelude::OpenMlsProvider as _;

use crate::delivery::{self, PeerTransportAddress};
use crate::error::GroupError;
use crate::identity::{self, GROUP_IDENTITY_FILE_NAME};
use crate::persistence::{self, GroupRoster};
use crate::roster_sync;

/// Subdirectory (relative to the keystore directory) holding one
/// encrypted group-state file per group, named `<group_name>.enc`
/// (mirrors `add.rs`/`send.rs`'s own private `GROUPS_DIR_NAME` copies
/// — this module adds a fourth rather than consolidating, consistent
/// with this crate's existing file-name-constant duplication pattern).
const GROUPS_DIR_NAME: &str = "groups";

/// Removes `peer_name` from the group named `group_name`: commits the
/// removal, persists the updated state and roster, and fans out the
/// resulting Commit AND a RosterSync (the new, post-removal roster) to
/// every REMAINING member — `peer_name` itself receives nothing.
///
/// # Errors
///
/// Returns [`GroupError::PeerNotInRoster`] if `peer_name` is not in
/// the group's currently persisted roster. Returns [`GroupError`] if
/// the group state or peer identity cannot be loaded, if
/// `MlsGroup::remove_members`/`merge_pending_commit` itself fails, or
/// if the updated state cannot be persisted. Does NOT return an error
/// for a Commit/RosterSync delivery failure once the state mutation
/// has already been durably saved.
pub async fn remove_member<F, Fut>(
    keystore_dir: &Path,
    passphrase: &[u8],
    group_name: &str,
    peer_name: &str,
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

    let identity_path = keystore_dir.join(GROUP_IDENTITY_FILE_NAME);
    let identity = identity::load_group_identity(&identity_path, passphrase)?;

    let leaf_index = old_roster
        .leaf_index_for(peer_name)
        .ok_or_else(|| GroupError::PeerNotInRoster(peer_name.to_string()))?;

    let (commit_msg, _welcome_msg, _group_info) = group.remove_members(
        &provider,
        &identity.signature_key_pair,
        std::slice::from_ref(&leaf_index),
    )?;
    group.merge_pending_commit(&provider)?;

    let new_roster = GroupRoster {
        members: old_roster
            .members
            .iter()
            .filter(|(name, _)| name != peer_name)
            .cloned()
            .collect(),
    };

    // Build the RosterSync application message BEFORE the durable
    // save below: `create_message` advances the sender's own
    // secret-tree/ratchet state as a required step of encryption (the
    // same rule `add_member`'s own module docs establish), so this
    // message's ratchet advancement must be captured in the SAME save
    // as the Commit-merge's storage state.
    let roster_sync_message = group.create_message(
        &provider,
        &identity.signature_key_pair,
        &roster_sync::encode(&new_roster)?,
    )?;

    persistence::save_group_state(
        &group_state_path,
        passphrase,
        &group,
        provider.storage(),
        &new_roster,
    )?;

    let group_id_bytes = group.group_id().to_vec();

    // Fan out the Commit to the REMAINING members (`new_roster`) —
    // `peer_name` receives nothing. Per-member outcomes discarded
    // (module docs).
    let _commit_results = delivery::deliver_to_members(
        &new_roster,
        &peer_lookup,
        &connect,
        &group_id_bytes,
        &commit_msg,
    )
    .await;

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

    use base64::Engine as _;
    use openmls::prelude::tls_codec::DeserializeBytes as _;
    use openmls::prelude::{
        Capabilities, Ciphersuite, CredentialWithKey, KeyPackageIn, MlsGroup, MlsGroupCreateConfig,
        ProtocolVersion,
    };
    use openmls_libcrux_crypto::Provider;
    use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, DuplexStream};
    use tokio::sync::Mutex;

    use super::*;
    use crate::keypackage;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
    type ConnectFuture = Pin<
        Box<
            dyn std::future::Future<Output = Result<Box<dyn AsyncWrite + Unpin + Send>, GroupError>>
                + Send,
        >,
    >;

    const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

    /// A `connect` closure routing to a per-address QUEUE of
    /// single-use `DuplexStream` halves (mirrors `add.rs`'s own
    /// `queued_streams` test helper exactly).
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

    /// Reads back a `[marker byte][remaining bytes to EOF]` frame from
    /// `stream`. Local to this test module rather than calling a
    /// nonexistent `crate::delivery::test_support::read_frame` (no such
    /// module exists in `delivery.rs`) — mirrors the marker-byte-then-
    /// rest-of-stream pattern already used by `add.rs`'s/
    /// `hermetic_multi_party.rs`'s own frame-reading test helpers.
    async fn read_frame<S>(
        mut stream: S,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + Unpin,
    {
        stream.read_u8().await?; // marker byte
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        Ok(buf)
    }

    #[tokio::test]
    async fn remove_member_updates_roster_and_excludes_removed_peer() -> TestResult {
        let dir = std::env::temp_dir().join(format!(
            "umbra-group-remove-test-{}-{}",
            std::process::id(),
            "roundtrip"
        ));
        std::fs::create_dir_all(&dir)?;
        let passphrase = b"remove-member-test-passphrase";

        // Build a real 2-member group directly (alice + bob), mirroring
        // `add.rs`'s own test fixture, then add carol via the
        // already-tested `crate::add::add_member` to reach 3 members.
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
        let mut group = MlsGroup::new(
            &provider,
            &alice_identity.signature_key_pair,
            &group_create_config,
            credential_with_key,
        )?;

        let groups_dir = dir.join("groups");
        std::fs::create_dir_all(&groups_dir)?;
        let group_state_path = groups_dir.join("my-cell.enc");

        // Three members are needed to exercise a real delivery: after
        // removing carol, someone other than alice (the actor, whose
        // own address is deliberately never in `peer_lookup` — this
        // file's and `hermetic_multi_party.rs`'s established
        // convention) must remain in the roster to receive the Commit
        // and RosterSync. A 2-member (alice+bob) group with bob
        // removed would leave alice as the ONLY roster member, and
        // since alice's own address is never resolvable via
        // `peer_lookup`, nothing would ever be delivered — that
        // configuration cannot exercise this test's delivery
        // assertions at all.
        let bob_dir = std::env::temp_dir().join(format!(
            "umbra-group-remove-test-{}-{}",
            std::process::id(),
            "bob"
        ));
        std::fs::create_dir_all(&bob_dir)?;
        let bob_kp_blob = keypackage::export_keypackage(&bob_dir, b"bob-pw")?;
        let bob_kp_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&bob_kp_blob)?;
        let bob_kp_in = KeyPackageIn::tls_deserialize_exact_bytes(&bob_kp_bytes)?;
        let bob_kp = bob_kp_in.validate(provider.crypto(), ProtocolVersion::Mls10)?;
        let (_commit, _welcome, _info) =
            group.add_members(&provider, &alice_identity.signature_key_pair, &[bob_kp])?;
        group.merge_pending_commit(&provider)?;
        let alice_leaf = group.own_leaf_index();
        let bob_leaf = group
            .members()
            .find(|m| m.index != alice_leaf)
            .map(|m| m.index)
            .ok_or("bob leaf not found")?;

        let carol_dir = std::env::temp_dir().join(format!(
            "umbra-group-remove-test-{}-{}",
            std::process::id(),
            "carol"
        ));
        std::fs::create_dir_all(&carol_dir)?;
        let carol_kp_blob = keypackage::export_keypackage(&carol_dir, b"carol-pw")?;
        let carol_kp_bytes =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&carol_kp_blob)?;
        let carol_kp_in = KeyPackageIn::tls_deserialize_exact_bytes(&carol_kp_bytes)?;
        let carol_kp = carol_kp_in.validate(provider.crypto(), ProtocolVersion::Mls10)?;
        let (_commit, _welcome, _info) =
            group.add_members(&provider, &alice_identity.signature_key_pair, &[carol_kp])?;
        group.merge_pending_commit(&provider)?;
        let carol_leaf = group
            .members()
            .find(|m| m.index != alice_leaf && m.index != bob_leaf)
            .map(|m| m.index)
            .ok_or("carol leaf not found")?;

        let initial_roster = GroupRoster {
            members: vec![
                ("alice".to_string(), alice_leaf),
                ("bob".to_string(), bob_leaf),
                ("carol".to_string(), carol_leaf),
            ],
        };
        persistence::save_group_state(
            &group_state_path,
            passphrase,
            &group,
            provider.storage(),
            &initial_roster,
        )?;

        let bob_addr = PeerTransportAddress::Mesh("bob-mesh".to_string());
        let (bob_commit_member, bob_commit_observer) = tokio::io::duplex(8192);
        let (bob_roster_sync_member, bob_roster_sync_observer) = tokio::io::duplex(8192);
        let connect = queued_streams(vec![(
            bob_addr.clone(),
            std::collections::VecDeque::from([bob_commit_member, bob_roster_sync_member]),
        )]);
        let peer_lookup = move |name: &str| {
            if name == "bob" {
                Some(bob_addr.clone())
            } else {
                None
            }
        };

        remove_member(&dir, passphrase, "my-cell", "carol", peer_lookup, connect).await?;

        let (loaded_group, loaded_roster, _provider) =
            persistence::load_group_state(&group_state_path, passphrase)?;
        assert_eq!(loaded_group.members().count(), 2);
        assert!(loaded_roster.leaf_index_for("carol").is_none());
        assert_eq!(loaded_roster.members.len(), 2);
        assert!(loaded_roster.leaf_index_for("alice").is_some());
        assert!(loaded_roster.leaf_index_for("bob").is_some());

        let commit_bytes = read_frame(bob_commit_observer).await?;
        assert!(!commit_bytes.is_empty());
        let roster_sync_bytes = read_frame(bob_roster_sync_observer).await?;
        assert!(!roster_sync_bytes.is_empty());

        std::fs::remove_dir_all(&dir)?;
        std::fs::remove_dir_all(&bob_dir)?;
        std::fs::remove_dir_all(&carol_dir)?;
        Ok(())
    }

    #[tokio::test]
    async fn remove_member_rejects_unknown_peer() -> TestResult {
        let dir = std::env::temp_dir().join(format!(
            "umbra-group-remove-test-{}-{}",
            std::process::id(),
            "unknown-peer"
        ));
        std::fs::create_dir_all(&dir)?;
        let passphrase = b"remove-unknown-test-passphrase";
        crate::create::create_group(&dir, passphrase, "my-cell", "alice")?;

        let result = remove_member(
            &dir,
            passphrase,
            "my-cell",
            "nobody",
            |_| None,
            |_: &PeerTransportAddress| {
                Box::pin(async {
                    Err(GroupError::Malformed(
                        "connect() should not be called".into(),
                    ))
                }) as ConnectFuture
            },
        )
        .await;
        assert!(matches!(result, Err(GroupError::PeerNotInRoster(name)) if name == "nobody"));

        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
