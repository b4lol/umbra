//! `umbra group remove`: removes a member from an existing PQ-MLS
//! group by committing a `Remove` proposal, persisting the updated
//! group state, and fanning out the resulting `Commit` plus a fresh
//! roster sync to the REMAINING members (TODO B.2.2).
//!
//! # Who may remove whom (a deliberate ruling, not an oversight)
//!
//! There is no ACL: any member of a cell may remove any other member.
//! The single-cell increment's trust model is co-equal — every member
//! can already add members, send as themselves, or withhold/garbage
//! their own deliveries, so removal power adds no new capability class.
//! MLS itself enforces the one property that matters: a removed member
//! can still decrypt traffic from BEFORE their removal (nothing can
//! take that back — they already hold those keys), but the Commit
//! advances the group epoch without them, so nothing sent AFTER the
//! removal is readable by them (TreeKEM's native post-removal
//! security). This is documented operator-facing in
//! docs/THREAT_MODEL.md's group-mode scope.
//!
//! # Delivery-failure semantics (same ruling as `add.rs`/`send.rs`)
//!
//! The state mutation (the removal commit) is persisted BEFORE any
//! delivery is attempted. Per-member delivery failures never produce
//! an `Err` once the state is durable — a member who misses the Commit
//! is stuck at the old epoch and will reject new messages until they
//! receive it, exactly the ruled semantics of `add_member`'s Commit
//! fan-out. The removed member deliberately receives NOTHING.
//!
//! # Roster sync after removal (TODO B.2.1)
//!
//! MLS Commits carry no Umbra peer names, so the remaining members
//! would not learn that `peer_name` is gone from the roster. Exactly
//! as after an `add_member`, a full roster snapshot (typed application
//! message, tag `0x01`) is fanned out to every REMAINING member after
//! the Commit — see [`crate::roster_sync`]'s module docs.

use std::path::Path;

use openmls::prelude::OpenMlsProvider as _;

use crate::delivery::{self, PeerTransportAddress};
use crate::error::GroupError;
use crate::identity::{self, GROUP_IDENTITY_FILE_NAME};
use crate::persistence::{self};
use crate::roster_sync;

/// Subdirectory (relative to the keystore directory) holding one
/// encrypted group-state file per group, named `<group_name>.enc`
/// (mirrors `create.rs`'s private `GROUPS_DIR_NAME` — duplicated rather
/// than imported since that constant is private to `create.rs`; both
/// name the same subdirectory by design).
const GROUPS_DIR_NAME: &str = "groups";

/// Removes `peer_name` from the group named `group_name`.
///
/// Loads the group's persisted state and this peer's group identity
/// from `keystore_dir` (production Argon2id costs — like
/// [`crate::create::create_group`], this is a CLI-facing entry point
/// with no cost-param seam), resolves `peer_name` to an MLS leaf index
/// via the persisted roster, commits the removal via
/// `MlsGroup::remove_members`, merges the pending commit, drops the
/// peer from the roster, and persists the updated state — all BEFORE
/// attempting any delivery (see the module docs' "Delivery-failure
/// semantics" section for why).
///
/// The resulting `Commit` is then delivered to every REMAINING member
/// (the roster as it is AFTER the removal — the removed member can no
/// longer process the new epoch, so sending them the Commit would be
/// both useless and a needless disclosure), followed by a full roster
/// sync to the same set (TODO B.2.1). `peer_lookup` and `connect` are
/// exactly as documented on [`delivery::deliver_to_members`].
///
/// # Errors
///
/// Returns [`GroupError::Malformed`] if `peer_name` is not in the
/// persisted roster (the roster is the only name ↔ leaf-index mapping;
/// refusing to guess a leaf index is deliberate — removing the WRONG
/// leaf would evict an innocent member). Returns [`GroupError`] if the
/// group state or peer identity cannot be loaded, if
/// `MlsGroup::remove_members`/`merge_pending_commit` itself fails, or
/// if the updated state cannot be persisted. Does NOT return an error
/// for a Commit/roster-sync DELIVERY failure once the state mutation
/// has already been durably saved; a roster-sync CREATION or
/// persistence failure (as opposed to a delivery failure) DOES surface
/// as `Err` — the removal itself is already durable at that point, so
/// the error means only the sync failed.
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

    // The group identity must already exist (same ruling as
    // `add_member`: mutating a group this peer never created/joined
    // with an identity is a real error, never papered over).
    let identity_path = keystore_dir.join(GROUP_IDENTITY_FILE_NAME);
    let identity = identity::load_group_identity(&identity_path, passphrase)?;

    // The roster is the ONLY name ↔ leaf-index mapping. Refuse to
    // guess: removing by a guessed leaf index could evict the wrong
    // member.
    let removed_leaf_index = old_roster.leaf_index_for(peer_name).ok_or_else(|| {
        GroupError::Malformed(format!(
            "peer '{peer_name}' is not in group '{group_name}'s roster"
        ))
    })?;

    // Sanity guard against roster drift: the leaf the roster names
    // must still be a member of the group. If the roster and the MLS
    // tree disagree, surfacing an error is the fail-closed behavior —
    // never remove a leaf that might belong to someone else.
    if !group
        .members()
        .any(|member| member.index == removed_leaf_index)
    {
        return Err(GroupError::Malformed(format!(
            "roster leaf index for '{peer_name}' is not a member of the MLS tree \
             (roster drift — state file inconsistent)"
        )));
    }

    let (commit_msg, _welcome, _group_info) = group.remove_members(
        &provider,
        &identity.signature_key_pair,
        &[removed_leaf_index],
    )?;
    group.merge_pending_commit(&provider)?;

    let mut new_roster = old_roster;
    new_roster.members.retain(|(name, _)| name != peer_name);

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

    // Fan out the Commit to the REMAINING members only. Per-member
    // outcomes are intentionally discarded (module docs).
    let _commit_results = delivery::deliver_to_members(
        &new_roster,
        &peer_lookup,
        &connect,
        &group_id_bytes,
        &commit_msg,
    )
    .await;

    // Finally, the roster sync (TODO B.2.1): the remaining members
    // learn the post-removal roster. Same ruled semantics as in
    // `add.rs` — creation/persistence failure is an `Err`, per-member
    // delivery failure is not.
    roster_sync::fan_out_roster_sync(
        &mut roster_sync::GroupSessionContext {
            group: &mut group,
            provider: &provider,
            identity: &identity,
            group_state_path: &group_state_path,
            passphrase,
        },
        &new_roster,
        &peer_lookup,
        &connect,
    )
    .await?;

    Ok(())
}
