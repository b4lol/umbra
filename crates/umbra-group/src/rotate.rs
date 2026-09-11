//! `umbra group rotate`: on-demand key rotation for an existing PQ-MLS
//! group via OpenMLS's `self_update` — a single Update Commit that
//! re-keys this member's leaf path and advances the group epoch,
//! fanned out to every member (TODO B.2.3).
//!
//! # What rotation does and does not do
//!
//! A `self_update` Commit refreshes this member's own leaf key material
//! and advances the group's epoch, giving post-compromise recovery for
//! the ROTATING member and re-mixing the epoch secret every member
//! derives from. It deliberately does NOT change membership (that is
//! `add.rs`/`remove.rs`) and does NOT rotate anyone else's leaf — each
//! member rotates their own. There is no automatic/periodic policy by
//! design (TODO B.2.3 ruling): rotation is operator-triggered via
//! `umbra group rotate`; a scheduler, if ever wanted, is a separate UX
//! decision.
//!
//! # No roster sync after rotation
//!
//! Membership is unchanged, so the roster is unchanged — the B.2.1
//! roster sync exists to propagate MEMBERSHIP knowledge, and there is
//! nothing new to learn after a rotation. The Commit alone advances
//! every member's epoch.
//!
//! # Delivery-failure semantics (same ruling as `add.rs`/`remove.rs`)
//!
//! The state mutation (the rotation commit) is persisted BEFORE any
//! delivery is attempted. Per-member delivery failures never produce
//! an `Err` once the state is durable — a member who misses the Commit
//! is stuck at the old epoch and will reject new messages until they
//! receive it.

use std::path::Path;

use openmls::prelude::{LeafNodeParameters, OpenMlsProvider as _};

use crate::delivery::{self, PeerTransportAddress};
use crate::error::GroupError;
use crate::identity::{self, GROUP_IDENTITY_FILE_NAME};
use crate::persistence;

/// Subdirectory (relative to the keystore directory) holding one
/// encrypted group-state file per group, named `<group_name>.enc`
/// (mirrors `create.rs`'s private `GROUPS_DIR_NAME` — duplicated rather
/// than imported since that constant is private to `create.rs`; both
/// name the same subdirectory by design).
const GROUPS_DIR_NAME: &str = "groups";

/// Rotates this member's key material in the group named `group_name`
/// (module docs).
///
/// Loads the group's persisted state and this peer's group identity
/// from `keystore_dir` (production Argon2id costs — like
/// [`crate::create::create_group`], this is a CLI-facing entry point
/// with no cost-param seam), commits a `self_update`, merges the
/// pending commit, and persists the updated state — all BEFORE
/// attempting any delivery (see the module docs' "Delivery-failure
/// semantics" section for why). The roster is persisted unchanged
/// (rotation changes no membership).
///
/// The resulting `Commit` is then delivered to every OTHER member of
/// the roster. `peer_lookup` and `connect` are exactly as documented
/// on [`delivery::deliver_to_members`].
///
/// # Errors
///
/// Returns [`GroupError`] if the group state or peer identity cannot
/// be loaded, if `MlsGroup::self_update`/`merge_pending_commit` itself
/// fails, or if the updated state cannot be persisted. Does NOT return
/// an error for a Commit DELIVERY failure once the state mutation has
/// already been durably saved.
pub async fn rotate_group_key<F, Fut>(
    keystore_dir: &Path,
    passphrase: &[u8],
    group_name: &str,
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

    // The group identity must already exist (same ruling as
    // `add_member`: mutating a group this peer never created/joined
    // with an identity is a real error, never papered over).
    let identity_path = keystore_dir.join(GROUP_IDENTITY_FILE_NAME);
    let identity = identity::load_group_identity(&identity_path, passphrase)?;

    let bundle = group.self_update(
        &provider,
        &identity.signature_key_pair,
        LeafNodeParameters::default(),
    )?;
    group.merge_pending_commit(&provider)?;

    // The state mutation is now durable. Nothing after this point may
    // turn a successful save into an `Err` return (ruled semantics —
    // see module docs).
    persistence::save_group_state(
        &group_state_path,
        passphrase,
        &group,
        provider.storage(),
        &roster,
    )?;

    let group_id_bytes = group.group_id().to_vec();

    // Fan out the Commit to every other member (the roster never lists
    // the local member). Per-member outcomes are intentionally
    // discarded (module docs).
    let _commit_results = delivery::deliver_to_members(
        &roster,
        &peer_lookup,
        &connect,
        &group_id_bytes,
        bundle.commit(),
    )
    .await;

    Ok(())
}
