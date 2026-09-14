//! `umbra group rotate`: on-demand key rotation for this peer's own
//! group membership via OpenMLS's `self_update` — no roster change,
//! Commit-only fan-out (TODO B.2.3). Deliberately manual-only: no
//! automatic/periodic rotation policy is implemented here.
//!
//! # Verified OpenMLS API shape (installed `openmls-0.9.0` source)
//!
//! ```text
//! pub fn self_update<Provider: OpenMlsProvider>(
//!     &mut self,
//!     provider: &Provider,
//!     signer: &impl Signer,
//!     leaf_node_parameters: LeafNodeParameters,
//! ) -> Result<CommitMessageBundle, SelfUpdateError<Provider::StorageError>>
//! ```
//! (`src/group/mls_group/updates.rs`). `LeafNodeParameters` derives
//! `Default` — passing the default (no credential/capability/
//! extension changes) still performs a genuine HPKE key rotation for
//! this peer's own leaf: an MLS Update proposal always rotates the
//! sender's path secret as its core TreeKEM mechanism, independent of
//! any leaf-node metadata change. `CommitMessageBundle::commit(&self)
//! -> &MlsMessageOut` is the commit accessor (`src/group/mls_group/
//! commit_builder.rs`).

use std::path::Path;

use openmls::prelude::{LeafNodeParameters, OpenMlsProvider as _};

use crate::delivery::{self, PeerTransportAddress};
use crate::error::GroupError;
use crate::identity::{self, GROUP_IDENTITY_FILE_NAME};
use crate::persistence;

/// Subdirectory (relative to the keystore directory) holding one
/// encrypted group-state file per group, named `<group_name>.enc`.
const GROUPS_DIR_NAME: &str = "groups";

/// Rotates this peer's own key material within the group named
/// `group_name`: commits a `self_update`, persists the updated state
/// (roster UNCHANGED), and fans out the resulting Commit to every
/// current member. No RosterSync is sent — membership did not change.
///
/// # Errors
///
/// Returns [`GroupError`] if the group state or peer identity cannot
/// be loaded, if `MlsGroup::self_update`/`merge_pending_commit` itself
/// fails, or if the updated state cannot be persisted. Does NOT return
/// an error for a per-member Commit delivery failure once the state
/// mutation has already been durably saved.
pub async fn rotate_key<F, Fut>(
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

    let identity_path = keystore_dir.join(GROUP_IDENTITY_FILE_NAME);
    let identity = identity::load_group_identity(&identity_path, passphrase)?;

    let bundle = group.self_update(
        &provider,
        &identity.signature_key_pair,
        LeafNodeParameters::default(),
    )?;
    let commit_msg = bundle.commit().clone();
    group.merge_pending_commit(&provider)?;

    persistence::save_group_state(
        &group_state_path,
        passphrase,
        &group,
        provider.storage(),
        &roster,
    )?;

    let group_id_bytes = group.group_id().to_vec();
    let _commit_results = delivery::deliver_to_members(
        &roster,
        &peer_lookup,
        &connect,
        &group_id_bytes,
        &commit_msg,
    )
    .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::PeerTransportAddress;
    use crate::{add, create, keypackage};
    use std::pin::Pin;
    use std::sync::Arc;
    use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, DuplexStream};
    use tokio::sync::Mutex;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
    type ConnectFuture = Pin<
        Box<
            dyn std::future::Future<Output = Result<Box<dyn AsyncWrite + Unpin + Send>, GroupError>>
                + Send,
        >,
    >;

    async fn read_frame<S>(
        mut stream: S,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>
    where
        S: AsyncRead + Unpin,
    {
        stream.read_u8().await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        Ok(buf)
    }

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

    #[tokio::test]
    async fn rotate_key_rotates_and_roster_is_unchanged() -> TestResult {
        let alice_dir = std::env::temp_dir().join(format!(
            "umbra-group-rotate-test-{}-{}",
            std::process::id(),
            "alice"
        ));
        let bob_dir = std::env::temp_dir().join(format!(
            "umbra-group-rotate-test-{}-{}",
            std::process::id(),
            "bob"
        ));
        std::fs::create_dir_all(&alice_dir)?;
        std::fs::create_dir_all(&bob_dir)?;
        let alice_pw = b"alice-rotate-pw";
        let bob_pw = b"bob-rotate-pw";

        create::create_group(&alice_dir, alice_pw, "cell", "alice")?;
        let bob_kp = keypackage::export_keypackage(&bob_dir, bob_pw)?;
        let bob_addr = PeerTransportAddress::Mesh("bob-mesh".to_string());

        // Add bob first (reuses already-tested add_member), draining
        // its Welcome/RosterSync deliveries into throwaway streams.
        {
            let (welcome_side, _welcome_observer) = tokio::io::duplex(8192);
            let (rs_side, _rs_observer) = tokio::io::duplex(8192);
            let queue = Arc::new(Mutex::new(std::collections::VecDeque::from([
                welcome_side,
                rs_side,
            ])));
            let bob_addr_for_connect = bob_addr.clone();
            let connect = move |address: &PeerTransportAddress| {
                let matches = *address == bob_addr_for_connect;
                let queue = Arc::clone(&queue);
                Box::pin(async move {
                    let next = if matches {
                        queue.lock().await.pop_front()
                    } else {
                        None
                    };
                    next.map(|s| Box::new(s) as Box<dyn AsyncWrite + Unpin + Send>)
                        .ok_or_else(|| GroupError::Malformed("unexpected connect() in test".into()))
                }) as ConnectFuture
            };
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
        }

        let (before_group, before_roster, _p) =
            persistence::load_group_state(&alice_dir.join("groups").join("cell.enc"), alice_pw)?;
        let epoch_before = before_group.epoch();

        let (bob_member_side, bob_observer_side) = tokio::io::duplex(8192);
        let connect = single_use_stream(bob_member_side);
        let peer_lookup = move |name: &str| {
            if name == "bob" {
                Some(bob_addr.clone())
            } else {
                None
            }
        };

        rotate_key(&alice_dir, alice_pw, "cell", peer_lookup, connect).await?;

        let (after_group, after_roster, _p) =
            persistence::load_group_state(&alice_dir.join("groups").join("cell.enc"), alice_pw)?;
        assert_ne!(
            epoch_before,
            after_group.epoch(),
            "self_update must advance the epoch"
        );
        assert_eq!(
            before_roster, after_roster,
            "rotate_key must not change the roster"
        );

        let commit_bytes = read_frame(bob_observer_side).await?;
        assert!(!commit_bytes.is_empty());

        std::fs::remove_dir_all(&alice_dir)?;
        std::fs::remove_dir_all(&bob_dir)?;
        Ok(())
    }
}
