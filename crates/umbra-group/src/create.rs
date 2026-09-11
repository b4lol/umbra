//! `umbra group create`: creates a new PQ-MLS group ("cell") with the
//! caller as its sole initial member, using a (generated-if-absent)
//! per-peer group identity, and persists the resulting group state
//! (spec Decision 6, TODO B.2).

use std::fs;
use std::path::Path;

use openmls::prelude::{
    Capabilities, Ciphersuite, CredentialWithKey, MlsGroup, MlsGroupCreateConfig, OpenMlsProvider,
};
use openmls_libcrux_crypto::Provider;

use crate::error::GroupError;
use crate::identity::{self, GroupIdentity};
use crate::persistence::{self, GroupRoster};

/// The X-Wing hybrid ciphersuite (see `tests/single_process_round_trip.rs`
/// and `persistence.rs` for the full verification notes on why this is
/// the only hybrid PQ ciphersuite available under this workspace's
/// feature set).
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

/// File name of the single, per-peer group-identity keystore, shared
/// across every group this peer creates or joins (`identity.rs`'s
/// `GroupIdentity` is a NEW Ed25519 identity "per Umbra peer", not per
/// group — see spec Decision 6).
const GROUP_IDENTITY_FILE_NAME: &str = "group-identity.enc";

/// Subdirectory (relative to the keystore directory) holding one
/// encrypted group-state file per group, named `<group_name>.enc`.
const GROUPS_DIR_NAME: &str = "groups";

/// Loads this peer's group identity from
/// `<keystore_dir>/group-identity.enc`, generating and persisting a
/// fresh one first if the file does not yet exist.
fn load_or_generate_identity(
    keystore_dir: &Path,
    passphrase: &[u8],
) -> Result<GroupIdentity, GroupError> {
    let identity_path = keystore_dir.join(GROUP_IDENTITY_FILE_NAME);
    if identity_path.exists() {
        identity::load_group_identity(&identity_path, passphrase)
    } else {
        let identity = identity::generate_group_identity()?;
        identity::save_group_identity(&identity_path, passphrase, &identity)?;
        Ok(identity)
    }
}

/// Creates a new PQ-MLS group named `group_name`, with the caller as
/// its sole initial member (using the X-Wing hybrid ciphersuite), and
/// persists its state to `<keystore_dir>/groups/<group_name>.enc`
/// (creating the `groups/` subdirectory if it does not already exist).
///
/// `self_name` is the caller's own cell-wide peer name — the name the
/// rest of the cell will address this device by. It is persisted in
/// the roster's [`GroupRoster::self_name`] so the roster syncs this
/// peer later originates (TODO B.2.1, after every add/remove) can
/// carry a self entry; without it, members added to this cell would
/// never learn how to address its creator back. The roster's `members`
/// list itself starts EMPTY (the local member is never listed in their
/// own roster — nobody fan-out-delivers to themselves).
///
/// Generates this peer's group identity first if
/// `<keystore_dir>/group-identity.enc` does not yet exist — a single
/// group identity is shared across every group a peer creates or
/// joins (spec Decision 6), so this file is NOT specific to
/// `group_name`.
///
/// Refuses to run at all if `<keystore_dir>/groups/<group_name>.enc`
/// already exists (mirrors `load_or_generate_identity`'s own
/// `identity_path.exists()` check above, for the same reason:
/// [`persistence::save_group_state_with_params`] overwrites-in-place
/// unconditionally — a deliberate change made for
/// [`crate::add::add_member`]'s own legitimate re-saves — so this is
/// now the ONLY place left that must still refuse to silently clobber
/// an existing group's entire MLS tree/epoch state).
///
/// # Errors
///
/// Returns [`GroupError::Malformed`] if `self_name` is empty.
/// Returns [`GroupError::AlreadyExists`] if the group state file
/// already exists. Returns [`GroupError`] if the group identity cannot
/// be generated, loaded, or saved; if the `groups/` directory cannot
/// be created; if MLS group creation itself fails; or if the resulting
/// state cannot be persisted.
pub fn create_group(
    keystore_dir: &Path,
    passphrase: &[u8],
    group_name: &str,
    self_name: &str,
) -> Result<(), GroupError> {
    if self_name.is_empty() {
        return Err(GroupError::Malformed(
            "self name must not be empty (the rest of the cell addresses this device by it)".into(),
        ));
    }
    let groups_dir = keystore_dir.join(GROUPS_DIR_NAME);
    let group_state_path = groups_dir.join(format!("{group_name}.enc"));
    if group_state_path.exists() {
        return Err(GroupError::AlreadyExists(format!(
            "group {group_name:?} already exists at {}",
            group_state_path.display()
        )));
    }

    let identity = load_or_generate_identity(keystore_dir, passphrase)?;

    fs::create_dir_all(&groups_dir)?;

    let provider = Provider::new()?;
    let credential_with_key = CredentialWithKey {
        credential: identity.credential.into(),
        signature_key: identity.signature_key_pair.public().into(),
    };
    let capabilities = Capabilities::for_provider(provider.crypto());
    let group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .capabilities(capabilities)
        .use_ratchet_tree_extension(true)
        .build();
    let group = MlsGroup::new(
        &provider,
        &identity.signature_key_pair,
        &group_create_config,
        credential_with_key,
    )?;

    persistence::save_group_state(
        &group_state_path,
        passphrase,
        &group,
        provider.storage(),
        &GroupRoster {
            members: Vec::new(),
            self_name: Some(self_name.to_string()),
            ..GroupRoster::default()
        },
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: this test exercises `create_group`'s real, production
    // Argon2id costs (it does not go through a `_with_params` test
    // seam — `create_group`'s public signature has no cost knob, by
    // design: it is a CLI-facing entry point, not a persistence
    // primitive), so it is slower than this crate's other keystore
    // round-trip tests.
    #[test]
    fn create_group_persists_a_loadable_state()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dir = std::env::temp_dir().join(format!(
            "umbra-group-create-test-{}-{}",
            std::process::id(),
            "my-cell"
        ));
        std::fs::create_dir_all(&dir)?;

        create_group(&dir, b"pw", "my-cell", "alice")?;

        // The group identity is generated once, shared across groups.
        assert!(dir.join(GROUP_IDENTITY_FILE_NAME).exists());

        let group_state_path = dir.join(GROUPS_DIR_NAME).join("my-cell.enc");
        assert!(group_state_path.exists());

        let (loaded_group, loaded_roster, _provider) =
            persistence::load_group_state(&group_state_path, b"pw")?;
        assert!(loaded_roster.members.is_empty());
        assert_eq!(loaded_roster.self_name.as_deref(), Some("alice"));
        assert_eq!(loaded_group.members().count(), 1);

        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    /// Guards against the data-loss regression flagged in code review:
    /// `save_group_state_with_params` was changed (for `add_member`'s
    /// own legitimate re-save needs) from `create_new(true)` to an
    /// unconditional overwrite-in-place, which would have made a
    /// second `create_group` call for the same name silently destroy
    /// the first group's entire MLS tree/epoch state. `create_group`
    /// itself must now be the call site refusing that clobber.
    #[test]
    fn create_group_twice_rejects_the_second_call_and_does_not_touch_disk()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dir = std::env::temp_dir().join(format!(
            "umbra-group-create-test-{}-{}",
            std::process::id(),
            "double-create"
        ));
        std::fs::create_dir_all(&dir)?;

        create_group(&dir, b"pw", "my-cell", "alice")?;
        let group_state_path = dir.join(GROUPS_DIR_NAME).join("my-cell.enc");
        let bytes_after_first_create = std::fs::read(&group_state_path)?;

        // Second call, same keystore dir and group name: must be
        // refused, not silently clobber the first group's state.
        let second_result = create_group(&dir, b"pw", "my-cell", "alice");
        assert!(
            matches!(second_result, Err(GroupError::AlreadyExists(_))),
            "expected AlreadyExists, got {second_result:?}"
        );

        // The on-disk state from the FIRST call must be byte-for-byte
        // untouched by the rejected second call.
        let bytes_after_second_attempt = std::fs::read(&group_state_path)?;
        assert_eq!(
            bytes_after_first_create, bytes_after_second_attempt,
            "the rejected second create_group call must not modify the persisted group state"
        );

        // The first group's state is still loadable and still a
        // single-member group (i.e. genuinely untouched, not just
        // byte-identical by coincidence).
        let (loaded_group, loaded_roster, _provider) =
            persistence::load_group_state(&group_state_path, b"pw")?;
        assert!(loaded_roster.members.is_empty());
        assert_eq!(loaded_group.members().count(), 1);

        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    /// An empty self name is refused up front: it would silently
    /// produce roster syncs with no self entry, recreating the exact
    /// bootstrap gap TODO B.2.1 exists to close.
    #[test]
    fn create_group_rejects_an_empty_self_name()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dir = std::env::temp_dir().join(format!(
            "umbra-group-create-test-{}-{}",
            std::process::id(),
            "empty-self-name"
        ));
        std::fs::create_dir_all(&dir)?;

        let result = create_group(&dir, b"pw", "my-cell", "");
        assert!(
            matches!(result, Err(GroupError::Malformed(_))),
            "expected Malformed, got {result:?}"
        );
        assert!(!dir.join(GROUPS_DIR_NAME).join("my-cell.enc").exists());

        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
