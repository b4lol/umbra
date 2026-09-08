//! Whole-group-state persistence: saves/loads an entire OpenMLS
//! group's state, plus Umbra's own member roster, as one
//! AEAD-encrypted blob (spec Decision 6, TODO B.2).
//!
//! # Design notes (corrected from the original task brief)
//!
//! The original plan assumed `MlsGroup` itself implements
//! `Serialize`/`Deserialize` directly. That is FALSE under this
//! workspace's feature set: `MlsGroup`'s `Serialize`/`Deserialize`
//! impls in the installed `openmls` 0.9.0 source are gated behind the
//! `migration-import`/`test-utils` features, and this workspace
//! enables neither (only `libcrux-provider`, per the root
//! `Cargo.toml`).
//!
//! What OpenMLS actually offers instead is a storage-backed
//! persistence contract:
//!
//! - Every OpenMLS operation (create/add/send/receive/commit) writes
//!   its updated state into whatever `openmls_traits::storage::
//!   StorageProvider` the caller's `OpenMlsProvider` exposes.
//! - `MlsGroup::load<Storage: StorageProvider>(storage: &Storage,
//!   group_id: &GroupId) -> Result<Option<MlsGroup>, Storage::Error>`
//!   (verified against the installed source,
//!   `openmls-0.9.0/src/group/mls_group/mod.rs`) reconstructs a live
//!   `MlsGroup` handle purely from what is already in `storage` for
//!   that `group_id`. It takes the storage directly, NOT a whole
//!   `OpenMlsProvider` — so no provider is needed just to load.
//!
//! `openmls_memory_storage::MemoryStorage` (the in-memory storage
//! backend used by `openmls_libcrux_crypto::Provider`) is, verified
//! against the installed 0.6.0 source:
//! `pub struct MemoryStorage { pub values: RwLock<HashMap<Vec<u8>,
//! Vec<u8>>> }` — one public field, no `#[non_exhaustive]`, no serde
//! derive of its own. That makes it freely constructible from outside
//! the crate via an ordinary struct literal, and its `values` map is
//! plain enough to serialize ourselves: [`save_group_state`] locks it,
//! clones the map out, and serializes it (with the group's id and
//! Umbra's [`GroupRoster`]) in a small local wrapper,
//! [`PersistedState`]; [`load_group_state`] deserializes that wrapper
//! and builds a fresh `MemoryStorage` from its map.
//!
//! Reconstructing a *usable* group, however, needs more than a
//! `MemoryStorage` — subsequent OpenMLS operations (e.g.
//! `MlsGroup::create_message`) take a full `&impl OpenMlsProvider`,
//! not just a storage reference. The obvious move — build an
//! `openmls_libcrux_crypto::Provider` around the restored storage —
//! does not work: its `crypto`/`storage` fields are private (verified
//! against the installed 0.4.0 source), and its only constructors
//! (`Provider::new`/`Provider::default`) always pair a fresh crypto
//! backend with a fresh, *empty* `MemoryStorage`; there is no
//! constructor that accepts a caller-supplied storage. So
//! [`load_group_state`] builds its own minimal `OpenMlsProvider` impl,
//! [`RestoredProvider`], out of a freshly instantiated
//! `openmls_libcrux_crypto::CryptoProvider` (`pub use`d from that
//! crate with a public `new()`; it is a stateless RNG/crypto backend
//! with nothing group-specific to persist) and the restored
//! `MemoryStorage`, and returns it so the caller can keep operating on
//! the loaded group.
//!
//! AEAD encryption of the serialized blob reuses the exact envelope
//! pattern `identity.rs` already established for this crate:
//! `umbra_crypto::keystore::{derive_keystore_key_with_params,
//! seal_envelope, open_envelope}`, with a `[magic 5][salt 16]
//! [envelope]` file layout and `0600` permissions on Unix.

use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::sync::RwLock;

use openmls::prelude::{GroupId, LeafNodeIndex, MlsGroup, OpenMlsProvider};
use openmls_libcrux_crypto::CryptoProvider;
use openmls_memory_storage::MemoryStorage;
use serde::{Deserialize, Serialize};
use umbra_crypto::keystore::{self, KS_SALT_LEN};
use zeroize::Zeroizing;

use crate::error::GroupError;

/// Magic header: `"UMGS"` + version byte (Umbra Group State, v1).
const MAGIC: [u8; 5] = *b"UMGS\x01";

/// Argon2id cost parameters, grouped into one struct so the
/// `_with_params` variants below (which, unlike `identity.rs`'s
/// otherwise-identical `_with_params` functions, also take `group`,
/// `storage`, and `roster` arguments) stay under clippy's
/// `too_many_arguments` limit.
#[derive(Debug, Clone, Copy)]
pub struct Argon2Params {
    /// Argon2id memory cost, in KiB.
    pub m_cost_kib: u32,
    /// Argon2id time cost (iteration count).
    pub t_cost: u32,
    /// Argon2id parallelism (lane count).
    pub p_cost: u32,
}

impl Argon2Params {
    /// Production Argon2id parameters (see `umbra_crypto::keystore`'s
    /// `ARGON2_*` constants).
    #[must_use]
    pub const fn production() -> Self {
        Self {
            m_cost_kib: keystore::ARGON2_M_KIB,
            t_cost: keystore::ARGON2_T_COST,
            p_cost: keystore::ARGON2_P_COST,
        }
    }
}

/// Maps Umbra peer names to their position (MLS leaf index) in a
/// group. OpenMLS's own credential/leaf-index data has no concept of
/// an "Umbra peer record" — this mapping is Umbra's own bookkeeping,
/// persisted alongside the group state so fan-out delivery (TODO B.2)
/// can later resolve each member's transport address from their peer
/// name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupRoster {
    /// `(Umbra peer name, MLS leaf index)` pairs, one per member.
    pub members: Vec<(String, LeafNodeIndex)>,
}

impl GroupRoster {
    /// Looks up a member's MLS leaf index by Umbra peer name.
    #[must_use]
    pub fn leaf_index_for(&self, peer_name: &str) -> Option<LeafNodeIndex> {
        self.members
            .iter()
            .find(|(name, _)| name == peer_name)
            .map(|(_, index)| *index)
    }
}

/// The full contents persisted for one group: a snapshot of OpenMLS's
/// own storage map (everything `MlsGroup::load` needs to reconstruct
/// a live handle), the group's id (so [`load_group_state`] knows
/// which group to ask `MlsGroup::load` for), and Umbra's own
/// [`GroupRoster`].
#[derive(Serialize, Deserialize)]
struct PersistedState {
    /// The group's MLS `GroupId`, as raw bytes (`GroupId::to_vec`).
    group_id: Vec<u8>,
    /// A snapshot of `MemoryStorage`'s `values` map, as `(key, value)`
    /// pairs rather than a `HashMap`: a `HashMap` with non-`String`
    /// keys does not round-trip through `serde_json`'s object
    /// representation, which requires string keys.
    storage: Vec<(Vec<u8>, Vec<u8>)>,
    /// Umbra's own peer roster for this group.
    roster: GroupRoster,
}

/// An `OpenMlsProvider` built around a restored, persisted
/// `MemoryStorage`. Its crypto/rand half is freshly instantiated on
/// every load — group persistence never depends on any state living
/// inside the crypto provider itself (a stateless RNG/crypto backend),
/// only inside `storage`. Returned by [`load_group_state`] so the
/// caller can keep performing OpenMLS operations (e.g.
/// `MlsGroup::create_message`) on the restored group.
///
/// `openmls_libcrux_crypto::Provider` itself cannot fill this role:
/// its fields are private and its only constructors always pair a
/// fresh crypto backend with a fresh, empty `MemoryStorage` (verified
/// against the installed 0.4.0 source) — there is no way to hand it a
/// caller-supplied storage.
pub struct RestoredProvider {
    /// The (freshly instantiated, stateless) libcrux crypto/rand
    /// backend.
    crypto: CryptoProvider,
    /// The restored group storage.
    storage: MemoryStorage,
}

impl OpenMlsProvider for RestoredProvider {
    type CryptoProvider = CryptoProvider;
    type RandProvider = CryptoProvider;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

/// Saves `group`'s entire persisted state (via `storage`, its backing
/// `MemoryStorage`) plus `roster`, AEAD-encrypted under `passphrase`
/// (production Argon2id parameters), to `path`. The file is written
/// with `0600` permissions on Unix.
///
/// `storage` must be the same `MemoryStorage` backing the
/// `OpenMlsProvider` that performed `group`'s operations (e.g.
/// `provider.storage()`) — `MlsGroup` itself does not own a storage
/// reference, so it must be passed separately.
///
/// # Errors
///
/// Returns [`GroupError`] for KDF, AEAD, serialization, or I/O
/// failures.
pub fn save_group_state(
    path: &Path,
    passphrase: &[u8],
    group: &MlsGroup,
    storage: &MemoryStorage,
    roster: &GroupRoster,
) -> Result<(), GroupError> {
    save_group_state_with_params(
        path,
        passphrase,
        group,
        storage,
        roster,
        Argon2Params::production(),
    )
}

/// [`save_group_state`] with explicit Argon2id parameters (tests use
/// reduced costs).
///
/// # Errors
///
/// See [`save_group_state`].
pub fn save_group_state_with_params(
    path: &Path,
    passphrase: &[u8],
    group: &MlsGroup,
    storage: &MemoryStorage,
    roster: &GroupRoster,
    params: Argon2Params,
) -> Result<(), GroupError> {
    let storage_entries: Vec<(Vec<u8>, Vec<u8>)> = storage
        .values
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    let persisted = PersistedState {
        group_id: group.group_id().to_vec(),
        storage: storage_entries,
        roster: roster.clone(),
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(&persisted)?);

    let mut salt = [0u8; KS_SALT_LEN];
    umbra_crypto::rng::fill(&mut salt)?;
    let key = keystore::derive_keystore_key_with_params(
        passphrase,
        &salt,
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
    )?;
    let envelope = Zeroizing::new(keystore::seal_envelope(&key, &plaintext)?);

    // File layout: [magic 5][salt 16][envelope].
    let capacity = MAGIC
        .len()
        .saturating_add(KS_SALT_LEN)
        .saturating_add(envelope.len());
    let mut file = Vec::with_capacity(capacity);
    file.extend_from_slice(&MAGIC);
    file.extend_from_slice(&salt);
    file.extend_from_slice(&envelope);

    // 0600 on Unix: create with restrictive permissions up front.
    #[cfg(unix)]
    let options = {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        options
    };
    #[cfg(not(unix))]
    let options = {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        options
    };
    let mut handle = options.open(path)?;
    handle.write_all(&file)?;
    handle.sync_all()?;
    Ok(())
}

/// Loads a group's persisted state from `path`, decrypting under
/// `passphrase`, and reconstructs a live `MlsGroup` handle (via
/// `MlsGroup::load`) plus its [`GroupRoster`] and a usable
/// [`RestoredProvider`] for further OpenMLS operations.
///
/// # Errors
///
/// Returns [`GroupError::Io`] if the file cannot be read,
/// [`GroupError::Malformed`] for a bad magic header or a truncated
/// file, [`GroupError::Crypto`] for a wrong passphrase or tampering
/// (AEAD), [`GroupError::Serde`] if the decrypted plaintext is not a
/// valid persisted state, [`GroupError::Signature`] if the restored
/// crypto provider fails to initialize, [`GroupError::Storage`] if
/// OpenMLS's own storage read fails, and [`GroupError::GroupNotFound`]
/// if no group with the persisted id is present in the restored
/// storage.
pub fn load_group_state(
    path: &Path,
    passphrase: &[u8],
) -> Result<(MlsGroup, GroupRoster, RestoredProvider), GroupError> {
    load_group_state_with_params(
        path,
        passphrase,
        keystore::ARGON2_M_KIB,
        keystore::ARGON2_T_COST,
        keystore::ARGON2_P_COST,
    )
}

/// [`load_group_state`] with explicit Argon2id parameters (tests use
/// reduced costs).
///
/// # Errors
///
/// See [`load_group_state`].
pub fn load_group_state_with_params(
    path: &Path,
    passphrase: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<(MlsGroup, GroupRoster, RestoredProvider), GroupError> {
    let raw = fs::read(path)?;
    let header = raw
        .get(..MAGIC.len())
        .ok_or_else(|| GroupError::Malformed("truncated group state file".into()))?;
    if header != MAGIC {
        return Err(GroupError::Malformed(
            "not an Umbra group state file".into(),
        ));
    }
    let stored_salt: [u8; KS_SALT_LEN] = umbra_crypto::kdf::read_at(&raw, MAGIC.len())?;
    let envelope_start = MAGIC.len().saturating_add(KS_SALT_LEN);
    let envelope = raw
        .get(envelope_start..)
        .ok_or_else(|| GroupError::Malformed("truncated group state envelope".into()))?;

    let key = keystore::derive_keystore_key_with_params(
        passphrase,
        &stored_salt,
        m_cost_kib,
        t_cost,
        p_cost,
    )?;
    let plaintext = keystore::open_envelope(&key, envelope)?;
    let persisted: PersistedState = serde_json::from_slice(&plaintext)?;

    let storage = MemoryStorage {
        values: RwLock::new(persisted.storage.into_iter().collect()),
    };
    let group_id = GroupId::from_slice(&persisted.group_id);
    let provider = RestoredProvider {
        crypto: CryptoProvider::new()?,
        storage,
    };

    let group = MlsGroup::load(&provider.storage, &group_id)?.ok_or(GroupError::GroupNotFound)?;

    Ok((group, persisted.roster, provider))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls::prelude::{
        BasicCredential, Capabilities, Ciphersuite, CredentialWithKey, MlsGroupCreateConfig,
        SignatureScheme,
    };
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_libcrux_crypto::Provider;

    /// The X-Wing hybrid ciphersuite (see `single_process_round_trip.rs`
    /// for the full verification notes on why this is the only hybrid
    /// PQ ciphersuite available under this workspace's feature set).
    const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

    /// Reduced Argon2id costs so these round-trip tests stay fast.
    const TEST_M_KIB: u32 = 8192;
    /// Reduced Argon2id time cost for tests.
    const TEST_T_COST: u32 = 2;
    /// Reduced Argon2id parallelism for tests.
    const TEST_P_COST: u32 = 1;

    /// Builds a minimal, single-member, real `MlsGroup` (no second
    /// member needed for a persistence-focused test) plus the
    /// provider and signer that created it.
    fn new_single_member_group()
    -> Result<(Provider, SignatureKeyPair, MlsGroup), Box<dyn std::error::Error + Send + Sync>>
    {
        let provider = Provider::new()?;
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519)?;
        let credential = BasicCredential::new(b"alice".to_vec());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };
        let capabilities = Capabilities::for_provider(provider.crypto());
        let group_create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .capabilities(capabilities)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new(
            &provider,
            &signer,
            &group_create_config,
            credential_with_key,
        )?;
        Ok((provider, signer, group))
    }

    #[test]
    fn save_and_load_round_trips_group_and_roster()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (provider, signer, group) = new_single_member_group()?;
        let roster = GroupRoster {
            members: vec![("alice".to_string(), group.own_leaf_index())],
        };

        let dir = std::env::temp_dir().join(format!(
            "umbra-group-state-test-{}-roundtrip",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("group.enc");

        save_group_state_with_params(
            &path,
            b"test-passphrase",
            &group,
            provider.storage(),
            &roster,
            Argon2Params {
                m_cost_kib: TEST_M_KIB,
                t_cost: TEST_T_COST,
                p_cost: TEST_P_COST,
            },
        )?;

        let (mut loaded_group, loaded_roster, restored_provider) = load_group_state_with_params(
            &path,
            b"test-passphrase",
            TEST_M_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;

        assert_eq!(loaded_roster, roster);
        assert_eq!(
            loaded_roster.leaf_index_for("alice"),
            Some(group.own_leaf_index())
        );
        assert_eq!(loaded_group.group_id(), group.group_id());

        // The loaded group must still be able to perform a real
        // OpenMLS operation using the restored provider.
        let _message = loaded_group.create_message(&restored_provider, &signer, b"hello group")?;

        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn wrong_passphrase_rejected() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (provider, _signer, group) = new_single_member_group()?;
        let roster = GroupRoster {
            members: vec![("alice".to_string(), group.own_leaf_index())],
        };

        let dir = std::env::temp_dir().join(format!(
            "umbra-group-state-wrongpw-{}-test",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("group.enc");

        save_group_state_with_params(
            &path,
            b"right",
            &group,
            provider.storage(),
            &roster,
            Argon2Params {
                m_cost_kib: TEST_M_KIB,
                t_cost: TEST_T_COST,
                p_cost: TEST_P_COST,
            },
        )?;

        assert!(
            load_group_state_with_params(
                &path,
                b"wrong",
                TEST_M_KIB,
                TEST_T_COST,
                TEST_P_COST
            )
            .is_err()
        );

        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
