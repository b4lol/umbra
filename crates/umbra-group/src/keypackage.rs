//! `umbra group export-keypackage`: generates a fresh MLS `KeyPackage`
//! for this peer's group identity and returns its base64-encoded wire
//! form, for out-of-band delivery to whoever will `Add` this peer to a
//! group (spec Decision 6, TODO B.2).
//!
//! # Why this needs its own persisted storage file (correction to the
//! original task brief)
//!
//! The original brief described this as a stateless operation: build a
//! `KeyPackage`, return its bytes, done. That is incomplete in a way
//! that breaks the later Welcome-processing step (Task 9).
//!
//! Verified against the installed `openmls` 0.9.0 source
//! (`src/key_packages/mod.rs`, `KeyPackageBuilder::build`, around line
//! 605): building a key package does not just return a `KeyPackage` —
//! it also writes the resulting `KeyPackageBundle` (which holds the
//! matching PRIVATE init and leaf-encryption keys) into the calling
//! `OpenMlsProvider`'s `storage()`, keyed by the key package's hash
//! reference:
//!
//! ```text
//! provider.storage().write_key_package(&full_kp.key_package.hash_ref(...)?, &full_kp)
//! ```
//!
//! Later, when a `Welcome` referencing this key package arrives in a
//! *separate* `umbra` process invocation (the same async,
//! restart-durable model this codebase already uses for two-party
//! PQXDH), `StagedWelcome::new_from_welcome` looks up that exact
//! `KeyPackageBundle` by hash reference and consumes it to decrypt the
//! group secrets. If the private key material only ever lived in an
//! ephemeral, process-local `MemoryStorage`, the second process could
//! never decrypt the Welcome — there would be no private key left
//! anywhere to do it with.
//!
//! So [`export_keypackage`] persists its `MemoryStorage` (the same
//! storage the `KeyPackage::builder()` call wrote into) across process
//! restarts, to a NEW file: `<keystore_dir>/keypackages.enc` — deliberately
//! separate from any group's own `groups/<name>.enc` state file (a key
//! package is pre-join: it is not yet tied to any specific group, and
//! a peer may hold several outstanding, unconsumed key packages across
//! several different eventual groups at once).
//!
//! The persistence mechanism mirrors `persistence.rs`'s
//! `save_group_state`/`load_group_state` as closely as this different
//! file's shape allows: same `[magic 5][salt 16][envelope]` file
//! layout, same Argon2id KDF via `umbra_crypto::keystore`, same
//! `Vec<(Vec<u8>, Vec<u8>)>` snapshot of `MemoryStorage`'s `values` map
//! (not a `HashMap` — `serde_json`'s object form needs `String` keys),
//! same `0600` permissions on Unix. It reuses `persistence::
//! RestoredProvider` directly for the "build an `OpenMlsProvider`
//! around a restored `MemoryStorage`" half, since that struct's shape
//! (a freshly instantiated, stateless `CryptoProvider` paired with a
//! restored `MemoryStorage`) fits this use case exactly, with nothing
//! group-specific about it. What's genuinely new here is the save/load
//! pair for this different file's plaintext shape (`Vec<(Vec<u8>,
//! Vec<u8>)>` alone, no `GroupId`, no `GroupRoster`) — reusing
//! `persistence::save_group_state`/`load_group_state` themselves isn't
//! possible, since those are typed around `MlsGroup` + `GroupId` +
//! `GroupRoster`, none of which apply before a group even exists.
//!
//! # For Task 9's implementer
//!
//! [`save_keypackage_storage`] and [`load_keypackage_storage`] are
//! `pub(crate)` (not private to this module) specifically so
//! `inbound.rs`'s future Welcome-processing code can call them
//! directly: load `keypackages.enc` into a [`persistence::
//! RestoredProvider`], hand that provider to
//! `StagedWelcome::new_from_welcome`, then (if the consumed key
//! package should no longer be reused — check OpenMLS's own behavior
//! here, it may already remove it from storage as a side effect of the
//! lookup) re-save the storage back to the same file.

use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::sync::RwLock;

use base64::Engine as _;
use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::{Capabilities, Ciphersuite, CredentialWithKey, KeyPackage, OpenMlsProvider};
use openmls_libcrux_crypto::CryptoProvider;
use openmls_memory_storage::MemoryStorage;
use serde::{Deserialize, Serialize};
use umbra_crypto::keystore::{self, KS_SALT_LEN};
use zeroize::Zeroizing;

use crate::error::GroupError;
use crate::identity::{self, GroupIdentity};
use crate::persistence::RestoredProvider;

/// The X-Wing hybrid ciphersuite (see `create.rs`/`persistence.rs` for
/// the full verification notes on why this is the only hybrid PQ
/// ciphersuite available under this workspace's feature set). Kept as
/// its own local constant (rather than importing `create::CIPHERSUITE`,
/// which is private to that module) to avoid coupling this module to
/// `create.rs`'s internals for a value both modules need independently.
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

/// File name of the single, per-peer group-identity keystore, shared
/// across every group this peer creates or joins (mirrors
/// `create.rs`'s `GROUP_IDENTITY_FILE_NAME` — duplicated rather than
/// imported since that constant is private to `create.rs`; both name
/// the same file by design).
const GROUP_IDENTITY_FILE_NAME: &str = "group-identity.enc";

/// File name of the persisted key-package storage snapshot (this
/// module's own file, distinct from any group's `groups/<name>.enc`
/// state file — see the module-level docs).
const KEYPACKAGES_FILE_NAME: &str = "keypackages.enc";

/// Magic header: `"UMKP"` + version byte (Umbra group Key Package
/// storage, v1).
const MAGIC: [u8; 5] = *b"UMKP\x01";

/// The full contents persisted for this peer's key-package storage: a
/// snapshot of OpenMLS's own storage map (everything a later
/// `StagedWelcome::new_from_welcome` needs to find and consume a
/// previously exported key package's private keys).
#[derive(Serialize, Deserialize)]
struct PersistedKeyPackageStorage {
    /// A snapshot of `MemoryStorage`'s `values` map, as `(key, value)`
    /// pairs rather than a `HashMap` (see `persistence.rs`'s
    /// `PersistedState::storage` for why).
    storage: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Loads this peer's group identity from
/// `<keystore_dir>/group-identity.enc`, generating and persisting a
/// fresh one first if the file does not yet exist. Mirrors
/// `create.rs`'s private `load_or_generate_identity` exactly (that
/// function is private to `create.rs`, so this is a deliberate,
/// small, exact duplication rather than a cross-module dependency for
/// a two-branch helper).
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

/// Saves a snapshot of `storage`'s `values` map to `path`,
/// AEAD-encrypted under `passphrase` (production Argon2id parameters).
/// The file is written with `0600` permissions on Unix.
///
/// `pub(crate)` so Task 9's Welcome-processing code (`inbound.rs`, not
/// yet built) can re-save the storage after consuming a key package.
///
/// # Errors
///
/// Returns [`GroupError`] for KDF, AEAD, serialization, or I/O
/// failures.
pub(crate) fn save_keypackage_storage(
    path: &Path,
    passphrase: &[u8],
    storage: &MemoryStorage,
) -> Result<(), GroupError> {
    save_keypackage_storage_with_params(
        path,
        passphrase,
        storage,
        keystore::ARGON2_M_KIB,
        keystore::ARGON2_T_COST,
        keystore::ARGON2_P_COST,
    )
}

/// [`save_keypackage_storage`] with explicit Argon2id parameters
/// (tests use reduced costs).
///
/// # Errors
///
/// See [`save_keypackage_storage`].
pub(crate) fn save_keypackage_storage_with_params(
    path: &Path,
    passphrase: &[u8],
    storage: &MemoryStorage,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<(), GroupError> {
    let storage_entries: Vec<(Vec<u8>, Vec<u8>)> = storage
        .values
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    let persisted = PersistedKeyPackageStorage {
        storage: storage_entries,
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(&persisted)?);

    let mut salt = [0u8; KS_SALT_LEN];
    umbra_crypto::rng::fill(&mut salt)?;
    let key =
        keystore::derive_keystore_key_with_params(passphrase, &salt, m_cost_kib, t_cost, p_cost)?;
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

    // Overwrite-in-place: unlike group-state/identity files (created
    // once via `create_new`), this file is legitimately re-saved on
    // every `export_keypackage` call (each call adds one more key
    // package to the same storage), so it must be replaceable rather
    // than rejected as already existing.
    let tmp_path = path.with_extension("enc.tmp");
    #[cfg(unix)]
    let options = {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        options
    };
    #[cfg(not(unix))]
    let options = {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        options
    };
    let mut handle = options.open(&tmp_path)?;
    handle.write_all(&file)?;
    handle.sync_all()?;
    drop(handle);
    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Loads a previously persisted key-package storage snapshot from
/// `path`, decrypting under `passphrase`, and returns a usable
/// [`RestoredProvider`] wrapping it.
///
/// `pub(crate)` so Task 9's Welcome-processing code can load this same
/// file directly.
///
/// # Errors
///
/// Returns [`GroupError::Io`] if the file cannot be read,
/// [`GroupError::Malformed`] for a bad magic header or a truncated
/// file, [`GroupError::Crypto`] for a wrong passphrase or tampering
/// (AEAD), [`GroupError::Serde`] if the decrypted plaintext is not a
/// valid persisted storage snapshot, and [`GroupError::Signature`] if
/// the restored crypto provider fails to initialize.
pub(crate) fn load_keypackage_storage(
    path: &Path,
    passphrase: &[u8],
) -> Result<RestoredProvider, GroupError> {
    load_keypackage_storage_with_params(
        path,
        passphrase,
        keystore::ARGON2_M_KIB,
        keystore::ARGON2_T_COST,
        keystore::ARGON2_P_COST,
    )
}

/// [`load_keypackage_storage`] with explicit Argon2id parameters
/// (tests use reduced costs).
///
/// # Errors
///
/// See [`load_keypackage_storage`].
pub(crate) fn load_keypackage_storage_with_params(
    path: &Path,
    passphrase: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<RestoredProvider, GroupError> {
    let raw = fs::read(path)?;
    let header = raw
        .get(..MAGIC.len())
        .ok_or_else(|| GroupError::Malformed("truncated key-package storage file".into()))?;
    if header != MAGIC {
        return Err(GroupError::Malformed(
            "not an Umbra key-package storage file".into(),
        ));
    }
    let stored_salt: [u8; KS_SALT_LEN] = umbra_crypto::kdf::read_at(&raw, MAGIC.len())?;
    let envelope_start = MAGIC.len().saturating_add(KS_SALT_LEN);
    let envelope = raw
        .get(envelope_start..)
        .ok_or_else(|| GroupError::Malformed("truncated key-package storage envelope".into()))?;

    let key = keystore::derive_keystore_key_with_params(
        passphrase,
        &stored_salt,
        m_cost_kib,
        t_cost,
        p_cost,
    )?;
    let plaintext = keystore::open_envelope(&key, envelope)?;
    let persisted: PersistedKeyPackageStorage = serde_json::from_slice(&plaintext)?;

    let storage = MemoryStorage {
        values: RwLock::new(persisted.storage.into_iter().collect()),
    };
    Ok(RestoredProvider::from_parts(CryptoProvider::new()?, storage))
}

/// Generates a fresh MLS `KeyPackage` for this peer's group identity
/// and returns its base64-encoded (`URL_SAFE_NO_PAD`, matching this
/// codebase's convention everywhere else — `pairing.rs`, `serve.rs`,
/// `mesh_serve.rs`, `umbra-nym-cli/src/cli.rs`) TLS-codec wire form.
///
/// Generates this peer's group identity first if
/// `<keystore_dir>/group-identity.enc` does not yet exist (mirrors
/// `create_group`'s behavior — a single group identity is shared
/// across every group a peer creates or joins).
///
/// As a side effect (see the module-level docs for why this is
/// required, not optional), the `KeyPackageBundle`'s private init and
/// leaf-encryption keys are persisted to
/// `<keystore_dir>/keypackages.enc`, merged with any previously
/// exported (and not-yet-consumed) key packages already stored there.
/// Only the public `KeyPackage` half is ever returned — the private
/// bundle never leaves this function.
///
/// # Errors
///
/// Returns [`GroupError`] if the group identity cannot be generated,
/// loaded, or saved; if the existing key-package storage cannot be
/// loaded (a malformed file or wrong passphrase); if key-package
/// creation itself fails; if the resulting storage cannot be
/// persisted; or if TLS-codec serialization of the resulting
/// `KeyPackage` fails.
pub fn export_keypackage(keystore_dir: &Path, passphrase: &[u8]) -> Result<String, GroupError> {
    let identity = load_or_generate_identity(keystore_dir, passphrase)?;

    let keypackages_path = keystore_dir.join(KEYPACKAGES_FILE_NAME);
    let provider = if keypackages_path.exists() {
        load_keypackage_storage(&keypackages_path, passphrase)?
    } else {
        RestoredProvider::from_parts(CryptoProvider::new()?, MemoryStorage::default())
    };

    let credential_with_key = CredentialWithKey {
        credential: identity.credential.into(),
        signature_key: identity.signature_key_pair.public().into(),
    };
    let capabilities = Capabilities::for_provider(provider.crypto());
    let key_package_bundle = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .build(
            CIPHERSUITE,
            &provider,
            &identity.signature_key_pair,
            credential_with_key,
        )?;

    save_keypackage_storage(&keypackages_path, passphrase, provider.storage())?;

    let bytes = key_package_bundle.key_package().tls_serialize_detached()?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls::prelude::tls_codec::DeserializeBytes as _;
    use openmls::prelude::KeyPackageIn;

    #[test]
    fn export_keypackage_produces_a_parseable_key_package()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dir = std::env::temp_dir().join(format!(
            "umbra-group-keypackage-test-{}-{}",
            std::process::id(),
            "parseable"
        ));
        std::fs::create_dir_all(&dir)?;

        let blob = export_keypackage(&dir, b"pw")?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&blob)?;
        let _key_package_in = KeyPackageIn::tls_deserialize_exact_bytes(&bytes)?;

        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn export_keypackage_persists_storage_and_is_fresh_each_call()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dir = std::env::temp_dir().join(format!(
            "umbra-group-keypackage-test-{}-{}",
            std::process::id(),
            "persists"
        ));
        std::fs::create_dir_all(&dir)?;

        let first = export_keypackage(&dir, b"pw")?;
        let keypackages_path = dir.join(KEYPACKAGES_FILE_NAME);
        assert!(keypackages_path.exists());
        let len_after_first = std::fs::metadata(&keypackages_path)?.len();

        let second = export_keypackage(&dir, b"pw")?;
        let len_after_second = std::fs::metadata(&keypackages_path)?.len();

        assert_ne!(first, second, "each export must generate a fresh key package");
        assert!(
            len_after_second > len_after_first,
            "the persisted storage must grow as more key packages accumulate"
        );

        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
