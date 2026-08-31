//! Persistent, passphrase-encrypted identity keystore (TODO A.3).
//!
//! The identity bundle's secret seeds are serialized and encrypted at
//! rest (Argon2id + ChaCha20-Poly1305 envelope — see
//! `umbra_crypto::keystore`) under a passphrase, at a caller-chosen path.
//! Messages still NEVER touch disk (ADR-003): only long-lived identity
//! material is persisted, and only at the explicit request of the user.
//!
//! File permissions are set to `0600` on Unix; the envelope's AEAD binds
//! the plaintext so any tampering fails the load.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use umbra_crypto::CryptoError;
use umbra_crypto::keys::{IdentityBundle, IdentitySeeds};
use umbra_crypto::keystore::{self, KS_SALT_LEN};
use zeroize::Zeroizing;

use crate::cli::CliError;

/// Magic header: `"UMKS"` + version byte.
const MAGIC: [u8; 5] = *b"UMKS\x01";

/// The secret-seed lengths, flattened for the serialization format.
const BLOB_LEN: usize = 32 + 32 + 64 + 32; // x25519 + spk + kem seed + dsa seed

/// Serializes the bundle's secret seeds into the keystore plaintext.
fn seeds_to_plaintext(seeds: &IdentitySeeds) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(BLOB_LEN));
    out.extend_from_slice(&seeds.x25519);
    out.extend_from_slice(&seeds.spk);
    out.extend_from_slice(&seeds.kem);
    out.extend_from_slice(&seeds.dsa);
    out
}

/// Parses the keystore plaintext back into seeds.
fn seeds_from_plaintext(plaintext: &[u8]) -> Result<IdentitySeeds, CliError> {
    if plaintext.len() != BLOB_LEN {
        return Err(CliError::Keystore(format!(
            "corrupt keystore plaintext: {} bytes, expected {BLOB_LEN}",
            plaintext.len()
        )));
    }
    let read32 = |offset: usize| -> Result<[u8; 32], CliError> {
        let mut out = [0u8; 32];
        let slice = plaintext
            .get(offset..offset.saturating_add(32))
            .ok_or_else(|| CliError::Keystore("corrupt keystore plaintext".into()))?;
        out.copy_from_slice(slice);
        Ok(out)
    };
    let mut kem_seed = [0u8; 64];
    let kem_slice = plaintext
        .get(64..128)
        .ok_or_else(|| CliError::Keystore("corrupt keystore plaintext".into()))?;
    kem_seed.copy_from_slice(kem_slice);
    let mut dsa_seed = [0u8; 32];
    let dsa_slice = plaintext
        .get(128..160)
        .ok_or_else(|| CliError::Keystore("corrupt keystore plaintext".into()))?;
    dsa_seed.copy_from_slice(dsa_slice);
    Ok(IdentitySeeds {
        x25519: read32(0)?,
        spk: read32(32)?,
        kem: kem_seed,
        dsa: dsa_seed,
    })
}

/// Saves an identity bundle to `path`, encrypted under `passphrase`
/// (production Argon2id parameters). The file is written with `0600`
/// permissions on Unix.
///
/// # Errors
///
/// Returns [`CliError`] for KDF, AEAD, or I/O failures.
pub fn save(path: &Path, passphrase: &[u8], bundle: &IdentityBundle) -> Result<(), CliError> {
    save_with_params(
        path,
        passphrase,
        bundle,
        keystore::ARGON2_M_KIB,
        keystore::ARGON2_T_COST,
        keystore::ARGON2_P_COST,
    )
}

/// [`save`] with explicit Argon2id parameters (tests use reduced costs).
///
/// # Errors
///
/// See [`save`].
pub fn save_with_params(
    path: &Path,
    passphrase: &[u8],
    bundle: &IdentityBundle,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<(), CliError> {
    let mut salt = [0u8; KS_SALT_LEN];
    umbra_crypto::rng::fill(&mut salt).map_err(CliError::Crypto)?;
    let key =
        keystore::derive_keystore_key_with_params(passphrase, &salt, m_cost_kib, t_cost, p_cost)
            .map_err(CliError::Crypto)?;
    let plaintext = seeds_to_plaintext(&bundle.secret_seeds());
    let envelope =
        Zeroizing::new(keystore::seal_envelope(&key, &plaintext).map_err(CliError::Crypto)?);
    // File layout: [magic 5][salt 16][nonce 12][ciphertext+tag]
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
    let mut handle = options
        .open(path)
        .map_err(|e| CliError::Keystore(format!("cannot create {}: {e}", path.display())))?;
    handle
        .write_all(&file)
        .map_err(|e| CliError::Keystore(format!("write failed: {e}")))?;
    handle
        .sync_all()
        .map_err(|e| CliError::Keystore(format!("sync failed: {e}")))?;
    Ok(())
}

/// Loads an identity bundle from `path`, decrypting under `passphrase`.
///
/// # Errors
///
/// Returns [`CliError`] for I/O failures, a malformed file, and
/// [`CliError::Keystore`] for a wrong passphrase or tampering (AEAD).
pub fn load(path: &Path, passphrase: &[u8]) -> Result<IdentityBundle, CliError> {
    load_with_params(
        path,
        passphrase,
        keystore::ARGON2_M_KIB,
        keystore::ARGON2_T_COST,
        keystore::ARGON2_P_COST,
    )
}

/// [`load`] with explicit Argon2id parameters (tests use reduced costs).
///
/// # Errors
///
/// See [`load`].
pub fn load_with_params(
    path: &Path,
    passphrase: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<IdentityBundle, CliError> {
    let raw = fs::read(path)
        .map_err(|e| CliError::Keystore(format!("cannot read {}: {e}", path.display())))?;
    let header = raw
        .get(..MAGIC.len())
        .ok_or_else(|| CliError::Keystore("truncated keystore file".into()))?;
    if header != MAGIC {
        return Err(CliError::Keystore("not an Umbra keystore file".into()));
    }
    // File layout: [magic 5][salt 16][nonce 12][ciphertext+tag].
    let salt_len = KS_SALT_LEN;
    let stored_salt: [u8; KS_SALT_LEN] =
        umbra_crypto::kdf::read_at(&raw, MAGIC.len()).map_err(CliError::Crypto)?;
    let envelope_start = MAGIC.len().saturating_add(salt_len);
    let envelope = raw
        .get(envelope_start..)
        .ok_or_else(|| CliError::Keystore("truncated keystore envelope".into()))?;

    let key = keystore::derive_keystore_key_with_params(
        passphrase,
        &stored_salt,
        m_cost_kib,
        t_cost,
        p_cost,
    )
    .map_err(CliError::Crypto)?;
    let plaintext = keystore::open_envelope(&key, envelope).map_err(|err| match err {
        CryptoError::DecryptFailed => {
            CliError::Keystore("wrong passphrase or corrupted keystore".into())
        }
        other => CliError::Crypto(other),
    })?;
    let seeds = seeds_from_plaintext(&plaintext)?;
    Ok(IdentityBundle::from_seeds(&seeds))
}

/// Loads the RAW identity seeds (keystore decryption only — no key
/// reconstruction). Used by the `serve` flow to rebuild a bundle per
/// inbound connection (`IdentityBundle::from_seeds`) without re-running
/// Argon2 per connection.
///
/// # Errors
///
/// Returns [`CliError::Keystore`] for missing/wrong files, a wrong
/// passphrase, or a corrupted keystore (AEAD verification failure), and
/// [`CliError::Crypto`] for other envelope failures.
pub fn load_seeds(path: &Path, passphrase: &[u8]) -> Result<IdentitySeeds, CliError> {
    load_seeds_with_params(
        path,
        passphrase,
        keystore::ARGON2_M_KIB,
        keystore::ARGON2_T_COST,
        keystore::ARGON2_P_COST,
    )
}

/// [`load_seeds`] with explicit Argon2id parameters (tests use reduced
/// costs).
///
/// # Errors
///
/// See [`load_seeds`].
pub fn load_seeds_with_params(
    path: &Path,
    passphrase: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<IdentitySeeds, CliError> {
    let raw = fs::read(path)
        .map_err(|e| CliError::Keystore(format!("cannot read {}: {e}", path.display())))?;
    let header = raw
        .get(..MAGIC.len())
        .ok_or_else(|| CliError::Keystore("truncated keystore file".into()))?;
    if header != MAGIC {
        return Err(CliError::Keystore("not an Umbra keystore file".into()));
    }
    let stored_salt: [u8; KS_SALT_LEN] =
        umbra_crypto::kdf::read_at(&raw, MAGIC.len()).map_err(CliError::Crypto)?;
    let envelope_start = MAGIC.len().saturating_add(KS_SALT_LEN);
    let envelope = raw
        .get(envelope_start..)
        .ok_or_else(|| CliError::Keystore("truncated keystore envelope".into()))?;

    let key = keystore::derive_keystore_key_with_params(
        passphrase,
        &stored_salt,
        m_cost_kib,
        t_cost,
        p_cost,
    )
    .map_err(CliError::Crypto)?;
    let plaintext = keystore::open_envelope(&key, envelope).map_err(|err| match err {
        CryptoError::DecryptFailed => {
            CliError::Keystore("wrong passphrase or corrupted keystore".into())
        }
        other => CliError::Crypto(other),
    })?;
    seeds_from_plaintext(&plaintext)
}
