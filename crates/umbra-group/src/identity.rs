//! Separate Ed25519 group-identity keystore for PQ-MLS group ("cell")
//! membership (spec Decision 6, TODO B.2).
//!
//! This is a NEW, independent identity — not a change to
//! `umbra_crypto::keys::IdentityBundle`/`IdentitySeeds` (the existing
//! two-party ML-DSA-65/X25519 identity used for pairing and 1:1
//! sessions). MLS leaf-node signing uses Ed25519 via
//! `openmls_basic_credential::SignatureKeyPair`; a member's MLS
//! `BasicCredential` identity is simply that signature key pair's
//! public key bytes, recomputed on load rather than persisted
//! separately (see [`credential_for`]).
//!
//! Persisted the same way as `umbra-cli`'s two-party identity keystore
//! (`crates/umbra-cli/src/keystore.rs`): an Argon2id-derived key sealing
//! a ChaCha20-Poly1305 envelope (`umbra_crypto::keystore`), written with
//! `0600` permissions on Unix. File layout: `[magic 5][salt 16][envelope]`,
//! where `envelope` is `[nonce 12][ciphertext+tag]` as produced by
//! [`umbra_crypto::keystore::seal_envelope`]. The encrypted plaintext is
//! the TLS-codec wire encoding of the `SignatureKeyPair` (private key,
//! public key, and signature scheme).

use std::fs;
use std::io::Write as _;
use std::path::Path;

use openmls::prelude::tls_codec::{DeserializeBytes as _, Serialize as _};
use openmls::prelude::{BasicCredential, SignatureScheme};
use openmls_basic_credential::SignatureKeyPair;
use umbra_crypto::keystore::{self, KS_SALT_LEN};
use zeroize::Zeroizing;

use crate::error::GroupError;

/// Magic header: `"UMGI"` + version byte (Umbra Group Identity, v1).
const MAGIC: [u8; 5] = *b"UMGI\x01";

/// A group-identity Ed25519 signing keypair, plus its MLS `BasicCredential`.
pub struct GroupIdentity {
    /// The Ed25519 signing keypair used for MLS leaf-node signatures.
    pub signature_key_pair: SignatureKeyPair,
    /// The MLS `BasicCredential` binding this identity's public key.
    pub credential: BasicCredential,
}

/// Builds the `BasicCredential` for a signature key pair: its identity is
/// always the signature key pair's public key bytes, so it is never
/// persisted separately — only recomputed, both at generation and on load.
fn credential_for(signature_key_pair: &SignatureKeyPair) -> BasicCredential {
    BasicCredential::new(signature_key_pair.public().to_vec())
}

/// Generates a fresh Ed25519 group identity.
///
/// # Errors
///
/// Returns [`GroupError::Signature`] if key generation fails. In
/// practice this is unreachable for the Ed25519 scheme — the fallible
/// branch in `SignatureKeyPair::new` only covers other/unsupported
/// signature schemes (verified against the installed
/// `openmls_basic_credential` 0.6.0 source) — but the underlying
/// constructor is fallible, so this surfaces the `Result` rather than
/// unwrapping/panicking (CODE_MANIFESTO Zero Panic Doctrine).
pub fn generate_group_identity() -> Result<GroupIdentity, GroupError> {
    let signature_key_pair = SignatureKeyPair::new(SignatureScheme::ED25519)?;
    let credential = credential_for(&signature_key_pair);
    Ok(GroupIdentity {
        signature_key_pair,
        credential,
    })
}

/// Serializes a signature key pair into the keystore plaintext (its
/// TLS-codec wire encoding: private key, public key, signature scheme).
fn signature_key_pair_to_plaintext(
    signature_key_pair: &SignatureKeyPair,
) -> Result<Zeroizing<Vec<u8>>, GroupError> {
    Ok(Zeroizing::new(signature_key_pair.tls_serialize_detached()?))
}

/// Parses the keystore plaintext back into a signature key pair.
fn signature_key_pair_from_plaintext(plaintext: &[u8]) -> Result<SignatureKeyPair, GroupError> {
    Ok(SignatureKeyPair::tls_deserialize_exact_bytes(plaintext)?)
}

/// Saves a group identity to `path`, encrypted under `passphrase`
/// (production Argon2id parameters). The file is written with `0600`
/// permissions on Unix.
///
/// # Errors
///
/// Returns [`GroupError`] for KDF, AEAD, TLS-codec, or I/O failures.
pub fn save_group_identity(
    path: &Path,
    passphrase: &[u8],
    identity: &GroupIdentity,
) -> Result<(), GroupError> {
    save_group_identity_with_params(
        path,
        passphrase,
        identity,
        keystore::ARGON2_M_KIB,
        keystore::ARGON2_T_COST,
        keystore::ARGON2_P_COST,
    )
}

/// [`save_group_identity`] with explicit Argon2id parameters (tests use
/// reduced costs).
///
/// # Errors
///
/// See [`save_group_identity`].
pub fn save_group_identity_with_params(
    path: &Path,
    passphrase: &[u8],
    identity: &GroupIdentity,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<(), GroupError> {
    let mut salt = [0u8; KS_SALT_LEN];
    umbra_crypto::rng::fill(&mut salt)?;
    let key =
        keystore::derive_keystore_key_with_params(passphrase, &salt, m_cost_kib, t_cost, p_cost)?;
    let plaintext = signature_key_pair_to_plaintext(&identity.signature_key_pair)?;
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

/// Loads a group identity from `path`, decrypting under `passphrase`.
///
/// # Errors
///
/// Returns [`GroupError::Io`] if the file cannot be read,
/// [`GroupError::Malformed`] for a bad magic header or a truncated file,
/// [`GroupError::Crypto`] for a wrong passphrase or tampering (AEAD), and
/// [`GroupError::Codec`] if the decrypted plaintext is not a valid
/// signature key pair.
pub fn load_group_identity(path: &Path, passphrase: &[u8]) -> Result<GroupIdentity, GroupError> {
    load_group_identity_with_params(
        path,
        passphrase,
        keystore::ARGON2_M_KIB,
        keystore::ARGON2_T_COST,
        keystore::ARGON2_P_COST,
    )
}

/// [`load_group_identity`] with explicit Argon2id parameters (tests use
/// reduced costs).
///
/// # Errors
///
/// See [`load_group_identity`].
pub fn load_group_identity_with_params(
    path: &Path,
    passphrase: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<GroupIdentity, GroupError> {
    let raw = fs::read(path)?;
    let header = raw
        .get(..MAGIC.len())
        .ok_or_else(|| GroupError::Malformed("truncated keystore file".into()))?;
    if header != MAGIC {
        return Err(GroupError::Malformed(
            "not an Umbra group-identity keystore file".into(),
        ));
    }
    let stored_salt: [u8; KS_SALT_LEN] = umbra_crypto::kdf::read_at(&raw, MAGIC.len())?;
    let envelope_start = MAGIC.len().saturating_add(KS_SALT_LEN);
    let envelope = raw
        .get(envelope_start..)
        .ok_or_else(|| GroupError::Malformed("truncated keystore envelope".into()))?;

    let key = keystore::derive_keystore_key_with_params(
        passphrase,
        &stored_salt,
        m_cost_kib,
        t_cost,
        p_cost,
    )?;
    let plaintext = keystore::open_envelope(&key, envelope)?;
    let signature_key_pair = signature_key_pair_from_plaintext(&plaintext)?;
    let credential = credential_for(&signature_key_pair);
    Ok(GroupIdentity {
        signature_key_pair,
        credential,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reduced Argon2id costs so the keystore round-trip tests stay fast
    /// (mirrors `umbra-cli`'s `tests/keystore_pairing.rs`).
    const TEST_M_KIB: u32 = 8192;
    /// Reduced Argon2id time cost for tests.
    const TEST_T_COST: u32 = 2;
    /// Reduced Argon2id parallelism for tests.
    const TEST_P_COST: u32 = 1;

    #[test]
    fn generate_produces_a_usable_identity() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        let identity = generate_group_identity()?;
        // Ed25519 public keys are always 32 bytes.
        assert_eq!(identity.signature_key_pair.public().len(), 32);
        assert_eq!(
            identity.signature_key_pair.signature_scheme(),
            SignatureScheme::ED25519
        );
        // The credential identity must match the public key exactly.
        assert_eq!(
            identity.credential.identity(),
            identity.signature_key_pair.public()
        );
        Ok(())
    }

    #[test]
    fn save_and_load_round_trips() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dir = std::env::temp_dir().join(format!(
            "umbra-group-identity-test-{}-{}",
            std::process::id(),
            "roundtrip"
        ));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("group_identity.enc");
        let identity = generate_group_identity()?;
        save_group_identity_with_params(
            &path,
            b"test-passphrase",
            &identity,
            TEST_M_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;
        let loaded = load_group_identity_with_params(
            &path,
            b"test-passphrase",
            TEST_M_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;
        assert_eq!(
            loaded.signature_key_pair.public(),
            identity.signature_key_pair.public()
        );
        assert_eq!(
            loaded.signature_key_pair.signature_scheme(),
            identity.signature_key_pair.signature_scheme()
        );
        assert_eq!(loaded.credential.identity(), identity.credential.identity());
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn wrong_passphrase_rejected() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dir = std::env::temp_dir().join(format!(
            "umbra-group-identity-wrongpw-{}-{}",
            std::process::id(),
            "test"
        ));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("group_identity.enc");
        save_group_identity_with_params(
            &path,
            b"right",
            &generate_group_identity()?,
            TEST_M_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;
        assert!(
            load_group_identity_with_params(
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
