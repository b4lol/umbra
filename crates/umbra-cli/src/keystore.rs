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

/// Hardware-key-gated keystore magic (version 2): a keystore saved with
/// this magic requires BOTH the passphrase and a hardware-key HMAC
/// response to unlock — see [`save_with_hardware_key`]. The original
/// passphrase-only format ([`MAGIC`], version 1) is completely
/// unmodified by this addition.
const MAGIC_HW: [u8; 5] = *b"UMKS\x02";

/// The fixed challenge every caller must feed to
/// `umbra_hwkey::challenge_response` to compute a valid `hmac_response`
/// for [`save_with_hardware_key`]/[`load_with_hardware_key`]. Fixed
/// (not per-file/per-salt) deliberately: the token's own secret key is
/// what gates access, and this is a purely local computation (never
/// transmitted or replayed across a network), so a per-file challenge
/// would not meaningfully raise the difficulty of forging a response
/// without physical access to the token — while a fixed challenge avoids
/// threading a caller-generated salt through `save` before the salt
/// that normally protects the KDF even exists.
pub const HARDWARE_KEY_CHALLENGE: &[u8] = b"umbra-keystore-hardware-key-challenge-v1";

/// Detects whether the keystore file at `path` requires a hardware-key
/// HMAC response to unlock ([`MAGIC_HW`]) rather than a plain
/// passphrase ([`MAGIC`]) — reads only the 5-byte magic header; no
/// decryption is attempted.
///
/// # Errors
///
/// Returns [`CliError::Keystore`] if the file cannot be read, is
/// truncated, or its header matches neither known magic.
pub fn is_hardware_key_gated(path: &Path) -> Result<bool, CliError> {
    let raw = fs::read(path)
        .map_err(|e| CliError::Keystore(format!("cannot read {}: {e}", path.display())))?;
    let header = raw
        .get(..MAGIC.len())
        .ok_or_else(|| CliError::Keystore("truncated keystore file".into()))?;
    if header == MAGIC {
        Ok(false)
    } else if header == MAGIC_HW {
        Ok(true)
    } else {
        Err(CliError::Keystore("not an Umbra keystore file".into()))
    }
}

/// Concatenates `passphrase` and `hmac_response` into the single byte
/// string fed to Argon2id for a hardware-key-gated keystore. No
/// separator: both operands are opaque input material to the KDF, which
/// never needs to split them back apart.
fn combined_kdf_input(passphrase: &[u8], hmac_response: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut combined = Zeroizing::new(Vec::with_capacity(
        passphrase.len().saturating_add(hmac_response.len()),
    ));
    combined.extend_from_slice(passphrase);
    combined.extend_from_slice(hmac_response);
    combined
}

/// Saves an identity bundle to `path`, encrypted under `passphrase ||
/// hmac_response` (production Argon2id parameters), marked
/// hardware-key-gated (`MAGIC_HW`). `hmac_response` must be the caller's
/// own `umbra_hwkey::challenge_response(..., HARDWARE_KEY_CHALLENGE)`
/// output — this function does not compute it and has no dependency on
/// `umbra-hwkey`.
///
/// # Errors
///
/// Returns [`CliError`] for KDF, AEAD, or I/O failures.
pub fn save_with_hardware_key(
    path: &Path,
    passphrase: &[u8],
    hmac_response: &[u8],
    bundle: &IdentityBundle,
) -> Result<(), CliError> {
    save_with_hardware_key_with_params(
        path,
        passphrase,
        hmac_response,
        bundle,
        keystore::ARGON2_M_KIB,
        keystore::ARGON2_T_COST,
        keystore::ARGON2_P_COST,
    )
}

/// [`save_with_hardware_key`] with explicit Argon2id parameters (tests
/// use reduced costs).
///
/// # Errors
///
/// See [`save_with_hardware_key`].
pub fn save_with_hardware_key_with_params(
    path: &Path,
    passphrase: &[u8],
    hmac_response: &[u8],
    bundle: &IdentityBundle,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<(), CliError> {
    let mut salt = [0u8; KS_SALT_LEN];
    umbra_crypto::rng::fill(&mut salt).map_err(CliError::Crypto)?;
    let combined = combined_kdf_input(passphrase, hmac_response);
    let key =
        keystore::derive_keystore_key_with_params(&combined, &salt, m_cost_kib, t_cost, p_cost)
            .map_err(CliError::Crypto)?;
    let plaintext = seeds_to_plaintext(&bundle.secret_seeds());
    let envelope =
        Zeroizing::new(keystore::seal_envelope(&key, &plaintext).map_err(CliError::Crypto)?);
    let capacity = MAGIC_HW
        .len()
        .saturating_add(KS_SALT_LEN)
        .saturating_add(envelope.len());
    let mut file = Vec::with_capacity(capacity);
    file.extend_from_slice(&MAGIC_HW);
    file.extend_from_slice(&salt);
    file.extend_from_slice(&envelope);

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

/// Loads an identity bundle from a hardware-key-gated (`MAGIC_HW`)
/// keystore at `path`, given the correct `passphrase` and the correct
/// `hmac_response` for [`HARDWARE_KEY_CHALLENGE`].
///
/// # Errors
///
/// Returns [`CliError::Keystore`] if the file is a plain (non-hardware-
/// key) keystore, if it's neither known format, for I/O failures, and
/// for a wrong passphrase/`hmac_response` (AEAD verification failure —
/// deliberately the SAME message a wrong passphrase alone produces, so
/// a caller cannot tell which factor was wrong).
pub fn load_with_hardware_key(
    path: &Path,
    passphrase: &[u8],
    hmac_response: &[u8],
) -> Result<IdentityBundle, CliError> {
    load_with_hardware_key_with_params(
        path,
        passphrase,
        hmac_response,
        keystore::ARGON2_M_KIB,
        keystore::ARGON2_T_COST,
        keystore::ARGON2_P_COST,
    )
}

/// [`load_with_hardware_key`] with explicit Argon2id parameters.
///
/// # Errors
///
/// See [`load_with_hardware_key`].
pub fn load_with_hardware_key_with_params(
    path: &Path,
    passphrase: &[u8],
    hmac_response: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<IdentityBundle, CliError> {
    let raw = fs::read(path)
        .map_err(|e| CliError::Keystore(format!("cannot read {}: {e}", path.display())))?;
    let header = raw
        .get(..MAGIC_HW.len())
        .ok_or_else(|| CliError::Keystore("truncated keystore file".into()))?;
    if header == MAGIC {
        return Err(CliError::Keystore(
            "this keystore does not require a hardware key".into(),
        ));
    }
    if header != MAGIC_HW {
        return Err(CliError::Keystore("not an Umbra keystore file".into()));
    }
    let stored_salt: [u8; KS_SALT_LEN] =
        umbra_crypto::kdf::read_at(&raw, MAGIC_HW.len()).map_err(CliError::Crypto)?;
    let envelope_start = MAGIC_HW.len().saturating_add(KS_SALT_LEN);
    let envelope = raw
        .get(envelope_start..)
        .ok_or_else(|| CliError::Keystore("truncated keystore envelope".into()))?;

    let combined = combined_kdf_input(passphrase, hmac_response);
    let key = keystore::derive_keystore_key_with_params(
        &combined,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Fresh temp keystore path, unique per test/label pair (mirrors
    /// this workspace's other crates' `temp_dir`-style helpers).
    fn temp_keystore_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "umbra-cli-keystore-hwkey-test-{}-{label}.enc",
            std::process::id()
        ))
    }

    /// Serializes this module's own three `#[test]` functions against
    /// each other. Unlike `umbra-hwkey`'s single-test integration file
    /// (one `tests/*.rs` file = one process, so it has no intra-file
    /// concurrency hazard by construction), THIS module is a unit-test
    /// module: all three tests below compile into the SAME
    /// `umbra-cli` test binary, and Rust's default harness runs
    /// `#[test]` functions in parallel threads within one process.
    /// Every one of these three tests calls [`real_hmac_response`],
    /// which drives the same on-disk SoftHSM2 token directory
    /// (`TOKEN_DIR`) through an external `softhsm2-util --init-token`
    /// process plus `umbra_hwkey`'s own PKCS#11 calls — concurrent
    /// threads interleaving a directory removal/recreation with another
    /// thread's in-progress token init corrupts the shared token store
    /// (observed directly: a concurrent run reliably produced
    /// `Pkcs11(Pkcs11(GeneralError, Initialize))` on one of the three
    /// tests). Holding this lock for [`real_hmac_response`]'s entire
    /// body — mirroring `umbra_hwkey`'s own internal `PKCS11_LOCK`
    /// pattern, which only serializes ITS OWN two functions against each
    /// other and does not extend to this test's external
    /// `softhsm2-util` process or directory operations — is the
    /// deliberately simple, provably-correct fix.
    static TEST_TOKEN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Initializes a fresh SoftHSM2 token (via the same
    /// `SOFTHSM2_CONF`-pointed fixture `umbra-hwkey`'s own hermetic test
    /// uses), generates a real HMAC key, and returns the real
    /// `hmac_response` for [`HARDWARE_KEY_CHALLENGE`]. A distinct
    /// token/key label from `umbra-hwkey`'s own test
    /// (`umbra-cli-keystore-test`) keeps the two easy to tell apart in
    /// any diagnostic output. See [`TEST_TOKEN_LOCK`] for why this
    /// function's entire body must run under that lock: this module's
    /// three tests all call it, and — unlike `umbra-hwkey`'s own
    /// single-test integration file — they share one test binary.
    fn real_hmac_response() -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let _guard = match TEST_TOKEN_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        const TOKEN_DIR: &str = "/tmp/umbra-hwkey-softhsm-test-tokens";
        let _ = std::fs::remove_dir_all(TOKEN_DIR);
        std::fs::create_dir_all(TOKEN_DIR)?;

        let init = std::process::Command::new("softhsm2-util")
            .args([
                "--init-token",
                "--free",
                "--label",
                "umbra-cli-keystore-test",
                "--pin",
                "1234",
                "--so-pin",
                "0000",
            ])
            .output()?;
        if !init.status.success() {
            return Err(format!(
                "softhsm2-util --init-token failed: {}",
                String::from_utf8_lossy(&init.stderr)
            )
            .into());
        }

        let module = std::path::Path::new("/usr/lib64/pkcs11/libsofthsm2.so");
        let label = "umbra-cli-keystore-test-key";
        umbra_hwkey::generate_hmac_key(module, b"1234", label)?;
        let response =
            umbra_hwkey::challenge_response(module, b"1234", label, HARDWARE_KEY_CHALLENGE)?;

        let _ = std::fs::remove_dir_all(TOKEN_DIR);
        Ok(response)
    }

    /// The full round trip: save with a real hardware-key response,
    /// load with the same response, confirm the bundle's public keys
    /// match — and confirm `is_hardware_key_gated` and the OLD, plain
    /// `load` behave correctly against the same file.
    #[test]
    fn hardware_key_round_trip_and_format_separation()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let response = real_hmac_response()?;
        let path = temp_keystore_path("roundtrip");
        let passphrase = b"hardware-key-test-passphrase";
        let bundle = IdentityBundle::generate();

        save_with_hardware_key(&path, passphrase, &response, &bundle)?;

        assert!(
            is_hardware_key_gated(&path)?,
            "a hardware-key-gated file must report itself as such"
        );

        let loaded = load_with_hardware_key(&path, passphrase, &response)?;
        assert_eq!(
            loaded.x25519.public_bytes(),
            bundle.x25519.public_bytes(),
            "the round-tripped bundle's public key must match the original"
        );

        // The OLD, unmodified `load` must refuse this file outright —
        // proves real format separation, not just new functions bolted
        // on alongside an unchanged one.
        assert!(
            load(&path, passphrase).is_err(),
            "the plain (non-hardware-key) load must refuse a UMKS\\x02 file"
        );

        std::fs::remove_file(&path)?;
        Ok(())
    }

    /// A wrong `hmac_response` (a different, freshly-generated token
    /// key's output for the same challenge) must fail exactly like a
    /// wrong passphrase does — the same error message, no
    /// factor-distinguishing leak.
    #[test]
    fn wrong_hmac_response_fails_like_a_wrong_passphrase()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let response = real_hmac_response()?;
        let path = temp_keystore_path("wrong-response");
        let passphrase = b"hardware-key-test-passphrase";
        let bundle = IdentityBundle::generate();
        save_with_hardware_key(&path, passphrase, &response, &bundle)?;

        let mut wrong_response = response;
        wrong_response[0] ^= 0xFF;
        let result = load_with_hardware_key(&path, passphrase, &wrong_response);
        let error = result
            .err()
            .ok_or("expected an error for a wrong hmac_response")?;
        assert_eq!(
            error.to_string(),
            "keystore failure: wrong passphrase or corrupted keystore",
            "a wrong hmac_response must fail with the SAME message a wrong passphrase uses"
        );

        std::fs::remove_file(&path)?;
        Ok(())
    }

    /// `is_hardware_key_gated` and `load_with_hardware_key` must both
    /// correctly recognize a PLAIN (non-hardware-key) keystore file as
    /// not-hardware-key-gated, and `load_with_hardware_key` must refuse
    /// it with a distinct, clear message (not the generic wrong-passphrase
    /// one — this is a caller-usage mistake, not an authentication
    /// failure).
    #[test]
    fn plain_keystore_is_not_hardware_key_gated()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = temp_keystore_path("plain");
        let passphrase = b"plain-keystore-test-passphrase";
        let bundle = IdentityBundle::generate();
        save(&path, passphrase, &bundle)?;

        assert!(
            !is_hardware_key_gated(&path)?,
            "a plain keystore must report itself as NOT hardware-key-gated"
        );

        let result = load_with_hardware_key(&path, passphrase, b"irrelevant-32-byte-value-here!!!");
        let error = result
            .err()
            .ok_or("expected an error loading a plain keystore via the hardware-key path")?;
        assert_eq!(
            error.to_string(),
            "keystore failure: this keystore does not require a hardware key"
        );

        std::fs::remove_file(&path)?;
        Ok(())
    }
}
