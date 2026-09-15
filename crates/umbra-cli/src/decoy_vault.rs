//! Decoy Vault, Phase 2 (TODO B.3): file I/O and [`IdentityBundle`]
//! binding on top of Phase 1's [`umbra_crypto::decoy_vault`] container
//! format. Still entirely unwired from any CLI subcommand or GUI —
//! Phase 3.
//!
//! Reuses `umbra_cli::keystore`'s existing seed-serialization format
//! (`seeds_to_plaintext`/`seeds_from_plaintext`) — the SAME plaintext
//! shape an ordinary (non-decoy) keystore file uses for its own
//! envelope, just now sealed inside a Phase 1 hidden-volume container
//! instead of a `UMKS` envelope.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use umbra_crypto::decoy_vault as dv;
use umbra_crypto::keys::IdentityBundle;
use umbra_crypto::keystore as crypto_keystore;

use crate::cli::CliError;
use crate::keystore::{seeds_from_plaintext, seeds_to_plaintext};

/// Creates a fresh decoy-vault file at `path` with `outer_bundle` as
/// its outer (decoy) identity. Refuses to overwrite an existing file.
///
/// # Errors
///
/// Returns [`CliError`] for KDF/AEAD failures (via
/// [`umbra_crypto::decoy_vault::create_container`]) or I/O failures.
pub fn create(
    path: &Path,
    outer_passphrase: &[u8],
    outer_bundle: &IdentityBundle,
) -> Result<(), CliError> {
    create_with_params(
        path,
        outer_passphrase,
        outer_bundle,
        crypto_keystore::ARGON2_M_KIB,
        crypto_keystore::ARGON2_T_COST,
        crypto_keystore::ARGON2_P_COST,
    )
}

/// [`create`] with explicit Argon2id parameters (tests use reduced
/// costs).
///
/// # Errors
///
/// See [`create`].
pub fn create_with_params(
    path: &Path,
    outer_passphrase: &[u8],
    outer_bundle: &IdentityBundle,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<(), CliError> {
    let plaintext = seeds_to_plaintext(&outer_bundle.secret_seeds());
    let container =
        dv::create_container_with_params(outer_passphrase, &plaintext, m_cost_kib, t_cost, p_cost)
            .map_err(CliError::Crypto)?;
    write_new_file(path, &container)
}

/// Writes (or overwrites) `hidden_bundle` as the hidden identity
/// within an EXISTING decoy-vault file at `path`.
///
/// # Errors
///
/// Returns [`CliError`] for KDF/AEAD failures, or I/O failures
/// reading/writing `path`.
pub fn write_hidden(
    path: &Path,
    hidden_passphrase: &[u8],
    hidden_bundle: &IdentityBundle,
) -> Result<(), CliError> {
    write_hidden_with_params(
        path,
        hidden_passphrase,
        hidden_bundle,
        crypto_keystore::ARGON2_M_KIB,
        crypto_keystore::ARGON2_T_COST,
        crypto_keystore::ARGON2_P_COST,
    )
}

/// [`write_hidden`] with explicit Argon2id parameters.
///
/// # Errors
///
/// See [`write_hidden`].
pub fn write_hidden_with_params(
    path: &Path,
    hidden_passphrase: &[u8],
    hidden_bundle: &IdentityBundle,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<(), CliError> {
    let mut container = fs::read(path)
        .map_err(|e| CliError::Keystore(format!("cannot read {}: {e}", path.display())))?;
    let plaintext = seeds_to_plaintext(&hidden_bundle.secret_seeds());
    dv::write_hidden_with_params(
        &mut container,
        hidden_passphrase,
        &plaintext,
        m_cost_kib,
        t_cost,
        p_cost,
    )
    .map_err(CliError::Crypto)?;
    overwrite_file(path, &container)
}

/// Loads the outer (decoy) identity from a decoy-vault file at `path`.
///
/// # Errors
///
/// Returns [`CliError`] for I/O failures or a wrong `passphrase`
/// (AEAD).
pub fn load_outer(path: &Path, passphrase: &[u8]) -> Result<IdentityBundle, CliError> {
    load_outer_with_params(
        path,
        passphrase,
        crypto_keystore::ARGON2_M_KIB,
        crypto_keystore::ARGON2_T_COST,
        crypto_keystore::ARGON2_P_COST,
    )
}

/// [`load_outer`] with explicit Argon2id parameters.
///
/// # Errors
///
/// See [`load_outer`].
pub fn load_outer_with_params(
    path: &Path,
    passphrase: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<IdentityBundle, CliError> {
    let container = fs::read(path)
        .map_err(|e| CliError::Keystore(format!("cannot read {}: {e}", path.display())))?;
    let plaintext = dv::open_outer_with_params(&container, passphrase, m_cost_kib, t_cost, p_cost)
        .map_err(CliError::Crypto)?;
    let seeds = seeds_from_plaintext(&plaintext)?;
    Ok(IdentityBundle::from_seeds(&seeds))
}

/// Loads the hidden (real) identity from a decoy-vault file at `path`.
/// Fails IDENTICALLY (same error text) whether `passphrase` is wrong
/// or no hidden volume was ever written — preserving Phase 1's
/// deniability property at this layer too.
///
/// # Errors
///
/// Returns [`CliError`] for I/O failures or a wrong `passphrase`/no
/// hidden volume present (AEAD).
pub fn load_hidden(path: &Path, passphrase: &[u8]) -> Result<IdentityBundle, CliError> {
    load_hidden_with_params(
        path,
        passphrase,
        crypto_keystore::ARGON2_M_KIB,
        crypto_keystore::ARGON2_T_COST,
        crypto_keystore::ARGON2_P_COST,
    )
}

/// [`load_hidden`] with explicit Argon2id parameters.
///
/// # Errors
///
/// See [`load_hidden`].
pub fn load_hidden_with_params(
    path: &Path,
    passphrase: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<IdentityBundle, CliError> {
    let container = fs::read(path)
        .map_err(|e| CliError::Keystore(format!("cannot read {}: {e}", path.display())))?;
    let plaintext = dv::open_hidden_with_params(&container, passphrase, m_cost_kib, t_cost, p_cost)
        .map_err(CliError::Crypto)?;
    let seeds = seeds_from_plaintext(&plaintext)?;
    Ok(IdentityBundle::from_seeds(&seeds))
}

/// Unlocks a decoy-vault file: tries BOTH the outer and hidden
/// identities with the SAME `passphrase`.
///
/// # Constant-time property (security-critical, do not "optimize")
///
/// Both [`load_outer_with_params`] and [`load_hidden_with_params`] are
/// called UNCONDITIONALLY — even when the first already succeeded.
/// Short-circuiting the second call would make this function's total
/// running time depend on WHICH region matched (one Argon2id
/// derivation vs. two), a real, measurable timing side-channel that
/// would defeat the entire point of a duress-safe single unlock
/// command: an observer timing `unlock` could otherwise infer whether
/// the outer or hidden identity was just opened, even without seeing
/// any output.
///
/// # Errors
///
/// Returns [`CliError`] if `passphrase` matches NEITHER region (the
/// outer failure's error text — identical to the hidden failure's, by
/// Phase 1/2's own deniability guarantee).
pub fn unlock(path: &Path, passphrase: &[u8]) -> Result<IdentityBundle, CliError> {
    unlock_with_params(
        path,
        passphrase,
        crypto_keystore::ARGON2_M_KIB,
        crypto_keystore::ARGON2_T_COST,
        crypto_keystore::ARGON2_P_COST,
    )
}

/// [`unlock`] with explicit Argon2id parameters.
///
/// # Errors
///
/// See [`unlock`].
pub fn unlock_with_params(
    path: &Path,
    passphrase: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<IdentityBundle, CliError> {
    let outer_result = load_outer_with_params(path, passphrase, m_cost_kib, t_cost, p_cost);
    let hidden_result = load_hidden_with_params(path, passphrase, m_cost_kib, t_cost, p_cost);
    match (outer_result, hidden_result) {
        (Ok(bundle), _) => Ok(bundle),
        (Err(_), Ok(bundle)) => Ok(bundle),
        (Err(outer_error), Err(_)) => Err(outer_error),
    }
}

/// Writes `contents` to a brand-new file at `path` with `0600`
/// permissions, refusing to overwrite an existing file. Mirrors
/// `umbra_cli::keystore::save_with_params`'s own exact file-creation
/// pattern.
fn write_new_file(path: &Path, contents: &[u8]) -> Result<(), CliError> {
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
        .write_all(contents)
        .map_err(|e| CliError::Keystore(format!("write failed: {e}")))?;
    handle
        .sync_all()
        .map_err(|e| CliError::Keystore(format!("sync failed: {e}")))?;
    Ok(())
}

/// Overwrites an EXISTING file at `path` with `contents` in full
/// (truncate + rewrite) — used by [`write_hidden`], which modifies an
/// already-created decoy-vault file.
fn overwrite_file(path: &Path, contents: &[u8]) -> Result<(), CliError> {
    let mut handle = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|e| CliError::Keystore(format!("cannot open {}: {e}", path.display())))?;
    handle
        .write_all(contents)
        .map_err(|e| CliError::Keystore(format!("write failed: {e}")))?;
    handle
        .sync_all()
        .map_err(|e| CliError::Keystore(format!("sync failed: {e}")))?;
    Ok(())
}

/// `umbra decoy-vault` subcommands (TODO B.3, Phase 3).
#[derive(Debug, clap::Subcommand)]
pub enum DecoyVaultCommand {
    /// Creates a new decoy-vault file with a fresh outer identity.
    Create,
    /// Adds a hidden identity to an existing decoy-vault file. Does
    /// NOT require knowledge of the outer passphrase (matches
    /// VeraCrypt's own UX: hidden-volume creation only needs the
    /// hidden passphrase and file access).
    AddHidden,
    /// Unlocks a decoy-vault file — tries the outer identity, then
    /// the hidden identity, with the SAME `--passphrase-file`. NEVER
    /// reveals which one (if either) actually matched: identical
    /// output, identical error text, identical timing either way.
    Unlock,
}

/// Dispatches a parsed `umbra decoy-vault` subcommand.
///
/// # Errors
///
/// Returns [`CliError`] on failure.
pub fn dispatch(command: &DecoyVaultCommand, cli: &crate::cli::Cli) -> Result<(), CliError> {
    match command {
        DecoyVaultCommand::Create => create_cmd(cli),
        DecoyVaultCommand::AddHidden => add_hidden_cmd(cli),
        DecoyVaultCommand::Unlock => unlock_cmd(cli),
    }
}

/// Resolves `--keystore PATH` (reused for decoy-vault files — same
/// role, "the identity file path", as the ordinary keystore command's
/// own use of this global flag).
fn keystore_path(cli: &crate::cli::Cli) -> Result<&Path, CliError> {
    cli.keystore
        .as_deref()
        .ok_or_else(|| CliError::Keystore("missing --keystore PATH".into()))
}

/// `umbra decoy-vault create`.
fn create_cmd(cli: &crate::cli::Cli) -> Result<(), CliError> {
    let path = keystore_path(cli)?;
    let passphrase = crate::cli::load_passphrase(cli)?;
    let bundle = IdentityBundle::generate();
    create(path, &passphrase, &bundle)?;
    crate::cli::output::line("decoy vault created");
    Ok(())
}

/// `umbra decoy-vault add-hidden`.
fn add_hidden_cmd(cli: &crate::cli::Cli) -> Result<(), CliError> {
    let path = keystore_path(cli)?;
    let passphrase = crate::cli::load_passphrase(cli)?;
    let bundle = IdentityBundle::generate();
    write_hidden(path, &passphrase, &bundle)?;
    crate::cli::output::line("hidden identity added");
    Ok(())
}

/// `umbra decoy-vault unlock`. Prints the resulting identity's
/// fingerprint — the SAME code path regardless of whether the outer
/// or hidden identity was actually unlocked (see [`unlock`]'s own
/// doc comment for why this indistinguishability matters).
fn unlock_cmd(cli: &crate::cli::Cli) -> Result<(), CliError> {
    let path = keystore_path(cli)?;
    let passphrase = crate::cli::load_passphrase(cli)?;
    let bundle = unlock(path, &passphrase)?;
    let fingerprint = umbra_crypto::kdf::identity_fingerprint(
        &bundle.x25519.public_bytes(),
        &bundle.dsa.public_bytes(),
    );
    crate::cli::output::line(&crate::cli::output::hex(&fingerprint));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_M_COST_KIB: u32 = 8192;
    const TEST_T_COST: u32 = 2;
    const TEST_P_COST: u32 = 1;

    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "umbra-cli-decoy-vault-test-{}-{label}.dv",
            std::process::id()
        ))
    }

    #[test]
    fn create_and_load_outer_round_trips() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = temp_path("outer-roundtrip");
        let _ = std::fs::remove_file(&path);
        let outer_bundle = IdentityBundle::generate();

        create_with_params(
            &path,
            b"outer-pw",
            &outer_bundle,
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;

        let loaded = load_outer_with_params(
            &path,
            b"outer-pw",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;
        assert_eq!(
            loaded.x25519.public_bytes(),
            outer_bundle.x25519.public_bytes()
        );

        std::fs::remove_file(&path)?;
        Ok(())
    }

    #[test]
    fn write_hidden_then_load_hidden_round_trips_without_disturbing_outer()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = temp_path("hidden-roundtrip");
        let _ = std::fs::remove_file(&path);
        let outer_bundle = IdentityBundle::generate();
        let hidden_bundle = IdentityBundle::generate();

        create_with_params(
            &path,
            b"outer-pw",
            &outer_bundle,
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;
        write_hidden_with_params(
            &path,
            b"hidden-pw",
            &hidden_bundle,
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;

        let loaded_hidden = load_hidden_with_params(
            &path,
            b"hidden-pw",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;
        assert_eq!(
            loaded_hidden.x25519.public_bytes(),
            hidden_bundle.x25519.public_bytes()
        );

        let loaded_outer = load_outer_with_params(
            &path,
            b"outer-pw",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;
        assert_eq!(
            loaded_outer.x25519.public_bytes(),
            outer_bundle.x25519.public_bytes()
        );

        std::fs::remove_file(&path)?;
        Ok(())
    }

    #[test]
    fn load_hidden_before_write_hidden_and_with_wrong_passphrase_fail_identically()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = temp_path("hidden-deniability");
        let _ = std::fs::remove_file(&path);
        let outer_bundle = IdentityBundle::generate();

        create_with_params(
            &path,
            b"outer-pw",
            &outer_bundle,
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;

        // No hidden volume ever written:
        let before = load_hidden_with_params(
            &path,
            b"hidden-pw",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        );
        let before_message = before.err().ok_or("expected an error")?.to_string();

        let hidden_bundle = IdentityBundle::generate();
        write_hidden_with_params(
            &path,
            b"hidden-pw",
            &hidden_bundle,
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;

        // Wrong passphrase against the NOW-real hidden volume:
        let wrong = load_hidden_with_params(
            &path,
            b"wrong-hidden-pw",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        );
        let wrong_message = wrong.err().ok_or("expected an error")?.to_string();

        assert_eq!(
            before_message, wrong_message,
            "\"no hidden volume\" and \"wrong passphrase\" must produce IDENTICAL error text"
        );

        std::fs::remove_file(&path)?;
        Ok(())
    }

    #[test]
    fn unlock_returns_outer_bundle_when_outer_passphrase_given()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = temp_path("unlock-outer");
        let _ = std::fs::remove_file(&path);
        let outer_bundle = IdentityBundle::generate();

        create_with_params(
            &path,
            b"outer-pw",
            &outer_bundle,
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;

        let unlocked = unlock_with_params(
            &path,
            b"outer-pw",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;
        assert_eq!(
            unlocked.x25519.public_bytes(),
            outer_bundle.x25519.public_bytes()
        );

        std::fs::remove_file(&path)?;
        Ok(())
    }

    #[test]
    fn unlock_returns_hidden_bundle_when_hidden_passphrase_given()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = temp_path("unlock-hidden");
        let _ = std::fs::remove_file(&path);
        let outer_bundle = IdentityBundle::generate();
        let hidden_bundle = IdentityBundle::generate();

        create_with_params(
            &path,
            b"outer-pw",
            &outer_bundle,
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;
        write_hidden_with_params(
            &path,
            b"hidden-pw",
            &hidden_bundle,
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;

        let unlocked = unlock_with_params(
            &path,
            b"hidden-pw",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;
        assert_eq!(
            unlocked.x25519.public_bytes(),
            hidden_bundle.x25519.public_bytes()
        );

        std::fs::remove_file(&path)?;
        Ok(())
    }

    #[test]
    fn unlock_fails_with_a_passphrase_matching_neither_region()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = temp_path("unlock-neither");
        let _ = std::fs::remove_file(&path);
        let outer_bundle = IdentityBundle::generate();

        create_with_params(
            &path,
            b"outer-pw",
            &outer_bundle,
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )?;

        let result = unlock_with_params(
            &path,
            b"neither-pw",
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        );
        assert!(result.is_err());

        std::fs::remove_file(&path)?;
        Ok(())
    }
}
