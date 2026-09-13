//! Keystore-unlock logic (TODO B.3): a pure, GTK-independent function so
//! it is hermetically unit-testable without a display server —
//! `main.rs` calls it with bytes read from a `gtk4::PasswordEntry`,
//! wrapped in `zeroize::Zeroizing` by the caller (this function itself
//! has no GTK dependency and does no zeroizing of its own — the
//! passphrase's lifetime is the caller's responsibility).

/// Attempts to unlock the keystore at `keystore_path` with `passphrase`,
/// returning the unlocked identity's fingerprint as lowercase hex (64
/// characters — `identity_fingerprint` returns 32 bytes) on success.
///
/// Reuses `umbra_cli::keystore::load` (the same function `serve`/`tui`/
/// `mesh_serve` already use) and `umbra_crypto::kdf::identity_fingerprint`
/// (the same computation `umbra fingerprint` already shows) — no new
/// crypto or keystore logic here, only the glue between them and a
/// plain `String` error the GUI's error label can display directly.
///
/// # Errors
///
/// Returns a display-ready error message on a wrong passphrase, a
/// missing/corrupt keystore file, or any other keystore-loading
/// failure — deliberately a plain `String`, not `umbra_cli::CliError`,
/// since this is the boundary where that internal error type becomes
/// GUI-displayable text.
pub fn unlock(keystore_path: &std::path::Path, passphrase: &[u8]) -> Result<String, String> {
    let bundle =
        umbra_cli::keystore::load(keystore_path, passphrase).map_err(|error| error.to_string())?;
    let fingerprint = umbra_crypto::kdf::identity_fingerprint(
        &bundle.x25519.public_bytes(),
        &bundle.dsa.public_bytes(),
    );
    Ok(umbra_cli::cli::output::hex(&fingerprint))
}

#[cfg(test)]
mod tests {
    use super::unlock;
    use umbra_crypto::keys::IdentityBundle;

    /// Fresh temp keystore path, unique per test/label pair (mirrors
    /// this workspace's other crates' `temp_dir`-style helpers).
    fn temp_keystore_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "umbra-gui-unlock-test-{}-{label}.enc",
            std::process::id()
        ))
    }

    /// The correct passphrase unlocks a real keystore and returns its
    /// fingerprint as 64 lowercase hex characters (32 bytes,
    /// `umbra_crypto::kdf::identity_fingerprint`'s output length).
    #[test]
    fn unlock_with_correct_passphrase_returns_the_fingerprint()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = temp_keystore_path("correct");
        let passphrase = b"unlock-test-passphrase";
        let bundle = IdentityBundle::generate();
        umbra_cli::keystore::save(&path, passphrase, &bundle)?;

        let result = unlock(&path, passphrase);
        std::fs::remove_file(&path)?;

        let fingerprint = result.map_err(|error| format!("expected Ok, got Err: {error}"))?;
        assert_eq!(
            fingerprint.len(),
            64,
            "fingerprint must be 32 bytes hex-encoded (64 hex characters)"
        );
        Ok(())
    }

    /// The wrong passphrase fails cleanly (no panic) rather than
    /// returning a fingerprint.
    #[test]
    fn unlock_with_wrong_passphrase_fails() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        let path = temp_keystore_path("wrong");
        let bundle = IdentityBundle::generate();
        umbra_cli::keystore::save(&path, b"correct-passphrase", &bundle)?;

        let result = unlock(&path, b"wrong-passphrase");
        std::fs::remove_file(&path)?;

        assert!(result.is_err(), "wrong passphrase must fail");
        Ok(())
    }
}
