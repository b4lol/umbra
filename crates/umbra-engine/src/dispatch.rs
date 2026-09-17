//! Request dispatch (TODO B.3.1): the Engine's only implemented
//! operation, `"unlock"` — auto-detects a Decoy Vault file (TODO B.3)
//! by its fixed size, exactly like `umbra-gui`'s own unlock flow did
//! before this increment moved the computation here.

use std::path::Path;

use crate::protocol::{Request, Response};

/// Dispatches one decoded [`Request`], returning the [`Response`] to
/// send back. Never fails itself — every failure mode (a missing
/// field, an unrecognized `op`, a keystore error) becomes an `Ok`
/// [`Response`] with `ok: false`, so the caller always has exactly one
/// line to write back.
#[must_use]
pub fn dispatch(request: &Request) -> Response {
    match request.op.as_str() {
        "unlock" => dispatch_unlock(request),
        other => Response::err(format!("unknown operation: {other}")),
    }
}

/// Implements the `"unlock"` operation: validates the required fields
/// are present, then delegates to [`unlock`].
fn dispatch_unlock(request: &Request) -> Response {
    let Some(keystore_path) = request.keystore_path.as_deref() else {
        return Response::err("missing keystore_path");
    };
    let Some(passphrase) = request.passphrase.as_deref() else {
        return Response::err("missing passphrase");
    };
    match unlock(
        keystore_path,
        passphrase.as_bytes(),
        request.hw_module.as_deref(),
        request.hw_pin.as_deref(),
        request.hw_key_label.as_deref(),
    ) {
        Ok(fingerprint) => Response::ok(fingerprint),
        Err(message) => Response::err(message),
    }
}

/// Unlocks a regular keystore, a hardware-key-gated keystore (TODO B.3
/// FIDO2 wiring), or a Decoy Vault file (auto-detected by its fixed
/// size, TODO B.3 Phases 1-3), and returns the unlocked identity's
/// fingerprint as lowercase hex.
///
/// Hardware-key gating is decided by inspecting `keystore_path` itself
/// (`umbra_cli::keystore::is_hardware_key_gated`), not by whether
/// `hw_module` etc. are present in the request — mirrors this
/// codebase's own established `load_identity` auto-detection.
fn unlock(
    keystore_path: &Path,
    passphrase: &[u8],
    hw_module: Option<&Path>,
    hw_pin: Option<&str>,
    hw_key_label: Option<&str>,
) -> Result<String, String> {
    let metadata = std::fs::metadata(keystore_path).map_err(|error| error.to_string())?;
    let container_len = u64::try_from(umbra_crypto::decoy_vault::CONTAINER_LEN).unwrap_or(u64::MAX);
    let bundle = if metadata.len() == container_len {
        umbra_cli::decoy_vault::unlock(keystore_path, passphrase)
            .map_err(|error| error.to_string())?
    } else if umbra_cli::keystore::is_hardware_key_gated(keystore_path)
        .map_err(|error| error.to_string())?
    {
        let (hw_module, hw_pin, hw_key_label) = match (hw_module, hw_pin, hw_key_label) {
            (Some(module), Some(pin), Some(label)) => (module, pin, label),
            _ => {
                return Err(
                    "this keystore requires a hardware key: launch umbra-gui with \
                     --hw-module and --hw-key-label, and fill in the PIN field"
                        .to_string(),
                );
            }
        };
        let response = umbra_hwkey::challenge_response(
            hw_module,
            hw_pin.as_bytes(),
            hw_key_label,
            umbra_cli::keystore::HARDWARE_KEY_CHALLENGE,
        )
        .map_err(|error| error.to_string())?;
        umbra_cli::keystore::load_with_hardware_key(keystore_path, passphrase, &response)
            .map_err(|error| error.to_string())?
    } else {
        umbra_cli::keystore::load(keystore_path, passphrase).map_err(|error| error.to_string())?
    };
    let fingerprint = umbra_crypto::kdf::identity_fingerprint(
        &bundle.x25519.public_bytes(),
        &bundle.dsa.public_bytes(),
    );
    Ok(umbra_cli::cli::output::hex(&fingerprint))
}

#[cfg(test)]
mod tests {
    use super::dispatch;
    use crate::protocol::Request;
    use umbra_cli::keystore::{HARDWARE_KEY_CHALLENGE, save_with_hardware_key};
    use umbra_crypto::keys::IdentityBundle;

    fn temp_keystore_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "umbra-engine-dispatch-test-{}-{label}.enc",
            std::process::id()
        ))
    }

    #[test]
    fn unlock_with_correct_passphrase_returns_the_fingerprint()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = temp_keystore_path("correct");
        let bundle = IdentityBundle::generate();
        umbra_cli::keystore::save(&path, b"correct-passphrase", &bundle)?;

        let request = Request {
            op: "unlock".to_string(),
            keystore_path: Some(path.clone()),
            passphrase: Some("correct-passphrase".to_string()),
            hw_module: None,
            hw_pin: None,
            hw_key_label: None,
        };
        let response = dispatch(&request);
        std::fs::remove_file(&path)?;

        assert!(response.ok);
        assert_eq!(response.fingerprint.map(|f| f.len()), Some(64));
        Ok(())
    }

    #[test]
    fn unlock_with_wrong_passphrase_fails() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        let path = temp_keystore_path("wrong");
        let bundle = IdentityBundle::generate();
        umbra_cli::keystore::save(&path, b"correct-passphrase", &bundle)?;

        let request = Request {
            op: "unlock".to_string(),
            keystore_path: Some(path.clone()),
            passphrase: Some("wrong-passphrase".to_string()),
            hw_module: None,
            hw_pin: None,
            hw_key_label: None,
        };
        let response = dispatch(&request);
        std::fs::remove_file(&path)?;

        assert!(!response.ok);
        assert!(response.error.is_some());
        Ok(())
    }

    #[test]
    fn unlock_with_decoy_vault_hidden_passphrase_returns_the_fingerprint()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = temp_keystore_path("decoy-hidden");
        let _ = std::fs::remove_file(&path);
        let outer_bundle = IdentityBundle::generate();
        let hidden_bundle = IdentityBundle::generate();
        umbra_cli::decoy_vault::create(&path, b"outer-pw", &outer_bundle)?;
        umbra_cli::decoy_vault::write_hidden(&path, b"hidden-pw", &hidden_bundle)?;

        let request = Request {
            op: "unlock".to_string(),
            keystore_path: Some(path.clone()),
            passphrase: Some("hidden-pw".to_string()),
            hw_module: None,
            hw_pin: None,
            hw_key_label: None,
        };
        let response = dispatch(&request);
        std::fs::remove_file(&path)?;

        assert!(response.ok);
        assert_eq!(response.fingerprint.map(|f| f.len()), Some(64));
        Ok(())
    }

    /// Real hardware-key round trip (TODO B.3 FIDO2 wiring), against a
    /// real SoftHSM2 software token — no mock, matching this project's
    /// established testing stance for every other hardware-key
    /// increment. The ONLY SoftHSM2-touching test in this binary
    /// (`crates/umbra-engine/src/dispatch.rs`'s own `mod tests`) —
    /// deliberately kept to one, since Rust's default test harness
    /// parallelizes within a binary and this repo's shared token store
    /// races under concurrent access (see this plan's own Global
    /// Constraints).
    #[test]
    fn unlock_with_hardware_key_returns_the_fingerprint()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Must match `crates/umbra-hwkey/tests/fixtures/softhsm2-test.conf`'s
        // `directories.tokendir` — this workspace's root
        // `.cargo/config.toml` FORCES `SOFTHSM2_CONF` to that fixture
        // for every `cargo test` invocation (see its own comment), so
        // SoftHSM2 writes here regardless of what directory name this
        // test might otherwise have picked.
        const TOKEN_DIR: &str = "/tmp/umbra-hwkey-softhsm-test-tokens";
        let _ = std::fs::remove_dir_all(TOKEN_DIR);
        std::fs::create_dir_all(TOKEN_DIR)?;
        let init = std::process::Command::new("softhsm2-util")
            .args([
                "--init-token",
                "--free",
                "--label",
                "umbra-engine-dispatch-test",
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

        let module_path = softhsm2_module_path()?;
        let label = "umbra-engine-dispatch-test-key";
        umbra_hwkey::generate_hmac_key(&module_path, b"1234", label)?;
        let response =
            umbra_hwkey::challenge_response(&module_path, b"1234", label, HARDWARE_KEY_CHALLENGE)?;

        let path = temp_keystore_path("hardware-key");
        let bundle = IdentityBundle::generate();
        save_with_hardware_key(&path, b"hw-test-passphrase", &response, &bundle)?;

        let request = Request {
            op: "unlock".to_string(),
            keystore_path: Some(path.clone()),
            passphrase: Some("hw-test-passphrase".to_string()),
            hw_module: Some(module_path),
            hw_pin: Some("1234".to_string()),
            hw_key_label: Some(label.to_string()),
        };
        // The token must still exist here: `dispatch` -> `unlock` calls
        // `challenge_response` AGAIN, independently re-deriving the HMAC
        // response from the live token (never trusting a caller-supplied
        // response) — so `TOKEN_DIR` is removed only after this call, not
        // before it (the plan's own original ordering removed it too
        // early, which fails every real run, not just a narrow check).
        let response = dispatch(&request);
        let _ = std::fs::remove_dir_all(TOKEN_DIR);
        std::fs::remove_file(&path)?;

        assert!(response.ok, "expected Ok, got: {response:?}");
        assert_eq!(response.fingerprint.map(|f| f.len()), Some(64));
        Ok(())
    }

    /// Locates the SoftHSM2 PKCS#11 module: an explicit
    /// `UMBRA_SOFTHSM2_MODULE` env var override first, then the common
    /// Fedora/Debian install paths — mirrors `umbra-cli`'s own
    /// `hwkey_test_support::softhsm2_module_path` exactly
    /// (`pub(crate)` there, not reusable from this external crate, so
    /// duplicated here for this one test).
    fn softhsm2_module_path() -> Result<std::path::PathBuf, Box<dyn std::error::Error + Send + Sync>>
    {
        if let Ok(path) = std::env::var("UMBRA_SOFTHSM2_MODULE") {
            return Ok(std::path::PathBuf::from(path));
        }
        for candidate in [
            "/usr/lib64/pkcs11/libsofthsm2.so",
            "/usr/lib/softhsm/libsofthsm2.so",
        ] {
            if std::path::Path::new(candidate).exists() {
                return Ok(std::path::PathBuf::from(candidate));
            }
        }
        Err("no SoftHSM2 PKCS#11 module found at any known path; set UMBRA_SOFTHSM2_MODULE".into())
    }

    #[test]
    fn unknown_op_fails_cleanly() {
        let request = Request {
            op: "future-op".to_string(),
            keystore_path: None,
            passphrase: None,
            hw_module: None,
            hw_pin: None,
            hw_key_label: None,
        };
        let response = dispatch(&request);
        assert!(!response.ok);
        assert_eq!(
            response.error.as_deref(),
            Some("unknown operation: future-op")
        );
    }
}
