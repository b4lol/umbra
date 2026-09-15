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
    match unlock(keystore_path, passphrase.as_bytes()) {
        Ok(fingerprint) => Response::ok(fingerprint),
        Err(message) => Response::err(message),
    }
}

/// Unlocks a regular keystore or a Decoy Vault file (auto-detected by
/// its fixed size, TODO B.3 Phases 1-3) and returns the unlocked
/// identity's fingerprint as lowercase hex. Identical logic to
/// `umbra-gui`'s pre-increment `unlock::unlock` — relocated here, not
/// rewritten, as this increment's whole point (TODO B.3.1).
fn unlock(keystore_path: &Path, passphrase: &[u8]) -> Result<String, String> {
    let metadata = std::fs::metadata(keystore_path).map_err(|error| error.to_string())?;
    let container_len = u64::try_from(umbra_crypto::decoy_vault::CONTAINER_LEN).unwrap_or(u64::MAX);
    let bundle = if metadata.len() == container_len {
        umbra_cli::decoy_vault::unlock(keystore_path, passphrase)
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
        };
        let response = dispatch(&request);
        std::fs::remove_file(&path)?;

        assert!(response.ok);
        assert_eq!(response.fingerprint.map(|f| f.len()), Some(64));
        Ok(())
    }

    #[test]
    fn unknown_op_fails_cleanly() {
        let request = Request {
            op: "future-op".to_string(),
            keystore_path: None,
            passphrase: None,
        };
        let response = dispatch(&request);
        assert!(!response.ok);
        assert_eq!(
            response.error.as_deref(),
            Some("unknown operation: future-op")
        );
    }
}
