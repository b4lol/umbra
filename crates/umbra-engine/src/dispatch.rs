//! Request dispatch (TODO B.3.1): routes each decoded [`Request`] to
//! its operation — `"unlock"` (auto-detects a Decoy Vault file, TODO
//! B.3, by its fixed size, exactly like `umbra-gui`'s own unlock flow
//! did before this increment moved the computation here), plus the
//! per-session `"list_peers"`, `"pair_payload"`, `"pair_import"`, and
//! `"pair_confirm"` operations added for TODO B.3's GUI messaging
//! design, Phase 1.

use std::path::{Path, PathBuf};

use umbra_crypto::keys::IdentityBundle;

use crate::protocol::{Request, Response};

/// Per-connection state accumulated once a `"unlock"` request
/// succeeds: the unlocked identity and the peers directory derived
/// from its keystore path. `None` until the first successful unlock;
/// every peer-list/pairing operation below requires it and fails
/// cleanly with `"not unlocked yet"` otherwise (TODO B.3's GUI
/// messaging design, Phase 1 — the Engine keeps the identity resident
/// for the rest of the connection's life, exactly as the spec
/// describes for the eventual full session phase, just without the
/// tagged event/response protocol that phase adds).
#[derive(Default)]
pub struct Session {
    /// Unlocked identity bundle and its derived peers directory, populated after successful unlock.
    identity: Option<(IdentityBundle, PathBuf)>,
}

/// Dispatches one decoded [`Request`] against the connection's
/// [`Session`], returning the [`Response`] to send back. Never fails
/// itself — every failure mode becomes an `Ok` [`Response`] with
/// `ok: false`, so the caller always has exactly one line to write
/// back.
#[must_use]
pub fn dispatch(request: &Request, session: &mut Session) -> Response {
    match request.op.as_str() {
        "unlock" => dispatch_unlock(request, session),
        "list_peers" => dispatch_list_peers(session),
        "pair_payload" => dispatch_pair_payload(session),
        "pair_import" => dispatch_pair_import(request, session),
        "pair_confirm" => dispatch_pair_confirm(request, session),
        other => Response::err(format!("unknown operation: {other}")),
    }
}

/// Implements the `"unlock"` operation: validates the required fields
/// are present, unlocks, and on success stores the identity and its
/// peers directory into `session` for later requests on this
/// connection.
fn dispatch_unlock(request: &Request, session: &mut Session) -> Response {
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
        Ok((fingerprint, bundle)) => {
            let peers_dir = keystore_path
                .parent()
                .map_or_else(|| PathBuf::from("peers"), |parent| parent.join("peers"));
            session.identity = Some((bundle, peers_dir));
            Response::ok(fingerprint)
        }
        Err(message) => Response::err(message),
    }
}

/// Unlocks a regular keystore, a hardware-key-gated keystore (TODO B.3
/// FIDO2 wiring), or a Decoy Vault file (auto-detected by its fixed
/// size, TODO B.3 Phases 1-3), and returns the unlocked identity's
/// fingerprint as lowercase hex and the bundle itself.
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
) -> Result<(String, IdentityBundle), String> {
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
    Ok((umbra_cli::cli::output::hex(&fingerprint), bundle))
}

/// Implements `"list_peers"`: names of every paired peer under the
/// current session's peers directory. Requires a prior successful
/// `"unlock"` on this connection.
fn dispatch_list_peers(session: &Session) -> Response {
    let Some((_, peers_dir)) = session.identity.as_ref() else {
        return Response::err("not unlocked yet");
    };
    match umbra_cli::peers::list_names(peers_dir) {
        Ok(names) => Response::peers(names),
        Err(error) => Response::err(error.to_string()),
    }
}

/// Implements `"pair_payload"`: this session's own base64url pairing
/// payload, for the operator to hand to a peer out of band (QR code /
/// copy-paste). Requires a prior successful `"unlock"`.
fn dispatch_pair_payload(session: &Session) -> Response {
    let Some((bundle, _)) = session.identity.as_ref() else {
        return Response::err("not unlocked yet");
    };
    match umbra_cli::pairing::payload_for(bundle) {
        Ok(payload) => Response::payload(payload),
        Err(error) => Response::err(error.to_string()),
    }
}

/// Implements `"pair_import"`: validates a peer's pairing payload and
/// returns the shared SAS code for out-of-band verification. Does NOT
/// persist a peer record yet — see `"pair_confirm"`. Requires a prior
/// successful `"unlock"`.
fn dispatch_pair_import(request: &Request, session: &Session) -> Response {
    let Some((bundle, _)) = session.identity.as_ref() else {
        return Response::err("not unlocked yet");
    };
    let Some(peer_payload) = request.peer_payload.as_deref() else {
        return Response::err("missing peer_payload");
    };
    if let Err(error) = umbra_cli::pairing::parse_payload(peer_payload) {
        return Response::err(error.to_string());
    }
    let own_payload = match umbra_cli::pairing::payload_for(bundle) {
        Ok(payload) => payload,
        Err(error) => return Response::err(error.to_string()),
    };
    let sas = umbra_cli::pairing::pairing_sas(&own_payload, peer_payload);
    Response::sas(sas.to_string())
}

/// Implements `"pair_confirm"`: the operator has compared the SAS
/// code out of band and confirmed it matches, so the peer record is
/// now persisted. Re-validates `peer_payload` independently inside
/// `save_peer` (never trusts that a prior `"pair_import"` call
/// actually happened on this connection — a client could send
/// `"pair_confirm"` first). Requires a prior successful `"unlock"`.
fn dispatch_pair_confirm(request: &Request, session: &Session) -> Response {
    let Some((_, peers_dir)) = session.identity.as_ref() else {
        return Response::err("not unlocked yet");
    };
    let Some(peer_name) = request.peer_name.as_deref() else {
        return Response::err("missing peer_name");
    };
    let Some(peer_payload) = request.peer_payload.as_deref() else {
        return Response::err("missing peer_payload");
    };
    match umbra_cli::peers::save_peer(
        peers_dir,
        peer_name,
        peer_payload,
        request.peer_onion.as_deref(),
        None,
        None,
    ) {
        Ok(()) => Response::success(),
        Err(error) => Response::err(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{Session, dispatch};
    use crate::protocol::Request;
    use umbra_cli::keystore::{HARDWARE_KEY_CHALLENGE, save_with_hardware_key};
    use umbra_crypto::keys::IdentityBundle;

    /// Unique-per-test-case keystore file path. Deliberately places the
    /// file under its OWN PID+label-scoped DIRECTORY (created here),
    /// not directly in the bare system temp dir: `dispatch_unlock`
    /// derives its `Session`'s peers directory from `keystore_path`'s
    /// PARENT, so a bare-temp-dir file would give every test in this
    /// module the SAME parent (and thus the same, colliding, peers
    /// directory) under Rust's default parallel test harness — the
    /// scoped directory here keeps each test's `Session`-internal
    /// peers directory, not just its keystore file, genuinely unique.
    fn temp_keystore_path(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "umbra-engine-dispatch-test-{}-{label}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        dir.join("keystore.enc")
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
            ..Request::default()
        };
        let mut session = Session::default();
        let response = dispatch(&request, &mut session);
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
            ..Request::default()
        };
        let mut session = Session::default();
        let response = dispatch(&request, &mut session);
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
            ..Request::default()
        };
        let mut session = Session::default();
        let response = dispatch(&request, &mut session);
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
            ..Request::default()
        };
        // The token must still exist here: `dispatch` -> `unlock` calls
        // `challenge_response` AGAIN, independently re-deriving the HMAC
        // response from the live token (never trusting a caller-supplied
        // response) — so `TOKEN_DIR` is removed only after this call, not
        // before it (the plan's own original ordering removed it too
        // early, which fails every real run, not just a narrow check).
        let mut session = Session::default();
        let response = dispatch(&request, &mut session);
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
            ..Request::default()
        };
        let mut session = Session::default();
        let response = dispatch(&request, &mut session);
        assert!(!response.ok);
        assert_eq!(
            response.error.as_deref(),
            Some("unknown operation: future-op")
        );
    }

    #[test]
    fn session_ops_before_unlock_all_fail_with_not_unlocked_yet() {
        let mut session = Session::default();
        for op in ["list_peers", "pair_payload", "pair_import", "pair_confirm"] {
            let request = Request {
                op: op.to_string(),
                ..Request::default()
            };
            let response = dispatch(&request, &mut session);
            assert!(!response.ok, "op {op} unexpectedly succeeded");
            assert_eq!(
                response.error.as_deref(),
                Some("not unlocked yet"),
                "op {op}"
            );
        }
    }

    #[test]
    fn pair_payload_after_unlock_returns_a_valid_payload()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = temp_keystore_path("pair-payload");
        let bundle = IdentityBundle::generate();
        umbra_cli::keystore::save(&path, b"pw", &bundle)?;
        let mut session = Session::default();
        let unlock_request = Request {
            op: "unlock".to_string(),
            keystore_path: Some(path.clone()),
            passphrase: Some("pw".to_string()),
            ..Request::default()
        };
        assert!(dispatch(&unlock_request, &mut session).ok);

        let response = dispatch(
            &Request {
                op: "pair_payload".to_string(),
                ..Request::default()
            },
            &mut session,
        );
        std::fs::remove_file(&path)?;

        assert!(response.ok, "expected Ok, got: {response:?}");
        let payload = response.payload.ok_or("expected a payload")?;
        // The own payload must decode against the SAME identity's public
        // keys — round-tripping it through `parse_payload` proves the
        // Engine actually built it from `bundle`, not a stub.
        let expected = umbra_cli::pairing::payload_for(&bundle)?;
        assert_eq!(payload, expected);
        Ok(())
    }

    #[test]
    fn pair_import_computes_a_sas_without_saving_a_peer_record()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = temp_keystore_path("pair-import");
        let bundle = IdentityBundle::generate();
        umbra_cli::keystore::save(&path, b"pw", &bundle)?;
        let peer_bundle = IdentityBundle::generate();
        let peer_payload = umbra_cli::pairing::payload_for(&peer_bundle)?;

        let mut session = Session::default();
        assert!(
            dispatch(
                &Request {
                    op: "unlock".to_string(),
                    keystore_path: Some(path.clone()),
                    passphrase: Some("pw".to_string()),
                    ..Request::default()
                },
                &mut session,
            )
            .ok
        );

        let response = dispatch(
            &Request {
                op: "pair_import".to_string(),
                peer_payload: Some(peer_payload.clone()),
                ..Request::default()
            },
            &mut session,
        );
        let own_payload = umbra_cli::pairing::payload_for(&bundle)?;
        let peers_dir = path.parent().ok_or("no parent")?.join("peers");
        let no_peers_saved = umbra_cli::peers::list_names(&peers_dir)?.is_empty();
        std::fs::remove_file(&path)?;
        let _ = std::fs::remove_dir_all(&peers_dir);

        assert!(response.ok, "expected Ok, got: {response:?}");
        let sas = response.sas.ok_or("expected a sas code")?;
        assert_eq!(
            sas,
            umbra_cli::pairing::pairing_sas(&own_payload, &peer_payload).to_string()
        );
        assert!(no_peers_saved, "pair_import must not persist a peer record");
        Ok(())
    }

    #[test]
    fn pair_confirm_then_list_peers_shows_the_saved_peer()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = temp_keystore_path("pair-confirm");
        let bundle = IdentityBundle::generate();
        umbra_cli::keystore::save(&path, b"pw", &bundle)?;
        let peer_bundle = IdentityBundle::generate();
        let peer_payload = umbra_cli::pairing::payload_for(&peer_bundle)?;
        let peers_dir = path.parent().ok_or("no parent")?.join("peers");

        let mut session = Session::default();
        assert!(
            dispatch(
                &Request {
                    op: "unlock".to_string(),
                    keystore_path: Some(path.clone()),
                    passphrase: Some("pw".to_string()),
                    ..Request::default()
                },
                &mut session,
            )
            .ok
        );

        let confirm_response = dispatch(
            &Request {
                op: "pair_confirm".to_string(),
                peer_name: Some("alice".to_string()),
                peer_payload: Some(peer_payload),
                ..Request::default()
            },
            &mut session,
        );
        let list_response = dispatch(
            &Request {
                op: "list_peers".to_string(),
                ..Request::default()
            },
            &mut session,
        );
        std::fs::remove_file(&path)?;
        let _ = std::fs::remove_dir_all(&peers_dir);

        assert!(
            confirm_response.ok,
            "expected Ok, got: {confirm_response:?}"
        );
        assert!(list_response.ok, "expected Ok, got: {list_response:?}");
        assert_eq!(list_response.peer_names, Some(vec!["alice".to_string()]));
        Ok(())
    }
}
