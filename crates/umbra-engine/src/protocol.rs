//! Wire protocol between `umbra-gui` and `umbra-engine` (TODO B.3.1):
//! newline-delimited JSON (NDJSON) over one `AF_UNIX` stream
//! connection — this codebase's own established event-stream
//! convention (`umbra_cli::serve`'s stdout events), reused here
//! rather than inventing a new wire format.
//!
//! No protocol-version field: `umbra-engine` and `umbra-gui` are built
//! and shipped together from the same workspace, with exactly one
//! consumer of this protocol — a version field would guard against a
//! scenario (an old GUI talking to a new Engine, or vice versa) that
//! cannot happen here.

use serde::{Deserialize, Serialize};

/// One request line, `umbra-gui` -> `umbra-engine`.
///
/// `keystore_path`/`passphrase` are `Option` rather than fields of an
/// `op`-tagged enum so an unrecognized `op` can still be PARSED (and
/// answered with a clean [`Response`] error) instead of failing to
/// deserialize at all.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Request {
    /// The requested operation: `"unlock"`, `"list_peers"`,
    /// `"pair_payload"`, `"pair_import"`, or `"pair_confirm"`.
    pub op: String,
    /// The keystore or decoy-vault file to operate on (required for
    /// `"unlock"`). Its parent directory must equal the Engine's own
    /// `--keystore-dir` startup argument.
    #[serde(default)]
    pub keystore_path: Option<std::path::PathBuf>,
    /// The passphrase to unlock with (required for `"unlock"`).
    ///
    /// A JSON string, so it must be valid UTF-8 — true today because
    /// the only production caller is a GTK `PasswordEntry`'s typed
    /// text (always valid UTF-8 by construction); base64-encoding to
    /// support arbitrary bytes is deferred until a caller actually
    /// needs it (YAGNI).
    #[serde(default)]
    pub passphrase: Option<String>,
    /// Path to the hardware token's PKCS#11 module (TODO B.3 FIDO2
    /// wiring). Required, together with `hw_pin`/`hw_key_label`, ONLY
    /// if the target `keystore_path` turns out to be hardware-key-gated
    /// (`umbra_cli::keystore::is_hardware_key_gated`) — the Engine
    /// decides this by inspecting the file, not from this field's mere
    /// presence. Its parent directory must equal the Engine's own
    /// `--hw-module-dir` startup argument.
    #[serde(default)]
    pub hw_module: Option<std::path::PathBuf>,
    /// The hardware token's PIN.
    #[serde(default)]
    pub hw_pin: Option<String>,
    /// Label of the token-held HMAC key (as passed to
    /// `umbra_hwkey::challenge_response`).
    #[serde(default)]
    pub hw_key_label: Option<String>,
    /// Local display name to save a peer under (required for
    /// `"pair_confirm"`), `[A-Za-z0-9_-]+` — validated by
    /// `umbra_cli::peers::save_peer`.
    #[serde(default)]
    pub peer_name: Option<String>,
    /// A peer's base64url pairing payload (required for
    /// `"pair_import"` and `"pair_confirm"`) — received out of band
    /// (QR / copy-paste) from the peer's own `"pair_payload"`
    /// response.
    #[serde(default)]
    pub peer_payload: Option<String>,
    /// The peer's `.onion` service address, if the operator has one to
    /// record now (optional, `"pair_confirm"` only — mirrors `umbra
    /// pair --onion`'s own optional flag).
    #[serde(default)]
    pub peer_onion: Option<String>,
}

/// One response line, `umbra-engine` -> `umbra-gui`.
///
/// A plain struct (not a tagged enum) matching the wire format
/// verbatim: exactly one of `fingerprint`/`peer_names`/`payload`/`sas`/
/// `error` is populated (or none, for a bare `"pair_confirm"`
/// success), selected by `ok` together with which operation was
/// requested.
#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    /// Whether the operation succeeded.
    pub ok: bool,
    /// The unlocked identity's fingerprint (64 lowercase hex
    /// characters), present only when `ok` is `true`.
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// A display-ready error message, present only when `ok` is
    /// `false`.
    #[serde(default)]
    pub error: Option<String>,
    /// Paired peer names (`"list_peers"` only), sorted.
    #[serde(default)]
    pub peer_names: Option<Vec<String>>,
    /// This session's own base64url pairing payload (`"pair_payload"`
    /// only).
    #[serde(default)]
    pub payload: Option<String>,
    /// The shared 6-digit SAS code for out-of-band verification
    /// (`"pair_import"` only).
    #[serde(default)]
    pub sas: Option<String>,
}

impl Response {
    /// Builds a bare successful response with no operation-specific
    /// payload (`"pair_confirm"`, and the shared base every other
    /// success builder below starts from).
    #[must_use]
    pub fn success() -> Self {
        Self {
            ok: true,
            fingerprint: None,
            error: None,
            peer_names: None,
            payload: None,
            sas: None,
        }
    }

    /// Builds a successful `"unlock"` response.
    #[must_use]
    pub fn ok(fingerprint: String) -> Self {
        Self {
            fingerprint: Some(fingerprint),
            ..Self::success()
        }
    }

    /// Builds a successful `"list_peers"` response.
    #[must_use]
    pub fn peers(names: Vec<String>) -> Self {
        Self {
            peer_names: Some(names),
            ..Self::success()
        }
    }

    /// Builds a successful `"pair_payload"` response.
    #[must_use]
    pub fn payload(payload: String) -> Self {
        Self {
            payload: Some(payload),
            ..Self::success()
        }
    }

    /// Builds a successful `"pair_import"` response.
    #[must_use]
    pub fn sas(sas: String) -> Self {
        Self {
            sas: Some(sas),
            ..Self::success()
        }
    }

    /// Builds a failure response.
    #[must_use]
    pub fn err(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(message.into()),
            ..Self::success()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Request, Response};

    #[test]
    fn request_round_trips_through_json() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let request = Request {
            op: "unlock".to_string(),
            keystore_path: Some(std::path::PathBuf::from("/tmp/ks.enc")),
            passphrase: Some("secret".to_string()),
            ..Request::default()
        };
        let line = serde_json::to_string(&request)?;
        let decoded: Request = serde_json::from_str(&line)?;
        assert_eq!(decoded.op, "unlock");
        assert_eq!(
            decoded.keystore_path,
            Some(std::path::PathBuf::from("/tmp/ks.enc"))
        );
        assert_eq!(decoded.passphrase.as_deref(), Some("secret"));
        Ok(())
    }

    #[test]
    fn request_with_hardware_key_fields_round_trips_through_json()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let request = Request {
            op: "unlock".to_string(),
            keystore_path: Some(std::path::PathBuf::from("/tmp/ks.enc")),
            passphrase: Some("secret".to_string()),
            hw_module: Some(std::path::PathBuf::from("/usr/lib64/pkcs11/libsofthsm2.so")),
            hw_pin: Some("1234".to_string()),
            hw_key_label: Some("my-key".to_string()),
            ..Request::default()
        };
        let line = serde_json::to_string(&request)?;
        let decoded: Request = serde_json::from_str(&line)?;
        assert_eq!(
            decoded.hw_module,
            Some(std::path::PathBuf::from("/usr/lib64/pkcs11/libsofthsm2.so"))
        );
        assert_eq!(decoded.hw_pin.as_deref(), Some("1234"));
        assert_eq!(decoded.hw_key_label.as_deref(), Some("my-key"));
        Ok(())
    }

    #[test]
    fn success_response_round_trips_through_json()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let response = Response::ok("a".repeat(64));
        let line = serde_json::to_string(&response)?;
        let decoded: Response = serde_json::from_str(&line)?;
        assert!(decoded.ok);
        assert_eq!(decoded.fingerprint, Some("a".repeat(64)));
        assert_eq!(decoded.error, None);
        Ok(())
    }

    #[test]
    fn failure_response_round_trips_through_json()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let response = Response::err("wrong passphrase or corrupted keystore");
        let line = serde_json::to_string(&response)?;
        let decoded: Response = serde_json::from_str(&line)?;
        assert!(!decoded.ok);
        assert_eq!(decoded.fingerprint, None);
        assert_eq!(
            decoded.error.as_deref(),
            Some("wrong passphrase or corrupted keystore")
        );
        Ok(())
    }

    #[test]
    fn unrecognized_op_still_deserializes() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        let line = r#"{"op":"future-op"}"#;
        let decoded: Request = serde_json::from_str(line)?;
        assert_eq!(decoded.op, "future-op");
        assert_eq!(decoded.keystore_path, None);
        assert_eq!(decoded.passphrase, None);
        Ok(())
    }

    #[test]
    fn pairing_request_fields_round_trip_through_json()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let request = Request {
            op: "pair_confirm".to_string(),
            peer_name: Some("alice".to_string()),
            peer_payload: Some("payload-bytes".to_string()),
            peer_onion: Some("a".repeat(56)),
            ..Request::default()
        };
        let line = serde_json::to_string(&request)?;
        let decoded: Request = serde_json::from_str(&line)?;
        assert_eq!(decoded.op, "pair_confirm");
        assert_eq!(decoded.peer_name.as_deref(), Some("alice"));
        assert_eq!(decoded.peer_payload.as_deref(), Some("payload-bytes"));
        assert_eq!(decoded.peer_onion, Some("a".repeat(56)));
        Ok(())
    }

    #[test]
    fn list_peers_response_round_trips_through_json()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let response = Response::peers(vec!["alice".to_string(), "bob".to_string()]);
        let line = serde_json::to_string(&response)?;
        let decoded: Response = serde_json::from_str(&line)?;
        assert!(decoded.ok);
        assert_eq!(
            decoded.peer_names,
            Some(vec!["alice".to_string(), "bob".to_string()])
        );
        Ok(())
    }

    #[test]
    fn pair_payload_response_round_trips_through_json()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let response = Response::payload("own-payload-bytes".to_string());
        let line = serde_json::to_string(&response)?;
        let decoded: Response = serde_json::from_str(&line)?;
        assert!(decoded.ok);
        assert_eq!(decoded.payload.as_deref(), Some("own-payload-bytes"));
        Ok(())
    }

    #[test]
    fn pair_import_response_round_trips_through_json()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let response = Response::sas("123456".to_string());
        let line = serde_json::to_string(&response)?;
        let decoded: Response = serde_json::from_str(&line)?;
        assert!(decoded.ok);
        assert_eq!(decoded.sas.as_deref(), Some("123456"));
        Ok(())
    }
}
