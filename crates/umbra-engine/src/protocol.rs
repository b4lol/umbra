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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
    /// Present for every session-phase request (`"list_peers"`,
    /// `"pair_payload"`, `"pair_import"`, `"pair_confirm"`, `"send"`)
    /// once a connection has completed a successful `"unlock"` —
    /// absent for `"unlock"` itself, whose exchange stays untagged
    /// (TODO B.3 GUI messaging design, Phase 2). The GUI assigns and
    /// increments this per request on one connection; the Engine
    /// echoes it back in the tagged [`SessionLine`] it writes;
    /// see [`SessionLine`] doc.
    #[serde(default)]
    pub request_id: Option<u64>,
    /// Message text for `"send"` (Phase 3: delivered as one PQXDH
    /// session over the shared bootstrapped Tor transport).
    #[serde(default)]
    pub text: Option<String>,
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

/// One line the Engine writes to a connection's SESSION PHASE (TODO
/// B.3 GUI messaging design, Phase 2) — starting immediately after a
/// successful `"unlock"` on this connection, EVERY line the Engine
/// writes is one of these, discriminated by `kind`. A plain struct
/// (not a tagged enum), matching this module's existing
/// `Request`/`Response` convention and the wire format verbatim:
///
/// ```json
/// {"kind":"response","request_id":3,"ok":true,"payload":"..."}
/// {"kind":"event","event":"ready","address":"..."}
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionLine {
    /// `"response"` (answers one GUI-initiated request, by
    /// `request_id`) or `"event"` (unprompted).
    pub kind: String,
    /// Present when `kind == "response"`: echoes the request's own
    /// `request_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<u64>,
    /// Present when `kind == "event"`: which event. `"ready"` (the
    /// published onion address, Phase 2), `"inbound-text"` and
    /// `"session-error"` (Phase 4). Send outcomes are NOT events —
    /// they arrive as ordinary tagged `"response"` lines to the
    /// `"send"` request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    /// A `"response"` line's success flag (absent/irrelevant for
    /// `"event"` lines).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    /// A `"response"` line's error message, present when
    /// `ok == Some(false)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// `"list_peers"` response payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_names: Option<Vec<String>>,
    /// `"pair_payload"` response payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// `"pair_import"` response payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sas: Option<String>,
    /// The `"ready"` event's own onion address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The `"inbound-text"` event's payload: the decrypted message
    /// bytes, base64url-no-pad encoded (Phase 4). Sender attribution
    /// is NOT available at this layer (`receive_message` returns the
    /// plaintext only), so the event deliberately carries no `peer`
    /// field — the GUI renders these in a separate inbox, never
    /// misattributed to a selected conversation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

impl SessionLine {
    /// Wraps an existing (untagged) [`Response`] into a tagged
    /// `"response"` line, echoing `request_id`. Used to retrofit
    /// Phase 1's four ops (`list_peers`/`pair_payload`/`pair_import`/
    /// `pair_confirm`) into the session phase, and for `"send"`.
    #[must_use]
    pub fn from_response(request_id: Option<u64>, response: Response) -> Self {
        Self {
            kind: "response".to_string(),
            request_id,
            event: None,
            ok: Some(response.ok),
            error: response.error,
            peer_names: response.peer_names,
            payload: response.payload,
            sas: response.sas,
            address: None,
            data: None,
        }
    }

    /// Builds the `"ready"` event line.
    #[must_use]
    pub fn ready(address: String) -> Self {
        Self {
            kind: "event".to_string(),
            request_id: None,
            event: Some("ready".to_string()),
            ok: None,
            error: None,
            peer_names: None,
            payload: None,
            sas: None,
            address: Some(address),
            data: None,
        }
    }

    /// Builds an `"inbound-text"` event line (Phase 4): `data` is the
    /// decrypted plaintext, base64url-no-pad.
    #[must_use]
    pub fn inbound_text(data: String) -> Self {
        Self {
            kind: "event".to_string(),
            request_id: None,
            event: Some("inbound-text".to_string()),
            ok: None,
            error: None,
            peer_names: None,
            payload: None,
            sas: None,
            address: None,
            data: Some(data),
        }
    }

    /// Builds a `"session-error"` event line (Phase 4): bootstrap or
    /// inbound-loop failures, previously stderr-only.
    #[must_use]
    pub fn session_error(message: String) -> Self {
        Self {
            kind: "event".to_string(),
            request_id: None,
            event: Some("session-error".to_string()),
            ok: None,
            error: Some(message),
            peer_names: None,
            payload: None,
            sas: None,
            address: None,
            data: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Request, Response, SessionLine};

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

    #[test]
    fn request_id_and_text_round_trip_through_json()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let request = Request {
            op: "send".to_string(),
            request_id: Some(7),
            peer_name: Some("alice".to_string()),
            text: Some("hello".to_string()),
            ..Request::default()
        };
        let line = serde_json::to_string(&request)?;
        let decoded: Request = serde_json::from_str(&line)?;
        assert_eq!(decoded.request_id, Some(7));
        assert_eq!(decoded.text.as_deref(), Some("hello"));
        Ok(())
    }

    #[test]
    fn session_line_response_round_trips_and_matches_the_spec_shape()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let session_line =
            SessionLine::from_response(Some(3), Response::payload("own-payload".to_string()));
        let line = serde_json::to_string(&session_line)?;
        assert_eq!(
            line,
            r#"{"kind":"response","request_id":3,"ok":true,"payload":"own-payload"}"#
        );
        let decoded: SessionLine = serde_json::from_str(&line)?;
        assert_eq!(decoded.kind, "response");
        assert_eq!(decoded.request_id, Some(3));
        assert_eq!(decoded.ok, Some(true));
        assert_eq!(decoded.payload.as_deref(), Some("own-payload"));
        Ok(())
    }

    #[test]
    fn session_line_ready_event_round_trips_and_matches_the_spec_shape()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let session_line = SessionLine::ready("onion-address-placeholder".to_string());
        let line = serde_json::to_string(&session_line)?;
        assert_eq!(
            line,
            r#"{"kind":"event","event":"ready","address":"onion-address-placeholder"}"#
        );
        let decoded: SessionLine = serde_json::from_str(&line)?;
        assert_eq!(decoded.kind, "event");
        assert_eq!(decoded.event.as_deref(), Some("ready"));
        assert_eq!(
            decoded.address.as_deref(),
            Some("onion-address-placeholder")
        );
        assert_eq!(decoded.request_id, None);
        assert_eq!(decoded.ok, None);
        Ok(())
    }

    #[test]
    fn session_line_inbound_text_event_round_trips()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let session_line = SessionLine::inbound_text("aGVsbG8".to_string());
        let line = serde_json::to_string(&session_line)?;
        assert_eq!(
            line,
            r#"{"kind":"event","event":"inbound-text","data":"aGVsbG8"}"#
        );
        let decoded: SessionLine = serde_json::from_str(&line)?;
        assert_eq!(decoded.event.as_deref(), Some("inbound-text"));
        assert_eq!(decoded.data.as_deref(), Some("aGVsbG8"));
        assert_eq!(decoded.request_id, None);
        Ok(())
    }

    #[test]
    fn session_line_session_error_event_round_trips()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let session_line = SessionLine::session_error("bootstrap failed".to_string());
        let line = serde_json::to_string(&session_line)?;
        assert_eq!(
            line,
            r#"{"kind":"event","event":"session-error","error":"bootstrap failed"}"#
        );
        let decoded: SessionLine = serde_json::from_str(&line)?;
        assert_eq!(decoded.event.as_deref(), Some("session-error"));
        assert_eq!(decoded.error.as_deref(), Some("bootstrap failed"));
        Ok(())
    }
}
