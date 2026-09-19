//! `UmbraCoreController` trait (docs/SPECIFICATION.md §3, FFI Specification).
//!
//! Method signatures take `&self` so the trait stays object-safe for
//! UniFFI; the SPECIFICATION sketch omitted receivers for brevity.

use std::path::PathBuf;
use std::sync::Mutex;

use umbra_crypto::keys::IdentityBundle;

/// Public identity material exposed across the FFI boundary.
///
/// Only PUBLIC key bytes cross the bridge; private keys never leave the
/// Rust core (RAM-only doctrine).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IdentityKeys {
    /// X25519 identity public key.
    pub x25519_public: Vec<u8>,
    /// ML-KEM-768 encapsulation key.
    pub kem_public: Vec<u8>,
    /// ML-DSA-65 verification key.
    pub dsa_public: Vec<u8>,
}

/// FFI-layer error type.
#[derive(Debug, thiserror::Error)]
pub enum CoreControllerError {
    /// Crypto-layer failure.
    #[error(transparent)]
    Crypto(#[from] umbra_crypto::CryptoError),

    /// Feature structurally defined but not yet wired (TODO B.4).
    #[error("not yet implemented: {0}")]
    Unsupported(&'static str),

    /// Keystore/decoy-vault-layer failure during unlock.
    #[error("{0}")]
    Keystore(String),
}

/// UniFFI-exported error type (TODO B.4 Phase 1).
///
/// [`CoreControllerError`] cannot derive `uniffi::Error` directly: one
/// variant wraps a foreign crate's [`umbra_crypto::CryptoError`] (which
/// does not implement UniFFI's `Lower`/`Lift` traits) and another holds
/// a `&'static str` (UniFFI's proc-macros only support owned `String`
/// payloads). Rather than changing `CoreControllerError`'s shape for
/// every Rust-internal caller, this FFI-only wrapper flattens any
/// [`CoreControllerError`] to its rendered message string at the
/// boundary — the same approach `unlock_identity`'s own
/// `CoreControllerError::Keystore(String)` variant already uses.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiControllerError {
    /// Any [`CoreControllerError`], flattened to its `Display` message.
    #[error("{0}")]
    Failed(String),
}

impl From<CoreControllerError> for FfiControllerError {
    fn from(error: CoreControllerError) -> Self {
        Self::Failed(error.to_string())
    }
}

/// The controller interface consumed by the Android UI (docs/SPECIFICATION.md §3).
pub trait UmbraCoreController: Send + Sync {
    /// Generates a new ephemeral identity and a Tor v3 Onion endpoint.
    ///
    /// # Errors
    ///
    /// Identity-generation failures.
    fn initialize_identity(&self) -> Result<IdentityKeys, CoreControllerError>;

    /// Unlocks an existing identity from `keystore_path` with
    /// `passphrase`. Auto-detects a Decoy Vault file by its fixed
    /// size (matching the Linux GUI Engine's own `dispatch::unlock`
    /// pattern, `crates/umbra-engine/src/dispatch.rs`) — no separate
    /// "is this a decoy vault" flag needed from the caller.
    ///
    /// # Errors
    ///
    /// Wrong passphrase, missing/corrupt file, or any underlying
    /// keystore-layer failure.
    fn unlock_identity(
        &self,
        keystore_path: &str,
        passphrase: &str,
    ) -> Result<IdentityKeys, CoreControllerError>;

    /// Lists the current session's paired peer names, sorted.
    ///
    /// # Errors
    ///
    /// Returns an error if no identity is unlocked yet, or on any
    /// underlying I/O failure.
    fn list_peers(&self) -> Result<Vec<String>, CoreControllerError>;

    /// Returns this session's own base64url pairing payload, to hand
    /// to a peer out of band (QR display).
    ///
    /// # Errors
    ///
    /// Returns an error if no identity is unlocked yet.
    fn pairing_payload(&self) -> Result<String, CoreControllerError>;

    /// Validates a peer's pairing payload (QR scan result) and
    /// returns the shared 6-digit SAS code for out-of-band
    /// verification. Does NOT persist a peer record yet — see
    /// [`UmbraCoreController::confirm_peer`]. Deliberately split from
    /// a single-step connect (matches the Linux GUI's own
    /// `pair_import`/`pair_confirm` design,
    /// `crates/umbra-engine/src/dispatch.rs`): never persist a peer
    /// before the operator has confirmed the SAS code matches out of
    /// band.
    ///
    /// # Errors
    ///
    /// Returns an error on an invalid payload, or if no identity is
    /// unlocked yet.
    fn import_peer_payload(&self, peer_payload: &str) -> Result<String, CoreControllerError>;

    /// Persists a peer record under `peer_name`, once the operator
    /// has confirmed the SAS code from
    /// [`UmbraCoreController::import_peer_payload`] matches out of
    /// band. `peer_onion`, if given, is this peer's `.onion` service
    /// address (optional — a peer may be added payload-only and given
    /// an address later).
    ///
    /// # Errors
    ///
    /// Returns an error on an invalid name/payload/address, or if no
    /// identity is unlocked yet.
    fn confirm_peer(
        &self,
        peer_name: &str,
        peer_payload: &str,
        peer_onion: Option<String>,
    ) -> Result<(), CoreControllerError>;

    /// Generates the one-time pairing QR payload (out-of-band, CRYPTOGRAPHY
    /// §5).
    ///
    /// # Errors
    ///
    /// Pairing-payload failures.
    fn generate_pairing_payload(&self) -> Result<String, CoreControllerError>;

    /// Processes the peer's QR payload and initiates the secure handshake.
    ///
    /// # Errors
    ///
    /// Handshake or payload-validation failures.
    fn connect_peer(&self, peer_payload: &str) -> Result<(), CoreControllerError>;

    /// Sends an end-to-end encrypted, fixed-size packet message.
    ///
    /// # Errors
    ///
    /// Transport or sealing failures.
    fn send_message(&self, recipient_onion: &str, content: &str)
    -> Result<(), CoreControllerError>;

    /// Panic button: wipes all memory and terminates all sessions
    /// (`zeroize` + `Motion Wipe` entry points).
    fn trigger_panic_wipe(&self);
}

/// Skeleton controller returned until the engine wiring lands.
///
/// Every method returns [`CoreControllerError::Unsupported`] with the
/// relevant TODO reference; the type exists so the Android side can compile
/// against the interface from day one.
#[derive(Debug, Default)]
pub struct StubController;

impl UmbraCoreController for StubController {
    fn initialize_identity(&self) -> Result<IdentityKeys, CoreControllerError> {
        Err(CoreControllerError::Unsupported(
            "engine wiring lands with TODO A.4/B.4",
        ))
    }

    fn unlock_identity(
        &self,
        _keystore_path: &str,
        _passphrase: &str,
    ) -> Result<IdentityKeys, CoreControllerError> {
        Err(CoreControllerError::Unsupported(
            "engine wiring lands with TODO A.4/B.4",
        ))
    }

    fn list_peers(&self) -> Result<Vec<String>, CoreControllerError> {
        Err(CoreControllerError::Unsupported(
            "peers/pairing lands with TODO B.4 Phase 0",
        ))
    }

    fn pairing_payload(&self) -> Result<String, CoreControllerError> {
        Err(CoreControllerError::Unsupported(
            "peers/pairing lands with TODO B.4 Phase 0",
        ))
    }

    fn import_peer_payload(&self, _peer_payload: &str) -> Result<String, CoreControllerError> {
        Err(CoreControllerError::Unsupported(
            "peers/pairing lands with TODO B.4 Phase 0",
        ))
    }

    fn confirm_peer(
        &self,
        _peer_name: &str,
        _peer_payload: &str,
        _peer_onion: Option<String>,
    ) -> Result<(), CoreControllerError> {
        Err(CoreControllerError::Unsupported(
            "peers/pairing lands with TODO B.4 Phase 0",
        ))
    }

    fn generate_pairing_payload(&self) -> Result<String, CoreControllerError> {
        Err(CoreControllerError::Unsupported(
            "pairing lands with TODO A.3/B.4",
        ))
    }

    fn connect_peer(&self, _peer_payload: &str) -> Result<(), CoreControllerError> {
        Err(CoreControllerError::Unsupported(
            "pairing lands with TODO A.3/B.4",
        ))
    }

    fn send_message(
        &self,
        _recipient_onion: &str,
        _content: &str,
    ) -> Result<(), CoreControllerError> {
        Err(CoreControllerError::Unsupported(
            "transport wiring lands with TODO A.2/B.4",
        ))
    }

    fn trigger_panic_wipe(&self) {
        // No state exists in the stub; the real implementation zeroizes all
        // sessions and keys (ADR-009, Motion Wipe).
    }
}

/// Per-connection-equivalent session state (TODO B.4 Phase 0): the
/// unlocked identity and its derived peers directory, populated once
/// [`UmbraCoreController::unlock_identity`] succeeds. Held directly
/// in-process rather than behind a socket — Android has no `:engine`
/// process split for v1 (ANDROID.md §5: the OS's own per-app sandbox
/// already provides the isolation Linux's Landlock split exists to
/// add), so this is the direct, single-process analog of the Linux
/// Engine's own `Session` struct
/// (`crates/umbra-engine/src/dispatch.rs`).
#[derive(Default)]
struct Session {
    /// The unlocked identity bundle and its derived peers directory,
    /// `None` until a successful `unlock_identity` call.
    identity: Option<(IdentityBundle, PathBuf)>,
}

/// The real [`UmbraCoreController`] implementation (TODO B.4 Phase 0),
/// replacing [`StubController`] method by method as each operation's
/// Rust-side wiring lands. Methods not yet covered by this plan still
/// return [`CoreControllerError::Unsupported`], matching
/// `StubController`'s own messages — see each method below.
#[derive(Default, uniffi::Object)]
pub struct LiveController {
    /// The controller's single in-memory session, populated by
    /// `unlock_identity` and cleared by `trigger_panic_wipe`.
    session: Mutex<Session>,
}

impl LiveController {
    /// Builds a fresh, unlocked-nothing-yet controller.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// UniFFI-exported surface (TODO B.4 Phase 1): thin wrappers around the
/// [`UmbraCoreController`] trait methods above, under UniFFI-compatible
/// signatures (an owning `Arc<Self>` constructor, owned `String` args
/// instead of `&str`). The trait methods themselves are untouched;
/// these delegate to them.
#[uniffi::export]
impl LiveController {
    /// UniFFI constructor: builds a fresh, unlocked-nothing-yet controller.
    #[uniffi::constructor]
    #[must_use]
    pub fn new_ffi() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::default())
    }

    /// UniFFI-shaped wrapper around [`UmbraCoreController::unlock_identity`].
    ///
    /// # Errors
    ///
    /// See [`UmbraCoreController::unlock_identity`].
    #[uniffi::method(name = "unlockIdentity")]
    pub fn unlock_identity_ffi(
        &self,
        keystore_path: String,
        passphrase: String,
    ) -> Result<IdentityKeys, FfiControllerError> {
        UmbraCoreController::unlock_identity(self, &keystore_path, &passphrase)
            .map_err(FfiControllerError::from)
    }

    /// UniFFI-shaped wrapper around [`UmbraCoreController::list_peers`].
    ///
    /// # Errors
    ///
    /// See [`UmbraCoreController::list_peers`].
    #[uniffi::method(name = "listPeers")]
    pub fn list_peers_ffi(&self) -> Result<Vec<String>, FfiControllerError> {
        UmbraCoreController::list_peers(self).map_err(FfiControllerError::from)
    }

    /// UniFFI-shaped wrapper around [`UmbraCoreController::pairing_payload`].
    ///
    /// # Errors
    ///
    /// See [`UmbraCoreController::pairing_payload`].
    #[uniffi::method(name = "pairingPayload")]
    pub fn pairing_payload_ffi(&self) -> Result<String, FfiControllerError> {
        UmbraCoreController::pairing_payload(self).map_err(FfiControllerError::from)
    }

    /// UniFFI-shaped wrapper around
    /// [`UmbraCoreController::import_peer_payload`].
    ///
    /// # Errors
    ///
    /// See [`UmbraCoreController::import_peer_payload`].
    #[uniffi::method(name = "importPeerPayload")]
    pub fn import_peer_payload_ffi(
        &self,
        peer_payload: String,
    ) -> Result<String, FfiControllerError> {
        UmbraCoreController::import_peer_payload(self, &peer_payload)
            .map_err(FfiControllerError::from)
    }

    /// UniFFI-shaped wrapper around [`UmbraCoreController::confirm_peer`].
    ///
    /// # Errors
    ///
    /// See [`UmbraCoreController::confirm_peer`].
    #[uniffi::method(name = "confirmPeer")]
    pub fn confirm_peer_ffi(
        &self,
        peer_name: String,
        peer_payload: String,
        peer_onion: Option<String>,
    ) -> Result<(), FfiControllerError> {
        UmbraCoreController::confirm_peer(self, &peer_name, &peer_payload, peer_onion)
            .map_err(FfiControllerError::from)
    }

    /// UniFFI-shaped wrapper around
    /// [`UmbraCoreController::trigger_panic_wipe`].
    #[uniffi::method(name = "triggerPanicWipe")]
    pub fn trigger_panic_wipe_ffi(&self) {
        UmbraCoreController::trigger_panic_wipe(self);
    }
}

/// Projects an [`IdentityBundle`]'s PUBLIC material into the
/// FFI-safe [`IdentityKeys`] shape (never the private halves).
fn identity_keys_from_bundle(bundle: &IdentityBundle) -> IdentityKeys {
    IdentityKeys {
        x25519_public: bundle.x25519.public_bytes().to_vec(),
        kem_public: bundle.kem.public_bytes().to_vec(),
        dsa_public: bundle.dsa.public_bytes(),
    }
}

impl UmbraCoreController for LiveController {
    fn initialize_identity(&self) -> Result<IdentityKeys, CoreControllerError> {
        Err(CoreControllerError::Unsupported(
            "ephemeral identity generation lands with TODO A.4/B.4",
        ))
    }

    fn unlock_identity(
        &self,
        keystore_path: &str,
        passphrase: &str,
    ) -> Result<IdentityKeys, CoreControllerError> {
        let path = std::path::Path::new(keystore_path);
        let metadata = std::fs::metadata(path)
            .map_err(|error| CoreControllerError::Keystore(error.to_string()))?;
        let container_len =
            u64::try_from(umbra_crypto::decoy_vault::CONTAINER_LEN).unwrap_or(u64::MAX);
        let bundle = if metadata.len() == container_len {
            umbra_cli::decoy_vault::unlock(path, passphrase.as_bytes())
                .map_err(|error| CoreControllerError::Keystore(error.to_string()))?
        } else {
            umbra_cli::keystore::load(path, passphrase.as_bytes())
                .map_err(|error| CoreControllerError::Keystore(error.to_string()))?
        };
        let keys = identity_keys_from_bundle(&bundle);
        let peers_dir = path
            .parent()
            .map_or_else(|| PathBuf::from("peers"), |parent| parent.join("peers"));
        let mut session = self.session.lock().map_err(|_error| {
            CoreControllerError::Keystore("session state poisoned".to_string())
        })?;
        session.identity = Some((bundle, peers_dir));
        Ok(keys)
    }

    fn list_peers(&self) -> Result<Vec<String>, CoreControllerError> {
        let session = self.session.lock().map_err(|_error| {
            CoreControllerError::Keystore("session state poisoned".to_string())
        })?;
        let Some((_, peers_dir)) = session.identity.as_ref() else {
            return Err(CoreControllerError::Keystore(
                "not unlocked yet".to_string(),
            ));
        };
        umbra_cli::peers::list_names(peers_dir)
            .map_err(|error| CoreControllerError::Keystore(error.to_string()))
    }

    fn pairing_payload(&self) -> Result<String, CoreControllerError> {
        let session = self.session.lock().map_err(|_error| {
            CoreControllerError::Keystore("session state poisoned".to_string())
        })?;
        let Some((bundle, _)) = session.identity.as_ref() else {
            return Err(CoreControllerError::Keystore(
                "not unlocked yet".to_string(),
            ));
        };
        umbra_cli::pairing::payload_for(bundle)
            .map_err(|error| CoreControllerError::Keystore(error.to_string()))
    }

    fn import_peer_payload(&self, peer_payload: &str) -> Result<String, CoreControllerError> {
        let session = self.session.lock().map_err(|_error| {
            CoreControllerError::Keystore("session state poisoned".to_string())
        })?;
        let Some((bundle, _)) = session.identity.as_ref() else {
            return Err(CoreControllerError::Keystore(
                "not unlocked yet".to_string(),
            ));
        };
        umbra_cli::pairing::parse_payload(peer_payload)
            .map_err(|error| CoreControllerError::Keystore(error.to_string()))?;
        let own_payload = umbra_cli::pairing::payload_for(bundle)
            .map_err(|error| CoreControllerError::Keystore(error.to_string()))?;
        Ok(umbra_cli::pairing::pairing_sas(&own_payload, peer_payload).to_string())
    }

    fn confirm_peer(
        &self,
        peer_name: &str,
        peer_payload: &str,
        peer_onion: Option<String>,
    ) -> Result<(), CoreControllerError> {
        let session = self.session.lock().map_err(|_error| {
            CoreControllerError::Keystore("session state poisoned".to_string())
        })?;
        let Some((_, peers_dir)) = session.identity.as_ref() else {
            return Err(CoreControllerError::Keystore(
                "not unlocked yet".to_string(),
            ));
        };
        umbra_cli::peers::save_peer(
            peers_dir,
            peer_name,
            peer_payload,
            peer_onion.as_deref(),
            None,
            None,
        )
        .map_err(|error| CoreControllerError::Keystore(error.to_string()))
    }

    fn generate_pairing_payload(&self) -> Result<String, CoreControllerError> {
        Err(CoreControllerError::Unsupported(
            "use pairing_payload() (TODO B.4 Phase 0) instead — this older, \
             pre-peer-record method is out of this plan's scope",
        ))
    }

    fn connect_peer(&self, _peer_payload: &str) -> Result<(), CoreControllerError> {
        Err(CoreControllerError::Unsupported(
            "use import_peer_payload()/confirm_peer() (TODO B.4 Phase 0) \
             instead — this older, pre-peer-record method is out of this \
             plan's scope",
        ))
    }

    fn send_message(
        &self,
        _recipient_onion: &str,
        _content: &str,
    ) -> Result<(), CoreControllerError> {
        Err(CoreControllerError::Unsupported(
            "transport wiring lands with a later TODO B.4 phase",
        ))
    }

    fn trigger_panic_wipe(&self) {
        // Dropping the session's identity is this controller's own
        // zeroize trigger: `IdentityBundle` zeroizes its private
        // material on drop (existing, unchanged crate behavior).
        if let Ok(mut session) = self.session.lock() {
            session.identity = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbra_crypto::keys::IdentityBundle;

    fn temp_keystore_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "umbra-ffi-controller-test-{}-{label}.enc",
            std::process::id()
        ))
    }

    #[test]
    fn unlock_identity_with_correct_passphrase_returns_public_keys()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = temp_keystore_path("correct");
        let bundle = IdentityBundle::generate();
        umbra_cli::keystore::save(&path, b"correct-passphrase", &bundle)?;

        let controller = LiveController::new();
        let result = controller.unlock_identity(
            path.to_str().ok_or("non-UTF8 test path")?,
            "correct-passphrase",
        );
        std::fs::remove_file(&path)?;

        let keys = result.map_err(|error| format!("expected Ok, got Err: {error}"))?;
        assert_eq!(keys.x25519_public, bundle.x25519.public_bytes());
        assert_eq!(keys.kem_public, bundle.kem.public_bytes());
        assert_eq!(keys.dsa_public, bundle.dsa.public_bytes());
        Ok(())
    }

    #[test]
    fn unlock_identity_with_wrong_passphrase_fails()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = temp_keystore_path("wrong");
        let bundle = IdentityBundle::generate();
        umbra_cli::keystore::save(&path, b"correct-passphrase", &bundle)?;

        let controller = LiveController::new();
        let result = controller.unlock_identity(
            path.to_str().ok_or("non-UTF8 test path")?,
            "wrong-passphrase",
        );
        std::fs::remove_file(&path)?;

        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn unlock_identity_with_decoy_vault_hidden_passphrase_returns_public_keys()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = temp_keystore_path("decoy-hidden");
        let _ = std::fs::remove_file(&path);
        let outer_bundle = IdentityBundle::generate();
        let hidden_bundle = IdentityBundle::generate();
        umbra_cli::decoy_vault::create(&path, b"outer-pw", &outer_bundle)?;
        umbra_cli::decoy_vault::write_hidden(&path, b"hidden-pw", &hidden_bundle)?;

        let controller = LiveController::new();
        let result =
            controller.unlock_identity(path.to_str().ok_or("non-UTF8 test path")?, "hidden-pw");
        std::fs::remove_file(&path)?;

        let keys = result.map_err(|error| format!("expected Ok, got Err: {error}"))?;
        assert_eq!(keys.x25519_public, hidden_bundle.x25519.public_bytes());
        Ok(())
    }

    #[test]
    fn trigger_panic_wipe_clears_the_session()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = temp_keystore_path("panic-wipe");
        let bundle = IdentityBundle::generate();
        umbra_cli::keystore::save(&path, b"pw", &bundle)?;

        let controller = LiveController::new();
        controller
            .unlock_identity(path.to_str().ok_or("non-UTF8 test path")?, "pw")
            .map_err(|error| format!("expected Ok, got Err: {error}"))?;
        std::fs::remove_file(&path)?;

        controller.trigger_panic_wipe();
        let session = controller
            .session
            .lock()
            .map_err(|_error| "session lock poisoned")?;
        assert!(session.identity.is_none());
        Ok(())
    }

    #[test]
    fn peers_and_pairing_before_unlock_all_fail()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let controller = LiveController::new();
        assert!(controller.list_peers().is_err());
        assert!(controller.pairing_payload().is_err());
        assert!(controller.import_peer_payload("irrelevant").is_err());
        assert!(
            controller
                .confirm_peer("alice", "irrelevant", None)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn pairing_payload_after_unlock_matches_payload_for()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = temp_keystore_path("pairing-payload");
        let bundle = IdentityBundle::generate();
        umbra_cli::keystore::save(&path, b"pw", &bundle)?;

        let controller = LiveController::new();
        controller
            .unlock_identity(path.to_str().ok_or("non-UTF8 test path")?, "pw")
            .map_err(|error| format!("expected Ok, got Err: {error}"))?;
        let payload = controller
            .pairing_payload()
            .map_err(|error| format!("expected Ok, got Err: {error}"))?;
        std::fs::remove_file(&path)?;

        let expected = umbra_cli::pairing::payload_for(&bundle)?;
        assert_eq!(payload, expected);
        Ok(())
    }

    #[test]
    fn import_peer_payload_does_not_persist_a_peer_record()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = temp_keystore_path("import-no-persist");
        let bundle = IdentityBundle::generate();
        umbra_cli::keystore::save(&path, b"pw", &bundle)?;
        let peer_bundle = IdentityBundle::generate();
        let peer_payload = umbra_cli::pairing::payload_for(&peer_bundle)?;

        let controller = LiveController::new();
        controller
            .unlock_identity(path.to_str().ok_or("non-UTF8 test path")?, "pw")
            .map_err(|error| format!("expected Ok, got Err: {error}"))?;
        let sas = controller
            .import_peer_payload(&peer_payload)
            .map_err(|error| format!("expected Ok, got Err: {error}"))?;
        let peers_dir = path.parent().ok_or("no parent")?.join("peers");
        let no_peers_saved = umbra_cli::peers::list_names(&peers_dir)?.is_empty();
        std::fs::remove_file(&path)?;
        let _ = std::fs::remove_dir_all(&peers_dir);

        assert_eq!(sas.len(), 6);
        assert!(
            no_peers_saved,
            "import_peer_payload must not persist a peer record"
        );
        Ok(())
    }

    #[test]
    fn confirm_peer_then_list_peers_shows_the_saved_peer()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = temp_keystore_path("confirm-then-list");
        let bundle = IdentityBundle::generate();
        umbra_cli::keystore::save(&path, b"pw", &bundle)?;
        let peer_bundle = IdentityBundle::generate();
        let peer_payload = umbra_cli::pairing::payload_for(&peer_bundle)?;
        let peers_dir = path.parent().ok_or("no parent")?.join("peers");

        let controller = LiveController::new();
        controller
            .unlock_identity(path.to_str().ok_or("non-UTF8 test path")?, "pw")
            .map_err(|error| format!("expected Ok, got Err: {error}"))?;
        controller
            .confirm_peer("alice", &peer_payload, None)
            .map_err(|error| format!("expected Ok, got Err: {error}"))?;
        let names = controller
            .list_peers()
            .map_err(|error| format!("expected Ok, got Err: {error}"))?;
        std::fs::remove_file(&path)?;
        let _ = std::fs::remove_dir_all(&peers_dir);

        assert_eq!(names, vec!["alice".to_string()]);
        Ok(())
    }
}
