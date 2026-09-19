//! `UmbraCoreController` trait (docs/SPECIFICATION.md §3, FFI Specification).
//!
//! Method signatures take `&self` so the trait stays object-safe for
//! UniFFI; the SPECIFICATION sketch omitted receivers for brevity.

use std::path::PathBuf;
use std::sync::Mutex;

use umbra_crypto::keys::{IdentityBundle, KEM_PK_LEN, X25519_PK_LEN};

/// Public identity material exposed across the FFI boundary.
///
/// Only PUBLIC key bytes cross the bridge; private keys never leave the
/// Rust core (RAM-only doctrine).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityKeys {
    /// X25519 identity public key.
    pub x25519_public: [u8; X25519_PK_LEN],
    /// ML-KEM-768 encapsulation key.
    pub kem_public: [u8; KEM_PK_LEN],
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
#[derive(Default)]
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

/// Projects an [`IdentityBundle`]'s PUBLIC material into the
/// FFI-safe [`IdentityKeys`] shape (never the private halves).
fn identity_keys_from_bundle(bundle: &IdentityBundle) -> IdentityKeys {
    IdentityKeys {
        x25519_public: bundle.x25519.public_bytes(),
        kem_public: bundle.kem.public_bytes(),
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
        let mut session = self
            .session
            .lock()
            .map_err(|_error| CoreControllerError::Unsupported("session state poisoned"))?;
        session.identity = Some((bundle, peers_dir));
        Ok(keys)
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
        let result = controller.unlock_identity(
            path.to_str().ok_or("non-UTF8 test path")?,
            "hidden-pw",
        );
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
}
