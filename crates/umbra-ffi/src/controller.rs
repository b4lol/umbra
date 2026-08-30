//! `UmbraCoreController` trait (SPECIFICATION.md §3, FFI Specification).
//!
//! Method signatures take `&self` so the trait stays object-safe for
//! UniFFI; the SPECIFICATION sketch omitted receivers for brevity.

use umbra_crypto::keys::{KEM_PK_LEN, X25519_PK_LEN};

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
}

/// The controller interface consumed by the Android UI (SPECIFICATION.md §3).
pub trait UmbraCoreController: Send + Sync {
    /// Generates a new ephemeral identity and a Tor v3 Onion endpoint.
    ///
    /// # Errors
    ///
    /// Identity-generation failures.
    fn initialize_identity(&self) -> Result<IdentityKeys, CoreControllerError>;

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
