//! Safe driver surface for hardware security keys (HARDWARE_SECURITY.md §6,
//! ADR-009: FIDO2 / YubiKey CC EAL6+ dual-hardware token binding).

use thiserror::Error;

/// Hardware-bridge error type.
#[derive(Debug, Error)]
pub enum HardwareError {
    /// The key is absent, locked, or rejected the challenge.
    #[error("hardware key rejected the operation")]
    KeyRejected,

    /// Transport failure (USB/NFC).
    #[error("hardware transport failure")]
    Transport,

    /// A syscall backing the safe API failed.
    #[error("syscall {name} failed: {source}")]
    Syscall {
        /// Name of the failing syscall (diagnostics only).
        name: &'static str,
        /// Kernel-reported error.
        source: std::io::Error,
    },

    /// The requested guarded-memory layout is impossible on this platform
    /// (for example, an alignment larger than the page size).
    #[error("invalid guarded-memory layout")]
    InvalidLayout,

    /// Raw-driver feature not yet wired (TODO B.5/B.7).
    #[error("not yet implemented: {0}")]
    Unsupported(&'static str),
}

/// Safe operations on an external hardware security key.
///
/// Dual-Hardware Token Binding (ADR-009): session unlock and key derivation
/// additionally require this physical token; without it, keys can never be
/// loaded into memory.
pub trait HardwareSecurityKey: Send + Sync {
    /// Returns the key's attestation certificate bytes (CC EAL6+ identity).
    ///
    /// # Errors
    ///
    /// See [`HardwareError`].
    fn attest(&self) -> Result<Vec<u8>, HardwareError>;

    /// Verifies user presence (touch / NFC tap).
    ///
    /// # Errors
    ///
    /// See [`HardwareError`].
    fn verify_presence(&self) -> Result<(), HardwareError>;
}
