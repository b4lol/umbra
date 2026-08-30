//! Unified error type for the cryptography core.
//!
//! Every fallible operation returns `Result<_, CryptoError>`; panics are
//! forbidden by the CODE_MANIFESTO (§1, Zero Panic Doctrine).

use thiserror::Error;

/// Errors produced by the Umbra cryptography core.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// AEAD authentication failed: the ciphertext, tag, or AAD did not verify.
    #[error("AEAD authentication failed")]
    DecryptFailed,

    /// AEAD seal failed (for example, a payload exceeds an AEAD limit).
    #[error("AEAD encryption failed")]
    EncryptFailed,

    /// A fixed-size input had the wrong length.
    #[error("invalid input length: expected {expected}, got {actual}")]
    InvalidLength {
        /// The exact length the operation required.
        expected: usize,
        /// The length that was actually provided.
        actual: usize,
    },

    /// A key failed structural validation (for example, a low-order point or
    /// a malformed KEM key).
    #[error("key rejected: malformed or non-contributory")]
    InvalidKey,

    /// A handshake step failed (bad participant keys or non-contributory DH).
    #[error("handshake aborted")]
    HandshakeFailed,

    /// The OS entropy source returned an error.
    #[error("OS entropy source failure")]
    RngFailure,

    /// A signature did not verify.
    #[error("signature verification failed")]
    InvalidSignature,

    /// A feature is structurally defined but not yet wired (integration
    /// points are documented per TODO.md Section A/B).
    #[error("not yet implemented: {0}")]
    Unsupported(&'static str),
}
