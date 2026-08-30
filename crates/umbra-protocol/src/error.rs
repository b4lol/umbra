//! Unified error type for the wire-protocol layer.

use thiserror::Error;

/// Errors produced by the Umbra protocol layer.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Cryptography-layer failure propagated upward.
    #[error(transparent)]
    Crypto(#[from] umbra_crypto::CryptoError),

    /// The packet did not start with the Umbra magic bytes.
    #[error("bad magic header")]
    BadMagic,

    /// The packet carried an unsupported protocol version.
    #[error("unsupported protocol version: {0}")]
    BadVersion(u8),

    /// The packet type byte did not map to a known opcode.
    #[error("unknown packet opcode: {0}")]
    UnknownOpcode(u8),

    /// A fixed-size field had the wrong length.
    #[error("invalid length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Required length.
        expected: usize,
        /// Provided length.
        actual: usize,
    },

    /// The payload exceeded [`crate::types::PAYLOAD_MAX`].
    #[error("payload too large: {actual} > {max}")]
    PayloadTooLarge {
        /// Maximum allowed payload size.
        max: usize,
        /// Attempted payload size.
        actual: usize,
    },

    /// Media input could not be decoded or re-encoded.
    #[error("unsupported or corrupt media input")]
    InvalidMedia,

    /// Media input or decoded dimensions exceed the sterilizer limits
    /// ([`crate::media::MAX_DIMENSION_PX`] and friends).
    #[error("media exceeds sterilizer limits")]
    MediaTooLarge,

    /// A session transition violated the state machine.
    #[error("invalid session state transition")]
    StateViolation,

    /// A feature is structurally defined but not yet wired.
    #[error("not yet implemented: {0}")]
    Unsupported(&'static str),
}
