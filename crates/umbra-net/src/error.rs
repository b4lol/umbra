//! Unified error type for the transport layer.

use thiserror::Error;

/// Errors produced by the transport layer.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The peer address failed validation.
    #[error("invalid peer address")]
    InvalidPeer,

    /// The backing channel or socket closed unexpectedly.
    #[error("transport channel closed")]
    ChannelClosed,

    /// Cryptography-layer failure propagated upward.
    #[error(transparent)]
    Protocol(#[from] umbra_protocol::ProtocolError),

    /// A transport feature is structurally defined but not yet wired.
    #[error("not yet implemented: {0}")]
    Unsupported(&'static str),

    /// An operation exceeded its bounded duration (for example, the Tor
    /// bootstrap on a censored network).
    #[error("operation timed out: {operation}")]
    Timeout {
        /// Human-readable operation name.
        operation: &'static str,
    },

    /// The ephemeral storage layout could not be derived.
    #[error("could not derive an ephemeral directory")]
    EphemeralDir,

    /// The transport configuration could not be built (paths, defaults).
    #[error("transport configuration failure: {details}")]
    Config {
        /// Display of the underlying configuration error.
        details: String,
    },

    /// An I/O failure on the underlying socket.
    #[error("transport I/O failure: {0}")]
    Io(std::io::Error),

    /// Arti (Tor) failure. Present only with the `tor` feature.
    #[cfg(feature = "tor")]
    #[error(transparent)]
    Tor(#[from] arti_client::Error),
}
