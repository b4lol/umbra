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

    /// An I/O failure on the underlying socket.
    #[error("transport I/O failure")]
    Io,
}
