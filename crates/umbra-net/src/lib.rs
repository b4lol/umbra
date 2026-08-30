//! # Umbra Network & Transport
//!
//! Dynamic network and transport router (ARCHITECTURE.md "Network Router"):
//!
//! - [`OnionAddr`]: validated Tor v3 onion service addresses.
//! - [`Transport`]: async transport abstraction with a hermetic
//!   [`LoopbackTransport`] for deterministic tests (CONTRIBUTING §"Hermetic
//!   and Deterministic Tests").
//! - [`cover`]: Poisson cover-traffic pump (TODO A.3, ADR-005).
//! - `feature = "tor"`: embedded Arti Tor v3 transport (TODO A.2).
//!
//! Pluggable Transports (Obfs4/Snowflake), the Nym mixnet adapter, and the
//! BLE/Wi-Fi Direct Off-Grid Mesh are v2+ scope (ADR-027).

#![forbid(unsafe_code)]

pub mod addr;
pub mod cover;
pub mod error;
pub mod transport;

#[cfg(feature = "tor")]
pub mod tor;

pub use addr::OnionAddr;
pub use cover::CoverPump;
pub use error::TransportError;
pub use transport::{LoopbackPair, LoopbackTransport, Transport};

/// Prelude re-exporting the most-used transport types.
pub mod prelude {
    pub use crate::addr::OnionAddr;
    pub use crate::error::TransportError;
    pub use crate::transport::{LoopbackPair, Transport};
}
