//! # Umbra Wire Protocol
//!
//! Protocol and metadata-masking layer (`umbra-protocol`, TODO.md A.3):
//!
//! - **Fixed 1024-byte packet framing** with cryptographic random padding
//!   ([`packet`], SPECIFICATION.md §1).
//! - **Deterministic media metadata sterilizer** — full pixel re-encode
//!   ([`media`], TODO A.3) and **MEDIA_CHUNK transfer framing**
//!   ([`media_chunk`], SPECIFICATION.md opcode `0x06`).
//! - **Typestate sessions** making illegal states unrepresentable
//!   ([`session`], CODE_MANIFESTO / ADR-021).
//! - **Poisson-distributed cover traffic** scheduling ([`cover`], ADR-005).
//! - **SAS** short authentication strings ([`sas`], CRYPTOGRAPHY.md §5).

#![forbid(unsafe_code)]

pub mod cover;
pub mod error;
pub mod media;
pub mod media_chunk;
pub mod newtypes;
pub mod packet;
pub mod sas;
pub mod session;
pub mod smp;
pub mod types;

pub use error::ProtocolError;
pub use media::{MAX_DIMENSION_PX, sterilize};
pub use packet::{SealedPacket, UnsealedPacket};
pub use types::PacketType;

/// Prelude re-exporting the most-used protocol types.
pub mod prelude {
    pub use crate::newtypes::{EpochId, SequenceNumber};
    pub use crate::packet::{SealedPacket, UnsealedPacket, seal, unseal};
    pub use crate::session::{EstablishedSession, HandshakeInProgress, Session, Unauthenticated};
    pub use crate::types::{PACKET_LEN, PAYLOAD_MAX, PacketType};
}
