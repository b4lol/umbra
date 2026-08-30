//! # Umbra Cryptography Core
//!
//! Post-quantum hybrid cryptography for the Umbra protocol. Implements the
//! primitives table of `CRYPTOGRAPHY.md` §1 with pure-Rust RustCrypto crates
//! only (ADR-026):
//!
//! - **PQXDH** hybrid handshake: X25519 (DH1..DH3) + ML-KEM-768, combined
//!   through HKDF-SHA512 ([`pqxdh`]).
//! - **Double Ratchet** session ratchet with ChaCha20-Poly1305 ([`ratchet`]).
//! - **AEAD** wrapper with constant-time authenticated encryption ([`aead`]).
//! - **ML-DSA-65** signatures for identity attestation ([`signing`]).
//!
//! Doctrine (CODE_MANIFESTO): zero panic, zero assumptions, constant-time
//! comparisons via `subtle`, and `zeroize` on all key material.

#![forbid(unsafe_code)]

pub mod aead;
pub mod error;
pub mod kdf;
pub mod keys;
pub mod pqxdh;
pub mod ratchet;
pub mod rng;
pub mod signing;

pub use error::CryptoError;
pub use kdf::RootKey;
pub use pqxdh::InitialHandshake;

/// Prelude re-exporting the most-used types for downstream crates.
pub mod prelude {
    pub use crate::aead::AeadCipher;
    pub use crate::error::CryptoError;
    pub use crate::kdf::RootKey;
    pub use crate::keys::{IdentityBundle, MlKemKeyPair, X25519KeyPair, X25519PublicKey};
    pub use crate::pqxdh::{InitialHandshake, initiator_start, responder_respond};
    pub use crate::ratchet::{DoubleRatchet, RatchetMessage};
    pub use crate::signing::MlDsaKeyPair;
}
