//! # Umbra Hardware Security Bridge
//!
//! The sole crate permitted to use `unsafe` (CONTRIBUTING §2, ADR-012):
//! direct physical-hardware and OS-kernel communication only — `mlock` page
//! locking, guard pages, TPM/Secure Enclave, FIDO2/YubiKey raw drivers,
//! hardware TRNG.
//!
//! Rules for every `unsafe` item (ADR-012):
//!
//! 1. Encapsulated behind a 100% Safe public API.
//! 2. `// SAFETY:` justification documenting the invariants
//!    (`-D clippy::undocumented_unsafe_blocks`).
//! 3. Scanned with `cargo-geiger` / `cargo-deny` in CI.
//!
//! Modules:
//!
//! - [`memory`]: guard-page-protected, RAM-locked key storage.
//! - [`process`]: `mlockall` + core-dump suppression.
//! - [`token`]: external FIDO2/YubiKey driver surface.

pub mod memory;
pub mod process;
pub mod token;

pub use memory::GuardedBuffer;
pub use token::{HardwareError, HardwareSecurityKey};
