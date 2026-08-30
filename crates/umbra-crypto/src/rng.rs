//! Randomness plumbing for Umbra.
//!
//! Two layers:
//!
//! 1. **Fallible** [`fill`]: used on data paths (nonces, padding). Errors are
//!    surfaced as [`CryptoError::RngFailure`]; the caller decides.
//! 2. **Infallible adapter** [`system_rng`]: third-party RustCrypto APIs
//!    (`Kem::generate_keypair_from_rng`, `Encapsulate`, `Generate`) demand an
//!    infallible [`rand_core::CryptoRng`]. We bridge OS entropy through
//!    `rand_core::UnwrapErr`, which panics if the OS entropy source fails.
//!
//! # Panic boundary (documented exception to the Zero Panic Doctrine)
//!
//! A failed `getrandom(2)` at key-generation time is an unrecoverable boot
//! condition: silently continuing with deterministic bytes would be far more
//! dangerous. This is the same trade-off RustCrypto itself makes
//! (`kem::Kem::generate_keypair` wraps `UnwrapErr(SysRng)`). The panic boundary
//! is confined to key-generation call sites; every per-message path stays
//! fallible.

use crate::error::CryptoError;

/// Fills `dest` with cryptographically secure random bytes from the OS.
///
/// # Errors
///
/// Returns [`CryptoError::RngFailure`] if the OS entropy source fails.
pub fn fill(dest: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(dest).map_err(|_e| CryptoError::RngFailure)
}

/// Infallible system RNG adapter for RustCrypto APIs that require
/// [`rand_core::CryptoRng`].
///
/// See the module-level documentation for the documented panic boundary.
pub type SystemRng = rand_core::UnwrapErr<getrandom::SysRng>;

/// Creates the process-wide system RNG adapter.
///
/// See the module-level documentation for the documented panic boundary.
#[must_use]
pub fn system_rng() -> SystemRng {
    rand_core::UnwrapErr(getrandom::SysRng)
}
