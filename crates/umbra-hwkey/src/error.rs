//! Error type for `umbra-hwkey` (TODO B.3).

/// Errors this crate's PKCS#11 operations can produce.
#[derive(Debug, thiserror::Error)]
pub enum HwKeyError {
    /// The underlying PKCS#11 module reported an error (module load
    /// failure, login rejection, mechanism failure, etc.).
    #[error("PKCS#11 error: {0}")]
    Pkcs11(#[from] cryptoki::error::Error),
    /// No PKCS#11 token is present in any slot.
    #[error("no PKCS#11 token present in any slot")]
    NoTokenPresent,
    /// No key with the requested label exists on the token.
    #[error("no key labeled {0:?} found on the token")]
    KeyNotFound(String),
    /// The sign operation returned an unexpected-length output (this
    /// crate only ever requests `CKM_SHA256_HMAC`, which must return
    /// exactly 32 bytes — a mismatch means the token or mechanism
    /// behaved unexpectedly, not a bug in the challenge itself).
    #[error("HMAC-SHA256 sign returned {0} bytes, expected 32")]
    UnexpectedSignatureLength(usize),
}
