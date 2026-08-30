//! SAS (Short Authentication String) derivation (CRYPTOGRAPHY.md §5).
//!
//! Out-of-band verification against MITM: both parties derive the same
//! 6-digit code from the shared secret and compare it visually or over a
//! trusted channel. Equality checks are constant-time (`subtle`).

use core::fmt;

use subtle::ConstantTimeEq;

use umbra_crypto::kdf;

/// Context string for the SAS key derivation.
const SAS_CONTEXT: &str = "Umbra SAS v1";

/// Domain-separation label hashed under the derived key.
const SAS_LABEL: &[u8] = b"umbra-sas-code";

/// A 6-digit numeric short authentication string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SasCode {
    /// Big-endian bytes of the numeric code (constant-time comparable).
    digits: [u8; 4],
}

impl SasCode {
    /// Derives the SAS code from a 32-byte shared secret.
    #[must_use]
    pub fn derive(shared_secret: &[u8; 32]) -> Self {
        let key = kdf::derive_key(SAS_CONTEXT, shared_secret);
        let digest = kdf::keyed_digest(&key, SAS_LABEL);
        let raw = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        #[allow(clippy::arithmetic_side_effects)]
        let code = raw % 1_000_000;
        Self {
            digits: code.to_be_bytes(),
        }
    }

    /// Numeric value in `0..1_000_000`.
    #[must_use]
    pub fn value(&self) -> u32 {
        u32::from_be_bytes(self.digits)
    }

    /// Constant-time equality against a peer's code.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        bool::from(self.digits.ct_eq(&other.digits))
    }
}

impl fmt::Display for SasCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:06}", self.value())
    }
}
