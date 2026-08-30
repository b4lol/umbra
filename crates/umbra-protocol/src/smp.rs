//! Socialist Millionaire Protocol integration point (CRYPTOGRAPHY.md §5,
//! TODO A.3).
//!
//! SMP proves, in zero knowledge, that both parties share the same secret
//! password without revealing it. The full OTR-style SMP state machine is
//! **deliberately not hand-rolled here**: inventing zero-knowledge proofs
//! violates the CODE_MANIFESTO's "no invented crypto" discipline. This
//! module pins the integration surface so the verified implementation can
//! be dropped in behind the same API.

use crate::error::ProtocolError;
use crate::sas::SasCode;

/// Progressive steps of the OTR SMP exchange (v3, five-message variant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmpStep {
    /// Step 1: commitment to the secret and a random exponent.
    Commitment,
    /// Step 2: the responder's challenge values.
    Challenge,
    /// Step 3: the initiator's proof values.
    Proof,
    /// Step 4: the responder's final verification values.
    Verification,
    /// Step 5: mutual acceptance signal.
    Acceptance,
}

/// Runs one SMP step.
///
/// # Errors
///
/// Always returns [`ProtocolError::Unsupported`]: the verified SMP state
/// machine lands with TODO A.3. Until then, use
/// [`crate::sas::SasCode`] over an out-of-band channel.
pub fn run_step(_step: SmpStep) -> Result<SasCode, ProtocolError> {
    Err(ProtocolError::Unsupported(
        "OTR-SMP state machine lands with TODO A.3; use SAS out-of-band pairing meanwhile",
    ))
}
