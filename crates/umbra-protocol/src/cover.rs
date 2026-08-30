//! Poisson-distributed cover-traffic scheduling (README "Traffic-Analysis
//! Protection", ADR-005).
//!
//! Inter-packet delays follow an exponential distribution (the continuous
//! inter-arrival view of a Poisson process):
//! `delay = -ln(1 - u) / lambda` for `u` uniform in `[0, 1)`.
//!
//! Float arithmetic here is annotated explicitly: `rate_hz` is validated
//! non-zero and finite at construction, so division cannot produce
//! surprising overflow paths, and the result is re-validated as finite.

use core::time::Duration;

use umbra_crypto::rng;

use crate::error::ProtocolError;

/// Default lower bound applied to sampled delays, in seconds.
pub const MIN_DELAY_SECS: f64 = 0.001;

/// Schedules exponentially distributed inter-packet delays.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PoissonScheduler {
    /// Mean packet rate in packets per second (validated non-zero, finite).
    rate_hz: f64,
}

impl PoissonScheduler {
    /// Creates a scheduler for a mean rate of `rate_hz` packets/second.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidLength`] (misuse of the length
    /// variant would be wrong, so this returns a dedicated message via
    /// [`ProtocolError::Unsupported`]) if the rate is non-finite or not
    /// strictly positive.
    pub fn new(rate_hz: f64) -> Result<Self, ProtocolError> {
        if !rate_hz.is_finite() || rate_hz <= 0.0 {
            return Err(ProtocolError::Unsupported(
                "PoissonScheduler rate must be finite and > 0",
            ));
        }
        Ok(Self { rate_hz })
    }

    /// Mean packet rate in packets per second.
    #[must_use]
    pub const fn rate_hz(&self) -> f64 {
        self.rate_hz
    }

    /// Draws a uniform sample from OS entropy in `[0, 1)`.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Crypto`] on entropy failure.
    pub fn sample_uniform() -> Result<f64, ProtocolError> {
        let mut bytes = [0u8; 8];
        rng::fill(&mut bytes).map_err(crate::error::ProtocolError::from)?;
        let raw = u64::from_be_bytes(bytes);
        // Take the top 53 bits so the value lands in [0, 1) as an f64.
        // The multiplier is the exact bit pattern of 2^-53 and the operand
        // is bounded by 2^53, so the product cannot overflow.
        let shifted = raw >> 11;
        #[allow(clippy::arithmetic_side_effects)]
        let unit = (shifted as f64) * f64::from_bits(0x3CA0_0000_0000_0000); // 2^-53
        Ok(unit)
    }

    /// Samples the next inter-packet delay.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Crypto`] on entropy failure and
    /// [`ProtocolError::Unsupported`] if the sample degenerates.
    pub fn next_delay(&self) -> Result<Duration, ProtocolError> {
        let uniform = Self::sample_uniform()?;
        let complement = 1.0 - uniform;
        if complement <= 0.0 {
            return Err(ProtocolError::Unsupported("degenerate uniform sample"));
        }
        #[allow(clippy::arithmetic_side_effects)]
        let secs = complement.ln() / -self.rate_hz;
        let secs = secs.max(MIN_DELAY_SECS);
        if !secs.is_finite() {
            return Err(ProtocolError::Unsupported("non-finite delay"));
        }
        Ok(Duration::from_secs_f64(secs))
    }
}
