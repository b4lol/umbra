//! Semantic newtypes (ADR-021: primitive integers are forbidden in protocol
//! logic; "Make Illegal States Unrepresentable").

/// Monotonic message sequence number within one ratchet chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SequenceNumber(u64);

impl SequenceNumber {
    /// The initial sequence number.
    pub const INITIAL: Self = Self(0);

    /// Wraps a raw counter value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Raw value for wire encoding.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns the successor, or `None` on `u64` overflow (checked
    /// arithmetic per CODE_MANIFESTO §3).
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }
}

/// Epoch identifier for a ratchet chain generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct EpochId(u32);

impl EpochId {
    /// The initial epoch.
    pub const INITIAL: Self = Self(0);

    /// Wraps a raw value.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Raw value for wire encoding.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns the successor, or `None` on `u32` overflow.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }
}
