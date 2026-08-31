//! 60-second self-destructing clipboard manager (TODO A.4, ADR-018).
//!
//! Copies live in a `Zeroizing` RAM buffer plus a pluggable system
//! backend; [`ClipboardManager::tick`] wipes both after the TTL. The
//! system clipboard backend for Wayland (`wl-data-control`) is v2 scope —
//! the manager logic, TTL, and wipe semantics are implemented and tested
//! here against a memory backend.

use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

/// Clipboard content time-to-live (ADR-018: 60-second async countdown).
pub const CLIPBOARD_TTL: Duration = Duration::from_secs(60);

/// System clipboard sink/source. Implemented by real backends (Wayland
/// data-control, X11) and by the test memory backend.
pub trait ClipboardBackend: Send {
    /// Publishes data to the system clipboard.
    fn write(&mut self, data: &[u8]);

    /// Clears the system clipboard (overwrite with a zero-length value).
    fn clear(&mut self);
}

/// In-memory backend for tests and offline use.
#[derive(Debug, Default)]
pub struct MemoryBackend {
    /// Current clipboard content (zeroized on clear/drop).
    data: Zeroizing<Vec<u8>>,
}

impl ClipboardBackend for MemoryBackend {
    fn write(&mut self, data: &[u8]) {
        // Zeroize the previous content before overwriting.
        self.data.zeroize();
        self.data = Zeroizing::new(data.to_vec());
    }

    fn clear(&mut self) {
        self.data.zeroize();
        self.data = Zeroizing::new(Vec::new());
    }
}

impl MemoryBackend {
    /// Read accessor for tests.
    #[must_use]
    pub fn peek(&self) -> &[u8] {
        &self.data
    }
}

/// A clipboard entry with a 60-second self-destruct countdown.
pub struct ClipboardManager {
    /// System backend.
    backend: Box<dyn ClipboardBackend + Send>,
    /// RAM copy of the copied bytes (zeroized on wipe/drop).
    stored: Option<Zeroizing<Vec<u8>>>,
    /// When the entry self-destructs.
    deadline: Instant,
    /// Configurable TTL (60s in production; shorter in tests).
    ttl: Duration,
}

impl ClipboardManager {
    /// Creates a manager with the production 60-second TTL.
    #[must_use]
    pub fn new(backend: Box<dyn ClipboardBackend + Send>) -> Self {
        Self::with_ttl(backend, CLIPBOARD_TTL)
    }

    /// Creates a manager with a custom TTL (tests use short values).
    #[must_use]
    pub fn with_ttl(backend: Box<dyn ClipboardBackend + Send>, ttl: Duration) -> Self {
        Self {
            backend,
            stored: None,
            deadline: Instant::now(),
            ttl,
        }
    }

    /// Copies `data`: publishes to the system backend and arms the
    /// self-destruct countdown.
    pub fn set(&mut self, data: &[u8]) {
        self.backend.write(data);
        self.stored = Some(Zeroizing::new(data.to_vec()));
        self.deadline = Instant::now()
            .checked_add(self.ttl)
            .unwrap_or_else(Instant::now);
    }

    /// Advances the countdown: wipes RAM + system clipboard once the TTL
    /// has elapsed. Returns whether a wipe happened.
    pub fn tick(&mut self) -> bool {
        let expired = self
            .stored
            .as_ref()
            .is_some_and(|_| Instant::now() >= self.deadline);
        if expired {
            self.wipe();
        }
        expired
    }

    /// Whether content is currently held.
    #[must_use]
    pub fn holds_content(&self) -> bool {
        self.stored.is_some()
    }

    /// Time left before self-destruct, if content is held.
    #[must_use]
    pub fn remaining(&self) -> Option<Duration> {
        self.stored
            .as_ref()
            .map(|_| self.deadline.saturating_duration_since(Instant::now()))
    }

    /// Immediately wipes the RAM copy and clears the system backend.
    pub fn wipe(&mut self) {
        self.backend.clear();
        self.stored = None;
    }
}

impl Drop for ClipboardManager {
    fn drop(&mut self) {
        // RAM copy zeroizes via Zeroizing; the system clipboard is cleared
        // so no residue survives the process.
        self.wipe();
    }
}
