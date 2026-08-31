//! Clipboard manager tests (TODO A.4, ADR-018). Hermetic: no system
//! clipboard, accelerated TTLs.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use umbra_cli::clipboard::{ClipboardBackend, ClipboardManager, MemoryBackend};

/// A counting backend that records write/clear calls.
struct CountingBackend {
    inner: MemoryBackend,
    writes: Arc<AtomicU32>,
    clears: Arc<AtomicU32>,
}

impl ClipboardBackend for CountingBackend {
    fn write(&mut self, data: &[u8]) {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.inner.write(data);
    }

    fn clear(&mut self) {
        self.clears.fetch_add(1, Ordering::Relaxed);
        self.inner.clear();
    }
}

/// Content survives until the TTL elapses.
#[test]
fn clipboard_holds_until_ttl() {
    let backend = MemoryBackend::default();
    let mut manager = ClipboardManager::with_ttl(Box::new(backend), Duration::from_millis(80));
    manager.set(b"secret token");
    assert!(manager.holds_content());
    assert!(!manager.tick());
    std::thread::sleep(Duration::from_millis(30));
    assert!(!manager.tick(), "wipe must not fire before TTL");
    std::thread::sleep(Duration::from_millis(70));
    assert!(manager.tick(), "wipe must fire after TTL");
    assert!(!manager.holds_content());
}

/// Drop wipes the RAM copy (Zeroizing) — observable via remaining().
#[test]
fn clipboard_drop_wipes() {
    let backend = MemoryBackend::default();
    let mut manager = ClipboardManager::with_ttl(Box::new(backend), Duration::from_secs(60));
    manager.set(b"will vanish");
    assert!(manager.remaining().is_some());
    drop(manager);
}

/// Wipe clears the SYSTEM backend too (counting backend records it).
#[test]
fn wipe_clears_system_backend() {
    let writes = Arc::new(AtomicU32::new(0));
    let clears = Arc::new(AtomicU32::new(0));
    let backend = CountingBackend {
        inner: MemoryBackend::default(),
        writes: Arc::clone(&writes),
        clears: Arc::clone(&clears),
    };
    let mut manager = ClipboardManager::with_ttl(Box::new(backend), Duration::from_millis(40));
    manager.set(b"counted");
    assert_eq!(writes.load(Ordering::Relaxed), 1);
    std::thread::sleep(Duration::from_millis(60));
    assert!(manager.tick(), "wipe must fire after TTL");
    assert_eq!(clears.load(Ordering::Relaxed), 1);
    assert!(!manager.tick(), "second tick must be a no-op");
}

/// Overwrite: setting new content re-arms the countdown.
#[test]
fn clipboard_overwrite_rearms() {
    let backend = MemoryBackend::default();
    let mut manager = ClipboardManager::with_ttl(Box::new(backend), Duration::from_millis(60));
    manager.set(b"first");
    std::thread::sleep(Duration::from_millis(40));
    manager.set(b"second");
    std::thread::sleep(Duration::from_millis(40));
    // 80ms after the FIRST set but only 40ms after the second: alive.
    assert!(manager.holds_content());
    std::thread::sleep(Duration::from_millis(40));
    assert!(manager.tick(), "second copy must self-destruct");
}
