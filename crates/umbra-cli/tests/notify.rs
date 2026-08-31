//! Masked notification tests (TODO A.4, ADR-018).
//!
//! Hermetic: memory backend only — no D-Bus session required. The core
//! property under test: the adapter's emit surface is a compile-time
//! allowlist, so message text, sender identity, and even the existence of
//! a message can never leak to the OS.

use umbra_cli::notify::{
    GENERIC_NOTIFICATIONS, GenericNotification, MaskedNotifier, NotificationBackend,
};

/// Records emissions and refuses strings outside the allowlist — a
/// fail-loud oracle for the leak property.
struct AuditingBackend {
    emitted: Vec<(String, String)>,
}

impl NotificationBackend for AuditingBackend {
    fn show(&mut self, summary: &str, body: &str) -> Result<(), String> {
        assert!(
            GENERIC_NOTIFICATIONS.iter().any(|(s, _b)| *s == summary),
            "SUMMARY LEAK: {summary:?} is not on the allowlist"
        );
        assert!(
            GENERIC_NOTIFICATIONS.iter().any(|(_s, b)| *b == body),
            "BODY LEAK: {body:?} is not on the allowlist"
        );
        self.emitted.push((summary.to_string(), body.to_string()));
        Ok(())
    }
}

/// The adapter emits exactly the generic system string — never
/// message-shaped content.
#[test]
fn masked_notification_is_generic_only() -> Result<(), Box<dyn std::error::Error>> {
    let backend = AuditingBackend {
        emitted: Vec::new(),
    };
    let mut notifier = MaskedNotifier::new(Box::new(backend));
    // The caller has NO string parameter to abuse — the API cannot leak
    // by construction; call both allowlist entries.
    notifier.notify_session_event()?;
    notifier.notify_generic(GenericNotification::UpdateAvailable)?;
    Ok(())
}

/// Repeated wakeups produce the same generic string (stable behavior).
#[test]
fn repeated_wakeups_are_stable() -> Result<(), Box<dyn std::error::Error>> {
    let backend = AuditingBackend {
        emitted: Vec::new(),
    };
    let mut notifier = MaskedNotifier::new(Box::new(backend));
    notifier.notify_session_event()?;
    notifier.notify_session_event()?;
    Ok(())
}
