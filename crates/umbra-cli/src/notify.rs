//! Zero-knowledge masked notifications over D-Bus (TODO A.4, ADR-018).
//!
//! The OS (and anything listening on the notification bus) is NEVER told
//! the message text, the sender identity, or even that a message exists:
//! the adapter emits a fixed allowlist of generic system strings
//! ("System Update"), nothing else (SPECIFICATION.md opcode 0x04 notes,
//! ADR-018 "Sıfır Bilgili Bildirimler"). The real message is painted from
//! `mlock` RAM only after biometric/passphrase unlock.
//!
//! Wake-up transport side: the arrival signal itself is a
//! Zero-Knowledge Wakeup Ping over Tor (umbra-net), which carries no text
//! at all. This module is the LAST hop — OS-facing — and the easiest to
//! audit: every string it can emit is a compile-time constant.

use crate::cli::CliError;

/// The complete allowlist of strings this adapter may ever emit.
/// Anything outside this table is a bug, by construction.
#[doc(hidden)]
pub const GENERIC_NOTIFICATIONS: [(&str, &str); 2] = [
    // (summary, body) — indistinguishable from OS housekeeping.
    ("System Update", "System update completed successfully."),
    ("System Update", "System update is available."),
];

/// Notification sink abstraction (D-Bus in production, memory in tests).
pub trait NotificationBackend: Send {
    /// Shows one notification.
    ///
    /// # Errors
    ///
    /// Backend failures (bus unavailable, marshaling errors).
    fn show(&mut self, summary: &str, body: &str) -> Result<(), String>;
}

/// D-Bus `org.freedesktop.Notifications` backend (blocking zbus).
pub struct DbusNotifications;

impl NotificationBackend for DbusNotifications {
    fn show(&mut self, summary: &str, body: &str) -> Result<(), String> {
        let connection = zbus::blocking::Connection::session()
            .map_err(|e| format!("D-Bus session unavailable: {e}"))?;
        let proxy = zbus::blocking::Proxy::new(
            &connection,
            "org.freedesktop.Notifications",
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications",
        )
        .map_err(|e| format!("notification proxy error: {e}"))?;
        proxy
            .call_noreply(
                "Notify",
                &(
                    "Umbra", // app name
                    0u32,    // replaces id
                    "",      // no icon
                    summary,
                    body,
                    std::vec::Vec::<String>::new(), // actions
                    std::collections::HashMap::<String, zvariant::Value>::new(), // hints
                    -1i32,                          // expire: default
                ),
            )
            .map_err(|e| format!("Notify call failed: {e}"))?;
        Ok(())
    }
}

/// In-memory backend for hermetic tests and audits.
#[derive(Debug, Default)]
pub struct MemoryNotifications {
    /// Emitted (summary, body) pairs.
    pub emitted: std::vec::Vec<(String, String)>,
}

impl NotificationBackend for MemoryNotifications {
    fn show(&mut self, summary: &str, body: &str) -> Result<(), String> {
        self.emitted.push((summary.to_string(), body.to_string()));
        Ok(())
    }
}

/// Selector over the compile-time notification allowlist (no
/// caller-controlled strings can ever reach the OS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenericNotification {
    /// "System update completed successfully."
    UpdateCompleted,
    /// "System update is available."
    UpdateAvailable,
}

/// Masked notification adapter: the ONLY entry point to the OS
/// notification surface, and it accepts no caller-controlled strings.
pub struct MaskedNotifier {
    /// Notification sink (D-Bus in production, memory in tests).
    backend: Box<dyn NotificationBackend + Send>,
}

impl MaskedNotifier {
    /// Creates an adapter over the given backend.
    #[must_use]
    pub fn new(backend: Box<dyn NotificationBackend + Send>) -> Self {
        Self { backend }
    }

    /// Emits the generic "System Update" notification for a received
    /// wakeup ping. The content is selected from the compile-time
    /// allowlist — the message text, sender, and the fact that this is a
    /// message at all never reach the OS.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Notify`] if the backend fails.
    pub fn notify_session_event(&mut self) -> Result<(), CliError> {
        self.notify_generic(GenericNotification::UpdateCompleted)
    }

    /// Emits one notification from the compile-time allowlist.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Notify`] if the backend fails.
    pub fn notify_generic(&mut self, kind: GenericNotification) -> Result<(), CliError> {
        // `kind` is a closed enum: the index is always in range.
        let (summary, body) = GENERIC_NOTIFICATIONS
            .get(kind as usize)
            .copied()
            .unwrap_or(GENERIC_NOTIFICATIONS[0]);
        self.backend.show(summary, body).map_err(CliError::Notify)
    }
}

/// Builds the production D-Bus adapter.
#[must_use]
pub fn dbus_notifier() -> MaskedNotifier {
    MaskedNotifier::new(Box::new(DbusNotifications))
}
