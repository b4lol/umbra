//! Wayland-only session enforcement (TODO B.3): a pure, GTK-independent
//! check so it is hermetically unit-testable without a display server —
//! `main.rs` calls it BEFORE touching GTK/Adwaita at all.

/// Returns whether a Wayland session is present, based on the
/// `WAYLAND_DISPLAY` environment variable's value: present and
/// non-empty means yes. Scoped deliberately narrow (TODO B.3 design,
/// 2026-09-13) — no `XDG_SESSION_TYPE` cross-check, no XWayland
/// detection.
#[must_use]
pub fn wayland_session_present(wayland_display: Option<&str>) -> bool {
    wayland_display.is_some_and(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::wayland_session_present;

    /// `WAYLAND_DISPLAY` set to a real compositor socket name — the
    /// normal case on this project's target desktop.
    #[test]
    fn present_when_wayland_display_is_set() {
        assert!(wayland_session_present(Some("wayland-0")));
    }

    /// `WAYLAND_DISPLAY` entirely unset (e.g. a plain X11 session with
    /// no Wayland compositor running) must be rejected.
    #[test]
    fn absent_when_wayland_display_is_unset() {
        assert!(!wayland_session_present(None));
    }

    /// An empty (but present) `WAYLAND_DISPLAY` value is not a real
    /// session either — treated the same as unset.
    #[test]
    fn absent_when_wayland_display_is_empty() {
        assert!(!wayland_session_present(Some("")));
    }
}
