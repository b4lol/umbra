//! `umbra-gui` binary entry point (TODO B.3, Wayland-only skeleton,
//! 2026-09-13). Checks for a Wayland session BEFORE touching GTK/Adwaita
//! at all; if present, opens an empty placeholder window. No keystore,
//! session, or sandboxing yet — see
//! `docs/superpowers/specs/2026-09-13-gui-wayland-skeleton-design.md`.

use adw::prelude::*;
use gtk4::prelude::BoxExt;

/// GTK application ID (reverse-DNS convention) for this skeleton.
const APPLICATION_ID: &str = "org.umbra.Gui";

fn main() -> gtk4::glib::ExitCode {
    let wayland_display = std::env::var("WAYLAND_DISPLAY").ok();
    if !umbra_gui::wayland::wayland_session_present(wayland_display.as_deref()) {
        eprintln!(
            "umbra-gui: refusing to start: no Wayland session detected \
             (WAYLAND_DISPLAY is unset or empty). Umbra's GUI is Wayland-only."
        );
        std::process::exit(1);
    }

    // Closes the `GDK_BACKEND=x11`/XWayland bypass: without this, GDK could
    // still connect via a non-Wayland backend even though the check above
    // confirmed a Wayland session exists, defeating this binary's
    // Wayland-only guarantee. Must run before any other GDK/GTK call.
    gtk4::gdk::set_allowed_backends("wayland");

    let application = adw::Application::builder()
        .application_id(APPLICATION_ID)
        .build();
    application.connect_activate(build_window);
    application.run()
}

/// Builds and presents the (currently empty) placeholder window: a
/// header bar over one label. Everything below this point is the ONLY
/// GTK/Adwaita-touching code in this binary — the Wayland check above
/// has already run and passed before this is ever called.
fn build_window(application: &adw::Application) {
    let header_bar = adw::HeaderBar::new();
    let placeholder = gtk4::Label::builder()
        .label("Umbra — GUI skeleton (TODO B.3)")
        .build();

    let content = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    content.append(&header_bar);
    content.append(&placeholder);

    let window = adw::ApplicationWindow::builder()
        .application(application)
        .title("Umbra")
        .default_width(480)
        .default_height(320)
        .content(&content)
        .build();
    window.present();
}
