//! `umbra-gui` binary entry point (TODO B.3). Checks for a Wayland
//! session BEFORE touching GTK/Adwaita at all; if present, hardens
//! process memory (ADR-025) before the passphrase can touch RAM, then
//! spawns the `umbra-engine` process (TODO B.3.1) and opens a
//! keystore-unlock view backed by it. On success, shows the unlocked
//! identity's fingerprint. No messaging, peer list, or sandboxing of
//! THIS process yet — see
//! `docs/superpowers/specs/2026-09-13-gui-keystore-unlock-design.md`
//! and `docs/superpowers/specs/2026-09-15-engine-ui-separation-design.md`.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use adw::prelude::*;
use gtk4::prelude::{BoxExt, ButtonExt, EditableExt, WidgetExt};
use umbra_gui::engine_client::EngineClient;

/// GTK application ID (reverse-DNS convention).
const APPLICATION_ID: &str = "org.umbra.Gui";

/// `umbra-gui`'s command-line arguments: only the keystore path — the
/// passphrase itself is entered interactively in the GUI (spec
/// decision, 2026-09-13: deliberately NOT a `--passphrase-file` flag
/// like the CLI/TUI use, since a masked password field is the natural
/// desktop-GUI equivalent of a terminal password prompt).
#[derive(clap::Parser)]
#[command(name = "umbra-gui", version, about)]
struct Cli {
    /// Path to the keystore file (see `umbra keygen`/`umbra init`).
    #[arg(long, value_name = "PATH")]
    keystore: PathBuf,
}

fn main() -> gtk4::glib::ExitCode {
    let wayland_display = std::env::var("WAYLAND_DISPLAY").ok();
    if !umbra_gui::wayland::wayland_session_present(wayland_display.as_deref()) {
        eprintln!(
            "umbra-gui: refusing to start: no Wayland session detected \
             (WAYLAND_DISPLAY is unset or empty). Umbra's GUI is Wayland-only."
        );
        std::process::exit(1);
    }

    // ADR-025: memory hardening BEFORE the passphrase (entered shortly,
    // in the unlock view) or any other secret touches RAM. Kept in
    // THIS process too (defense in depth, TODO B.3.1): the passphrase
    // still passes through here transiently, in a `Zeroizing` buffer,
    // between the `PasswordEntry` widget and the Engine socket write —
    // only the unlock COMPUTATION itself, and the resulting identity
    // key material, live exclusively in the separate Engine process.
    //
    // Core-dump suppression only — NOT `umbra_hardware::process::
    // harden_process()`'s full bundle, which also calls `mlockall
    // (MCL_CURRENT | MCL_FUTURE)`. `MCL_CURRENT` alone locks every page
    // already mapped at call time, and GTK4/Libadwaita's own baseline
    // footprint (Pango/Cairo/GDK plus their shared libraries) already
    // exceeds a constrained `RLIMIT_MEMLOCK` (8 MiB, empirically
    // confirmed in this project's own dev sandbox) before this
    // process's own passphrase buffer is even allocated — so
    // `mlockall` itself fails with `ENOMEM` immediately (root-caused
    // by actually running this binary under this sandbox's real
    // Wayland session, TODO B.3.1's own manual-verification step; see
    // `crates/umbra-engine/src/lib.rs::run`'s own analogous fix for
    // the same conflict on the Engine side, and
    // `crates/umbra-cli/src/cli.rs`'s `init_with`, which hit and
    // documented it first). This keeps the free, unrelated protections
    // (`disable_core_dumps`/`limit_core_dumps`) and drops only
    // `lock_all_memory`.
    if let Err(error) = umbra_hardware::process::disable_core_dumps()
        .and_then(|()| umbra_hardware::process::limit_core_dumps())
    {
        eprintln!("umbra-gui: memory hardening failed: {error}");
        std::process::exit(1);
    }

    let cli = <Cli as clap::Parser>::parse();

    // Closes the `GDK_BACKEND=x11`/XWayland bypass: without this, GDK
    // could still connect via a non-Wayland backend even though the
    // check above confirmed a Wayland session exists. Must run before
    // any other GDK/GTK call.
    gtk4::gdk::set_allowed_backends("wayland");

    // TODO B.3.1: spawn the sandboxed Engine process BEFORE building
    // any window. No in-process fallback on failure — see this
    // increment's spec, "no in-process fallback to the old direct-
    // unlock code path, since that would defeat the separation
    // entirely."
    let (engine_client, canonical_keystore_path) = match EngineClient::spawn(&cli.keystore) {
        Ok(result) => result,
        Err(message) => {
            eprintln!("umbra-gui: failed to start the Engine process: {message}");
            std::process::exit(1);
        }
    };
    let engine_client = Rc::new(RefCell::new(engine_client));

    let application = adw::Application::builder()
        .application_id(APPLICATION_ID)
        .build();
    application.connect_activate(move |application| {
        build_window(application, &canonical_keystore_path, engine_client.clone());
    });
    // `run()` would re-parse the PROCESS'S OWN argv through GLib's option
    // parser (`ApplicationExtManual::run()` forwards `std::env::args_os()`
    // straight into `g_application_run`) — since `--keystore` isn't a
    // registered `GOption`, that rejects it as an unrecognized option
    // before `connect_activate` ever fires, even though `clap` above
    // already parsed it successfully. `clap` is this binary's one and
    // only argv parser, so GLib must be handed no arguments at all.
    application.run_with_args::<&str>(&[])
}

/// Builds and presents the keystore-unlock window: a header bar over a
/// `gtk4::Stack` switching between the `"unlock"` view (a masked
/// password field + button + hidden-by-default error label) and the
/// `"identity"` view (the unlocked fingerprint). Everything below this
/// point is the ONLY GTK/Adwaita-touching code in this binary — the
/// Wayland check, memory hardening, and Engine spawn above have
/// already run.
///
/// # Honest scope: the password field's own memory is not zeroized
///
/// `gtk4::PasswordEntry`'s internal text buffer is a GLib `GString`
/// owned by the GTK toolkit itself, outside this project's
/// `zeroize`/`Zeroizing` control (and outside safe Rust's reach without
/// `unsafe`, which this workspace forbids). Only the copy THIS function
/// extracts from it, once read at unlock-button-click time, is wrapped
/// in `zeroize::Zeroizing` before being sent to the Engine over the
/// `AF_UNIX` socket — a real, accepted residual of using a GUI toolkit
/// that predates and does not itself practice zeroize-on-drop hygiene.
fn build_window(
    application: &adw::Application,
    keystore_path: &Path,
    engine_client: Rc<RefCell<EngineClient>>,
) {
    let stack = gtk4::Stack::new();

    let password_entry = gtk4::PasswordEntry::builder().show_peek_icon(true).build();
    let error_label = gtk4::Label::builder().visible(false).build();
    let unlock_button = gtk4::Button::builder().label("Unlock").build();

    let unlock_box = gtk4::Box::new(gtk4::Orientation::Vertical, 8);
    unlock_box.append(&password_entry);
    unlock_box.append(&unlock_button);
    unlock_box.append(&error_label);
    stack.add_named(&unlock_box, Some("unlock"));

    let identity_container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    stack.add_named(&identity_container, Some("identity"));
    stack.set_visible_child_name("unlock");

    let keystore_path = keystore_path.to_path_buf();
    let stack_for_closure = stack.clone();
    unlock_button.connect_clicked(move |_button| {
        let passphrase = zeroize::Zeroizing::new(password_entry.text().as_bytes().to_vec());
        let mut engine_client = engine_client.borrow_mut();
        match engine_client.unlock(&keystore_path, &passphrase) {
            Ok(fingerprint) => {
                let reveal_widget = umbra_gui::scratch_reveal::build_scratch_reveal(&format!(
                    "Fingerprint: {fingerprint}"
                ));
                identity_container.append(&reveal_widget);
                stack_for_closure.set_visible_child_name("identity");
            }
            Err(message) => {
                error_label.set_label(&message);
                error_label.set_visible(true);
                password_entry.set_text("");
            }
        }
    });

    let header_bar = adw::HeaderBar::new();
    let content = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    content.append(&header_bar);
    content.append(&stack);

    let window = adw::ApplicationWindow::builder()
        .application(application)
        .title("Umbra")
        .default_width(480)
        .default_height(320)
        .content(&content)
        .build();
    window.present();
}
