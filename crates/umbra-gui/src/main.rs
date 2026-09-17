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
    /// Path to the hardware token's PKCS#11 module (TODO B.3 FIDO2
    /// wiring). Required together with `--hw-key-label` to unlock a
    /// hardware-key-gated keystore; omit both for a plain or Decoy
    /// Vault keystore.
    #[arg(long, value_name = "PATH")]
    hw_module: Option<PathBuf>,
    /// Label of the token-held HMAC key (as passed to
    /// `umbra_hwkey::challenge_response`).
    #[arg(long, value_name = "LABEL")]
    hw_key_label: Option<String>,
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
    let (engine_client, canonical_keystore_path) =
        match EngineClient::spawn(&cli.keystore, cli.hw_module.as_deref()) {
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
    let hw_module = cli.hw_module.clone();
    let hw_key_label = cli.hw_key_label.clone();
    application.connect_activate(move |application| {
        build_window(
            application,
            &canonical_keystore_path,
            engine_client.clone(),
            hw_module.as_deref(),
            hw_key_label.as_deref(),
        );
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
    hw_module: Option<&Path>,
    hw_key_label: Option<&str>,
) {
    let stack = gtk4::Stack::new();

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

    let password_entry = gtk4::PasswordEntry::builder().show_peek_icon(true).build();
    // TODO B.3 FIDO2 wiring: a second masked field for the hardware
    // token's PIN — only shown when this GUI was launched with BOTH
    // `--hw-module`/`--hw-key-label` (mirrors the CLI's own "all three
    // hw flags required together" rule, minus the PIN itself, which
    // this GUI collects interactively rather than via `--hw-pin-file`
    // — see this increment's spec for why).
    let hw_pin_entry = if hw_module.is_some() && hw_key_label.is_some() {
        Some(
            gtk4::PasswordEntry::builder()
                .show_peek_icon(true)
                .placeholder_text("Hardware token PIN")
                .build(),
        )
    } else {
        None
    };
    let error_label = gtk4::Label::builder().visible(false).build();
    let unlock_button = gtk4::Button::builder().label("Unlock").build();

    let unlock_box = gtk4::Box::new(gtk4::Orientation::Vertical, 8);
    unlock_box.append(&password_entry);
    if let Some(hw_pin_entry) = hw_pin_entry.as_ref() {
        unlock_box.append(hw_pin_entry);
    }
    unlock_box.append(&unlock_button);
    unlock_box.append(&error_label);
    stack.add_named(&unlock_box, Some("unlock"));

    let identity_container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    stack.add_named(&identity_container, Some("identity"));
    stack.set_visible_child_name("unlock");

    let keystore_path = keystore_path.to_path_buf();
    let hw_module = hw_module.map(std::path::Path::to_path_buf);
    let hw_key_label = hw_key_label.map(str::to_string);
    let hw_pin_entry_for_closure = hw_pin_entry.clone();
    let stack_for_closure = stack.clone();
    let window_for_peers = window.clone();
    let engine_client_for_peers = engine_client.clone();
    unlock_button.connect_clicked(move |_button| {
        let passphrase = zeroize::Zeroizing::new(password_entry.text().as_bytes().to_vec());
        let hw_pin = zeroize::Zeroizing::new(
            hw_pin_entry_for_closure
                .as_ref()
                .map(|entry| entry.text().as_bytes().to_vec())
                .unwrap_or_default(),
        );
        // The `RefMut` from `borrow_mut()` must be dropped before the
        // `Ok` arm below calls `build_peer_panel`, which borrows the
        // same `RefCell` again (via `engine_client_for_peers`, an
        // `Rc::clone` of it) — a named local's `Drop` runs at the end
        // of its enclosing block, not its last use, so without this
        // scope the guard would still be held through the whole
        // `match` and the second borrow would panic with
        // `BorrowMutError`. Scoping the borrow to just this block lets
        // it drop before `unlock_result` is matched.
        let unlock_result = {
            let mut engine_client = engine_client.borrow_mut();
            engine_client.unlock(
                &keystore_path,
                &passphrase,
                hw_module.as_deref(),
                &hw_pin,
                hw_key_label.as_deref(),
            )
        };
        match unlock_result {
            Ok(fingerprint) => {
                let reveal_widget = umbra_gui::scratch_reveal::build_scratch_reveal(&format!(
                    "Fingerprint: {fingerprint}"
                ));
                identity_container.append(&reveal_widget);
                let (peer_panel, _refresh) =
                    build_peer_panel(engine_client_for_peers.clone(), &window_for_peers);
                identity_container.append(&peer_panel);
                stack_for_closure.set_visible_child_name("identity");
            }
            Err(message) => {
                error_label.set_label(&message);
                error_label.set_visible(true);
                password_entry.set_text("");
                if let Some(hw_pin_entry) = hw_pin_entry_for_closure.as_ref() {
                    hw_pin_entry.set_text("");
                }
            }
        }
    });

    window.present();
}

/// Builds the peer-list panel: a heading, a `ListBox` of paired peer
/// names, and an "Add peer" button. Returns the panel widget and a
/// `Rc<dyn Fn()>` that re-fetches `list_peers` and repopulates the
/// `ListBox` — called once here to populate it initially, and again
/// after a successful pairing (Step 3).
fn build_peer_panel(
    engine_client: Rc<RefCell<EngineClient>>,
    window: &adw::ApplicationWindow,
) -> (gtk4::Box, Rc<dyn Fn()>) {
    let panel = gtk4::Box::new(gtk4::Orientation::Vertical, 8);
    let heading = gtk4::Label::builder()
        .label("Peers")
        .halign(gtk4::Align::Start)
        .build();
    let list_box = gtk4::ListBox::new();
    let peer_error_label = gtk4::Label::builder().visible(false).build();
    let add_button = gtk4::Button::builder().label("+ Add peer").build();
    panel.append(&heading);
    panel.append(&list_box);
    panel.append(&peer_error_label);
    panel.append(&add_button);

    let list_box_for_refresh = list_box.clone();
    let peer_error_label_for_refresh = peer_error_label.clone();
    let engine_client_for_refresh = engine_client.clone();
    let refresh: Rc<dyn Fn()> = Rc::new(move || {
        while let Some(row) = list_box_for_refresh.row_at_index(0) {
            list_box_for_refresh.remove(&row);
        }
        match engine_client_for_refresh.borrow_mut().list_peers() {
            Ok(names) => {
                peer_error_label_for_refresh.set_visible(false);
                for name in names {
                    list_box_for_refresh.append(&gtk4::Label::new(Some(&name)));
                }
            }
            Err(message) => {
                peer_error_label_for_refresh.set_label(&message);
                peer_error_label_for_refresh.set_visible(true);
            }
        }
    });
    refresh();

    let window_for_dialog = window.clone();
    let engine_client_for_dialog = engine_client.clone();
    let refresh_for_dialog = refresh.clone();
    add_button.connect_clicked(move |_button| {
        open_pairing_dialog(
            &window_for_dialog,
            engine_client_for_dialog.clone(),
            refresh_for_dialog.clone(),
        );
    });

    (panel, refresh)
}

/// Opens a modal pairing dialog: shows this identity's own payload,
/// takes the peer's payload + a chosen local name, computes and shows
/// the SAS code, and on explicit confirmation saves the peer record —
/// deliberately never saving before that confirmation (see the design
/// spec's note on this being a disclosed improvement over `umbra
/// pair`'s own save-then-show-SAS order, not a mirror of it).
fn open_pairing_dialog(
    parent: &adw::ApplicationWindow,
    engine_client: Rc<RefCell<EngineClient>>,
    refresh_peers: Rc<dyn Fn()>,
) {
    let dialog = gtk4::Window::builder()
        .transient_for(parent)
        .modal(true)
        .title("Add peer")
        .default_width(420)
        .default_height(320)
        .build();

    let stack = gtk4::Stack::new();

    let own_payload_entry = gtk4::Entry::builder().editable(false).build();
    match engine_client.borrow_mut().pair_payload() {
        Ok(payload) => own_payload_entry.set_text(&payload),
        Err(message) => own_payload_entry.set_text(&format!("error: {message}")),
    }
    let peer_payload_entry = gtk4::Entry::builder()
        .placeholder_text("Paste the peer's payload")
        .build();
    let peer_name_entry = gtk4::Entry::builder()
        .placeholder_text("Local name for this peer")
        .build();
    let peer_onion_entry = gtk4::Entry::builder()
        .placeholder_text("Peer's .onion address (optional)")
        .build();
    let import_error_label = gtk4::Label::builder().visible(false).build();
    let import_button = gtk4::Button::builder().label("Import").build();

    let import_page = gtk4::Box::new(gtk4::Orientation::Vertical, 8);
    import_page.append(&gtk4::Label::new(Some("Your payload (share out of band):")));
    import_page.append(&own_payload_entry);
    import_page.append(&peer_payload_entry);
    import_page.append(&peer_name_entry);
    import_page.append(&peer_onion_entry);
    import_page.append(&import_button);
    import_page.append(&import_error_label);
    stack.add_named(&import_page, Some("import"));

    let sas_label = gtk4::Label::new(None);
    let confirm_error_label = gtk4::Label::builder().visible(false).build();
    let confirm_button = gtk4::Button::builder()
        .label("Confirm — SAS matches")
        .build();
    let cancel_button = gtk4::Button::builder().label("Cancel").build();

    let confirm_page = gtk4::Box::new(gtk4::Orientation::Vertical, 8);
    confirm_page.append(&gtk4::Label::new(Some(
        "Compare this code with your peer over a trusted channel:",
    )));
    confirm_page.append(&sas_label);
    confirm_page.append(&confirm_button);
    confirm_page.append(&cancel_button);
    confirm_page.append(&confirm_error_label);
    stack.add_named(&confirm_page, Some("confirm"));

    stack.set_visible_child_name("import");
    dialog.set_child(Some(&stack));

    // Holds the EXACT payload string a successful `pair_import` call
    // was made with, so `pair_confirm` below is structurally bound to
    // computing its SAS over the same bytes rather than re-reading
    // `peer_payload_entry` a second time (which today happens to still
    // hold the same text only because the import page becomes
    // unreachable once the confirm page is shown — a UI-reachability
    // argument, not a structural guarantee, and fragile to future
    // refactors).
    let imported_payload: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));

    let stack_for_import = stack.clone();
    let engine_client_for_import = engine_client.clone();
    let peer_payload_entry_for_import = peer_payload_entry.clone();
    let sas_label_for_import = sas_label.clone();
    let import_error_label_for_import = import_error_label.clone();
    let imported_payload_for_import = imported_payload.clone();
    import_button.connect_clicked(move |_button| {
        let peer_payload = peer_payload_entry_for_import.text().to_string();
        // Bind the owned `Result` to a local first (same reasoning as
        // `confirm_button`'s handler below): keeps the `RefCell`
        // borrow scoped to this `let`, so it's released before the
        // `Ok` arm below borrows `imported_payload_for_import`.
        let import_result = engine_client_for_import
            .borrow_mut()
            .pair_import(&peer_payload);
        match import_result {
            Ok(sas) => {
                *imported_payload_for_import.borrow_mut() = Some(peer_payload);
                import_error_label_for_import.set_visible(false);
                sas_label_for_import.set_label(&sas);
                stack_for_import.set_visible_child_name("confirm");
            }
            Err(message) => {
                import_error_label_for_import.set_label(&message);
                import_error_label_for_import.set_visible(true);
            }
        }
    });

    let engine_client_for_confirm = engine_client.clone();
    let peer_name_entry_for_confirm = peer_name_entry.clone();
    let peer_onion_entry_for_confirm = peer_onion_entry.clone();
    let confirm_error_label_for_confirm = confirm_error_label.clone();
    let dialog_for_confirm = dialog.clone();
    let refresh_peers_for_confirm = refresh_peers.clone();
    let imported_payload_for_confirm = imported_payload.clone();
    confirm_button.connect_clicked(move |_button| {
        // Scoped tightly to this `let` so the borrow is released before
        // any of the branches below run (mirrors the `RefCell`-borrow
        // care already taken for `engine_client` in this same handler).
        let peer_payload = imported_payload_for_confirm.borrow().clone();
        let Some(peer_payload) = peer_payload else {
            confirm_error_label_for_confirm
                .set_label("no successfully imported payload to confirm");
            confirm_error_label_for_confirm.set_visible(true);
            return;
        };
        let peer_name = peer_name_entry_for_confirm.text().to_string();
        let peer_onion = peer_onion_entry_for_confirm.text().to_string();
        let peer_onion = if peer_onion.is_empty() {
            None
        } else {
            Some(peer_onion.as_str())
        };
        // As in `unlock_button`'s handler above: `match`'s scrutinee
        // temporary lives for the whole match statement, so calling
        // `.borrow_mut()` directly in the scrutinee would keep the
        // `RefCell` borrowed through the `Ok` arm below, where
        // `refresh_peers_for_confirm` (the `build_peer_panel` refresh
        // closure) borrows the same `RefCell` again — panicking with
        // `BorrowMutError`. Binding the call's owned `Result` to a
        // named local first drops the `RefMut` at the end of this
        // `let` statement, before the `match` runs.
        let confirm_result = engine_client_for_confirm.borrow_mut().pair_confirm(
            &peer_name,
            &peer_payload,
            peer_onion,
        );
        match confirm_result {
            Ok(()) => {
                refresh_peers_for_confirm();
                dialog_for_confirm.close();
            }
            Err(message) => {
                confirm_error_label_for_confirm.set_label(&message);
                confirm_error_label_for_confirm.set_visible(true);
            }
        }
    });

    let dialog_for_cancel = dialog.clone();
    cancel_button.connect_clicked(move |_button| {
        dialog_for_cancel.close();
    });

    dialog.present();
}
