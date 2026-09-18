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
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use adw::prelude::*;
use gtk4::prelude::{BoxExt, ButtonExt, EditableExt, WidgetExt};
use umbra_gui::engine_client::EngineClient;

/// GTK application ID (reverse-DNS convention).
const APPLICATION_ID: &str = "org.umbra.Gui";

/// Sidebar pseudo-conversation for inbound texts (Phase 4): sender
/// attribution does not exist at the Engine's layer (`receive_message`
/// returns plaintext only), so inbound messages land here — never
/// inside a named peer's log, which would misattribute them. Not a
/// valid engine-side peer name (peer names are validated against a
/// strict character set), so it can never collide with a real one.
const INBOX_PEER: &str = "· inbox (unattributed) ·";

/// Per-conversation log bound (Phase 5), mirroring `tui.rs`'s
/// `MAX_LOG_LINES = 400`: a chat log is attacker-influenced content
/// arriving without user action, so its memory footprint must stay
/// bounded exactly like the TUI's.
const MAX_CHAT_LOG_LINES: usize = 400;

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
    let status_label = gtk4::Label::new(Some("bootstrapping Tor (up to ~3 minutes)…"));
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
                identity_container.append(&status_label);
                // Session phase (TODO B.3 GUI messaging, Phase 2):
                // `start_session` MUST complete before
                // `build_peer_panel` below, whose initial refresh calls
                // `list_peers` — that now requires an active session.
                let (event_tx, event_rx) = async_channel::unbounded();
                if let Err(message) = engine_client_for_peers.borrow_mut().start_session(event_tx) {
                    error_label.set_label(&format!("session start failed: {message}"));
                    error_label.set_visible(true);
                }
                // Phase 3 chat area: per-peer message log + compose row.
                // Log entries live in `chat_logs` (one bounded list per
                // conversation name); `selected_peer` tracks the sidebar
                // selection the compose row sends to.
                let selected_peer: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
                let chat_logs: ChatLogs = Rc::new(RefCell::new(HashMap::new()));
                let chat_with_label = gtk4::Label::new(Some("no peer selected"));
                let log_view = gtk4::ListBox::new();
                log_view.add_css_class("boxed-list");
                let log_scroll = gtk4::ScrolledWindow::builder()
                    .child(&log_view)
                    .min_content_height(160)
                    .vexpand(true)
                    .build();
                let compose_entry = gtk4::Entry::builder()
                    .placeholder_text("Message…")
                    .build();
                let send_button = gtk4::Button::builder().label("Send").build();
                // Phase 5: disabled-with-a-reason states (mirrors
                // tui.rs's inline messages). `tor_ready` flips on the
                // Ready event; the reason shows as the compose box's
                // placeholder text.
                let tor_ready = Rc::new(std::cell::Cell::new(false));
                let update_send_state: Rc<dyn Fn()> = {
                    let send_button = send_button.clone();
                    let compose_entry = compose_entry.clone();
                    let selected_peer = selected_peer.clone();
                    let tor_ready = tor_ready.clone();
                    Rc::new(move || {
                        let selected = selected_peer.borrow().clone();
                        let (sensitive, reason) = if !tor_ready.get() {
                            (false, "bootstrapping Tor — sending not available yet")
                        } else if selected.is_none() {
                            (false, "no peer selected")
                        } else if selected.as_deref() == Some(INBOX_PEER) {
                            (false, "the inbox is receive-only")
                        } else {
                            (true, "Message…")
                        };
                        send_button.set_sensitive(sensitive);
                        compose_entry.set_sensitive(sensitive);
                        compose_entry.set_placeholder_text(Some(reason));
                    })
                };
                update_send_state();
                let chat_box = gtk4::Box::new(gtk4::Orientation::Vertical, 8);
                chat_box.append(&chat_with_label);
                chat_box.append(&log_scroll);
                let compose_row = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
                compose_entry.set_hexpand(true);
                compose_row.append(&compose_entry);
                compose_row.append(&send_button);
                chat_box.append(&compose_row);
                // Phase 5: persistent privacy/trust footer (mirrors the
                // TUI's always-on notice — the operator sees the
                // anonymity tier, always, no opt-out). Tor is this
                // increment's only transport.
                let privacy_footer = gtk4::Label::builder()
                    .label(
                        "Tor onion service · anonymity: STRONG (both endpoints hidden) · \
                         content: STRONG (PQXDH X25519 + ML-KEM-768, ML-DSA identity) · \
                         metadata protection rests on Tor itself",
                    )
                    .wrap(true)
                    .wrap_mode(gtk4::pango::WrapMode::WordChar)
                    .halign(gtk4::Align::Start)
                    .css_classes(["dim-label", "caption"])
                    .build();
                chat_box.append(&privacy_footer);

                let status_label_for_events = status_label.clone();
                let chat_logs_for_events = chat_logs.clone();
                let selected_peer_for_events = selected_peer.clone();
                let log_view_for_events = log_view.clone();
                let tor_ready_for_events = tor_ready.clone();
                let update_send_state_for_events = update_send_state.clone();
                // glib 0.22 removed `MainContext::channel`; the event
                // receiver is consumed by a future on the default main
                // context instead (dropping the returned `JoinHandle`
                // detaches the task, which is what we want — it lives
                // until the channel closes at Engine exit).
                gtk4::glib::MainContext::default().spawn_local(async move {
                    while let Ok(event) = event_rx.recv().await {
                        match event {
                            umbra_gui::engine_client::EngineEvent::Ready(address) => {
                                status_label_for_events.set_label(
                                    "bootstrapped — onion service ready (address redacted client-side)",
                                );
                                let _ = address; // Not yet displayed/copyable; Phase 3+ UI work.
                                tor_ready_for_events.set(true);
                                update_send_state_for_events();
                            }
                            umbra_gui::engine_client::EngineEvent::Sent(_peer) => {
                                // The composed line was already echoed to
                                // the log at click time; per the honest
                                // caveat on `EngineEvent::Sent`, there is
                                // no stronger delivery signal to show.
                            }
                            umbra_gui::engine_client::EngineEvent::SendError(peer, message) => {
                                append_chat_line(
                                    &chat_logs_for_events,
                                    &selected_peer_for_events,
                                    &log_view_for_events,
                                    &peer,
                                    ChatLine::System(format!("send failed: {message}")),
                                );
                            }
                            umbra_gui::engine_client::EngineEvent::InboundText(text) => {
                                append_chat_line(
                                    &chat_logs_for_events,
                                    &selected_peer_for_events,
                                    &log_view_for_events,
                                    INBOX_PEER,
                                    ChatLine::Received(text),
                                );
                            }
                            umbra_gui::engine_client::EngineEvent::SessionError(message) => {
                                status_label_for_events
                                    .set_label(&format!("session error: {message}"));
                            }
                        }
                    }
                });
                let (peer_panel, _refresh) = build_peer_panel(
                    engine_client_for_peers.clone(),
                    &window_for_peers,
                    selected_peer.clone(),
                    chat_with_label.clone(),
                    log_view.clone(),
                    chat_logs.clone(),
                    update_send_state.clone(),
                );
                identity_container.append(&peer_panel);
                identity_container.append(&chat_box);

                let engine_client_for_send = engine_client_for_peers.clone();
                send_button.connect_clicked(move |_button| {
                    let peer = selected_peer.borrow().clone();
                    let text = compose_entry.text().to_string();
                    if text.is_empty() {
                        return;
                    }
                    let Some(peer) = peer else {
                        return;
                    };
                    if peer == INBOX_PEER {
                        // The inbox is receive-only (senders are not
                        // attributable); there is nobody to answer.
                        return;
                    }
                    let send_result = engine_client_for_send.borrow().send(&peer, &text);
                    match send_result {
                        Ok(()) => {
                            append_chat_line(
                                &chat_logs,
                                &selected_peer,
                                &log_view,
                                &peer,
                                ChatLine::Own(text.clone()),
                            );
                            compose_entry.set_text("");
                        }
                        Err(message) => append_chat_line(
                            &chat_logs,
                            &selected_peer,
                            &log_view,
                            &peer,
                            ChatLine::System(format!("send failed: {message}")),
                        ),
                    }
                });
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

/// One chat-log entry. Message content (both directions) renders as a
/// Scratch-to-Reveal widget — chat history is sensitive content and
/// the anti-shoulder-surfing doctrine applies to it exactly as it does
/// to the fingerprint; system lines (send failures) stay plain.
enum ChatLine {
    /// An own message, echoed at click time (the honest caveat on
    /// `EngineEvent::Sent` applies: queued into Arti, not delivered).
    Own(String),
    /// A decrypted inbound message (inbox; unattributed).
    Received(String),
    /// A local system line (send failure, etc.) — never masked.
    System(String),
}

/// Chat log storage: one bounded entry list per conversation name.
type ChatLogs = Rc<RefCell<HashMap<String, Vec<ChatLine>>>>;

/// Builds the row widget for one chat line: message content masked
/// behind Scratch-to-Reveal (single-line preview — newlines are
/// flattened), system lines as plain dim labels.
fn chat_line_widget(line: &ChatLine) -> gtk4::Widget {
    match line {
        ChatLine::Own(text) | ChatLine::Received(text) => {
            // ~9 px per 14 pt monospace glyph + padding, clamped:
            // sized to the content so short messages stay compact and
            // long ones stay readable (no wrapping in the widget).
            let flat: String = text
                .chars()
                .map(|c| if c == '\n' { ' ' } else { c })
                .collect();
            let content_width = i32::try_from(flat.chars().count())
                .unwrap_or(i32::MAX)
                .saturating_mul(9)
                .saturating_add(24);
            let width = content_width.clamp(160, 560);
            let widget = umbra_gui::scratch_reveal::build_scratch_reveal_sized(&flat, width, 32);
            match line {
                ChatLine::Own(_) => widget.set_halign(gtk4::Align::End),
                _ => widget.set_halign(gtk4::Align::Start),
            }
            widget.upcast()
        }
        ChatLine::System(text) => gtk4::Label::builder()
            .label(text)
            .halign(gtk4::Align::Start)
            .css_classes(["dim-label"])
            .build()
            .upcast(),
    }
}

/// Appends one line to `peer`'s chat log buffer, and re-renders the
/// log view when that peer is the currently selected one. Shared by
/// the send button (own echo), the event loop (send failures), and
/// (Phase 4) inbound messages.
fn append_chat_line(
    chat_logs: &ChatLogs,
    selected_peer: &Rc<RefCell<Option<String>>>,
    log_view: &gtk4::ListBox,
    peer: &str,
    line: ChatLine,
) {
    {
        let mut logs = chat_logs.borrow_mut();
        let entries = logs.entry(peer.to_string()).or_default();
        entries.push(line);
        // Bounded memory (Phase 5): drop whole oldest lines once a log
        // exceeds MAX_CHAT_LOG_LINES.
        let overflow = entries.len().saturating_sub(MAX_CHAT_LOG_LINES);
        if overflow > 0 {
            entries.drain(..overflow);
        }
    }
    if selected_peer.borrow().as_deref() == Some(peer) {
        render_chat_log(chat_logs, log_view, Some(peer));
    }
}

/// Renders `peer`'s whole log into the log view (used when the
/// sidebar selection changes).
fn render_chat_log(chat_logs: &ChatLogs, log_view: &gtk4::ListBox, peer: Option<&str>) {
    while let Some(row) = log_view.row_at_index(0) {
        log_view.remove(&row);
    }
    let Some(peer) = peer else {
        return;
    };
    let logs = chat_logs.borrow();
    let Some(entries) = logs.get(peer) else {
        return;
    };
    for line in entries {
        log_view.append(&chat_line_widget(line));
    }
}

/// Builds the peer-list panel: a heading, a `ListBox` of paired peer
/// names, and an "Add peer" button. Returns the panel widget and a
/// `Rc<dyn Fn()>` that re-fetches `list_peers` and repopulates the
/// `ListBox` — called once here to populate it initially, and again
/// after a successful pairing (Step 3). Selecting a row binds the chat
/// area (compose target label + per-peer log view) to that peer.
fn build_peer_panel(
    engine_client: Rc<RefCell<EngineClient>>,
    window: &adw::ApplicationWindow,
    selected_peer: Rc<RefCell<Option<String>>>,
    chat_with_label: gtk4::Label,
    log_view: gtk4::ListBox,
    chat_logs: ChatLogs,
    on_selection_changed: Rc<dyn Fn()>,
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

    // The rows currently shown, in order — `connect_row_selected`
    // hands back an index, not the name, so the selection handler
    // looks the name up here. Replaced wholesale by each refresh.
    let listed_names: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));

    let list_box_for_refresh = list_box.clone();
    let peer_error_label_for_refresh = peer_error_label.clone();
    let engine_client_for_refresh = engine_client.clone();
    let listed_names_for_refresh = listed_names.clone();
    let refresh: Rc<dyn Fn()> = Rc::new(move || {
        while let Some(row) = list_box_for_refresh.row_at_index(0) {
            list_box_for_refresh.remove(&row);
        }
        match engine_client_for_refresh.borrow_mut().list_peers() {
            Ok(names) => {
                peer_error_label_for_refresh.set_visible(false);
                // Row 0 is always the unattributed-inbound inbox (Phase
                // 4); real peers follow it.
                *listed_names_for_refresh.borrow_mut() = std::iter::once(INBOX_PEER.to_string())
                    .chain(names.iter().cloned())
                    .collect();
                list_box_for_refresh.append(&gtk4::Label::new(Some(INBOX_PEER)));
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

    let listed_names_for_select = listed_names.clone();
    list_box.connect_row_selected(move |_list_box, row| {
        let selected = row.and_then(|row| {
            let index = usize::try_from(row.index()).ok()?;
            listed_names_for_select.borrow().get(index).cloned()
        });
        chat_with_label.set_label(&match selected.as_deref() {
            Some(name) => format!("chatting with: {name}"),
            None => "no peer selected".to_string(),
        });
        render_chat_log(&chat_logs, &log_view, selected.as_deref());
        *selected_peer.borrow_mut() = selected;
        on_selection_changed();
    });

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
