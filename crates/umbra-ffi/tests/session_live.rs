//! LIVE-NETWORK session test (`#[ignore]`): run manually,
//! `cargo test -p umbra-ffi --features tor --test session_live -- --ignored --nocapture`.
//! Needs real Tor connectivity and several minutes of bootstrap. Throwaway
//! identity in the workspace `target/` (Arti's fs-mistrust rejects `/tmp`);
//! the address is never printed.
#![cfg(feature = "tor")]

use std::time::{Duration, Instant};

use umbra_native::{LiveController, SessionEvent};

/// Log line for an event: the kind plus non-secret details only (never an
/// address or message text).
fn describe(event: &SessionEvent) -> String {
    match event {
        SessionEvent::Bootstrapping => "Bootstrapping".to_string(),
        SessionEvent::Ready { .. } => "Ready".to_string(),
        SessionEvent::Inbound { text } => format!("Inbound({} chars)", text.len()),
        SessionEvent::SessionError { message } => format!("SessionError: {message}"),
        SessionEvent::Sent { frames, bytes, .. } => format!("Sent({frames} frames, {bytes} bytes)"),
        SessionEvent::SendError { message, .. } => format!("SendError: {message}"),
        SessionEvent::Fatal { message } => format!("Fatal: {message}"),
    }
}

/// Polls events until `want` matches or `deadline` passes; a `Fatal` aborts.
fn wait_for(
    controller: &LiveController,
    deadline: Duration,
    mut want: impl FnMut(&SessionEvent) -> bool,
) -> Result<SessionEvent, String> {
    let end = Instant::now()
        .checked_add(deadline)
        .ok_or("deadline overflow")?;
    while Instant::now() < end {
        if let Some(event) = controller.next_event_ffi(1_000) {
            if let SessionEvent::Fatal { message } = &event {
                return Err(format!("fatal: {message}"));
            }
            if want(&event) {
                return Ok(event);
            }
        }
    }
    Err("timed out waiting for event".to_string())
}

#[test]
#[ignore = "needs live Tor connectivity"]
fn self_send_over_real_tor() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!("umbra-ffi-session-live-{nanos}"));
    std::fs::create_dir_all(&base)?;
    let keystore = base.join("keystore.bin");
    let keystore_str = keystore.to_str().ok_or("non-UTF8 path")?;

    let controller = LiveController::new();
    controller.create_identity_ffi(keystore_str.to_string(), "live-test-passphrase".to_string())?;
    controller.start_session_ffi("umbralive".to_string())?;

    let ready = wait_for(&controller, Duration::from_secs(400), |event| {
        matches!(event, SessionEvent::Ready { .. })
    })?;
    let SessionEvent::Ready { address } = ready else {
        return Err("unreachable".into());
    };
    println!("ready (address redacted, {} chars)", address.len());

    let payload = controller.pairing_payload_ffi()?;
    controller.confirm_peer_ffi("selfpeer".to_string(), payload, Some(address))?;
    controller.send_message_ffi(
        "selfpeer".to_string(),
        "hello-from-the-live-test".to_string(),
    )?;

    let mut got_sent = false;
    let mut got_text = false;
    let started = Instant::now();
    let end = started
        .checked_add(Duration::from_secs(300))
        .ok_or("deadline overflow")?;
    while Instant::now() < end && !(got_sent && got_text) {
        let event = controller.next_event_ffi(1_000);
        if let Some(event) = &event {
            println!("[{:>3}s] {}", started.elapsed().as_secs(), describe(event));
        }
        match event {
            Some(SessionEvent::Sent { .. }) => got_sent = true,
            Some(SessionEvent::Inbound { text }) if text == "hello-from-the-live-test" => {
                got_text = true;
            }
            Some(SessionEvent::Fatal { message }) => {
                return Err(format!("fatal: {message}").into());
            }
            _ => {}
        }
    }
    controller.stop_session_ffi();
    let _ = std::fs::remove_dir_all(&base);
    assert!(got_sent, "no Sent event");
    assert!(got_text, "no Inbound event with the sent text");
    Ok(())
}
