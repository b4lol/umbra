//! LIVE-NETWORK host-side peer for on-device verification (`#[ignore]`).
//!
//! Plays the "other end" for the Android app: unlocks an existing keystore
//! (created by `umbra init`, so this also proves CLI-keystore compatibility),
//! runs a real Tor session, and is driven through files in `UMBRA_P2E_DIR`:
//!
//! * writes `address.txt` once its onion service is published;
//! * appends every inbound message to `inbox.log` (`[secs] text`);
//! * sends the content of `outbox.txt` to the peer named in `UMBRA_P2E_PEER`
//!   (default `phone`), then deletes it and logs the outcome in `events.log`;
//! * if `UMBRA_P2E_PING_MINUTES` is set, sends `ping <n>` to the peer every that many
//!   minutes (the soak test: the phone's feed shows which pings arrived promptly);
//! * exits when `stop` appears or after `UMBRA_P2E_MINUTES` (default 45).
//!
//! Needed because the CLI's `serve`/`send` call `mlockall`, which the dev
//! sandbox's 8 MiB `RLIMIT_MEMLOCK` rejects. Run manually:
//! `UMBRA_P2E_DIR=... UMBRA_P2E_PASS=... cargo test -p umbra-ffi --features tor
//!  --test host_peer_live -- --ignored --nocapture`.
#![cfg(feature = "tor")]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use umbra_native::{LiveController, SessionEvent};

/// Appends one line to a log file (best effort).
fn log_line(path: &std::path::Path, line: &str) {
    use std::io::Write as _;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{line}");
    }
}

#[test]
#[ignore = "needs live Tor connectivity and an external driver"]
fn host_peer() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dir = PathBuf::from(std::env::var("UMBRA_P2E_DIR")?);
    let pass = std::env::var("UMBRA_P2E_PASS")?;
    let peer = std::env::var("UMBRA_P2E_PEER").unwrap_or_else(|_| "phone".to_string());
    let minutes: u64 = std::env::var("UMBRA_P2E_MINUTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(45);
    let keystore = dir.join("ks");
    let events_log = dir.join("events.log");
    let inbox_log = dir.join("inbox.log");

    let controller = LiveController::new();
    controller.unlock_identity_ffi(keystore.to_str().ok_or("non-UTF8 path")?.to_string(), pass)?;
    controller.start_session_ffi("umbrahost".to_string())?;

    let ping_every: Option<Duration> = std::env::var("UMBRA_P2E_PING_MINUTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|minutes| *minutes > 0)
        .map(|minutes| Duration::from_secs(minutes.saturating_mul(60)));
    let mut next_ping: Option<Instant> = None;
    let mut ping_count: u32 = 0;
    let started = Instant::now();
    let end = started
        .checked_add(Duration::from_secs(minutes.saturating_mul(60)))
        .ok_or("deadline overflow")?;
    while Instant::now() < end && !dir.join("stop").exists() {
        if let Some(event) = controller.next_event_ffi(1_000) {
            let secs = started.elapsed().as_secs();
            match &event {
                SessionEvent::Ready { address } => {
                    std::fs::write(dir.join("address.txt"), address)?;
                    log_line(&events_log, &format!("[{secs}s] Ready"));
                }
                SessionEvent::Inbound { text } => {
                    log_line(&inbox_log, &format!("[{secs}s] {text}"));
                    log_line(
                        &events_log,
                        &format!("[{secs}s] Inbound({} chars)", text.len()),
                    );
                }
                SessionEvent::Sent { frames, bytes, .. } => {
                    log_line(
                        &events_log,
                        &format!("[{secs}s] Sent({frames} frames, {bytes} bytes)"),
                    );
                }
                SessionEvent::SendError { message, .. } => {
                    log_line(&events_log, &format!("[{secs}s] SendError: {message}"));
                }
                SessionEvent::SessionError { message } => {
                    log_line(&events_log, &format!("[{secs}s] SessionError: {message}"));
                }
                SessionEvent::Fatal { message } => {
                    log_line(&events_log, &format!("[{secs}s] Fatal: {message}"));
                    return Err(format!("fatal: {message}").into());
                }
                SessionEvent::Bootstrapping => {
                    log_line(&events_log, &format!("[{secs}s] Bootstrapping"));
                }
            }
        }
        if let Some(every) = ping_every {
            let due = *next_ping.get_or_insert_with(|| {
                Instant::now()
                    .checked_add(every)
                    .unwrap_or_else(Instant::now)
            });
            if Instant::now() >= due {
                ping_count = ping_count.saturating_add(1);
                let secs = started.elapsed().as_secs();
                match controller.send_message_ffi(peer.clone(), format!("ping {ping_count}")) {
                    Ok(()) => log_line(&events_log, &format!("[{secs}s] ping {ping_count} queued")),
                    Err(error) => log_line(
                        &events_log,
                        &format!("[{secs}s] ping {ping_count} rejected: {error}"),
                    ),
                }
                next_ping = Instant::now().checked_add(every);
            }
        }
        let outbox = dir.join("outbox.txt");
        if outbox.exists() {
            let text = std::fs::read_to_string(&outbox)?;
            std::fs::remove_file(&outbox)?;
            let secs = started.elapsed().as_secs();
            match controller.send_message_ffi(peer.clone(), text.trim_end().to_string()) {
                Ok(()) => log_line(&events_log, &format!("[{secs}s] send queued")),
                Err(error) => log_line(&events_log, &format!("[{secs}s] send rejected: {error}")),
            }
        }
    }
    controller.stop_session_ffi();
    Ok(())
}
