//! Poisson cover-traffic pump (ADR-005, TODO A.3).
//!
//! Bridges the protocol layer's Poisson scheduler ([`PoissonScheduler`],
//! `umbra_protocol::cover`) to a [`Transport`]: on a Poisson-distributed
//! schedule the pump asks its packet source for a sealed `DUMMY_COVER`
//! packet and pushes it onto the wire.
//!
//! Honest scope: this pump is the ADR-005 baseline (fixed-size + Poisson
//! timing). Classifier-level traffic fingerprinting additionally requires
//! WTF-PAD Markov adaptive padding (TARGETED_DEFENSES §3A), which remains
//! v2+ scope (ADR-027) — this pump alone does not defeat it.
//!
//! Key discipline: the source MUST seal cover packets under the per-session
//! packet key (`umbra_protocol::session::Session::cover_packet`). A fixed
//! or global key would make cover traffic distinguishable and forgeable —
//! a cross-user linkability failure (SPECIFICATION opcode 0x04 premise).
//!
//! Pre-pairing transition leak (unavoidable, documented): before a session
//! exists the source yields `Ok(None)` and no packet is sent — an observer
//! can infer "no established session" from silence. The schedule starts
//! with the session and stops at teardown (TODO A.3 wiring).
//!
//! ADR-006 deviation (recorded): transient send failures are swallowed
//! (`let _ = send`) — cover traffic must not reveal link health. The
//! source error path is the only terminal one.

use std::sync::Arc;
use std::time::Duration;

use umbra_protocol::cover::PoissonScheduler;
use umbra_protocol::packet::SealedPacket;

use crate::addr::OnionAddr;
use crate::error::TransportError;
use crate::transport::Transport;

/// A running cover-traffic pump. Dropping it does NOT stop the task; call
/// [`CoverPump::stop`] for a deterministic shutdown.
pub struct CoverPump {
    /// Handle to the pump task; aborted on stop.
    handle: tokio::task::JoinHandle<()>,
}

impl CoverPump {
    /// Spawns the pump: on a Poisson schedule, produces a packet via
    /// `source` and sends it to `peer`.
    ///
    /// Source contract: `Err(_)` aborts the pump (transport is broken);
    /// `Ok(None)` skips the tick (no session); `Ok(Some(packet))` is sent.
    /// Sends that fail with a *transient* transport error do not stop the
    /// pump — only a source error does; the scheduler retimes the next
    /// tick from the moment the previous tick completed.
    #[must_use]
    pub fn spawn<T, S, Fut>(
        transport: Arc<T>,
        peer: OnionAddr,
        scheduler: PoissonScheduler,
        mut source: S,
    ) -> Self
    where
        T: Transport + 'static,
        S: FnMut() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<Option<SealedPacket>, TransportError>> + Send,
    {
        let handle = tokio::spawn(async move {
            loop {
                // The next delay is sampled after each tick completes, so
                // the long-run rate matches the scheduler's mean.
                // Degenerate scheduler: stop silently. Silence itself is
                // not observable as an error on the wire, and the owner can
                // poll `finished()` — swallowed only in the internal-loop
                // sense, never on a data path.
                let Ok(delay) = scheduler.next_delay() else {
                    return;
                };
                tokio::time::sleep(delay).await;
                match source().await {
                    Ok(Some(packet)) => {
                        // Transient send failures do not stop the pump:
                        // cover traffic must not reveal link health.
                        let _ = transport.send(&peer, &packet).await;
                    }
                    Ok(None) => {}     // no session: skip the tick.
                    Err(_e) => return, // transport broken: stop.
                }
            }
        });
        Self { handle }
    }

    /// Deterministically stops the pump at the next await point.
    pub fn stop(self) {
        self.handle.abort();
    }

    /// Whether the pump task has finished (stopped or errored out).
    #[must_use]
    pub fn finished(&self) -> bool {
        self.handle.is_finished()
    }
}

/// Convenience: how many ticks a pump at `rate_hz` should emit during
/// `window` — used by tests to pick sane windows.
#[must_use]
pub fn expected_ticks(rate_hz: f64, window: Duration) -> f64 {
    rate_hz * window.as_secs_f64()
}
