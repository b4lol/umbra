/*
 * umbra-pt-proxy — the obfs4 tunnel relay.
 *
 * After the SOCKS5 upstream dial succeeds, this module runs the obfs4
 * client handshake on the upstream socket and then shuttles bytes both
 * ways: client plaintext is chopped into payload packets, padded per
 * the length distribution and framed; upstream frames are decoded,
 * parsed as packets and their payloads delivered to the client.
 *
 * Traffic shaping (iat-mode, roadmap step 5):
 *  - Every connection seeds a length distribution (probdist over
 *    [0, 1448]) locally; the bridge's PRNG-seed packet RESETS it (and
 *    the iat distribution, via SHA-256(seed)) so both ends share the
 *    server's shape — Go parity.
 *  - iat-mode 0/1: one padding burst per read burst, target
 *    lenDist.Sample(). Mode 0 then writes immediately.
 *  - iat-mode 1: the burst is written in ≤1448-byte chunks with a
 *    sampled inter-chunk delay (iatDist.Sample() * 100 µs).
 *  - iat-mode 2 (paranoid): every chunk length is sampled from lenDist;
 *    the burst tail is padded UP to the target (Go padBurst semantics,
 *    resample on wrap) — a sampled 0 is skipped because it cannot make
 *    progress (Go panics there; we resample, a documented deviation).
 *    Mode-2 bursts are queued RAW and encoded only when they reach the
 *    head of the queue: the per-chunk pad-ups are encoded at flush
 *    time, so the payload frames must be encoded at flush time too —
 *    otherwise a later burst would advance the framing DRBG before an
 *    earlier burst's pad frames and the wire stream would desync.
 *  - Delays are SCHEDULED, never slept inline: this is a single-threaded
 *    poll loop, so a sleep would stall the reverse direction. Chunks
 *    sit in a bounded pending queue with monotonic deadlines; the poll
 *    timeout is clamped to the next deadline. Delays quantize UP to
 *    whole milliseconds (poll granularity) — shape-preserving.
 *
 * Teardown policy matches the Go reference: obfs4 has no close frame,
 * so EOF or any error on EITHER side tears the whole tunnel down.
 *
 * Security invariants:
 *  1. Fixed-size buffers; the upstream accumulation buffer is bounded
 *     and a full buffer without frame progress is fatal; the pending
 *     write queue is bounded and applies backpressure (the client fd is
 *     masked out of the poll set while it is full).
 *  2. The handshake is deadline-guarded; the relay loop has a
 *     per-direction idle bound.
 *  3. Handshake state, session keys, shaping state and queue contents
 *     are wiped on every exit path.
 */

#ifndef UMBRA_PT_RELAY_H
#define UMBRA_PT_RELAY_H

#include "obfs4.h"

/* Runs the obfs4 handshake on `upstream_fd` and relays until EOF,
 * error, or idle timeout. `iat_mode` is the bridge line's iat-mode
 * (0/1/2, validated at startup). Never returns a status: all failures
 * are logged and both sockets are left for the caller to close. */
void relay_run(int client_fd, int upstream_fd, const Obfs4BridgeCert *cert,
               int iat_mode);

#endif /* UMBRA_PT_RELAY_H */
