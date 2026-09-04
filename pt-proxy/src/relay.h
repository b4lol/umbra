/*
 * umbra-pt-proxy — the obfs4 tunnel relay.
 *
 * After the SOCKS5 upstream dial succeeds, this module runs the obfs4
 * client handshake on the upstream socket and then shuttles bytes both
 * ways: client plaintext is chopped into payload packets (one padding
 * burst per read burst, Go iat-mode-0 parity) and framed; upstream
 * frames are decoded, parsed as packets and their payloads delivered
 * to the client. The bridge's PRNG-seed packet is accepted and ignored
 * (we do no length shaping).
 *
 * Teardown policy matches the Go reference: obfs4 has no close frame,
 * so EOF or any error on EITHER side tears the whole tunnel down.
 *
 * Security invariants:
 *  1. Fixed-size buffers; the upstream accumulation buffer is bounded
 *     and a full buffer without frame progress is fatal.
 *  2. The handshake is deadline-guarded; the relay loop has a
 *     per-direction idle bound.
 *  3. Handshake state, session keys and framing state are wiped on
 *     every exit path.
 */

#ifndef UMBRA_PT_RELAY_H
#define UMBRA_PT_RELAY_H

#include "obfs4.h"

/* Runs the obfs4 handshake on `upstream_fd` and relays until EOF,
 * error, or idle timeout. Never returns a status: all failures are
 * logged and both sockets are left for the caller to close. */
void relay_run(int client_fd, int upstream_fd, const Obfs4BridgeCert *cert);

#endif /* UMBRA_PT_RELAY_H */
