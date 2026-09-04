/*
 * umbra-pt-proxy — SOCKS5 front-end (RFC 1928), no-auth, CONNECT only.
 *
 * Role in the architecture (ADR-030): arti connects here over loopback
 * and asks for a CONNECT to the bridge address; the accepted upstream
 * socket is then wrapped in the obfs4 handshake and the tunnel is
 * relayed (relay.c) — the client's Tor bytes never touch the upstream
 * in plaintext.
 *
 * Security invariants:
 *  1. Every read is length-prefixed and bounded (greeting 2+255,
 *     request ≤ 4+1+255+2); a short/oversized frame is a protocol
 *     error, never a buffer overrun.
 *  2. Per-connection I/O deadlines (SO_RCVTIMEO/SO_SNDTIMEO): a stalled
 *     client cannot pin a worker forever.
 *  3. Upstream connect is bounded (non-blocking + poll).
 *  4. Only CONNECT is supported; BIND/UDP ASSOCIATE get 0x07.
 */

#ifndef UMBRA_PT_SOCKS5_H
#define UMBRA_PT_SOCKS5_H

#include "obfs4.h"

/* Handles one accepted loopback connection end to end (greeting,
 * CONNECT, bounded upstream dial, reply, obfs4 relay, teardown). Never
 * returns a status: all failures are logged and the connection is
 * closed — the caller owns no error path. `cert` is the bridge's obfs4
 * certificate (validated once at startup). */
void socks5_handle(int conn_fd, const Obfs4BridgeCert *cert);

#endif /* UMBRA_PT_SOCKS5_H */
