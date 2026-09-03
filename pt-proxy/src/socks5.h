/*
 * umbra-pt-proxy — SOCKS5 front-end (RFC 1928), no-auth, CONNECT only.
 *
 * Role in the architecture (ADR-030): arti connects here over loopback
 * and asks for a CONNECT to the bridge address; once the obfs4 protocol
 * lands, the accepted upstream socket is wrapped in the obfs4 handshake
 * before any Tor byte flows. UNTIL THEN the relay is disabled: a
 * successful dial is answered and immediately torn down with a stderr
 * diagnostic, so a misconfigured client sees a fast, visible failure
 * instead of a silent plaintext path.
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

/* Handles one accepted loopback connection end to end (greeting,
 * CONNECT, bounded upstream dial, reply, teardown). Never returns a
 * status: all failures are logged and the connection is closed — the
 * caller owns no error path. */
void socks5_handle(int conn_fd);

#endif /* UMBRA_PT_SOCKS5_H */
