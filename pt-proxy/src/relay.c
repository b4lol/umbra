/*
 * umbra-pt-proxy — the obfs4 tunnel relay. See relay.h for the
 * architecture notes and the security invariants.
 */

#include "relay.h"

#include "obfs4_frame.h"
#include "obfs4_packet.h"

#include <errno.h>
#include <poll.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Handshake read deadline on the upstream socket (bridges can be slow;
 * the SOCKS5-phase 10 s deadline stays what it is). */
#define RELAY_HANDSHAKE_TIMEOUT_SEC 30
/* Relay idle bound per direction (matches umbra-net's
 * READ_IDLE_TIMEOUT): a tunnel silent for 5 minutes is torn down. */
#define RELAY_IDLE_TIMEOUT_MS 300000

/* Client read burst: one burst = one padding sample (Go Write parity). */
#define RELAY_CLIENT_CHUNK (16u * OBFS4_MAX_PACKET_PAYLOAD)
/* Upstream accumulation buffer: many frames, bounded; a full buffer
 * with no decodable frame is a protocol error. */
#define RELAY_UPSTREAM_BUF (16u * OBFS4_MAX_SEGMENT_LEN)

/* Writes the whole buffer or fails (EINTR-retried). */
static int write_full(int fd, const uint8_t *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, buf + done, len - done);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}

/* Runs the client handshake on the upstream socket. On success `keys`
 * holds the session keys and the bytes past the handshake are left in
 * `rest`/`rest_len` for the frame decoder. The SOCKS5 client socket is
 * watched alongside — but only for a genuine hangup: because the SOCKS5
 * success reply is sent before the handshake completes, the client MAY
 * already be piping payload at us, and that data must neither abort the
 * handshake nor be consumed (MSG_PEEK). Returns 0 on success. */
static int relay_handshake(int upstream_fd, int client_fd,
                           const Obfs4BridgeCert *cert,
                           Obfs4SessionKeys *keys, uint8_t *rest,
                           size_t *rest_len)
{
    static uint8_t request[OBFS4_CLIENT_MIN_HANDSHAKE_LEN +
                           OBFS4_CLIENT_MAX_PAD_LEN];
    static uint8_t resp[OBFS4_MAX_HANDSHAKE_LEN];
    Obfs4ClientHandshake hs;
    size_t request_len = 0;
    size_t resp_len = 0;
    size_t consumed = 0;
    int poll_client = 1;
    int rc = -1;

    *rest_len = 0;
    if (obfs4_client_init(&hs, cert) != OBFS4_OK) {
        return -1;
    }
    if (obfs4_client_request(&hs, request, sizeof(request), &request_len) !=
            OBFS4_OK ||
        write_full(upstream_fd, request, request_len) != 0) {
        goto out;
    }

    for (;;) {
        struct pollfd fds[2];
        ssize_t n = 0;
        Obfs4Status st;
        int ready;

        if (resp_len >= sizeof(resp)) {
            goto out; /* full buffer without a valid mark: fatal */
        }

        fds[0].fd = upstream_fd;
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        fds[1].fd = poll_client ? client_fd : -1;
        fds[1].events = POLLIN;
        fds[1].revents = 0;
        ready = poll(fds, 2, RELAY_HANDSHAKE_TIMEOUT_SEC * 1000);
        if (ready <= 0) {
            if (ready < 0 && errno == EINTR) {
                continue;
            }
            goto out; /* handshake deadline or poll error */
        }
        if (fds[1].revents != 0) {
            uint8_t peek;
            ssize_t p = recv(client_fd, &peek, 1, MSG_PEEK);
            if (p <= 0) {
                goto out; /* EOF or error: the client is gone */
            }
            /* Early payload: legal, must not be consumed here; stop
             * polling the client (the data stays queued for the relay
             * loop) and keep waiting for the handshake. */
            poll_client = 0;
        }
        if (fds[0].revents == 0) {
            continue;
        }
        n = read(upstream_fd, resp + resp_len, sizeof(resp) - resp_len);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) {
                continue;
            }
            goto out; /* EOF or error */
        }
        resp_len += (size_t)n;

        st = obfs4_client_finish(&hs, resp, resp_len, keys, &consumed);
        if (st == OBFS4_AGAIN) {
            continue;
        }
        if (st != OBFS4_OK) {
            goto out;
        }
        break;
    }

    memcpy(rest, resp + consumed, resp_len - consumed);
    *rest_len = resp_len - consumed;
    rc = 0;

out:
    sodium_memzero(request, sizeof(request));
    sodium_memzero(resp, sizeof(resp));
    obfs4_client_wipe(&hs);
    return rc;
}

/* Drains any unconsumed client bytes before the socket is closed:
 * data left in the receive buffer turns close(2) into a RST, which
 * surfaces to the SOCKS5 client as ECONNRESET instead of a clean EOF.
 * Bounded — a peer that keeps flooding gets its RST anyway. */
static void relay_drain_client(int client_fd)
{
    uint8_t sink[4096];
    int i;

    for (i = 0; i < 16; i++) {
        if (recv(client_fd, sink, sizeof(sink), MSG_DONTWAIT) <= 0) {
            break;
        }
    }
    sodium_memzero(sink, sizeof(sink));
}

/* Encodes one client burst (payload chunks + one padding burst) and
 * writes it upstream. Returns 0 on success. */
static int relay_client_burst(Obfs4FrameEncoder *enc, const uint8_t *data,
                              size_t data_len, int upstream_fd)
{
    static uint8_t out[RELAY_CLIENT_CHUNK + OBFS4_MAX_SEGMENT_LEN +
                       2u * OBFS4_MAX_SEGMENT_LEN];
    size_t used = 0;
    size_t off = 0;
    size_t n = 0;

    while (off < data_len) {
        size_t chunk = data_len - off;
        if (chunk > OBFS4_MAX_PACKET_PAYLOAD) {
            chunk = OBFS4_MAX_PACKET_PAYLOAD;
        }
        if (obfs4_packet_encode(enc, OBFS4_PACKET_TYPE_PAYLOAD, data + off,
                                chunk, 0u, out + used, sizeof(out) - used,
                                &n) != OBFS4_OK) {
            sodium_memzero(out, sizeof(out));
            return -1;
        }
        used += n;
        off += chunk;
    }
    /* One padding burst per write burst (Go iat-mode-0 parity; uniform
     * sample instead of the Go probdist — a documented traffic-shape
     * deviation, wire-compatible). */
    if (obfs4_packet_padburst(enc, used,
                              (uint16_t)randombytes_uniform(
                                  OBFS4_MAX_SEGMENT_LEN),
                              out + used, sizeof(out) - used,
                              &n) != OBFS4_OK) {
        sodium_memzero(out, sizeof(out));
        return -1;
    }
    used += n;

    if (write_full(upstream_fd, out, used) != 0) {
        sodium_memzero(out, sizeof(out));
        return -1;
    }
    sodium_memzero(out, sizeof(out));
    return 0;
}

/* Decodes every complete frame in the accumulate buffer and delivers
 * payloads to the client. Returns 0 on success, -1 on a fatal
 * protocol/crypto error. */
static int relay_drain_upstream(Obfs4FrameDecoder *dec, uint8_t *buf,
                                size_t *buf_len, int client_fd)
{
    uint8_t decoded[OBFS4_MAX_FRAME_PAYLOAD];

    for (;;) {
        Obfs4PacketKind kind;
        const uint8_t *payload = NULL;
        size_t payload_len = 0;
        size_t decoded_len = 0;
        Obfs4Status st =
            obfs4_frame_decode(dec, buf, buf_len, decoded, &decoded_len);

        if (st == OBFS4_AGAIN) {
            sodium_memzero(decoded, sizeof(decoded));
            return 0;
        }
        if (st != OBFS4_OK) {
            sodium_memzero(decoded, sizeof(decoded));
            return -1;
        }
        if (obfs4_packet_parse(decoded, decoded_len, &kind, &payload,
                               &payload_len) != OBFS4_OK) {
            sodium_memzero(decoded, sizeof(decoded));
            return -1;
        }
        if (kind == OBFS4_PKT_PAYLOAD && payload_len > 0u &&
            write_full(client_fd, payload, payload_len) != 0) {
            sodium_memzero(decoded, sizeof(decoded));
            return -1;
        }
        sodium_memzero(decoded, sizeof(decoded));
    }
}

void relay_run(int client_fd, int upstream_fd, const Obfs4BridgeCert *cert)
{
    Obfs4SessionKeys keys;
    Obfs4FrameEncoder enc;
    Obfs4FrameDecoder dec;
    static uint8_t client_buf[RELAY_CLIENT_CHUNK];
    static uint8_t up_buf[RELAY_UPSTREAM_BUF];
    size_t up_len = 0;

    if (relay_handshake(upstream_fd, client_fd, cert, &keys, up_buf,
                        &up_len) != 0) {
        fprintf(stderr, "umbra-pt-proxy: obfs4 handshake failed\n");
        sodium_memzero(&keys, sizeof(keys));
        relay_drain_client(client_fd);
        return;
    }
    obfs4_frame_encoder_init(&enc, &keys.send);
    obfs4_frame_decoder_init(&dec, &keys.recv);
    obfs4_session_keys_wipe(&keys);

    /* Bytes past the handshake mark may already hold frames (the seed
     * packet rides the server response burst). */
    if (relay_drain_upstream(&dec, up_buf, &up_len, client_fd) != 0) {
        goto out;
    }

    for (;;) {
        struct pollfd fds[2];
        int ready;

        fds[0].fd = client_fd;
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        fds[1].fd = upstream_fd;
        fds[1].events = POLLIN;
        fds[1].revents = 0;

        ready = poll(fds, 2, RELAY_IDLE_TIMEOUT_MS);
        if (ready <= 0) {
            if (ready < 0 && errno == EINTR) {
                continue;
            }
            break; /* idle timeout or poll error */
        }

        /* Client -> bridge. */
        if (fds[0].revents != 0) {
            ssize_t n;
            if ((fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                break;
            }
            n = read(client_fd, client_buf, sizeof(client_buf));
            if (n <= 0) {
                break; /* EOF/error: obfs4 has no close frame */
            }
            if (relay_client_burst(&enc, client_buf, (size_t)n,
                                   upstream_fd) != 0) {
                break;
            }
        }

        /* Bridge -> client. */
        if (fds[1].revents != 0) {
            ssize_t n;
            if ((fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                break;
            }
            if (up_len >= sizeof(up_buf)) {
                break; /* full buffer, no decodable frame: fatal */
            }
            n = read(upstream_fd, up_buf + up_len, sizeof(up_buf) - up_len);
            if (n <= 0) {
                break;
            }
            up_len += (size_t)n;
            if (relay_drain_upstream(&dec, up_buf, &up_len, client_fd) !=
                0) {
                break;
            }
        }
    }

out:
    relay_drain_client(client_fd);
    obfs4_frame_encoder_wipe(&enc);
    obfs4_frame_decoder_wipe(&dec);
    sodium_memzero(client_buf, sizeof(client_buf));
    sodium_memzero(up_buf, sizeof(up_buf));
}
